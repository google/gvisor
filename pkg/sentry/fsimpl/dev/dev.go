// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dev provides a filesystem implementation for /dev.
package dev

import (
	"fmt"
	"path"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Name is the dev filesystem name.
const Name = "dev"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fst FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, source /* source */, tmpfs.Name, &vfs.MountOptions{GetFilesystemOptions: vfs.GetFilesystemOptions{
		Data: "mode=0755", // opts from drivers/base/devtmpfs.c:devtmpfs_init()
	}}, nil)
	if err != nil {
		return nil, nil, err
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	iopts, _ := opts.InternalData.(InternalData) // If not provided, zero value is OK.

	// Initialize contents.
	if err := userspaceInit(ctx, vfsObj, creds, root, iopts.ShmMode); err != nil {
		return nil, nil, err
	}
	if err := vfsObj.ForEachDevice(func(pathname string, kind vfs.DeviceKind, major, minor uint32, perms uint16) error {
		if pathname == "" {
			return nil
		}
		mode := linux.FileMode(perms)
		switch kind {
		case vfs.CharDevice:
			mode |= linux.S_IFCHR
		case vfs.BlockDevice:
			mode |= linux.S_IFBLK
		default:
			panic(fmt.Sprintf("invalid DeviceKind: %v", kind))
		}
		return CreateDeviceFile(ctx, vfsObj, creds, root, pathname, major, minor, mode, nil /* uid */, nil /* gid */)
	}); err != nil {
		return nil, nil, err
	}

	root.Mount().Filesystem().IncRef()
	root.Dentry().IncRef()
	return root.Mount().Filesystem(), root.Dentry(), nil
}

// Release implements vfs.FilesystemType.Release.
func (fst *FilesystemType) Release(ctx context.Context) {}

// InternalData contains internal data passed in via vfs.GetFilesystemOptions.
type InternalData struct {
	// ShmMode indicates the mode to create the /dev/shm dir with.
	ShmMode *uint16
}

func pathOperationAt(root vfs.VirtualDentry, pathname string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(pathname),
	}
}

// CreateDeviceFile creates a device special file at the given pathname from root.
func CreateDeviceFile(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, pathname string, major, minor uint32, mode linux.FileMode, uid, gid *uint32) error {
	// Create any parent directories. See
	// devtmpfs.c:handle_create()=>create_path().
	parent := path.Dir(pathname)
	if err := vfsObj.MkdirAllAt(ctx, parent, root, creds, &vfs.MkdirOptions{
		Mode: 0755,
	}, true /* mustBeDir */); err != nil {
		return fmt.Errorf("failed to create device parent directory %q: %v", parent, err)
	}
	created := true
	pop := pathOperationAt(root, pathname)
	if err := vfsObj.MknodAt(ctx, creds, pop, &vfs.MknodOptions{Mode: mode, DevMajor: major, DevMinor: minor}); err != nil {
		if linuxerr.Equals(linuxerr.EEXIST, err) {
			// EEXIST is silently ignored; compare
			// opencontainers/runc:libcontainer/rootfs_linux.go:createDeviceNode().
			created = false
		} else {
			return fmt.Errorf("failed to create device file at %q: %w", pathname, err)
		}
	}
	if created && (uid != nil || gid != nil) {
		var opts vfs.SetStatOptions
		if uid != nil {
			opts.Stat.Mask |= linux.STATX_UID
			opts.Stat.UID = *uid
		}
		if gid != nil {
			opts.Stat.Mask |= linux.STATX_GID
			opts.Stat.GID = *gid
		}
		if err := vfsObj.SetStatAt(ctx, creds, pop, &opts); err != nil {
			return fmt.Errorf("failed to set UID/GID for device file %q: %w", pathname, err)
		}
	}
	return nil
}

// userspaceInit creates symbolic links and mount points in the devtmpfs
// instance that are created by userspace in Linux. It does not create mounts.
func userspaceInit(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, shmMode *uint16) error {
	// Initialize symlinks.
	for _, symlink := range []struct {
		source string
		target string
	}{
		// systemd: src/shared/dev-setup.c:dev_setup()
		{source: "fd", target: "/proc/self/fd"},
		{source: "stdin", target: "/proc/self/fd/0"},
		{source: "stdout", target: "/proc/self/fd/1"},
		{source: "stderr", target: "/proc/self/fd/2"},
		// /proc/kcore is not implemented.

		// Linux implements /dev/ptmx as a device node, but advises
		// container implementations to create /dev/ptmx as a symlink
		// to pts/ptmx (Documentation/filesystems/devpts.txt). Systemd
		// follows this advice (src/nspawn/nspawn.c:setup_pts()), while
		// LXC tries to create a bind mount and falls back to a symlink
		// (src/lxc/conf.c:lxc_setup_devpts()).
		{source: "ptmx", target: "pts/ptmx"},
	} {
		if err := vfsObj.SymlinkAt(ctx, creds, pathOperationAt(root, symlink.source), symlink.target); err != nil {
			return fmt.Errorf("failed to create symlink %q => %q: %v", symlink.source, symlink.target, err)
		}
	}

	// systemd: src/core/mount-setup.c:mount_table
	for _, dir := range []string{
		"shm",
		"pts",
	} {
		// "The access mode here doesn't really matter too much, since the
		// mounted file system will take precedence anyway"
		//   - systemd: src/core/mount-setup.c:mount_one()
		accessMode := linux.FileMode(0755)
		if shmMode != nil && dir == "shm" {
			accessMode = linux.FileMode(*shmMode)
		}
		if err := vfsObj.MkdirAt(ctx, creds, pathOperationAt(root, dir), &vfs.MkdirOptions{
			Mode: accessMode,
		}); err != nil {
			return fmt.Errorf("failed to create directory %q: %v", dir, err)
		}
	}

	return nil
}
