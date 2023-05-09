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

// Package devtmpfs provides an implementation of /dev based on tmpfs,
// analogous to Linux's devtmpfs.
package devtmpfs

import (
	"fmt"
	"path"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Name is the default filesystem name.
const Name = "devtmpfs"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct {
	initOnce sync.Once `state:"nosave"` // FIXME(gvisor.dev/issue/1663): not yet supported.
	initErr  error

	// fs is the tmpfs filesystem that backs all mounts of this FilesystemType.
	// root is fs' root. fs and root are immutable.
	fs   *vfs.Filesystem
	root *vfs.Dentry
}

// Name implements vfs.FilesystemType.Name.
func (*FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fst *FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fst.initOnce.Do(func() {
		fs, root, err := tmpfs.FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, "" /* source */, vfs.GetFilesystemOptions{
			Data: "mode=0755", // opts from drivers/base/devtmpfs.c:devtmpfs_init()
		})
		if err != nil {
			fst.initErr = err
			return
		}
		fst.fs = fs
		fst.root = root
	})
	if fst.initErr != nil {
		return nil, nil, fst.initErr
	}
	fst.fs.IncRef()
	fst.root.IncRef()
	return fst.fs, fst.root, nil
}

// Release implements vfs.FilesystemType.Release.
func (fst *FilesystemType) Release(ctx context.Context) {
	if fst.fs != nil {
		// Release the original reference obtained when creating the filesystem.
		fst.root.DecRef(ctx)
		fst.fs.DecRef(ctx)
	}
}

// Accessor allows devices to create device special files in devtmpfs.
type Accessor struct {
	vfsObj *vfs.VirtualFilesystem
	mntns  *vfs.MountNamespace
	root   vfs.VirtualDentry
	creds  *auth.Credentials
}

// NewAccessor returns an Accessor that supports creation of device special
// files in the devtmpfs instance registered with name fsTypeName in vfsObj.
func NewAccessor(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, fsTypeName string) (*Accessor, error) {
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "devtmpfs" /* source */, fsTypeName, &vfs.MountOptions{})
	if err != nil {
		return nil, err
	}
	// Pass a reference on root to the Accessor.
	root := mntns.Root()
	root.IncRef()
	return &Accessor{
		vfsObj: vfsObj,
		mntns:  mntns,
		root:   root,
		creds:  creds,
	}, nil
}

// Release must be called when a is no longer in use.
func (a *Accessor) Release(ctx context.Context) {
	a.root.DecRef(ctx)
	a.mntns.DecRef(ctx)
}

// accessorContext implements context.Context by extending an existing
// context.Context with an Accessor's values for VFS-relevant state.
type accessorContext struct {
	context.Context
	a *Accessor
}

func (a *Accessor) wrapContext(ctx context.Context) *accessorContext {
	return &accessorContext{
		Context: ctx,
		a:       a,
	}
}

// Value implements context.Context.Value.
func (ac *accessorContext) Value(key any) any {
	switch key {
	case vfs.CtxMountNamespace:
		ac.a.mntns.IncRef()
		return ac.a.mntns
	case vfs.CtxRoot:
		ac.a.root.IncRef()
		return ac.a.root
	default:
		return ac.Context.Value(key)
	}
}

func (a *Accessor) pathOperationAt(pathname string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  a.root,
		Start: a.root,
		Path:  fspath.Parse(pathname),
	}
}

// CreateDeviceFile creates a device special file at the given pathname in the
// devtmpfs instance accessed by the Accessor.
func (a *Accessor) CreateDeviceFile(ctx context.Context, pathname string, kind vfs.DeviceKind, major, minor uint32, perms uint16) error {
	actx := a.wrapContext(ctx)

	mode := (linux.FileMode)(perms)
	switch kind {
	case vfs.BlockDevice:
		mode |= linux.S_IFBLK
	case vfs.CharDevice:
		mode |= linux.S_IFCHR
	default:
		panic(fmt.Sprintf("invalid vfs.DeviceKind: %v", kind))
	}

	// Create any parent directories. See
	// devtmpfs.c:handle_create()=>path_create().
	parent := path.Dir(pathname)
	if err := a.vfsObj.MkdirAllAt(ctx, parent, a.root, a.creds, &vfs.MkdirOptions{
		Mode: 0755,
	}); err != nil {
		return fmt.Errorf("failed to create device parent directory %q: %v", parent, err)
	}

	// NOTE: Linux's devtmpfs refuses to automatically delete files it didn't
	// create, which it recognizes by storing a pointer to the kdevtmpfs struct
	// thread in struct inode::i_private. Accessor doesn't yet support deletion
	// of files at all, and probably won't as long as we don't need to support
	// kernel modules, so this is moot for now.
	return a.vfsObj.MknodAt(actx, a.creds, a.pathOperationAt(pathname), &vfs.MknodOptions{
		Mode:     mode,
		DevMajor: major,
		DevMinor: minor,
	})
}

// UserspaceInit creates symbolic links and mount points in the devtmpfs
// instance accessed by the Accessor that are created by userspace in Linux. It
// does not create mounts.
func (a *Accessor) UserspaceInit(ctx context.Context) error {
	actx := a.wrapContext(ctx)

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
		if err := a.vfsObj.SymlinkAt(actx, a.creds, a.pathOperationAt(symlink.source), symlink.target); err != nil {
			return fmt.Errorf("failed to create symlink %q => %q: %v", symlink.source, symlink.target, err)
		}
	}

	// systemd: src/core/mount-setup.c:mount_table
	for _, dir := range []string{
		"shm",
		"pts",
	} {
		if err := a.vfsObj.MkdirAt(actx, a.creds, a.pathOperationAt(dir), &vfs.MkdirOptions{
			// systemd: src/core/mount-setup.c:mount_one()
			Mode: 0755,
		}); err != nil {
			return fmt.Errorf("failed to create directory %q: %v", dir, err)
		}
	}

	return nil
}
