// Copyright 2021 The gVisor Authors.
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

package control

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Fs includes fs-related functions.
type Fs struct {
	Kernel *kernel.Kernel
}

// TarRootfsUpperLayerOpts contains options for the TarRootfsUpperLayer RPC.
type TarRootfsUpperLayerOpts struct {
	// ContainerID identifies which container's rootfs upper layer should be
	// serialized.
	ContainerID string
	// FilePayload contains the destination for output.
	urpc.FilePayload
}

// Returns a referenced mount namespace for the given container ID,
// or the root container if no ID is provided. Caller must DecRef the
// returned mntns when done.
func (f *Fs) mountNamespaceForContainer(containerID string) (*vfs.MountNamespace, error) {
	leader, err := findContainerInitProcess(f.Kernel, containerID)
	if err != nil {
		return nil, err
	}
	mntns := leader.MountNamespace()
	if mntns == nil || !mntns.TryIncRef() {
		return nil, fmt.Errorf("mount namespace for container %s has been destroyed", containerID)
	}
	return mntns, nil
}

// TarRootfsUpperLayer is a RPC stub which serializes the rootfs upper layer to
// a tar file. When the rootfs is not an overlayfs, it returns an error.
func (f *Fs) TarRootfsUpperLayer(o *TarRootfsUpperLayerOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}
	outFD := o.FilePayload.Files[0]
	defer outFD.Close()

	ctx := f.Kernel.SupervisorContext()
	mntns, err := f.mountNamespaceForContainer(o.ContainerID)
	if err != nil {
		return err
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	ts, ok := root.Mount().Filesystem().Impl().(vfs.TarSerializer)
	if !ok {
		return fmt.Errorf("rootfs is not an overlayfs")
	}
	if err := ts.TarUpperLayer(ctx, outFD); err != nil {
		return fmt.Errorf("failed to serialize rootfs upper layer to tar: %v", err)
	}
	return nil
}

// CatOpts contains options for the Cat RPC call.
type CatOpts struct {
	// Files are the filesystem paths for the files to cat.
	Files []string `json:"files"`

	// FilePayload contains the destination for output.
	urpc.FilePayload
}

// Cat is a RPC stub which prints out and returns the content of the files.
func (f *Fs) Cat(o *CatOpts, _ *struct{}) error {
	// Create an output stream.
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}

	output := o.FilePayload.Files[0]
	for _, file := range o.Files {
		if err := cat(f.Kernel, file, output); err != nil {
			return fmt.Errorf("cannot read from file %s: %v", file, err)
		}
	}

	return nil
}

// fdReader provides an io.Reader interface for a vfs.FileDescription.
type fdReader struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

// Read implements io.Reader.Read.
func (f *fdReader) Read(p []byte) (int, error) {
	n, err := f.fd.Read(f.ctx, usermem.BytesIOSequence(p), vfs.ReadOptions{})
	return int(n), err
}

func cat(k *kernel.Kernel, path string, output *os.File) error {
	ctx := k.SupervisorContext()
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	mns := k.GlobalInit().Leader().MountNamespace()
	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	fd, err := k.VFS().OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(path),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer fd.DecRef(ctx)

	_, err = io.Copy(output, &fdReader{ctx: ctx, fd: fd})
	return err
}

// ReadOpts contains options for the Read RPC call.
type ReadOpts struct {
	// ContainerID identifies which container's filesystem to read from.
	ContainerID string `json:"container_id"`

	// Path is the filesystem path for the file to read.
	Path string `json:"path"`

	// Size is the maximum number of bytes to read (0 means unlimited).
	Size int64 `json:"size"`

	// FilePayload contains the destination for output.
	urpc.FilePayload
}

// Read is a RPC stub which prints out and returns the content of the file up to the specified size.
func (f *Fs) Read(o *ReadOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}

	output := o.FilePayload.Files[0]
	ctx := f.Kernel.SupervisorContext()
	mntns, err := f.mountNamespaceForContainer(o.ContainerID)
	if err != nil {
		return err
	}
	defer mntns.DecRef(ctx)

	creds := auth.NewRootCredentials(f.Kernel.RootUserNamespace())
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	fd, err := f.Kernel.VFS().OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(o.Path),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", o.Path, err)
	}
	defer fd.DecRef(ctx)

	reader := &fdReader{ctx: ctx, fd: fd}
	if o.Size > 0 {
		_, err = io.Copy(output, io.LimitReader(reader, o.Size))
	} else {
		_, err = io.Copy(output, reader)
	}
	return err
}

// MountOpts contains options for the Mount RPC call.
type MountOpts struct {
	// ContainerID identifies which container's mount namespace to mount into.
	ContainerID string `json:"container_id"`

	// Source is the mount source (e.g. device name or host path).
	Source string `json:"source"`

	// Target is the absolute path inside the container where the filesystem
	// will be mounted.
	Target string `json:"target"`

	// FSType is the filesystem type name (e.g., "gofer", "tmpfs").
	FSType string `json:"fs_type"`

	// Flags are the Linux mount flags (e.g. MS_RDONLY, MS_NOEXEC).
	Flags uint64 `json:"flags"`

	// Data contains filesystem-specific mount options (e.g. "cache=remote,aname=/").
	Data string `json:"data"`

	// FilePayload contains file descriptors sent over SCM_RIGHTS (e.g. socket FD to Gofer).
	urpc.FilePayload
}

// Mount is a RPC stub which mounts a filesystem into a container's mount namespace.
func (f *Fs) Mount(o *MountOpts, _ *struct{}) error {
	target := path.Clean(o.Target)
	if target == "" || !path.IsAbs(target) {
		return fmt.Errorf("target must be an absolute path: %q", o.Target)
	}

	supportedFlags := uint64(linux.MS_RDONLY | linux.MS_NOEXEC | linux.MS_NODEV | linux.MS_NOSUID | linux.MS_NOATIME)
	if (o.Flags & ^supportedFlags) != 0 {
		return unix.EINVAL
	}

	// Close all payload files upon return.
	defer func() {
		for _, file := range o.FilePayload.Files {
			file.Close()
		}
	}()

	var cu cleanup.Cleanup
	defer cu.Clean()

	ctx := f.Kernel.SupervisorContext()
	mntns, err := f.mountNamespaceForContainer(o.ContainerID)
	if err != nil {
		return err
	}
	defer mntns.DecRef(ctx)

	creds := auth.NewRootCredentials(f.Kernel.RootUserNamespace())
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	fsType := o.FSType
	if fsType == "gofer" {
		fsType = "9p"
	}

	data := o.Data
	goferFD := -1
	// For 9p/gofer mounts, we receive the host connection FD in FilePayload.
	// We must duplicate this FD because the incoming FD will be closed when the
	// RPC returns (via FilePayload cleanup), but the VFS mount needs to keep
	// the connection open.
	if len(o.FilePayload.Files) > 0 && fsType == "9p" {
		fd := int(o.FilePayload.Files[0].Fd())
		dupFD, err := unix.Dup(fd)
		if err != nil {
			return fmt.Errorf("failed to dup gofer FD: %v", err)
		}
		goferFD = dupFD
		cu.Add(func() { _ = unix.Close(goferFD) })
		// Append the duped FD to mount options if not already specified.
		if !strings.Contains(data, "trans=fd") {
			if len(data) > 0 {
				data += ","
			}
			data += fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d", goferFD, goferFD)
		}
	}

	// Ensure the parent directory exists. We do not automatically create
	// parent directories to match standard Linux mount behavior where the
	// target mount point's parent must exist.
	parent := path.Dir(target)
	parentPop := &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(parent),
		FollowFinalSymlink: true,
	}
	if stat, err := f.Kernel.VFS().StatAt(ctx, creds, parentPop, &vfs.StatOptions{Mask: linux.STATX_TYPE}); err != nil {
		return fmt.Errorf("parent directory %s does not exist: %w", parent, err)
	} else if stat.Mask&linux.STATX_TYPE == 0 || stat.Mode&linux.FileTypeMask != linux.ModeDirectory {
		return fmt.Errorf("parent %s is not a directory", parent)
	}

	// Ensure target directory exists (or create it if parent is writeable).
	if err := f.Kernel.VFS().MkdirAllAt(ctx, target, root, creds, &vfs.MkdirOptions{Mode: 0755, ForSyntheticMountpoint: true}, true /* mustBeDir */); err != nil {
		return fmt.Errorf("failed to ensure target directory %s exists: %v", target, err)
	}

	opts := &vfs.MountOptions{
		ReadOnly: (o.Flags & linux.MS_RDONLY) != 0,
		Flags: vfs.MountFlags{
			NoExec:  (o.Flags & linux.MS_NOEXEC) != 0,
			NoDev:   (o.Flags & linux.MS_NODEV) != 0,
			NoSUID:  (o.Flags & linux.MS_NOSUID) != 0,
			NoATime: (o.Flags & linux.MS_NOATIME) != 0,
		},
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data:          data,
			InternalMount: true,
		},
	}

	pop := &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(target),
		FollowFinalSymlink: true,
	}

	if _, err := f.Kernel.VFS().MountAt(ctx, creds, o.Source, pop, fsType, opts); err != nil {
		return fmt.Errorf("failed to mount %s at %s: %v", o.FSType, target, err)
	}

	cu.Release()
	return nil
}

// UmountOpts contains options for the Umount RPC call.
type UmountOpts struct {
	// ContainerID identifies which container's mount namespace to unmount from.
	ContainerID string `json:"container_id"`

	// Target is the absolute path inside the container to unmount.
	Target string `json:"target"`

	// Flags are Linux umount2 flags (e.g. MNT_DETACH).
	Flags uint32 `json:"flags"`
}

// Umount is a RPC stub which unmounts a filesystem from a container's mount namespace.
func (f *Fs) Umount(o *UmountOpts, _ *struct{}) error {
	target := path.Clean(o.Target)
	if target == "" || !path.IsAbs(target) {
		return fmt.Errorf("target must be an absolute path: %q", o.Target)
	}

	ctx := f.Kernel.SupervisorContext()
	mntns, err := f.mountNamespaceForContainer(o.ContainerID)
	if err != nil {
		return err
	}
	defer mntns.DecRef(ctx)

	creds := auth.NewRootCredentials(f.Kernel.RootUserNamespace())
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	pop := &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(target),
		FollowFinalSymlink: (o.Flags & linux.UMOUNT_NOFOLLOW) == 0,
	}

	opts := &vfs.UmountOptions{
		Flags: o.Flags,
	}

	if err := f.Kernel.VFS().UmountAt(ctx, creds, pop, opts); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", target, err)
	}

	return nil
}
