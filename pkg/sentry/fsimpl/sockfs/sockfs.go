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

// Package sockfs provides a filesystem implementation for anonymous sockets.
package sockfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// NewFilesystem creates a new sockfs filesystem.
//
// Note that there should only ever be one instance of sockfs.Filesystem,
// backing a global socket mount.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) *vfs.Filesystem {
	fs, _, err := filesystemType{}.GetFilesystem(nil, vfsObj, nil, "", vfs.GetFilesystemOptions{})
	if err != nil {
		panic("failed to create sockfs filesystem")
	}
	return fs
}

// filesystemType implements vfs.FilesystemType.
type filesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (fsType filesystemType) GetFilesystem(_ context.Context, vfsObj *vfs.VirtualFilesystem, _ *auth.Credentials, _ string, _ vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fs := &filesystem{}
	fs.Init(vfsObj, fsType)
	return fs.VFSFilesystem(), nil, nil
}

// Name implements FilesystemType.Name.
//
// Note that registering sockfs is unnecessary, except for the fact that it
// will not show up under /proc/filesystems as a result. This is a very minor
// discrepancy from Linux.
func (filesystemType) Name() string {
	return "sockfs"
}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
}

// inode implements kernfs.Inode.
//
// TODO(gvisor.dev/issue/1476): Add device numbers to this inode (which are
// not included in InodeAttrs) to store the numbers of the appropriate
// socket device. Override InodeAttrs.Stat() accordingly.
type inode struct {
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, syserror.ENXIO
}

// InitSocket initializes a socket FileDescription, with a corresponding
// Dentry in mnt.
//
// fd should be the FileDescription associated with socketImpl, i.e. its first
// field. mnt should be the global socket mount, Kernel.socketMount.
func InitSocket(socketImpl vfs.FileDescriptionImpl, fd *vfs.FileDescription, mnt *vfs.Mount, creds *auth.Credentials) error {
	fsimpl := mnt.Filesystem().Impl()
	fs := fsimpl.(*kernfs.Filesystem)

	// File mode matches net/socket.c:sock_alloc.
	filemode := linux.FileMode(linux.S_IFSOCK | 0600)
	i := &inode{}
	i.Init(creds, fs.NextIno(), filemode)

	d := &kernfs.Dentry{}
	d.Init(i)

	opts := &vfs.FileDescriptionOptions{UseDentryMetadata: true}
	if err := fd.Init(socketImpl, linux.O_RDWR, mnt, d.VFSDentry(), opts); err != nil {
		return err
	}
	return nil
}
