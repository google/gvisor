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

// filesystemType implements vfs.FilesystemType.
type filesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (fsType filesystemType) GetFilesystem(_ context.Context, vfsObj *vfs.VirtualFilesystem, _ *auth.Credentials, _ string, _ vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("sockfs.filesystemType.GetFilesystem should never be called")
}

// Name implements FilesystemType.Name.
//
// Note that registering sockfs is unnecessary, except for the fact that it
// will not show up under /proc/filesystems as a result. This is a very minor
// discrepancy from Linux.
func (filesystemType) Name() string {
	return "sockfs"
}

// NewFilesystem sets up and returns a new sockfs filesystem.
//
// Note that there should only ever be one instance of sockfs.Filesystem,
// backing a global socket mount.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) *vfs.Filesystem {
	fs := &kernfs.Filesystem{}
	fs.VFSFilesystem().Init(vfsObj, filesystemType{}, fs)
	return fs.VFSFilesystem()
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
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, syserror.ENXIO
}

// NewDentry constructs and returns a sockfs dentry.
//
// TODO(gvisor.dev/issue/1476): Currently, we are using
// sockfs.filesystem.NextIno() to get inode numbers. We should use
// device-specific numbers, so that we are not using the same generator for
// netstack, unix, etc.
func NewDentry(creds *auth.Credentials, ino uint64) *vfs.Dentry {
	// File mode matches net/socket.c:sock_alloc.
	filemode := linux.FileMode(linux.S_IFSOCK | 0600)
	i := &inode{}
	i.Init(creds, ino, filemode)

	d := &kernfs.Dentry{}
	d.Init(i)
	return d.VFSDentry()
}
