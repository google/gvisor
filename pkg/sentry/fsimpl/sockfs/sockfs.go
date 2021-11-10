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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// filesystemType implements vfs.FilesystemType.
//
// +stateify savable
type filesystemType struct{}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType filesystemType) GetFilesystem(_ context.Context, vfsObj *vfs.VirtualFilesystem, _ *auth.Credentials, _ string, _ vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("sockfs.filesystemType.GetFilesystem should never be called")
}

// Name implements vfs.FilesystemType.Name.
//
// Note that registering sockfs is unnecessary, except for the fact that it
// will not show up under /proc/filesystems as a result. This is a very minor
// discrepancy from Linux.
func (filesystemType) Name() string {
	return "sockfs"
}

// Release implements vfs.FilesystemType.Release.
func (filesystemType) Release(ctx context.Context) {}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// NewFilesystem sets up and returns a new sockfs filesystem.
//
// Note that there should only ever be one instance of sockfs.Filesystem,
// backing a global socket mount.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, err
	}
	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.Filesystem.VFSFilesystem().Init(vfsObj, filesystemType{}, fs)
	return fs.Filesystem.VFSFilesystem(), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	inode := vd.Dentry().Impl().(*kernfs.Dentry).Inode().(*inode)
	b.PrependComponent(fmt.Sprintf("socket:[%d]", inode.InodeAttrs.Ino()))
	return vfs.PrependPathSyntheticError{}
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// inode implements kernfs.Inode.
//
// +stateify savable
type inode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, linuxerr.ENXIO
}

// StatFS implements kernfs.Inode.StatFS.
func (i *inode) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.SOCKFS_MAGIC), nil
}

// NewDentry constructs and returns a sockfs dentry.
//
// Preconditions: mnt.Filesystem() must have been returned by NewFilesystem().
func NewDentry(ctx context.Context, mnt *vfs.Mount) *vfs.Dentry {
	fs := mnt.Filesystem().Impl().(*filesystem)

	// File mode matches net/socket.c:sock_alloc.
	filemode := linux.FileMode(linux.S_IFSOCK | 0777)
	i := &inode{}
	i.InodeAttrs.Init(ctx, auth.CredentialsFromContext(ctx), linux.UNNAMED_MAJOR, fs.devMinor, fs.Filesystem.NextIno(), filemode)

	d := &kernfs.Dentry{}
	d.Init(&fs.Filesystem, i)
	return d.VFSDentry()
}
