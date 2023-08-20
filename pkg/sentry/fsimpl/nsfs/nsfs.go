// Copyright 2023 The gVisor Authors.
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

// Package nsfs provides the filesystem implementation backing
// Kernel.NsfsMount.
package nsfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// +stateify savable
type filesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (filesystemType) Name() string {
	return "nsfs"
}

// Release implements vfs.FilesystemType.Release.
func (filesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (filesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("nsfs.filesystemType.GetFilesystem should never be called")
}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// NewFilesystem sets up and returns a new vfs.Filesystem implemented by nsfs.
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

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// Inode implements kernfs.Inode.
//
// +stateify savable
type Inode struct {
	kernfs.InodeAttrs
	kernfs.InodeAnonymous
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	inodeRefs

	locks     vfs.FileLocks
	namespace vfs.Namespace

	mnt *vfs.Mount
}

// DecRef implements kernfs.Inode.DecRef.
func (i *Inode) DecRef(ctx context.Context) {
	i.inodeRefs.DecRef(func() { i.namespace.Destroy(ctx) })
}

// Keep implements kernfs.Inode.Keep.
func (i *Inode) Keep() bool {
	return false
}

// NewInode creates a new nsfs inode.
func NewInode(ctx context.Context, mnt *vfs.Mount, namespace vfs.Namespace) *Inode {
	fs := mnt.Filesystem().Impl().(*filesystem)
	creds := auth.CredentialsFromContext(ctx)
	i := &Inode{
		namespace: namespace,
		mnt:       mnt,
	}
	i.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.Filesystem.NextIno(), nsfsMode)
	i.InitRefs()
	return i
}

const nsfsMode = linux.S_IFREG | linux.ModeUserRead | linux.ModeGroupRead | linux.ModeOtherRead

// Namespace returns the namespace associated with the inode.
func (i *Inode) Namespace() vfs.Namespace {
	return i.namespace
}

// Name returns the inode name that is used to implement readlink() of
// /proc/pid/ns/ files.
func (i *Inode) Name() string {
	return fmt.Sprintf("%s:[%d]", i.namespace.Type(), i.Ino())
}

// VirtualDentry returns VirtualDentry for the inode.
func (i *Inode) VirtualDentry() vfs.VirtualDentry {
	dentry := &kernfs.Dentry{}
	mnt := i.mnt
	fs := mnt.Filesystem().Impl().(*filesystem)
	i.IncRef()
	mnt.IncRef()
	dentry.Init(&fs.Filesystem, i)
	vd := vfs.MakeVirtualDentry(mnt, dentry.VFSDentry())
	return vd
}

// Mode implements kernfs.Inode.Mode.
func (i *Inode) Mode() linux.FileMode {
	return nsfsMode
}

// SetStat implements kernfs.Inode.SetStat.
//
// Linux sets S_IMMUTABLE to nsfs inodes that prevents any attribute changes on
// them.
func (i *Inode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// namespace FD is a synthetic file that represents a namespace in
// /proc/[pid]/ns/*.
//
// +stateify savable
type namespaceFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	vfsfd vfs.FileDescription
	inode *Inode
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *namespaceFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, vfs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *namespaceFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	creds := auth.CredentialsFromContext(ctx)
	return fd.inode.SetStat(ctx, vfs, creds, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *namespaceFD) Release(ctx context.Context) {
	fd.inode.DecRef(ctx)
}

// Open implements kernfs.Inode.Open.
func (i *Inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &namespaceFD{inode: i}
	i.IncRef()
	fd.LockFD.Init(&i.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// StatFS implements kernfs.Inode.StatFS.
func (i *Inode) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.NSFS_MAGIC), nil
}
