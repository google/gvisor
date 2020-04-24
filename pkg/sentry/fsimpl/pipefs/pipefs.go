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

// Package pipefs provides the filesystem implementation backing
// Kernel.PipeMount.
package pipefs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

type filesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (filesystemType) Name() string {
	return "pipefs"
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (filesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("pipefs.filesystemType.GetFilesystem should never be called")
}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem

	// TODO(gvisor.dev/issue/1193):
	//
	// - kernfs does not provide a way to implement statfs, from which we
	// should indicate PIPEFS_MAGIC.
	//
	// - kernfs does not provide a way to override names for
	// vfs.FilesystemImpl.PrependPath(); pipefs inodes should use synthetic
	// name fmt.Sprintf("pipe:[%d]", inode.ino).
}

// NewFilesystem sets up and returns a new vfs.Filesystem implemented by
// pipefs.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) *vfs.Filesystem {
	fs := &filesystem{}
	fs.Init(vfsObj, filesystemType{})
	return fs.VFSFilesystem()
}

// inode implements kernfs.Inode.
type inode struct {
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeNoopRefCount

	pipe *pipe.VFSPipe

	ino uint64
	uid auth.KUID
	gid auth.KGID
	// We use the creation timestamp for all of atime, mtime, and ctime.
	ctime ktime.Time
}

func newInode(ctx context.Context, fs *kernfs.Filesystem) *inode {
	creds := auth.CredentialsFromContext(ctx)
	return &inode{
		pipe:  pipe.NewVFSPipe(false /* isNamed */, pipe.DefaultPipeSize, usermem.PageSize),
		ino:   fs.NextIno(),
		uid:   creds.EffectiveKUID,
		gid:   creds.EffectiveKGID,
		ctime: ktime.NowFromContext(ctx),
	}
}

const pipeMode = 0600 | linux.S_IFIFO

// CheckPermissions implements kernfs.Inode.CheckPermissions.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, pipeMode, i.uid, i.gid)
}

// Mode implements kernfs.Inode.Mode.
func (i *inode) Mode() linux.FileMode {
	return pipeMode
}

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	ts := linux.NsecToStatxTimestamp(i.ctime.Nanoseconds())
	return linux.Statx{
		Mask:    linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS,
		Blksize: usermem.PageSize,
		Nlink:   1,
		UID:     uint32(i.uid),
		GID:     uint32(i.gid),
		Mode:    pipeMode,
		Ino:     i.ino,
		Size:    0,
		Blocks:  0,
		Atime:   ts,
		Ctime:   ts,
		Mtime:   ts,
		// TODO(gvisor.dev/issue/1197): Device number.
	}, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (i *inode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	return syserror.EPERM
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return i.pipe.Open(ctx, rp.Mount(), vfsd, opts.Flags)
}

// NewConnectedPipeFDs returns a pair of FileDescriptions representing the read
// and write ends of a newly-created pipe, as for pipe(2) and pipe2(2).
//
// Preconditions: mnt.Filesystem() must have been returned by NewFilesystem().
func NewConnectedPipeFDs(ctx context.Context, mnt *vfs.Mount, flags uint32) (*vfs.FileDescription, *vfs.FileDescription) {
	fs := mnt.Filesystem().Impl().(*kernfs.Filesystem)
	inode := newInode(ctx, fs)
	var d kernfs.Dentry
	d.Init(inode)
	defer d.DecRef()
	return inode.pipe.ReaderWriterPair(mnt, d.VFSDentry(), flags)
}
