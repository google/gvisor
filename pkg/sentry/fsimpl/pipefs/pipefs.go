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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// +stateify savable
type filesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (filesystemType) Name() string {
	return "pipefs"
}

// Release implements vfs.FilesystemType.Release.
func (filesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (filesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("pipefs.filesystemType.GetFilesystem should never be called")
}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// NewFilesystem sets up and returns a new vfs.Filesystem implemented by pipefs.
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
	b.PrependComponent(fmt.Sprintf("pipe:[%d]", inode.ino))
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
	kernfs.InodeAnonymous
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeNoopRefCount
	kernfs.InodeWatches

	locks  vfs.FileLocks
	pipe   *pipe.VFSPipe
	attrMu sync.Mutex `state:"nosave"`

	ino uint64
	uid auth.KUID
	gid auth.KGID
	// We use the creation timestamp for all of atime, mtime, and ctime.
	ctime ktime.Time
}

func newInode(ctx context.Context, fs *filesystem) *inode {
	creds := auth.CredentialsFromContext(ctx)
	return &inode{
		pipe:  pipe.NewVFSPipe(false /* isNamed */, pipe.DefaultPipeSize),
		ino:   fs.Filesystem.NextIno(),
		uid:   creds.EffectiveKUID,
		gid:   creds.EffectiveKGID,
		ctime: ktime.NowFromContext(ctx),
	}
}

const pipeMode = 0600 | linux.S_IFIFO

// CheckPermissions implements kernfs.Inode.CheckPermissions.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return vfs.GenericCheckPermissions(creds, ats, pipeMode, i.uid, i.gid)
}

// Mode implements kernfs.Inode.Mode.
func (i *inode) Mode() linux.FileMode {
	return pipeMode
}

// UID implements kernfs.Inode.UID.
func (i *inode) UID() auth.KUID {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return auth.KUID(i.uid)
}

// GID implements kernfs.Inode.GID.
func (i *inode) GID() auth.KGID {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return auth.KGID(i.gid)
}

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(_ context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	ts := linux.NsecToStatxTimestamp(i.ctime.Nanoseconds())
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return linux.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS,
		Blksize:  hostarch.PageSize,
		Nlink:    1,
		UID:      uint32(i.uid),
		GID:      uint32(i.gid),
		Mode:     pipeMode,
		Ino:      i.ino,
		Size:     0,
		Blocks:   0,
		Atime:    ts,
		Ctime:    ts,
		Mtime:    ts,
		DevMajor: linux.UNNAMED_MAJOR,
		DevMinor: vfsfs.Impl().(*filesystem).devMinor,
	}, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (i *inode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask&^(linux.STATX_UID|linux.STATX_GID) != 0 {
		return linuxerr.EPERM
	}
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	if err := vfs.CheckSetStat(ctx, creds, &opts, pipeMode, auth.KUID(i.uid), auth.KGID(i.gid)); err != nil {
		return err
	}
	if opts.Stat.Mask&linux.STATX_UID != 0 {
		i.uid = auth.KUID(opts.Stat.UID)
	}
	if opts.Stat.Mask&linux.STATX_GID != 0 {
		i.gid = auth.KGID(opts.Stat.GID)
	}
	return nil
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	return i.pipe.Open(ctx, rp.Mount(), d.VFSDentry(), opts.Flags, &i.locks)
}

// StatFS implements kernfs.Inode.StatFS.
func (i *inode) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.PIPEFS_MAGIC), nil
}

// NewConnectedPipeFDs returns a pair of FileDescriptions representing the read
// and write ends of a newly-created pipe, as for pipe(2) and pipe2(2).
//
// Preconditions: mnt.Filesystem() must have been returned by NewFilesystem().
func NewConnectedPipeFDs(ctx context.Context, mnt *vfs.Mount, flags uint32) (*vfs.FileDescription, *vfs.FileDescription, error) {
	fs := mnt.Filesystem().Impl().(*filesystem)
	inode := newInode(ctx, fs)
	var d kernfs.Dentry
	d.Init(&fs.Filesystem, inode)
	defer d.DecRef(ctx)
	return inode.pipe.ReaderWriterPair(ctx, mnt, d.VFSDentry(), flags)
}
