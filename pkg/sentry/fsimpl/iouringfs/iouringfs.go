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

// Package iouringfs provides a filesystem implementation for io_uring shared
// memory region
package iouringfs

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystemType implements vfs.FilesystemType.
//
// +stateify savable
type iouringFSType struct{}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (iouringFSType) GetFilesystem(_ context.Context, vfsObj *vfs.VirtualFilesystem, _ *auth.Credentials, _ string, _ vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("iouringfs.iouringFSType.GetFilesystem should never be called")
}

// Name implements vfs.FilesystemType.Name.
func (iouringFSType) Name() string {
	return "iouring"
}

// Release implements vfs.FilesystemType.Release.
func (iouringFSType) Release(ctx context.Context) {}

// +stateify savable
type iouringFS struct {
	kernfs.Filesystem

	devMinor uint32
}

// NewFilesystem sets up and returns a new iouring filesystem.
//
// Note that there should only ever be one instance of iouring.Filesystem,
// backing a global io_uring mount.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, err
	}

	fs := &iouringFS{
		devMinor: devMinor,
	}

	fs.Filesystem.VFSFilesystem().Init(vfsObj, iouringFSType{}, fs)

	return fs.Filesystem.VFSFilesystem(), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *iouringFS) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *iouringFS) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	inode := vd.Dentry().Impl().(*kernfs.Dentry).Inode().(*inode)
	b.PrependComponent(fmt.Sprintf("iouring:[%d]", inode.InodeAttrs.Ino()))
	return vfs.PrependPathSyntheticError{}
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *iouringFS) MountOptions() string {
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

// Open implements kernfs.Inode.Open. iouringfs inode can not be opened
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, syserror.EPERM
}

// StatFS implements kernfs.Inode.StatFS.
func (i *inode) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.SOCKFS_MAGIC), syserror.EPERM
}

// NewDentry constructs and returns a iouringfs dentry.
//
// Preconditions: mnt.Filesystem() must have been returned by NewFilesystem().
func newDentry(ctx context.Context, mnt *vfs.Mount) *vfs.Dentry {
	fs := mnt.Filesystem().Impl().(*iouringFS)

	filemode := linux.FileMode(linux.S_IFREG | 0600)
	i := &inode{}
	i.InodeAttrs.Init(ctx, auth.CredentialsFromContext(ctx), linux.UNNAMED_MAJOR, fs.devMinor, fs.Filesystem.NextIno(), filemode)

	d := &kernfs.Dentry{}
	d.Init(&fs.Filesystem, i)
	return d.VFSDentry()
}

// FileDescription is embedded by iouringfs implementations of
// vfs.FileDescriptionImpl.
//
// +stateify savable
type FileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD
	inode inode

	sqEntries, cqEntries uint32

	// memFile is a platform.File used to allocate pages to this regularFile.
	memFile *pgalloc.MemoryFile `state:"nosave"`

	mount *vfs.Mount

	mappings memmap.MappingSet

	data fsutil.FileRangeSet

	size uint64

	writableMappingPages uint64

	locks vfs.FileLocks
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *FileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return fd.inode.InodeAttrs.Stat(ctx, fd.mount.Filesystem(), opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *FileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	return syserror.EPERM
}

// Release implements vfs.FileDescriptionImpl.Release
func (f *FileDescription) Release(ctx context.Context) {
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *FileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *FileDescription) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	fd.mappings.AddMapping(ms, ar, offset, writable)

	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *FileDescription) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	fd.mappings.RemoveMapping(ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *FileDescription) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return fd.AddMapping(ctx, ms, dstAR, offset, writable)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (*FileDescription) InvalidateUnsavable(context.Context) error {
	return nil
}

func (fd *FileDescription) sqEndOffset() uint64 {
	SQEndOff := uint64(fd.sqEntries) * uint64(4) // 4 = sizeof(unsigned int)
	return fs.OffsetPageEnd(int64(linux.IORING_OFF_SQ_RING + SQEndOff))
}

func (fd *FileDescription) cqEndOffset() uint64 {
	CQEndOff := uint64(fd.cqEntries) * uint64((*linux.IoUringCqe)(nil).SizeBytes())
	return fs.OffsetPageEnd(int64(linux.IORING_OFF_CQ_RING + CQEndOff))
}

func (fd *FileDescription) sqeEndOffset() uint64 {
	SQESEndOff := uint64(fd.sqEntries) * uint64((*linux.IoUringSqe)(nil).SizeBytes())
	return fs.OffsetPageEnd(int64(linux.IORING_OFF_SQES + SQESEndOff))
}

func (fd *FileDescription) isInRing(maprange memmap.MappableRange) bool {
	if maprange.IsSupersetOf(memmap.MappableRange{Start: linux.IORING_OFF_SQ_RING, End: fd.sqEndOffset()}) {
		return true
	}

	if maprange.IsSupersetOf(memmap.MappableRange{Start: linux.IORING_OFF_CQ_RING, End: fd.cqEndOffset()}) {
		return true
	}

	if maprange.IsSupersetOf(memmap.MappableRange{Start: linux.IORING_OFF_SQES, End: fd.sqeEndOffset()}) {
		return true
	}

	return false

}

// Translate implements memmap.Mappable.Translate.
func (fd *FileDescription) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	// Not in Sq ring, Cq ring or Sqe ring ?
	if !fd.isInRing(required) {
		return nil, &memmap.BusError{io.EOF}
	}

	cerr := fd.data.Fill(ctx, required, optional, fd.sqeEndOffset(), fd.memFile, usage.Anonymous, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
		// Newly-allocated pages are zeroed, so we don't need to do anything.
		return dsts.NumBytes(), nil
	})

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := fd.data.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   fd.memFile,
			Offset: seg.FileRangeOf(segMR).Start,
			Perms:  hostarch.AnyAccess,
		})
		translatedEnd = segMR.End
	}

	// Don't return the error returned by f.data.Fill if it occurred outside of
	// required.
	if translatedEnd < required.End && cerr != nil {
		return ts, &memmap.BusError{cerr}
	}

	return ts, nil
}

func (fd *FileDescription) ReadFile(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	return fd.memFile.MapInternal(fr, at)
}

func NewIouringfsFile(ctx context.Context, mnt *vfs.Mount, SqEntries, CqEntries uint32) (*vfs.FileDescription, error) {
	d := newDentry(ctx, mnt)
	defer d.DecRef(ctx)

	fd, err := newFileDescription(ctx)
	if err != nil {
		return nil, err
	}

	fd.sqEntries = SqEntries
	fd.cqEntries = CqEntries
	fd.mount = mnt

	vfsfd := &fd.vfsfd
	if err := vfsfd.Init(fd, uint32(linux.O_RDWR), mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: false,
	}); err != nil {
		return nil, err
	}

	return vfsfd, nil
}

func newFileDescription(ctx context.Context) (*FileDescription, error) {
	fd := &FileDescription{}
	fd.LockFD.Init(&fd.locks)

	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic("MemoryFileProviderFromContext returned nil")
	}

	fd.memFile = mfp.MemoryFile()

	return fd, nil
}
