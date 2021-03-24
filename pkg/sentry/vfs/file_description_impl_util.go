// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"bytes"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The following design pattern is strongly recommended for filesystem
// implementations to adapt:
//   - Have a local fileDescription struct (containing FileDescription) which
//     embeds FileDescriptionDefaultImpl and overrides the default methods
//     which are common to all fd implementations for that filesystem like
//     StatusFlags, SetStatusFlags, Stat, SetStat, StatFS, etc.
//   - This should be embedded in all file description implementations as the
//     first field by value.
//   - Directory FDs would also embed DirectoryFileDescriptionDefaultImpl.

// FileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl to obtain implementations of many FileDescriptionImpl
// methods with default behavior analogous to Linux's.
//
// +stateify savable
type FileDescriptionDefaultImpl struct{}

// OnClose implements FileDescriptionImpl.OnClose analogously to
// file_operations::flush == NULL in Linux.
func (FileDescriptionDefaultImpl) OnClose(ctx context.Context) error {
	return nil
}

// StatFS implements FileDescriptionImpl.StatFS analogously to
// super_operations::statfs == NULL in Linux.
func (FileDescriptionDefaultImpl) StatFS(ctx context.Context) (linux.Statfs, error) {
	return linux.Statfs{}, syserror.ENOSYS
}

// Allocate implements FileDescriptionImpl.Allocate analogously to
// fallocate called on an invalid type of file in Linux.
//
// Note that directories can rely on this implementation even though they
// should technically return EISDIR. Allocate should never be called for a
// directory, because it requires a writable fd.
func (FileDescriptionDefaultImpl) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.ENODEV
}

// Readiness implements waiter.Waitable.Readiness analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) Readiness(mask waiter.EventMask) waiter.EventMask {
	// include/linux/poll.h:vfs_poll() => DEFAULT_POLLMASK
	return waiter.ReadableEvents | waiter.WritableEvents
}

// EventRegister implements waiter.Waitable.EventRegister analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
}

// EventUnregister implements waiter.Waitable.EventUnregister analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) EventUnregister(e *waiter.Entry) {
}

// PRead implements FileDescriptionImpl.PRead analogously to
// file_operations::read == file_operations::read_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// Read implements FileDescriptionImpl.Read analogously to
// file_operations::read == file_operations::read_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// PWrite implements FileDescriptionImpl.PWrite analogously to
// file_operations::write == file_operations::write_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// Write implements FileDescriptionImpl.Write analogously to
// file_operations::write == file_operations::write_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// IterDirents implements FileDescriptionImpl.IterDirents analogously to
// file_operations::iterate == file_operations::iterate_shared == NULL in
// Linux.
func (FileDescriptionDefaultImpl) IterDirents(ctx context.Context, cb IterDirentsCallback) error {
	return syserror.ENOTDIR
}

// Seek implements FileDescriptionImpl.Seek analogously to
// file_operations::llseek == NULL in Linux.
func (FileDescriptionDefaultImpl) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.ESPIPE
}

// Sync implements FileDescriptionImpl.Sync analogously to
// file_operations::fsync == NULL in Linux.
func (FileDescriptionDefaultImpl) Sync(ctx context.Context) error {
	return syserror.EINVAL
}

// ConfigureMMap implements FileDescriptionImpl.ConfigureMMap analogously to
// file_operations::mmap == NULL in Linux.
func (FileDescriptionDefaultImpl) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return syserror.ENODEV
}

// Ioctl implements FileDescriptionImpl.Ioctl analogously to
// file_operations::unlocked_ioctl == NULL in Linux.
func (FileDescriptionDefaultImpl) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// ListXattr implements FileDescriptionImpl.ListXattr analogously to
// inode_operations::listxattr == NULL in Linux.
func (FileDescriptionDefaultImpl) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	// This isn't exactly accurate; see FileDescription.ListXattr.
	return nil, syserror.ENOTSUP
}

// GetXattr implements FileDescriptionImpl.GetXattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) GetXattr(ctx context.Context, opts GetXattrOptions) (string, error) {
	return "", syserror.ENOTSUP
}

// SetXattr implements FileDescriptionImpl.SetXattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) SetXattr(ctx context.Context, opts SetXattrOptions) error {
	return syserror.ENOTSUP
}

// RemoveXattr implements FileDescriptionImpl.RemoveXattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) RemoveXattr(ctx context.Context, name string) error {
	return syserror.ENOTSUP
}

// DirectoryFileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl that always represent directories to obtain
// implementations of non-directory I/O methods that return EISDIR.
//
// +stateify savable
type DirectoryFileDescriptionDefaultImpl struct{}

// Allocate implements DirectoryFileDescriptionDefaultImpl.Allocate.
func (DirectoryFileDescriptionDefaultImpl) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.EISDIR
}

// PRead implements FileDescriptionImpl.PRead.
func (DirectoryFileDescriptionDefaultImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// Read implements FileDescriptionImpl.Read.
func (DirectoryFileDescriptionDefaultImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// PWrite implements FileDescriptionImpl.PWrite.
func (DirectoryFileDescriptionDefaultImpl) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// Write implements FileDescriptionImpl.Write.
func (DirectoryFileDescriptionDefaultImpl) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// DentryMetadataFileDescriptionImpl may be embedded by implementations of
// FileDescriptionImpl for which FileDescriptionOptions.UseDentryMetadata is
// true to obtain implementations of Stat and SetStat that panic.
//
// +stateify savable
type DentryMetadataFileDescriptionImpl struct{}

// Stat implements FileDescriptionImpl.Stat.
func (DentryMetadataFileDescriptionImpl) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	panic("illegal call to DentryMetadataFileDescriptionImpl.Stat")
}

// SetStat implements FileDescriptionImpl.SetStat.
func (DentryMetadataFileDescriptionImpl) SetStat(ctx context.Context, opts SetStatOptions) error {
	panic("illegal call to DentryMetadataFileDescriptionImpl.SetStat")
}

// DynamicBytesSource represents a data source for a
// DynamicBytesFileDescriptionImpl.
//
// +stateify savable
type DynamicBytesSource interface {
	// Generate writes the file's contents to buf.
	Generate(ctx context.Context, buf *bytes.Buffer) error
}

// StaticData implements DynamicBytesSource over a static string.
//
// +stateify savable
type StaticData struct {
	Data string
}

// Generate implements DynamicBytesSource.
func (s *StaticData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString(s.Data)
	return nil
}

// WritableDynamicBytesSource extends DynamicBytesSource to allow writes to the
// underlying source.
//
// TODO(b/179825241): Make utility for integer-based writable files.
type WritableDynamicBytesSource interface {
	DynamicBytesSource

	// Write sends writes to the source.
	Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error)
}

// DynamicBytesFileDescriptionImpl may be embedded by implementations of
// FileDescriptionImpl that represent read-only regular files whose contents
// are backed by a bytes.Buffer that is regenerated when necessary, consistent
// with Linux's fs/seq_file.c:single_open().
//
// DynamicBytesFileDescriptionImpl.SetDataSource() must be called before first
// use.
//
// +stateify savable
type DynamicBytesFileDescriptionImpl struct {
	data     DynamicBytesSource // immutable
	mu       sync.Mutex         `state:"nosave"` // protects the following fields
	buf      bytes.Buffer       `state:".([]byte)"`
	off      int64
	lastRead int64 // offset at which the last Read, PRead, or Seek ended
}

func (fd *DynamicBytesFileDescriptionImpl) saveBuf() []byte {
	return fd.buf.Bytes()
}

func (fd *DynamicBytesFileDescriptionImpl) loadBuf(p []byte) {
	fd.buf.Write(p)
}

// SetDataSource must be called exactly once on fd before first use.
func (fd *DynamicBytesFileDescriptionImpl) SetDataSource(data DynamicBytesSource) {
	fd.data = data
}

// Preconditions: fd.mu must be locked.
func (fd *DynamicBytesFileDescriptionImpl) preadLocked(ctx context.Context, dst usermem.IOSequence, offset int64, opts *ReadOptions) (int64, error) {
	// Regenerate the buffer if it's empty, or before pread() at a new offset.
	// Compare fs/seq_file.c:seq_read() => traverse().
	switch {
	case offset != fd.lastRead:
		fd.buf.Reset()
		fallthrough
	case fd.buf.Len() == 0:
		if err := fd.data.Generate(ctx, &fd.buf); err != nil {
			fd.buf.Reset()
			// fd.off is not updated in this case.
			fd.lastRead = 0
			return 0, err
		}
	}
	bs := fd.buf.Bytes()
	if offset >= int64(len(bs)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, bs[offset:])
	fd.lastRead = offset + int64(n)
	return int64(n), err
}

// PRead implements FileDescriptionImpl.PRead.
func (fd *DynamicBytesFileDescriptionImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.preadLocked(ctx, dst, offset, &opts)
	fd.mu.Unlock()
	return n, err
}

// Read implements FileDescriptionImpl.Read.
func (fd *DynamicBytesFileDescriptionImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.preadLocked(ctx, dst, fd.off, &opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// Seek implements FileDescriptionImpl.Seek.
func (fd *DynamicBytesFileDescriptionImpl) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		// fs/seq_file:seq_lseek() rejects SEEK_END etc.
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if offset != fd.lastRead {
		// Regenerate the file's contents immediately. Compare
		// fs/seq_file.c:seq_lseek() => traverse().
		fd.buf.Reset()
		if err := fd.data.Generate(ctx, &fd.buf); err != nil {
			fd.buf.Reset()
			fd.off = 0
			fd.lastRead = 0
			return 0, err
		}
		fd.lastRead = offset
	}
	fd.off = offset
	return offset, nil
}

// Preconditions: fd.mu must be locked.
func (fd *DynamicBytesFileDescriptionImpl) pwriteLocked(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	if opts.Flags&^(linux.RWF_HIPRI|linux.RWF_DSYNC|linux.RWF_SYNC) != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	limit, err := CheckLimit(ctx, offset, src.NumBytes())
	if err != nil {
		return 0, err
	}
	src = src.TakeFirst64(limit)

	writable, ok := fd.data.(WritableDynamicBytesSource)
	if !ok {
		return 0, syserror.EIO
	}
	n, err := writable.Write(ctx, src, offset)
	if err != nil {
		return 0, err
	}

	// Invalidate cached data that might exist prior to this call.
	fd.buf.Reset()
	return n, nil
}

// PWrite implements FileDescriptionImpl.PWrite.
func (fd *DynamicBytesFileDescriptionImpl) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.pwriteLocked(ctx, src, offset, opts)
	fd.mu.Unlock()
	return n, err
}

// Write implements FileDescriptionImpl.Write.
func (fd *DynamicBytesFileDescriptionImpl) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.pwriteLocked(ctx, src, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// GenericConfigureMMap may be used by most implementations of
// FileDescriptionImpl.ConfigureMMap.
func GenericConfigureMMap(fd *FileDescription, m memmap.Mappable, opts *memmap.MMapOpts) error {
	opts.Mappable = m
	opts.MappingIdentity = fd
	fd.IncRef()
	return nil
}

// LockFD may be used by most implementations of FileDescriptionImpl.Lock*
// functions. Caller must call Init().
//
// +stateify savable
type LockFD struct {
	locks *FileLocks
}

// Init initializes fd with FileLocks to use.
func (fd *LockFD) Init(locks *FileLocks) {
	fd.locks = locks
}

// Locks returns the locks associated with this file.
func (fd *LockFD) Locks() *FileLocks {
	return fd.locks
}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (fd *LockFD) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, block fslock.Blocker) error {
	return fd.locks.LockBSD(ctx, uid, ownerPID, t, block)
}

// UnlockBSD implements vfs.FileDescriptionImpl.UnlockBSD.
func (fd *LockFD) UnlockBSD(ctx context.Context, uid fslock.UniqueID) error {
	fd.locks.UnlockBSD(uid)
	return nil
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *LockFD) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block fslock.Blocker) error {
	return fd.locks.LockPOSIX(ctx, uid, ownerPID, t, r, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *LockFD) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	return fd.locks.UnlockPOSIX(ctx, uid, r)
}

// TestPOSIX implements vfs.FileDescriptionImpl.TestPOSIX.
func (fd *LockFD) TestPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, r fslock.LockRange) (linux.Flock, error) {
	return fd.locks.TestPOSIX(ctx, uid, t, r)
}

// NoLockFD implements Lock*/Unlock* portion of FileDescriptionImpl interface
// returning ENOLCK.
//
// +stateify savable
type NoLockFD struct{}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (NoLockFD) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, block fslock.Blocker) error {
	return syserror.ENOLCK
}

// UnlockBSD implements vfs.FileDescriptionImpl.UnlockBSD.
func (NoLockFD) UnlockBSD(ctx context.Context, uid fslock.UniqueID) error {
	return syserror.ENOLCK
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (NoLockFD) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block fslock.Blocker) error {
	return syserror.ENOLCK
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (NoLockFD) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	return syserror.ENOLCK
}

// TestPOSIX implements vfs.FileDescriptionImpl.TestPOSIX.
func (NoLockFD) TestPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, r fslock.LockRange) (linux.Flock, error) {
	return linux.Flock{}, syserror.ENOLCK
}
