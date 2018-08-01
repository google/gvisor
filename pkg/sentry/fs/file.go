// Copyright 2018 Google Inc.
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

package fs

import (
	"math"
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/amutex"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/lock"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// FileMaxOffset is the maximum possible file offset.
const FileMaxOffset = math.MaxInt64

// File is an open file handle. It is thread-safe.
//
// File provides stronger synchronization guarantees than Linux. Linux
// synchronizes lseek(2), read(2), and write(2) with respect to the file
// offset for regular files and only for those interfaces. See
// fs/read_write.c:fdget_pos, fs.read_write.c:fdput_pos and FMODE_ATOMIC_POS.
//
// In contrast, File synchronizes any operation that could take a long time
// under a single abortable mutex which also synchronizes lseek(2), read(2),
// and write(2).
//
// FIXME: Split synchronization from cancellation.
//
// +stateify savable
type File struct {
	refs.AtomicRefCount

	// UniqueID is the globally unique identifier of the File.
	UniqueID uint64

	// Dirent is the Dirent backing this File. This encodes the name
	// of the File via Dirent.FullName() as well as its identity via the
	// Dirent's Inode. The Dirent is non-nil.
	//
	// A File holds a reference to this Dirent. Using the returned Dirent is
	// only safe as long as a reference on the File is held. The association
	// between a File and a Dirent is immutable.
	//
	// Files that are not parented in a filesystem return a root Dirent
	// that holds a reference to their Inode.
	//
	// The name of the Dirent may reflect parentage if the Dirent is not a
	// root Dirent or the identity of the File on a pseudo filesystem (pipefs,
	// sockfs, etc).
	//
	// Multiple Files may hold a reference to the same Dirent. This is the
	// common case for Files that are parented and maintain consistency with
	// other files via the Dirent cache.
	Dirent *Dirent

	// flagsMu protects flags and async below.
	flagsMu sync.Mutex `state:"nosave"`

	// flags are the File's flags. Setting or getting flags is fully atomic
	// and is not protected by mu (below).
	flags FileFlags

	// async handles O_ASYNC notifications.
	async FileAsync

	// mu is dual-purpose: first, to make read(2) and write(2) thread-safe
	// in conformity with POSIX, and second, to cancel operations before they
	// begin in response to interruptions (i.e. signals).
	mu amutex.AbortableMutex `state:"nosave"`

	// FileOperations implements file system specific behavior for this File.
	FileOperations FileOperations

	// offset is the File's offset. Updating offset is protected by mu but
	// can be read atomically via File.Offset() outside of mu.
	offset int64
}

// NewFile returns a File. It takes a reference on the Dirent and owns the
// lifetime of the FileOperations. Files that do not support reading and
// writing at an arbitrary offset should set flags.Pread and flags.Pwrite
// to false respectively.
func NewFile(ctx context.Context, dirent *Dirent, flags FileFlags, fops FileOperations) *File {
	dirent.IncRef()
	f := &File{
		UniqueID:       uniqueid.GlobalFromContext(ctx),
		Dirent:         dirent,
		FileOperations: fops,
		flags:          flags,
	}
	f.mu.Init()
	return f
}

// DecRef destroys the File when it is no longer referenced.
func (f *File) DecRef() {
	f.DecRefWithDestructor(func() {
		// Drop BSD style locks.
		lockRng := lock.LockRange{Start: 0, End: lock.LockEOF}
		f.Dirent.Inode.LockCtx.BSD.UnlockRegion(lock.UniqueID(f.UniqueID), lockRng)

		// Release resources held by the FileOperations.
		f.FileOperations.Release()

		// Release a reference on the Dirent.
		f.Dirent.DecRef()

		f.flagsMu.Lock()
		if f.flags.Async && f.async != nil {
			f.async.Unregister(f)
		}
		f.flagsMu.Unlock()
	})
}

// Flags atomically loads the File's flags.
func (f *File) Flags() FileFlags {
	f.flagsMu.Lock()
	flags := f.flags
	f.flagsMu.Unlock()
	return flags
}

// SetFlags atomically changes the File's flags to the values contained
// in newFlags. See SettableFileFlags for values that can be set.
func (f *File) SetFlags(newFlags SettableFileFlags) {
	f.flagsMu.Lock()
	f.flags.Direct = newFlags.Direct
	f.flags.NonBlocking = newFlags.NonBlocking
	f.flags.Append = newFlags.Append
	if f.async != nil {
		if newFlags.Async && !f.flags.Async {
			f.async.Register(f)
		}
		if !newFlags.Async && f.flags.Async {
			f.async.Unregister(f)
		}
	}
	f.flags.Async = newFlags.Async
	f.flagsMu.Unlock()
}

// Offset atomically loads the File's offset.
func (f *File) Offset() int64 {
	return atomic.LoadInt64(&f.offset)
}

// Readiness implements waiter.Waitable.Readiness.
func (f *File) Readiness(mask waiter.EventMask) waiter.EventMask {
	return f.FileOperations.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (f *File) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	f.FileOperations.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (f *File) EventUnregister(e *waiter.Entry) {
	f.FileOperations.EventUnregister(e)
}

// Seek calls f.FileOperations.Seek with f as the File, updating the file
// offset to the value returned by f.FileOperations.Seek if the operation
// is successful.
//
// Returns syserror.ErrInterrupted if seeking was interrupted.
func (f *File) Seek(ctx context.Context, whence SeekWhence, offset int64) (int64, error) {
	if !f.mu.Lock(ctx) {
		return 0, syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	newOffset, err := f.FileOperations.Seek(ctx, f, whence, offset)
	if err == nil {
		atomic.StoreInt64(&f.offset, newOffset)
	}
	return newOffset, err
}

// Readdir reads the directory entries of this File and writes them out
// to the DentrySerializer until entries can no longer be written. If even
// a single directory entry is written then Readdir returns a nil error
// and the directory offset is advanced.
//
// Readdir unconditionally updates the access time on the File's Inode,
// see fs/readdir.c:iterate_dir.
//
// Returns syserror.ErrInterrupted if reading was interrupted.
func (f *File) Readdir(ctx context.Context, serializer DentrySerializer) error {
	if !f.mu.Lock(ctx) {
		return syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	offset, err := f.FileOperations.Readdir(ctx, f, serializer)
	atomic.StoreInt64(&f.offset, offset)
	return err
}

// Readv calls f.FileOperations.Read with f as the File, advancing the file
// offset if f.FileOperations.Read returns bytes read > 0.
//
// Returns syserror.ErrInterrupted if reading was interrupted.
func (f *File) Readv(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	if !f.mu.Lock(ctx) {
		return 0, syserror.ErrInterrupted
	}

	n, err := f.FileOperations.Read(ctx, f, dst, f.offset)
	if n > 0 {
		atomic.AddInt64(&f.offset, n)
	}
	f.mu.Unlock()
	return n, err
}

// Preadv calls f.FileOperations.Read with f as the File. It does not
// advance the file offset. If !f.Flags().Pread, Preadv should not be
// called.
//
// Otherwise same as Readv.
func (f *File) Preadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if !f.mu.Lock(ctx) {
		return 0, syserror.ErrInterrupted
	}

	n, err := f.FileOperations.Read(ctx, f, dst, offset)
	f.mu.Unlock()
	return n, err
}

// Writev calls f.FileOperations.Write with f as the File, advancing the
// file offset if f.FileOperations.Write returns bytes written > 0.
//
// Writev positions the write offset at EOF if f.Flags().Append. This is
// unavoidably racy for network file systems. Writev also truncates src
// to avoid overrunning the current file size limit if necessary.
//
// Returns syserror.ErrInterrupted if writing was interrupted.
func (f *File) Writev(ctx context.Context, src usermem.IOSequence) (int64, error) {
	if !f.mu.Lock(ctx) {
		return 0, syserror.ErrInterrupted
	}

	offset, err := f.checkWriteLocked(ctx, &src, f.offset)
	if err != nil {
		f.mu.Unlock()
		return 0, err
	}
	n, err := f.FileOperations.Write(ctx, f, src, offset)
	if n >= 0 {
		atomic.StoreInt64(&f.offset, offset+n)
	}
	f.mu.Unlock()
	return n, err
}

// Pwritev calls f.FileOperations.Write with f as the File. It does not
// advance the file offset. If !f.Flags().Pwritev, Pwritev should not be
// called.
//
// Otherwise same as Writev.
func (f *File) Pwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if !f.mu.Lock(ctx) {
		return 0, syserror.ErrInterrupted
	}

	offset, err := f.checkWriteLocked(ctx, &src, offset)
	if err != nil {
		f.mu.Unlock()
		return 0, err
	}
	n, err := f.FileOperations.Write(ctx, f, src, offset)
	f.mu.Unlock()
	return n, err
}

// checkWriteLocked returns the offset to write at or an error if the write
// would not succeed. May update src to fit a write operation into a file
// size limit.
func (f *File) checkWriteLocked(ctx context.Context, src *usermem.IOSequence, offset int64) (int64, error) {
	// Handle append only files. Note that this is still racy for network
	// filesystems.
	if f.Flags().Append {
		uattr, err := f.Dirent.Inode.UnstableAttr(ctx)
		if err != nil {
			// This is an odd error, most likely it is evidence
			// that something is terribly wrong with the filesystem.
			// Return a generic EIO error.
			log.Warningf("Failed to check write of inode %#v: %v", f.Dirent.Inode.StableAttr, err)
			return offset, syserror.EIO
		}
		offset = uattr.Size
	}

	// Is this a regular file?
	if IsRegular(f.Dirent.Inode.StableAttr) {
		// Enforce size limits.
		fileSizeLimit := limits.FromContext(ctx).Get(limits.FileSize).Cur
		if fileSizeLimit <= math.MaxInt64 {
			if offset >= int64(fileSizeLimit) {
				return offset, syserror.ErrExceedsFileSizeLimit
			}
			*src = src.TakeFirst64(int64(fileSizeLimit) - offset)
		}
	}

	return offset, nil
}

// Fsync calls f.FileOperations.Fsync with f as the File.
//
// Returns syserror.ErrInterrupted if syncing was interrupted.
func (f *File) Fsync(ctx context.Context, start int64, end int64, syncType SyncType) error {
	if !f.mu.Lock(ctx) {
		return syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	return f.FileOperations.Fsync(ctx, f, start, end, syncType)
}

// Flush calls f.FileOperations.Flush with f as the File.
//
// Returns syserror.ErrInterrupted if syncing was interrupted.
func (f *File) Flush(ctx context.Context) error {
	if !f.mu.Lock(ctx) {
		return syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	return f.FileOperations.Flush(ctx, f)
}

// ConfigureMMap calls f.FileOperations.ConfigureMMap with f as the File.
//
// Returns syserror.ErrInterrupted if interrupted.
func (f *File) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if !f.mu.Lock(ctx) {
		return syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	return f.FileOperations.ConfigureMMap(ctx, f, opts)
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (f *File) MappedName(ctx context.Context) string {
	name, _ := f.Dirent.FullName(RootFromContext(ctx))
	return name
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (f *File) DeviceID() uint64 {
	return f.Dirent.Inode.StableAttr.DeviceID
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (f *File) InodeID() uint64 {
	return f.Dirent.Inode.StableAttr.InodeID
}

// Msync implements memmap.MappingIdentity.Msync.
func (f *File) Msync(ctx context.Context, mr memmap.MappableRange) error {
	return f.Fsync(ctx, int64(mr.Start), int64(mr.End-1), SyncData)
}

// A FileAsync sends signals to its owner when w is ready for IO.
type FileAsync interface {
	Register(w waiter.Waitable)
	Unregister(w waiter.Waitable)
}

// Async gets the stored FileAsync or creates a new one with the supplied
// function. If the supplied function is nil, no FileAsync is created and the
// current value is returned.
func (f *File) Async(newAsync func() FileAsync) FileAsync {
	f.flagsMu.Lock()
	defer f.flagsMu.Unlock()
	if f.async == nil && newAsync != nil {
		f.async = newAsync()
		if f.flags.Async {
			f.async.Register(f)
		}
	}
	return f.async
}

// FileReader implements io.Reader and io.ReaderAt.
type FileReader struct {
	// Ctx is the context for the file reader.
	Ctx context.Context

	// File is the file to read from.
	File *File
}

// Read implements io.Reader.Read.
func (r *FileReader) Read(buf []byte) (int, error) {
	n, err := r.File.Readv(r.Ctx, usermem.BytesIOSequence(buf))
	return int(n), err
}

// ReadAt implements io.Reader.ReadAt.
func (r *FileReader) ReadAt(buf []byte, offset int64) (int, error) {
	n, err := r.File.Preadv(r.Ctx, usermem.BytesIOSequence(buf), offset)
	return int(n), err
}

// FileWriter implements io.Writer and io.WriterAt.
type FileWriter struct {
	// Ctx is the context for the file writer.
	Ctx context.Context

	// File is the file to write to.
	File *File
}

// Write implements io.Writer.Write.
func (w *FileWriter) Write(buf []byte) (int, error) {
	n, err := w.File.Writev(w.Ctx, usermem.BytesIOSequence(buf))
	return int(n), err
}

// WriteAt implements io.Writer.WriteAt.
func (w *FileWriter) WriteAt(buf []byte, offset int64) (int, error) {
	n, err := w.File.Pwritev(w.Ctx, usermem.BytesIOSequence(buf), offset)
	return int(n), err
}
