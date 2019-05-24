// Copyright 2018 The gVisor Authors.
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
	"time"

	"gvisor.googlesource.com/gvisor/pkg/amutex"
	"gvisor.googlesource.com/gvisor/pkg/metric"
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

var (
	// RecordWaitTime controls writing metrics for filesystem reads.
	// Enabling this comes at a small CPU cost due to performing two
	// monotonic clock reads per read call.
	//
	// Note that this is only performed in the direct read path, and may
	// not be consistently applied for other forms of reads, such as
	// splice.
	RecordWaitTime = false

	reads    = metric.MustCreateNewUint64Metric("/fs/reads", false /* sync */, "Number of file reads.")
	readWait = metric.MustCreateNewUint64Metric("/fs/read_wait", false /* sync */, "Time waiting on file reads, in nanoseconds.")
)

// IncrementWait increments the given wait time metric, if enabled.
func IncrementWait(m *metric.Uint64Metric, start time.Time) {
	if !RecordWaitTime {
		return
	}
	m.IncrementBy(uint64(time.Since(start)))
}

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
// FIXME(b/38451980): Split synchronization from cancellation.
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

	// saving indicates that this file is in the process of being saved.
	saving bool `state:"nosave"`

	// mu is dual-purpose: first, to make read(2) and write(2) thread-safe
	// in conformity with POSIX, and second, to cancel operations before they
	// begin in response to interruptions (i.e. signals).
	mu amutex.AbortableMutex `state:"nosave"`

	// FileOperations implements file system specific behavior for this File.
	FileOperations FileOperations `state:"wait"`

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

		// Only unregister if we are currently registered. There is nothing
		// to register if f.async is nil (this happens when async mode is
		// enabled without setting an owner). Also, we unregister during
		// save.
		f.flagsMu.Lock()
		if !f.saving && f.flags.Async && f.async != nil {
			f.async.Unregister(f)
		}
		f.async = nil
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
	var start time.Time
	if RecordWaitTime {
		start = time.Now()
	}
	if !f.mu.Lock(ctx) {
		IncrementWait(readWait, start)
		return 0, syserror.ErrInterrupted
	}

	reads.Increment()
	n, err := f.FileOperations.Read(ctx, f, dst, f.offset)
	if n > 0 {
		atomic.AddInt64(&f.offset, n)
	}
	f.mu.Unlock()
	IncrementWait(readWait, start)
	return n, err
}

// Preadv calls f.FileOperations.Read with f as the File. It does not
// advance the file offset. If !f.Flags().Pread, Preadv should not be
// called.
//
// Otherwise same as Readv.
func (f *File) Preadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	var start time.Time
	if RecordWaitTime {
		start = time.Now()
	}
	if !f.mu.Lock(ctx) {
		IncrementWait(readWait, start)
		return 0, syserror.ErrInterrupted
	}

	reads.Increment()
	n, err := f.FileOperations.Read(ctx, f, dst, offset)
	f.mu.Unlock()
	IncrementWait(readWait, start)
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

	// Handle append mode.
	if f.Flags().Append {
		if err := f.offsetForAppend(ctx, &f.offset); err != nil {
			f.mu.Unlock()
			return 0, err
		}
	}

	// Enforce file limits.
	limit, ok := f.checkLimit(ctx, f.offset)
	switch {
	case ok && limit == 0:
		f.mu.Unlock()
		return 0, syserror.ErrExceedsFileSizeLimit
	case ok:
		src = src.TakeFirst64(limit)
	}

	// We must hold the lock during the write.
	n, err := f.FileOperations.Write(ctx, f, src, f.offset)
	if n >= 0 {
		atomic.StoreInt64(&f.offset, f.offset+n)
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
	// "POSIX requires that opening a file with the O_APPEND flag should
	// have no effect on the location at which pwrite() writes data.
	// However, on Linux, if a file is opened with O_APPEND,  pwrite()
	// appends data to the end of the file, regardless of the value of
	// offset."
	if f.Flags().Append {
		if !f.mu.Lock(ctx) {
			return 0, syserror.ErrInterrupted
		}
		defer f.mu.Unlock()
		if err := f.offsetForAppend(ctx, &offset); err != nil {
			f.mu.Unlock()
			return 0, err
		}
	}

	// Enforce file limits.
	limit, ok := f.checkLimit(ctx, offset)
	switch {
	case ok && limit == 0:
		return 0, syserror.ErrExceedsFileSizeLimit
	case ok:
		src = src.TakeFirst64(limit)
	}

	return f.FileOperations.Write(ctx, f, src, offset)
}

// offsetForAppend sets the given offset to the end of the file.
//
// Precondition: the underlying file mutex should be held.
func (f *File) offsetForAppend(ctx context.Context, offset *int64) error {
	uattr, err := f.Dirent.Inode.UnstableAttr(ctx)
	if err != nil {
		// This is an odd error, we treat it as evidence that
		// something is terribly wrong with the filesystem.
		return syserror.EIO
	}

	// Update the offset.
	*offset = uattr.Size

	return nil
}

// checkLimit checks the offset that the write will be performed at. The
// returned boolean indicates that the write must be limited. The returned
// integer indicates the new maximum write length.
func (f *File) checkLimit(ctx context.Context, offset int64) (int64, bool) {
	if IsRegular(f.Dirent.Inode.StableAttr) {
		// Enforce size limits.
		fileSizeLimit := limits.FromContext(ctx).Get(limits.FileSize).Cur
		if fileSizeLimit <= math.MaxInt64 {
			if offset >= int64(fileSizeLimit) {
				return 0, true
			}
			return int64(fileSizeLimit) - offset, true
		}
	}

	return 0, false
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

// UnstableAttr calls f.FileOperations.UnstableAttr with f as the File.
//
// Returns syserror.ErrInterrupted if interrupted.
func (f *File) UnstableAttr(ctx context.Context) (UnstableAttr, error) {
	if !f.mu.Lock(ctx) {
		return UnstableAttr{}, syserror.ErrInterrupted
	}
	defer f.mu.Unlock()

	return f.FileOperations.UnstableAttr(ctx, f)
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (f *File) MappedName(ctx context.Context) string {
	root := RootFromContext(ctx)
	if root != nil {
		defer root.DecRef()
	}
	name, _ := f.Dirent.FullName(root)
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

// lockedReader implements io.Reader and io.ReaderAt.
//
// Note this reads the underlying file using the file operations directly. It
// is the responsibility of the caller to ensure that locks are appropriately
// held and offsets updated if required. This should be used only by internal
// functions that perform these operations and checks at other times.
type lockedReader struct {
	// Ctx is the context for the file reader.
	Ctx context.Context

	// File is the file to read from.
	File *File
}

// Read implements io.Reader.Read.
func (r *lockedReader) Read(buf []byte) (int, error) {
	if r.Ctx.Interrupted() {
		return 0, syserror.ErrInterrupted
	}
	n, err := r.File.FileOperations.Read(r.Ctx, r.File, usermem.BytesIOSequence(buf), r.File.offset)
	return int(n), err
}

// ReadAt implements io.Reader.ReadAt.
func (r *lockedReader) ReadAt(buf []byte, offset int64) (int, error) {
	if r.Ctx.Interrupted() {
		return 0, syserror.ErrInterrupted
	}
	n, err := r.File.FileOperations.Read(r.Ctx, r.File, usermem.BytesIOSequence(buf), offset)
	return int(n), err
}

// lockedWriter implements io.Writer and io.WriterAt.
//
// The same constraints as lockedReader apply; see above.
type lockedWriter struct {
	// Ctx is the context for the file writer.
	Ctx context.Context

	// File is the file to write to.
	File *File
}

// Write implements io.Writer.Write.
func (w *lockedWriter) Write(buf []byte) (int, error) {
	n, err := w.File.FileOperations.Write(w.Ctx, w.File, usermem.BytesIOSequence(buf), w.File.offset)
	return int(n), err
}

// WriteAt implements io.Writer.WriteAt.
func (w *lockedWriter) WriteAt(buf []byte, offset int64) (int, error) {
	n, err := w.File.FileOperations.Write(w.Ctx, w.File, usermem.BytesIOSequence(buf), offset)
	return int(n), err
}
