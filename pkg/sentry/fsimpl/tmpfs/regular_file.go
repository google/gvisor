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

package tmpfs

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// regularFile is a regular (=S_IFREG) tmpfs file.
//
// +stateify savable
type regularFile struct {
	inode inode

	// memFile is a platform.File used to allocate pages to this regularFile.
	memFile *pgalloc.MemoryFile `state:"nosave"`

	// memoryUsageKind is the memory accounting category under which pages backing
	// this regularFile's contents are accounted.
	memoryUsageKind usage.MemoryKind

	// mapsMu protects mappings.
	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks mappings of the file into memmap.MappingSpaces.
	//
	// Protected by mapsMu.
	mappings memmap.MappingSet

	// writableMappingPages tracks how many pages of virtual memory are mapped
	// as potentially writable from this file. If a page has multiple mappings,
	// each mapping is counted separately.
	//
	// This counter is susceptible to overflow as we can potentially count
	// mappings from many VMAs. We count pages rather than bytes to slightly
	// mitigate this.
	//
	// Protected by mapsMu.
	writableMappingPages uint64

	// dataMu protects the fields below.
	dataMu sync.RWMutex `state:"nosave"`

	// data maps offsets into the file to offsets into memFile that store
	// the file's data.
	//
	// Protected by dataMu.
	data fsutil.FileRangeSet

	// seals represents file seals on this inode.
	//
	// Protected by dataMu.
	seals uint32

	// size is the size of data.
	//
	// Protected by both dataMu and inode.mu; reading it requires holding
	// either mutex, while writing requires holding both AND using atomics.
	// Readers that do not require consistency (like Stat) may read the
	// value atomically without holding either lock.
	size uint64
}

func (fs *filesystem) newRegularFile(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, parentDir *directory) *inode {
	file := &regularFile{
		memFile:         fs.mfp.MemoryFile(),
		memoryUsageKind: usage.Tmpfs,
		seals:           linux.F_SEAL_SEAL,
	}
	file.inode.init(file, fs, kuid, kgid, linux.S_IFREG|mode, parentDir)
	file.inode.nlink = 1 // from parent directory
	return &file.inode
}

// newUnlinkedRegularFileDescription creates a regular file on the tmpfs
// filesystem represented by mount and returns an FD representing that file.
// The new file is not reachable by path traversal from any other file.
//
// newUnlinkedRegularFileDescription is analogous to Linux's
// mm/shmem.c:__shmem_file_setup().
//
// Preconditions: mount must be a tmpfs mount.
func newUnlinkedRegularFileDescription(ctx context.Context, creds *auth.Credentials, mount *vfs.Mount, name string) (*regularFileFD, error) {
	fs, ok := mount.Filesystem().Impl().(*filesystem)
	if !ok {
		panic("tmpfs.newUnlinkedRegularFileDescription() called with non-tmpfs mount")
	}

	inode := fs.newRegularFile(creds.EffectiveKUID, creds.EffectiveKGID, 0777, nil /* parentDir */)
	d := fs.newDentry(inode)
	defer d.DecRef(ctx)
	d.name = name

	fd := &regularFileFD{}
	fd.Init(&inode.locks)
	flags := uint32(linux.O_RDWR)
	if err := fd.vfsfd.Init(fd, flags, mount, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return fd, nil
}

// NewZeroFile creates a new regular file and file description as for
// mmap(MAP_SHARED | MAP_ANONYMOUS). The file has the given size and is
// initially (implicitly) filled with zeroes.
//
// Preconditions: mount must be a tmpfs mount.
func NewZeroFile(ctx context.Context, creds *auth.Credentials, mount *vfs.Mount, size uint64) (*vfs.FileDescription, error) {
	// Compare mm/shmem.c:shmem_zero_setup().
	fd, err := newUnlinkedRegularFileDescription(ctx, creds, mount, "dev/zero")
	if err != nil {
		return nil, err
	}
	rf := fd.inode().impl.(*regularFile)
	rf.memoryUsageKind = usage.Anonymous
	rf.size = size
	return &fd.vfsfd, err
}

// NewMemfd creates a new regular file and file description as for
// memfd_create.
//
// Preconditions: mount must be a tmpfs mount.
func NewMemfd(ctx context.Context, creds *auth.Credentials, mount *vfs.Mount, allowSeals bool, name string) (*vfs.FileDescription, error) {
	fd, err := newUnlinkedRegularFileDescription(ctx, creds, mount, name)
	if err != nil {
		return nil, err
	}
	if allowSeals {
		fd.inode().impl.(*regularFile).seals = 0
	}
	return &fd.vfsfd, nil
}

// truncate grows or shrinks the file to the given size. It returns true if the
// file size was updated.
func (rf *regularFile) truncate(newSize uint64) (bool, error) {
	rf.inode.mu.Lock()
	defer rf.inode.mu.Unlock()
	return rf.truncateLocked(newSize)
}

// Preconditions: rf.inode.mu must be held.
func (rf *regularFile) truncateLocked(newSize uint64) (bool, error) {
	oldSize := rf.size
	if newSize == oldSize {
		// Nothing to do.
		return false, nil
	}

	// Need to hold inode.mu and dataMu while modifying size.
	rf.dataMu.Lock()
	if newSize > oldSize {
		// Can we grow the file?
		if rf.seals&linux.F_SEAL_GROW != 0 {
			rf.dataMu.Unlock()
			return false, linuxerr.EPERM
		}
		// We only need to update the file size.
		atomic.StoreUint64(&rf.size, newSize)
		rf.dataMu.Unlock()
		return true, nil
	}

	// We are shrinking the file. First check if this is allowed.
	if rf.seals&linux.F_SEAL_SHRINK != 0 {
		rf.dataMu.Unlock()
		return false, linuxerr.EPERM
	}

	// Update the file size.
	atomic.StoreUint64(&rf.size, newSize)
	rf.dataMu.Unlock()

	// Invalidate past translations of truncated pages.
	oldpgend := fs.OffsetPageEnd(int64(oldSize))
	newpgend := fs.OffsetPageEnd(int64(newSize))
	if newpgend < oldpgend {
		rf.mapsMu.Lock()
		rf.mappings.Invalidate(memmap.MappableRange{newpgend, oldpgend}, memmap.InvalidateOpts{
			// Compare Linux's mm/shmem.c:shmem_setattr() =>
			// mm/memory.c:unmap_mapping_range(evencows=1).
			InvalidatePrivate: true,
		})
		rf.mapsMu.Unlock()
	}

	// We are now guaranteed that there are no translations of truncated pages,
	// and can remove them.
	rf.dataMu.Lock()
	rf.data.Truncate(newSize, rf.memFile)
	rf.dataMu.Unlock()
	return true, nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (rf *regularFile) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	rf.mapsMu.Lock()
	defer rf.mapsMu.Unlock()
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()

	// Reject writable mapping if F_SEAL_WRITE is set.
	if rf.seals&linux.F_SEAL_WRITE != 0 && writable {
		return linuxerr.EPERM
	}

	rf.mappings.AddMapping(ms, ar, offset, writable)
	if writable {
		pagesBefore := rf.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		rf.writableMappingPages += uint64(ar.Length() / hostarch.PageSize)

		if rf.writableMappingPages < pagesBefore {
			panic(fmt.Sprintf("Overflow while mapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, rf.writableMappingPages))
		}
	}

	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (rf *regularFile) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	rf.mapsMu.Lock()
	defer rf.mapsMu.Unlock()

	rf.mappings.RemoveMapping(ms, ar, offset, writable)

	if writable {
		pagesBefore := rf.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		rf.writableMappingPages -= uint64(ar.Length() / hostarch.PageSize)

		if rf.writableMappingPages > pagesBefore {
			panic(fmt.Sprintf("Underflow while unmapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, rf.writableMappingPages))
		}
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (rf *regularFile) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return rf.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (rf *regularFile) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	rf.dataMu.Lock()
	defer rf.dataMu.Unlock()

	// Constrain translations to f.attr.Size (rounded up) to prevent
	// translation to pages that may be concurrently truncated.
	pgend := fs.OffsetPageEnd(int64(rf.size))
	var beyondEOF bool
	if required.End > pgend {
		if required.Start >= pgend {
			return nil, &memmap.BusError{io.EOF}
		}
		beyondEOF = true
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}

	cerr := rf.data.Fill(ctx, required, optional, rf.size, rf.memFile, rf.memoryUsageKind, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
		// Newly-allocated pages are zeroed, so we don't need to do anything.
		return dsts.NumBytes(), nil
	})

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := rf.data.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   rf.memFile,
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
	if beyondEOF {
		return ts, &memmap.BusError{io.EOF}
	}
	return ts, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (*regularFile) InvalidateUnsavable(context.Context) error {
	return nil
}

// +stateify savable
type regularFileFD struct {
	fileDescription

	// off is the file offset. off is accessed using atomic memory operations.
	// offMu serializes operations that may mutate off.
	off   int64
	offMu sync.Mutex `state:"nosave"`
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release(context.Context) {
	// noop
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *regularFileFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	f := fd.inode().impl.(*regularFile)

	f.inode.mu.Lock()
	defer f.inode.mu.Unlock()
	oldSize := f.size
	size := offset + length
	if oldSize >= size {
		return nil
	}
	_, err := f.truncateLocked(size)
	return err
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	start := fsmetric.StartReadWait()
	defer fsmetric.FinishReadWait(fsmetric.TmpfsReadWait, start)
	fsmetric.TmpfsReads.Increment()

	if offset < 0 {
		return 0, linuxerr.EINVAL
	}

	// Check that flags are supported. RWF_DSYNC/RWF_SYNC can be ignored since
	// all state is in-memory.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^(linux.RWF_HIPRI|linux.RWF_DSYNC|linux.RWF_SYNC) != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	if dst.NumBytes() == 0 {
		return 0, nil
	}
	f := fd.inode().impl.(*regularFile)
	rw := getRegularFileReadWriter(f, offset)
	n, err := dst.CopyOutFrom(ctx, rw)
	putRegularFileReadWriter(rw)
	fd.inode().touchAtime(fd.vfsfd.Mount())
	return n, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// pwrite returns the number of bytes written, final offset and error. The
// final offset should be ignored by PWrite.
func (fd *regularFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, linuxerr.EINVAL
	}

	// Check that flags are supported. RWF_DSYNC/RWF_SYNC can be ignored since
	// all state is in-memory.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^(linux.RWF_HIPRI|linux.RWF_DSYNC|linux.RWF_SYNC) != 0 {
		return 0, offset, syserror.EOPNOTSUPP
	}

	srclen := src.NumBytes()
	if srclen == 0 {
		return 0, offset, nil
	}
	f := fd.inode().impl.(*regularFile)
	f.inode.mu.Lock()
	defer f.inode.mu.Unlock()
	// If the file is opened with O_APPEND, update offset to file size.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		// Locking f.inode.mu is sufficient for reading f.size.
		offset = int64(f.size)
	}
	if end := offset + srclen; end < offset {
		// Overflow.
		return 0, offset, linuxerr.EINVAL
	}

	srclen, err = vfs.CheckLimit(ctx, offset, srclen)
	if err != nil {
		return 0, offset, err
	}
	src = src.TakeFirst64(srclen)

	rw := getRegularFileReadWriter(f, offset)
	n, err := src.CopyInTo(ctx, rw)
	f.inode.touchCMtimeLocked()
	for {
		old := atomic.LoadUint32(&f.inode.mode)
		new := vfs.ClearSUIDAndSGID(old)
		if swapped := atomic.CompareAndSwapUint32(&f.inode.mode, old, new); swapped {
			break
		}
	}
	putRegularFileReadWriter(rw)
	return n, n + offset, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.offMu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.offMu.Unlock()
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.offMu.Lock()
	defer fd.offMu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// use offset as specified
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		offset += int64(atomic.LoadUint64(&fd.inode().impl.(*regularFile).size))
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	file := fd.inode().impl.(*regularFile)
	opts.SentryOwnedContent = true
	return vfs.GenericConfigureMMap(&fd.vfsfd, file, opts)
}

// regularFileReadWriter implements safemem.Reader and Safemem.Writer.
type regularFileReadWriter struct {
	file *regularFile

	// Offset into the file to read/write at. Note that this may be
	// different from the FD offset if PRead/PWrite is used.
	off uint64
}

var regularFileReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &regularFileReadWriter{}
	},
}

func getRegularFileReadWriter(file *regularFile, offset int64) *regularFileReadWriter {
	rw := regularFileReadWriterPool.Get().(*regularFileReadWriter)
	rw.file = file
	rw.off = uint64(offset)
	return rw
}

func putRegularFileReadWriter(rw *regularFileReadWriter) {
	rw.file = nil
	regularFileReadWriterPool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *regularFileReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	rw.file.dataMu.RLock()
	defer rw.file.dataMu.RUnlock()
	size := rw.file.size

	// Compute the range to read (limited by file size and overflow-checked).
	if rw.off >= size {
		return 0, io.EOF
	}
	end := size
	if rend := rw.off + dsts.NumBytes(); rend > rw.off && rend < end {
		end = rend
	}

	var done uint64
	seg, gap := rw.file.data.Find(uint64(rw.off))
	for rw.off < end {
		mr := memmap.MappableRange{uint64(rw.off), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings.
			ims, err := rw.file.memFile.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), hostarch.Read)
			if err != nil {
				return done, err
			}

			// Copy from internal mappings.
			n, err := safemem.CopySeq(dsts, ims)
			done += n
			rw.off += uint64(n)
			dsts = dsts.DropFirst64(n)
			if err != nil {
				return done, err
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			// Tmpfs holes are zero-filled.
			gapmr := gap.Range().Intersect(mr)
			dst := dsts.TakeFirst64(gapmr.Length())
			n, err := safemem.ZeroSeq(dst)
			done += n
			rw.off += uint64(n)
			dsts = dsts.DropFirst64(n)
			if err != nil {
				return done, err
			}

			// Continue.
			seg, gap = gap.NextSegment(), fsutil.FileRangeGapIterator{}
		}
	}
	return done, nil
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: rw.file.inode.mu must be held.
func (rw *regularFileReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	// Hold dataMu so we can modify size.
	rw.file.dataMu.Lock()
	defer rw.file.dataMu.Unlock()

	// Compute the range to write (overflow-checked).
	end := rw.off + srcs.NumBytes()
	if end <= rw.off {
		end = math.MaxInt64
	}

	// Check if seals prevent either file growth or all writes.
	switch {
	case rw.file.seals&linux.F_SEAL_WRITE != 0: // Write sealed
		return 0, linuxerr.EPERM
	case end > rw.file.size && rw.file.seals&linux.F_SEAL_GROW != 0: // Grow sealed
		// When growth is sealed, Linux effectively allows writes which would
		// normally grow the file to partially succeed up to the current EOF,
		// rounded down to the page boundary before the EOF.
		//
		// This happens because writes (and thus the growth check) for tmpfs
		// files proceed page-by-page on Linux, and the final write to the page
		// containing EOF fails, resulting in a partial write up to the start of
		// that page.
		//
		// To emulate this behaviour, artifically truncate the write to the
		// start of the page containing the current EOF.
		//
		// See Linux, mm/filemap.c:generic_perform_write() and
		// mm/shmem.c:shmem_write_begin().
		if pgstart := uint64(hostarch.Addr(rw.file.size).RoundDown()); end > pgstart {
			end = pgstart
		}
		if end <= rw.off {
			// Truncation would result in no data being written.
			return 0, linuxerr.EPERM
		}
	}

	// Page-aligned mr for when we need to allocate memory. RoundUp can't
	// overflow since end is an int64.
	pgstartaddr := hostarch.Addr(rw.off).RoundDown()
	pgendaddr, _ := hostarch.Addr(end).RoundUp()
	pgMR := memmap.MappableRange{uint64(pgstartaddr), uint64(pgendaddr)}

	var (
		done   uint64
		retErr error
	)
	seg, gap := rw.file.data.Find(uint64(rw.off))
	for rw.off < end {
		mr := memmap.MappableRange{uint64(rw.off), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings.
			ims, err := rw.file.memFile.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), hostarch.Write)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Copy to internal mappings.
			n, err := safemem.CopySeq(ims, srcs)
			done += n
			rw.off += uint64(n)
			srcs = srcs.DropFirst64(n)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			// Allocate memory for the write.
			gapMR := gap.Range().Intersect(pgMR)
			fr, err := rw.file.memFile.Allocate(gapMR.Length(), rw.file.memoryUsageKind)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Write to that memory as usual.
			seg, gap = rw.file.data.Insert(gap, gapMR, fr.Start), fsutil.FileRangeGapIterator{}

		default:
			panic("unreachable")
		}
	}
exitLoop:
	// If the write ends beyond the file's previous size, it causes the
	// file to grow.
	if rw.off > rw.file.size {
		atomic.StoreUint64(&rw.file.size, rw.off)
	}

	return done, retErr
}

// GetSeals returns the current set of seals on a memfd inode.
func GetSeals(fd *vfs.FileDescription) (uint32, error) {
	f, ok := fd.Impl().(*regularFileFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	rf := f.inode().impl.(*regularFile)
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()
	return rf.seals, nil
}

// AddSeals adds new file seals to a memfd inode.
func AddSeals(fd *vfs.FileDescription, val uint32) error {
	f, ok := fd.Impl().(*regularFileFD)
	if !ok {
		return linuxerr.EINVAL
	}
	rf := f.inode().impl.(*regularFile)
	rf.mapsMu.Lock()
	defer rf.mapsMu.Unlock()
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()

	if rf.seals&linux.F_SEAL_SEAL != 0 {
		// Seal applied which prevents addition of any new seals.
		return linuxerr.EPERM
	}

	// F_SEAL_WRITE can only be added if there are no active writable maps.
	if rf.seals&linux.F_SEAL_WRITE == 0 && val&linux.F_SEAL_WRITE != 0 {
		if rf.writableMappingPages > 0 {
			return syserror.EBUSY
		}
	}

	// Seals can only be added, never removed.
	rf.seals |= val
	return nil
}
