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
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
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
// Lock order:
//   mu
//     mapsMu
type regularFile struct {
	inode inode

	// memFile is a platform.File used to allocate pages to this regularFile.
	memFile *pgalloc.MemoryFile

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

	// mu protects the fields below.
	mu sync.RWMutex

	// data maps offsets into the file to offsets into memFile that store
	// the file's data.
	data fsutil.FileRangeSet

	// size is the size of data, but accessed using atomic memory
	// operations to avoid holding mu in inode.stat().
	size uint64

	// seals represents file seals on this inode.
	seals uint32
}

func (fs *filesystem) newRegularFile(creds *auth.Credentials, mode linux.FileMode) *inode {
	file := &regularFile{
		memFile: fs.memFile,
	}
	file.inode.init(file, fs, creds, mode)
	file.inode.nlink = 1 // from parent directory
	return &file.inode
}

// truncate grows or shrinks the file to the given size. It returns true if the
// file size was updated.
func (rf *regularFile) truncate(newSize uint64) (bool, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	oldSize := rf.size
	switch {
	case newSize == oldSize:
		// Nothing to do.
		return false, nil
	case newSize > oldSize:
		// Can we grow the file?
		if rf.seals&linux.F_SEAL_GROW != 0 {
			return false, syserror.EPERM
		}
		// We only need to update the file size.
		rf.size = newSize
		return true, nil
	}

	// We are shrinking the file.  First check if this is allowed.
	if rf.seals&linux.F_SEAL_SHRINK != 0 {
		return false, syserror.EPERM
	}

	// Update the file size.
	rf.size = newSize

	// Invalidate past translations of truncated pages.
	oldpgend := fs.OffsetPageEnd(int64(rf.size))
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
	rf.data.Truncate(newSize, rf.memFile)
	return true, nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (rf *regularFile) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	rf.mapsMu.Lock()
	defer rf.mapsMu.Unlock()

	// Reject writable mapping if F_SEAL_WRITE is set.
	if rf.seals&linux.F_SEAL_WRITE != 0 && writable {
		return syserror.EPERM
	}

	rf.mappings.AddMapping(ms, ar, offset, writable)
	if writable {
		pagesBefore := rf.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		rf.writableMappingPages += uint64(ar.Length() / usermem.PageSize)

		if rf.writableMappingPages < pagesBefore {
			panic(fmt.Sprintf("Overflow while mapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, rf.writableMappingPages))
		}
	}

	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (rf *regularFile) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	rf.mapsMu.Lock()
	defer rf.mapsMu.Unlock()

	rf.mappings.RemoveMapping(ms, ar, offset, writable)

	if writable {
		pagesBefore := rf.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		rf.writableMappingPages -= uint64(ar.Length() / usermem.PageSize)

		if rf.writableMappingPages > pagesBefore {
			panic(fmt.Sprintf("Underflow while unmapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, rf.writableMappingPages))
		}
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (rf *regularFile) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return rf.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (rf *regularFile) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

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

	cerr := rf.data.Fill(ctx, required, optional, rf.memFile, usage.Tmpfs, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
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
			Perms:  usermem.AnyAccess,
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

type regularFileFD struct {
	fileDescription

	// off is the file offset. off is accessed using atomic memory operations.
	// offMu serializes operations that may mutate off.
	off   int64
	offMu sync.Mutex
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release() {
	// noop
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	f := fd.inode().impl.(*regularFile)
	rw := getRegularFileReadWriter(f, offset)
	n, err := dst.CopyOutFrom(ctx, rw)
	putRegularFileReadWriter(rw)
	return int64(n), err
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
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	srclen := src.NumBytes()
	if srclen == 0 {
		return 0, nil
	}
	f := fd.inode().impl.(*regularFile)
	end := offset + srclen
	if end < offset {
		// Overflow.
		return 0, syserror.EFBIG
	}
	rw := getRegularFileReadWriter(f, offset)
	n, err := src.CopyInTo(ctx, rw)
	putRegularFileReadWriter(rw)
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PWrite(ctx, src, fd.off, opts)
	fd.off += n
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
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *regularFileFD) Sync(ctx context.Context) error {
	return nil
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
	rw.file.mu.RLock()

	// Compute the range to read (limited by file size and overflow-checked).
	if rw.off >= rw.file.size {
		rw.file.mu.RUnlock()
		return 0, io.EOF
	}
	end := rw.file.size
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
			ims, err := rw.file.memFile.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Read)
			if err != nil {
				rw.file.mu.RUnlock()
				return done, err
			}

			// Copy from internal mappings.
			n, err := safemem.CopySeq(dsts, ims)
			done += n
			rw.off += uint64(n)
			dsts = dsts.DropFirst64(n)
			if err != nil {
				rw.file.mu.RUnlock()
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
				rw.file.mu.RUnlock()
				return done, err
			}

			// Continue.
			seg, gap = gap.NextSegment(), fsutil.FileRangeGapIterator{}
		}
	}
	rw.file.mu.RUnlock()
	return done, nil
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *regularFileReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	rw.file.mu.Lock()

	// Compute the range to write (overflow-checked).
	end := rw.off + srcs.NumBytes()
	if end <= rw.off {
		end = math.MaxInt64
	}

	// Check if seals prevent either file growth or all writes.
	switch {
	case rw.file.seals&linux.F_SEAL_WRITE != 0: // Write sealed
		rw.file.mu.Unlock()
		return 0, syserror.EPERM
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
		if pgstart := uint64(usermem.Addr(rw.file.size).RoundDown()); end > pgstart {
			end = pgstart
		}
		if end <= rw.off {
			// Truncation would result in no data being written.
			rw.file.mu.Unlock()
			return 0, syserror.EPERM
		}
	}

	// Page-aligned mr for when we need to allocate memory. RoundUp can't
	// overflow since end is an int64.
	pgstartaddr := usermem.Addr(rw.off).RoundDown()
	pgendaddr, _ := usermem.Addr(end).RoundUp()
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
			ims, err := rw.file.memFile.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Write)
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
			fr, err := rw.file.memFile.Allocate(gapMR.Length(), usage.Tmpfs)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Write to that memory as usual.
			seg, gap = rw.file.data.Insert(gap, gapMR, fr.Start), fsutil.FileRangeGapIterator{}
		}
	}
exitLoop:
	// If the write ends beyond the file's previous size, it causes the
	// file to grow.
	if rw.off > rw.file.size {
		atomic.StoreUint64(&rw.file.size, rw.off)
	}

	rw.file.mu.Unlock()
	return done, retErr
}
