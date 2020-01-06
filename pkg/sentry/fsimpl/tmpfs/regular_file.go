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
	"io"
	"math"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

type regularFile struct {
	inode inode

	// memFile is a platform.File used to allocate pages to this regularFile.
	memFile *pgalloc.MemoryFile

	// mu protects the fields below.
	mu sync.RWMutex

	// data maps offsets into the file to offsets into memFile that store
	// the file's data.
	data fsutil.FileRangeSet

	// size is the size of data, but accessed using atomic memory
	// operations to avoid locking in inode.stat().
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

type regularFileFD struct {
	fileDescription

	// These are immutable.
	readable bool
	writable bool

	// off is the file offset. off is accessed using atomic memory operations.
	// offMu serializes operations that may mutate off.
	off   int64
	offMu sync.Mutex
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release() {
	if fd.writable {
		fd.vfsfd.VirtualDentry().Mount().EndWrite()
	}
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if !fd.readable {
		return 0, syserror.EINVAL
	}
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
	if !fd.writable {
		return 0, syserror.EINVAL
	}
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
