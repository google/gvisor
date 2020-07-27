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

package gofer

import (
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (d *dentry) isRegularFile() bool {
	return d.fileType() == linux.S_IFREG
}

type regularFileFD struct {
	fileDescription

	// off is the file offset. off is protected by mu.
	mu  sync.Mutex
	off int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release() {
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *regularFileFD) OnClose(ctx context.Context) error {
	if !fd.vfsfd.IsWritable() {
		return nil
	}
	// Skip flushing if writes may be buffered by the client, since (as with
	// the VFS1 client) we don't flush buffered writes on close anyway.
	d := fd.dentry()
	if d.fs.opts.interop == InteropModeExclusive {
		return nil
	}
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.handle.file.flush(ctx)
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *regularFileFD) Allocate(ctx context.Context, mode, offset, length uint64) error {

	d := fd.dentry()
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	size := offset + length

	// Allocating a smaller size is a noop.
	if size <= d.size {
		return nil
	}

	d.handleMu.Lock()
	defer d.handleMu.Unlock()

	err := d.handle.file.allocate(ctx, p9.ToAllocateMode(mode), offset, length)
	if err != nil {
		return err
	}
	d.dataMu.Lock()
	atomic.StoreUint64(&d.size, size)
	d.dataMu.Unlock()
	if !d.cachedMetadataAuthoritative() {
		d.touchCMtimeLocked()
	}
	return nil
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	// Check for reading at EOF before calling into MM (but not under
	// InteropModeShared, which makes d.size unreliable).
	d := fd.dentry()
	if d.fs.opts.interop != InteropModeShared && uint64(offset) >= atomic.LoadUint64(&d.size) {
		return 0, io.EOF
	}

	if fd.vfsfd.StatusFlags()&linux.O_DIRECT != 0 {
		// Lock d.metadataMu for the rest of the read to prevent d.size from
		// changing.
		d.metadataMu.Lock()
		defer d.metadataMu.Unlock()
		// Write dirty cached pages that will be touched by the read back to
		// the remote file.
		if err := d.writeback(ctx, offset, dst.NumBytes()); err != nil {
			return 0, err
		}
	}

	rw := getDentryReadWriter(ctx, d, offset)
	if fd.vfsfd.StatusFlags()&linux.O_DIRECT != 0 {
		// Require the read to go to the remote file.
		rw.direct = true
	}
	n, err := dst.CopyOutFrom(ctx, rw)
	putDentryReadWriter(rw)
	if d.fs.opts.interop != InteropModeShared {
		// Compare Linux's mm/filemap.c:do_generic_file_read() => file_accessed().
		d.touchAtime(fd.vfsfd.Mount())
	}
	return n, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// pwrite returns the number of bytes written, final offset, error. The final
// offset should be ignored by PWrite.
func (fd *regularFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select pwritev2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, syserror.EOPNOTSUPP
	}

	d := fd.dentry()
	// If the fd was opened with O_APPEND, make sure the file size is updated.
	// There is a possible race here if size is modified externally after
	// metadata cache is updated.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 && !d.cachedMetadataAuthoritative() {
		if err := d.updateFromGetattr(ctx); err != nil {
			return 0, offset, err
		}
	}

	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	// Set offset to file size if the fd was opened with O_APPEND.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		// Holding d.metadataMu is sufficient for reading d.size.
		offset = int64(d.size)
	}
	limit, err := vfs.CheckLimit(ctx, offset, src.NumBytes())
	if err != nil {
		return 0, offset, err
	}
	src = src.TakeFirst64(limit)
	n, err := fd.pwriteLocked(ctx, src, offset, opts)
	return n, offset + n, err
}

// Preconditions: fd.dentry().metatdataMu must be locked.
func (fd *regularFileFD) pwriteLocked(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	d := fd.dentry()
	if d.fs.opts.interop != InteropModeShared {
		// Compare Linux's mm/filemap.c:__generic_file_write_iter() =>
		// file_update_time(). This is d.touchCMtime(), but without locking
		// d.metadataMu (recursively).
		d.touchCMtimeLocked()
	}
	if fd.vfsfd.StatusFlags()&linux.O_DIRECT != 0 {
		// Write dirty cached pages that will be touched by the write back to
		// the remote file.
		if err := d.writeback(ctx, offset, src.NumBytes()); err != nil {
			return 0, err
		}
		// Remove touched pages from the cache.
		pgstart := usermem.PageRoundDown(uint64(offset))
		pgend, ok := usermem.PageRoundUp(uint64(offset + src.NumBytes()))
		if !ok {
			return 0, syserror.EINVAL
		}
		mr := memmap.MappableRange{pgstart, pgend}
		var freed []memmap.FileRange
		d.dataMu.Lock()
		cseg := d.cache.LowerBoundSegment(mr.Start)
		for cseg.Ok() && cseg.Start() < mr.End {
			cseg = d.cache.Isolate(cseg, mr)
			freed = append(freed, memmap.FileRange{cseg.Value(), cseg.Value() + cseg.Range().Length()})
			cseg = d.cache.Remove(cseg).NextSegment()
		}
		d.dataMu.Unlock()
		// Invalidate mappings of removed pages.
		d.mapsMu.Lock()
		d.mappings.Invalidate(mr, memmap.InvalidateOpts{})
		d.mapsMu.Unlock()
		// Finally free pages removed from the cache.
		mf := d.fs.mfp.MemoryFile()
		for _, freedFR := range freed {
			mf.DecRef(freedFR)
		}
	}
	rw := getDentryReadWriter(ctx, d, offset)
	if fd.vfsfd.StatusFlags()&linux.O_DIRECT != 0 {
		// Require the write to go to the remote file.
		rw.direct = true
	}
	n, err := src.CopyInTo(ctx, rw)
	putDentryReadWriter(rw)
	if n != 0 && fd.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 {
		// Write dirty cached pages touched by the write back to the remote
		// file.
		if err := d.writeback(ctx, offset, src.NumBytes()); err != nil {
			return 0, err
		}
		// Request the remote filesystem to sync the remote file.
		if err := d.handle.file.fsync(ctx); err != nil {
			return 0, err
		}
	}
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.mu.Unlock()
	return n, err
}

type dentryReadWriter struct {
	ctx    context.Context
	d      *dentry
	off    uint64
	direct bool
}

var dentryReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &dentryReadWriter{}
	},
}

func getDentryReadWriter(ctx context.Context, d *dentry, offset int64) *dentryReadWriter {
	rw := dentryReadWriterPool.Get().(*dentryReadWriter)
	rw.ctx = ctx
	rw.d = d
	rw.off = uint64(offset)
	rw.direct = false
	return rw
}

func putDentryReadWriter(rw *dentryReadWriter) {
	rw.ctx = nil
	rw.d = nil
	dentryReadWriterPool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *dentryReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}

	// If we have a mmappable host FD (which must be used here to ensure
	// coherence with memory-mapped I/O), or if InteropModeShared is in effect
	// (which prevents us from caching file contents and makes dentry.size
	// unreliable), or if the file was opened O_DIRECT, read directly from
	// dentry.handle without locking dentry.dataMu.
	rw.d.handleMu.RLock()
	if (rw.d.handle.fd >= 0 && !rw.d.fs.opts.forcePageCache) || rw.d.fs.opts.interop == InteropModeShared || rw.direct {
		n, err := rw.d.handle.readToBlocksAt(rw.ctx, dsts, rw.off)
		rw.d.handleMu.RUnlock()
		rw.off += n
		return n, err
	}

	// Otherwise read from/through the cache.
	mf := rw.d.fs.mfp.MemoryFile()
	fillCache := mf.ShouldCacheEvictable()
	var dataMuUnlock func()
	if fillCache {
		rw.d.dataMu.Lock()
		dataMuUnlock = rw.d.dataMu.Unlock
	} else {
		rw.d.dataMu.RLock()
		dataMuUnlock = rw.d.dataMu.RUnlock
	}

	// Compute the range to read (limited by file size and overflow-checked).
	if rw.off >= rw.d.size {
		dataMuUnlock()
		rw.d.handleMu.RUnlock()
		return 0, io.EOF
	}
	end := rw.d.size
	if rend := rw.off + dsts.NumBytes(); rend > rw.off && rend < end {
		end = rend
	}

	var done uint64
	seg, gap := rw.d.cache.Find(rw.off)
	for rw.off < end {
		mr := memmap.MappableRange{rw.off, end}
		switch {
		case seg.Ok():
			// Get internal mappings from the cache.
			ims, err := mf.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Read)
			if err != nil {
				dataMuUnlock()
				rw.d.handleMu.RUnlock()
				return done, err
			}

			// Copy from internal mappings.
			n, err := safemem.CopySeq(dsts, ims)
			done += n
			rw.off += n
			dsts = dsts.DropFirst64(n)
			if err != nil {
				dataMuUnlock()
				rw.d.handleMu.RUnlock()
				return done, err
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			gapMR := gap.Range().Intersect(mr)
			if fillCache {
				// Read into the cache, then re-enter the loop to read from the
				// cache.
				gapEnd, _ := usermem.PageRoundUp(gapMR.End)
				reqMR := memmap.MappableRange{
					Start: usermem.PageRoundDown(gapMR.Start),
					End:   gapEnd,
				}
				optMR := gap.Range()
				err := rw.d.cache.Fill(rw.ctx, reqMR, maxFillRange(reqMR, optMR), mf, usage.PageCache, rw.d.handle.readToBlocksAt)
				mf.MarkEvictable(rw.d, pgalloc.EvictableRange{optMR.Start, optMR.End})
				seg, gap = rw.d.cache.Find(rw.off)
				if !seg.Ok() {
					dataMuUnlock()
					rw.d.handleMu.RUnlock()
					return done, err
				}
				// err might have occurred in part of gap.Range() outside
				// gapMR. Forget about it for now; if the error matters and
				// persists, we'll run into it again in a later iteration of
				// this loop.
			} else {
				// Read directly from the file.
				gapDsts := dsts.TakeFirst64(gapMR.Length())
				n, err := rw.d.handle.readToBlocksAt(rw.ctx, gapDsts, gapMR.Start)
				done += n
				rw.off += n
				dsts = dsts.DropFirst64(n)
				// Partial reads are fine. But we must stop reading.
				if n != gapDsts.NumBytes() || err != nil {
					dataMuUnlock()
					rw.d.handleMu.RUnlock()
					return done, err
				}

				// Continue.
				seg, gap = gap.NextSegment(), fsutil.FileRangeGapIterator{}
			}
		}
	}
	dataMuUnlock()
	rw.d.handleMu.RUnlock()
	return done, nil
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: rw.d.metadataMu must be locked.
func (rw *dentryReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}

	// If we have a mmappable host FD (which must be used here to ensure
	// coherence with memory-mapped I/O), or if InteropModeShared is in effect
	// (which prevents us from caching file contents), or if the file was
	// opened with O_DIRECT, write directly to dentry.handle without locking
	// dentry.dataMu.
	rw.d.handleMu.RLock()
	if (rw.d.handle.fd >= 0 && !rw.d.fs.opts.forcePageCache) || rw.d.fs.opts.interop == InteropModeShared || rw.direct {
		n, err := rw.d.handle.writeFromBlocksAt(rw.ctx, srcs, rw.off)
		rw.off += n
		rw.d.dataMu.Lock()
		if rw.off > rw.d.size {
			atomic.StoreUint64(&rw.d.size, rw.off)
			// The remote file's size will implicitly be extended to the correct
			// value when we write back to it.
		}
		rw.d.dataMu.Unlock()
		rw.d.handleMu.RUnlock()
		return n, err
	}

	// Otherwise write to/through the cache.
	mf := rw.d.fs.mfp.MemoryFile()
	rw.d.dataMu.Lock()

	// Compute the range to write (overflow-checked).
	start := rw.off
	end := rw.off + srcs.NumBytes()
	if end <= rw.off {
		end = math.MaxInt64
	}

	var (
		done   uint64
		retErr error
	)
	seg, gap := rw.d.cache.Find(rw.off)
	for rw.off < end {
		mr := memmap.MappableRange{rw.off, end}
		switch {
		case seg.Ok():
			// Get internal mappings from the cache.
			segMR := seg.Range().Intersect(mr)
			ims, err := mf.MapInternal(seg.FileRangeOf(segMR), usermem.Write)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Copy to internal mappings.
			n, err := safemem.CopySeq(ims, srcs)
			done += n
			rw.off += n
			srcs = srcs.DropFirst64(n)
			rw.d.dirty.MarkDirty(segMR)
			if err != nil {
				retErr = err
				goto exitLoop
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			// Write directly to the file. At present, we never fill the cache
			// when writing, since doing so can convert small writes into
			// inefficient read-modify-write cycles, and we have no mechanism
			// for detecting or avoiding this.
			gapMR := gap.Range().Intersect(mr)
			gapSrcs := srcs.TakeFirst64(gapMR.Length())
			n, err := rw.d.handle.writeFromBlocksAt(rw.ctx, gapSrcs, gapMR.Start)
			done += n
			rw.off += n
			srcs = srcs.DropFirst64(n)
			// Partial writes are fine. But we must stop writing.
			if n != gapSrcs.NumBytes() || err != nil {
				retErr = err
				goto exitLoop
			}

			// Continue.
			seg, gap = gap.NextSegment(), fsutil.FileRangeGapIterator{}
		}
	}
exitLoop:
	if rw.off > rw.d.size {
		atomic.StoreUint64(&rw.d.size, rw.off)
		// The remote file's size will implicitly be extended to the correct
		// value when we write back to it.
	}
	// If InteropModeWritethrough is in effect, flush written data back to the
	// remote filesystem.
	if rw.d.fs.opts.interop == InteropModeWritethrough && done != 0 {
		if err := fsutil.SyncDirty(rw.ctx, memmap.MappableRange{
			Start: start,
			End:   rw.off,
		}, &rw.d.cache, &rw.d.dirty, rw.d.size, mf, rw.d.handle.writeFromBlocksAt); err != nil {
			// We have no idea how many bytes were actually flushed.
			rw.off = start
			done = 0
			retErr = err
		}
	}
	rw.d.dataMu.Unlock()
	rw.d.handleMu.RUnlock()
	return done, retErr
}

func (d *dentry) writeback(ctx context.Context, offset, size int64) error {
	if size == 0 {
		return nil
	}
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	d.dataMu.Lock()
	defer d.dataMu.Unlock()
	// Compute the range of valid bytes (overflow-checked).
	if uint64(offset) >= d.size {
		return nil
	}
	end := int64(d.size)
	if rend := offset + size; rend > offset && rend < end {
		end = rend
	}
	return fsutil.SyncDirty(ctx, memmap.MappableRange{
		Start: uint64(offset),
		End:   uint64(end),
	}, &d.cache, &d.dirty, d.size, d.fs.mfp.MemoryFile(), d.handle.writeFromBlocksAt)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	newOffset, err := regularFileSeekLocked(ctx, fd.dentry(), fd.off, offset, whence)
	if err != nil {
		return 0, err
	}
	fd.off = newOffset
	return newOffset, nil
}

// Calculate the new offset for a seek operation on a regular file.
func regularFileSeekLocked(ctx context.Context, d *dentry, fdOffset, offset int64, whence int32) (int64, error) {
	switch whence {
	case linux.SEEK_SET:
		// Use offset as specified.
	case linux.SEEK_CUR:
		offset += fdOffset
	case linux.SEEK_END, linux.SEEK_DATA, linux.SEEK_HOLE:
		// Ensure file size is up to date.
		if !d.cachedMetadataAuthoritative() {
			if err := d.updateFromGetattr(ctx); err != nil {
				return 0, err
			}
		}
		size := int64(atomic.LoadUint64(&d.size))
		// For SEEK_DATA and SEEK_HOLE, treat the file as a single contiguous
		// block of data.
		switch whence {
		case linux.SEEK_END:
			offset += size
		case linux.SEEK_DATA:
			if offset > size {
				return 0, syserror.ENXIO
			}
			// Use offset as specified.
		case linux.SEEK_HOLE:
			if offset > size {
				return 0, syserror.ENXIO
			}
			offset = size
		}
	default:
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	return offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *regularFileFD) Sync(ctx context.Context) error {
	return fd.dentry().syncSharedHandle(ctx)
}

func (d *dentry) syncSharedHandle(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()

	if d.handleWritable {
		d.dataMu.Lock()
		// Write dirty cached data to the remote file.
		err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size, d.fs.mfp.MemoryFile(), d.handle.writeFromBlocksAt)
		d.dataMu.Unlock()
		if err != nil {
			return err
		}
	}
	// Sync the remote file.
	return d.handle.sync(ctx)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	d := fd.dentry()
	switch d.fs.opts.interop {
	case InteropModeExclusive:
		// Any mapping is fine.
	case InteropModeWritethrough:
		// Shared writable mappings require a host FD, since otherwise we can't
		// synchronously flush memory-mapped writes to the remote file.
		if opts.Private || !opts.MaxPerms.Write {
			break
		}
		fallthrough
	case InteropModeShared:
		// All mappings require a host FD to be coherent with other filesystem
		// users.
		if d.fs.opts.forcePageCache {
			// Whether or not we have a host FD, we're not allowed to use it.
			return syserror.ENODEV
		}
		d.handleMu.RLock()
		haveFD := d.handle.fd >= 0
		d.handleMu.RUnlock()
		if !haveFD {
			return syserror.ENODEV
		}
	default:
		panic(fmt.Sprintf("unknown InteropMode %v", d.fs.opts.interop))
	}
	// After this point, d may be used as a memmap.Mappable.
	d.pf.hostFileMapperInitOnce.Do(d.pf.hostFileMapper.Init)
	return vfs.GenericConfigureMMap(&fd.vfsfd, d, opts)
}

func (d *dentry) mayCachePages() bool {
	if d.fs.opts.interop == InteropModeShared {
		return false
	}
	if d.fs.opts.forcePageCache {
		return true
	}
	d.handleMu.RLock()
	haveFD := d.handle.fd >= 0
	d.handleMu.RUnlock()
	return haveFD
}

// AddMapping implements memmap.Mappable.AddMapping.
func (d *dentry) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	d.mapsMu.Lock()
	mapped := d.mappings.AddMapping(ms, ar, offset, writable)
	// Do this unconditionally since whether we have a host FD can change
	// across save/restore.
	for _, r := range mapped {
		d.pf.hostFileMapper.IncRefOn(r)
	}
	if d.mayCachePages() {
		// d.Evict() will refuse to evict memory-mapped pages, so tell the
		// MemoryFile to not bother trying.
		mf := d.fs.mfp.MemoryFile()
		for _, r := range mapped {
			mf.MarkUnevictable(d, pgalloc.EvictableRange{r.Start, r.End})
		}
	}
	d.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (d *dentry) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	d.mapsMu.Lock()
	unmapped := d.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		d.pf.hostFileMapper.DecRefOn(r)
	}
	if d.mayCachePages() {
		// Pages that are no longer referenced by any application memory
		// mappings are now considered unused; allow MemoryFile to evict them
		// when necessary.
		mf := d.fs.mfp.MemoryFile()
		d.dataMu.Lock()
		for _, r := range unmapped {
			// Since these pages are no longer mapped, they are no longer
			// concurrently dirtyable by a writable memory mapping.
			d.dirty.AllowClean(r)
			mf.MarkEvictable(d, pgalloc.EvictableRange{r.Start, r.End})
		}
		d.dataMu.Unlock()
	}
	d.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (d *dentry) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return d.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (d *dentry) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	d.handleMu.RLock()
	if d.handle.fd >= 0 && !d.fs.opts.forcePageCache {
		d.handleMu.RUnlock()
		mr := optional
		if d.fs.opts.limitHostFDTranslation {
			mr = maxFillRange(required, optional)
		}
		return []memmap.Translation{
			{
				Source: mr,
				File:   &d.pf,
				Offset: mr.Start,
				Perms:  usermem.AnyAccess,
			},
		}, nil
	}

	d.dataMu.Lock()

	// Constrain translations to d.size (rounded up) to prevent translation to
	// pages that may be concurrently truncated.
	pgend, _ := usermem.PageRoundUp(d.size)
	var beyondEOF bool
	if required.End > pgend {
		if required.Start >= pgend {
			d.dataMu.Unlock()
			d.handleMu.RUnlock()
			return nil, &memmap.BusError{io.EOF}
		}
		beyondEOF = true
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}

	mf := d.fs.mfp.MemoryFile()
	cerr := d.cache.Fill(ctx, required, maxFillRange(required, optional), mf, usage.PageCache, d.handle.readToBlocksAt)

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := d.cache.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		// TODO(jamieliu): Make Translations writable even if writability is
		// not required if already kept-dirty by another writable translation.
		perms := usermem.AccessType{
			Read:    true,
			Execute: true,
		}
		if at.Write {
			// From this point forward, this memory can be dirtied through the
			// mapping at any time.
			d.dirty.KeepDirty(segMR)
			perms.Write = true
		}
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   mf,
			Offset: seg.FileRangeOf(segMR).Start,
			Perms:  perms,
		})
		translatedEnd = segMR.End
	}

	d.dataMu.Unlock()
	d.handleMu.RUnlock()

	// Don't return the error returned by c.cache.Fill if it occurred outside
	// of required.
	if translatedEnd < required.End && cerr != nil {
		return ts, &memmap.BusError{cerr}
	}
	if beyondEOF {
		return ts, &memmap.BusError{io.EOF}
	}
	return ts, nil
}

func maxFillRange(required, optional memmap.MappableRange) memmap.MappableRange {
	const maxReadahead = 64 << 10 // 64 KB, chosen arbitrarily
	if required.Length() >= maxReadahead {
		return required
	}
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.Start = required.Start
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.End = optional.Start + maxReadahead
	return optional
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (d *dentry) InvalidateUnsavable(ctx context.Context) error {
	// Whether we have a host fd (and consequently what memmap.File is
	// mapped) can change across save/restore, so invalidate all translations
	// unconditionally.
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	d.mappings.InvalidateAll(memmap.InvalidateOpts{})

	// Write the cache's contents back to the remote file so that if we have a
	// host fd after restore, the remote file's contents are coherent.
	mf := d.fs.mfp.MemoryFile()
	d.dataMu.Lock()
	defer d.dataMu.Unlock()
	if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size, mf, d.handle.writeFromBlocksAt); err != nil {
		return err
	}

	// Discard the cache so that it's not stored in saved state. This is safe
	// because per InvalidateUnsavable invariants, no new translations can have
	// been returned after we invalidated all existing translations above.
	d.cache.DropAll(mf)
	d.dirty.RemoveAll()

	return nil
}

// Evict implements pgalloc.EvictableMemoryUser.Evict.
func (d *dentry) Evict(ctx context.Context, er pgalloc.EvictableRange) {
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	d.dataMu.Lock()
	defer d.dataMu.Unlock()

	mr := memmap.MappableRange{er.Start, er.End}
	mf := d.fs.mfp.MemoryFile()
	// Only allow pages that are no longer memory-mapped to be evicted.
	for mgap := d.mappings.LowerBoundGap(mr.Start); mgap.Ok() && mgap.Start() < mr.End; mgap = mgap.NextGap() {
		mgapMR := mgap.Range().Intersect(mr)
		if mgapMR.Length() == 0 {
			continue
		}
		if err := fsutil.SyncDirty(ctx, mgapMR, &d.cache, &d.dirty, d.size, mf, d.handle.writeFromBlocksAt); err != nil {
			log.Warningf("Failed to writeback cached data %v: %v", mgapMR, err)
		}
		d.cache.Drop(mgapMR, mf)
		d.dirty.KeepClean(mgapMR)
	}
}

// dentryPlatformFile implements memmap.File. It exists solely because dentry
// cannot implement both vfs.DentryImpl.IncRef and memmap.File.IncRef.
//
// dentryPlatformFile is only used when a host FD representing the remote file
// is available (i.e. dentry.handle.fd >= 0), and that FD is used for
// application memory mappings (i.e. !filesystem.opts.forcePageCache).
type dentryPlatformFile struct {
	*dentry

	// fdRefs counts references on memmap.File offsets. fdRefs is protected
	// by dentry.dataMu.
	fdRefs fsutil.FrameRefSet

	// If this dentry represents a regular file, and handle.fd >= 0,
	// hostFileMapper caches mappings of handle.fd.
	hostFileMapper fsutil.HostFileMapper

	// hostFileMapperInitOnce is used to lazily initialize hostFileMapper.
	hostFileMapperInitOnce sync.Once
}

// IncRef implements memmap.File.IncRef.
func (d *dentryPlatformFile) IncRef(fr memmap.FileRange) {
	d.dataMu.Lock()
	d.fdRefs.IncRefAndAccount(fr)
	d.dataMu.Unlock()
}

// DecRef implements memmap.File.DecRef.
func (d *dentryPlatformFile) DecRef(fr memmap.FileRange) {
	d.dataMu.Lock()
	d.fdRefs.DecRefAndAccount(fr)
	d.dataMu.Unlock()
}

// MapInternal implements memmap.File.MapInternal.
func (d *dentryPlatformFile) MapInternal(fr memmap.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
	d.handleMu.RLock()
	bs, err := d.hostFileMapper.MapInternal(fr, int(d.handle.fd), at.Write)
	d.handleMu.RUnlock()
	return bs, err
}

// FD implements memmap.File.FD.
func (d *dentryPlatformFile) FD() int {
	d.handleMu.RLock()
	fd := d.handle.fd
	d.handleMu.RUnlock()
	return int(fd)
}
