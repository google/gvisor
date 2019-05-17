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

package fsutil

import (
	"fmt"
	"io"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// Lock order (compare the lock order model in mm/mm.go):
//
// CachingInodeOperations.attrMu ("fs locks")
//   CachingInodeOperations.mapsMu ("memmap.Mappable locks not taken by Translate")
//     CachingInodeOperations.dataMu ("memmap.Mappable locks taken by Translate")
//       CachedFileObject locks

// CachingInodeOperations caches the metadata and content of a CachedFileObject.
// It implements a subset of InodeOperations. As a utility it can be used to
// implement the full set of InodeOperations. Generally it should not be
// embedded to avoid unexpected inherited behavior.
//
// CachingInodeOperations implements Mappable for the CachedFileObject:
//
// - If CachedFileObject.FD returns a value >= 0 then the file descriptor
//   will be memory mapped on the host.
//
// - Otherwise, the contents of CachedFileObject are buffered into memory
//   managed by the CachingInodeOperations.
//
// Implementations of FileOperations for a CachedFileObject must read and
// write through CachingInodeOperations using Read and Write respectively.
//
// Implementations of InodeOperations.WriteOut must call Sync to write out
// in-memory modifications of data and metadata to the CachedFileObject.
//
// +stateify savable
type CachingInodeOperations struct {
	// backingFile is a handle to a cached file object.
	backingFile CachedFileObject

	// mfp is used to allocate memory that caches backingFile's contents.
	mfp pgalloc.MemoryFileProvider

	// forcePageCache indicates the sentry page cache should be used regardless
	// of whether the platform supports host mapped I/O or not. This must not be
	// modified after inode creation.
	forcePageCache bool

	attrMu sync.Mutex `state:"nosave"`

	// attr is unstable cached metadata.
	//
	// attr is protected by attrMu. attr.Size is protected by both attrMu and
	// dataMu; reading it requires locking either mutex, while mutating it
	// requires locking both.
	attr fs.UnstableAttr

	// dirtyAttr is metadata that was updated in-place but hasn't yet
	// been successfully written out.
	//
	// dirtyAttr is protected by attrMu.
	dirtyAttr fs.AttrMask

	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks mappings of the cached file object into
	// memmap.MappingSpaces.
	//
	// mappings is protected by mapsMu.
	mappings memmap.MappingSet

	dataMu sync.RWMutex `state:"nosave"`

	// cache maps offsets into the cached file to offsets into
	// mfp.MemoryFile() that store the file's data.
	//
	// cache is protected by dataMu.
	cache FileRangeSet

	// dirty tracks dirty segments in cache.
	//
	// dirty is protected by dataMu.
	dirty DirtySet

	// hostFileMapper caches internal mappings of backingFile.FD().
	hostFileMapper *HostFileMapper

	// refs tracks active references to data in the cache.
	//
	// refs is protected by dataMu.
	refs frameRefSet
}

// CachedFileObject is a file that may require caching.
type CachedFileObject interface {
	// ReadToBlocksAt reads up to dsts.NumBytes() bytes from the file to dsts,
	// starting at offset, and returns the number of bytes read. ReadToBlocksAt
	// may return a partial read without an error.
	ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error)

	// WriteFromBlocksAt writes up to srcs.NumBytes() bytes from srcs to the
	// file, starting at offset, and returns the number of bytes written.
	// WriteFromBlocksAt may return a partial write without an error.
	WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error)

	// SetMaskedAttributes sets the attributes in attr that are true in mask
	// on the backing file.
	//
	// SetMaskedAttributes may be called at any point, regardless of whether
	// the file was opened.
	SetMaskedAttributes(ctx context.Context, mask fs.AttrMask, attr fs.UnstableAttr) error

	// Allocate allows the caller to reserve disk space for the inode.
	// It's equivalent to fallocate(2) with 'mode=0'.
	Allocate(ctx context.Context, offset int64, length int64) error

	// Sync instructs the remote filesystem to sync the file to stable storage.
	Sync(ctx context.Context) error

	// FD returns a host file descriptor. If it is possible for
	// CachingInodeOperations.AddMapping to have ever been called with writable
	// = true, the FD must have been opened O_RDWR; otherwise, it may have been
	// opened O_RDONLY or O_RDWR. (mmap unconditionally requires that mapped
	// files are readable.) If no host file descriptor is available, FD returns
	// a negative number.
	//
	// For any given CachedFileObject, if FD() ever succeeds (returns a
	// non-negative number), it must always succeed.
	//
	// FD is called iff the file has been memory mapped. This implies that
	// the file was opened (see fs.InodeOperations.GetFile).
	FD() int
}

// NewCachingInodeOperations returns a new CachingInodeOperations backed by
// a CachedFileObject and its initial unstable attributes.
func NewCachingInodeOperations(ctx context.Context, backingFile CachedFileObject, uattr fs.UnstableAttr, forcePageCache bool) *CachingInodeOperations {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFileProvider))
	}
	return &CachingInodeOperations{
		backingFile:    backingFile,
		mfp:            mfp,
		forcePageCache: forcePageCache,
		attr:           uattr,
		hostFileMapper: NewHostFileMapper(),
	}
}

// Release implements fs.InodeOperations.Release.
func (c *CachingInodeOperations) Release() {
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	// Something has gone terribly wrong if we're releasing an inode that is
	// still memory-mapped.
	if !c.mappings.IsEmpty() {
		panic(fmt.Sprintf("Releasing CachingInodeOperations with mappings:\n%s", &c.mappings))
	}

	// Drop any cached pages that are still awaiting MemoryFile eviction. (This
	// means that MemoryFile no longer needs to evict them.)
	mf := c.mfp.MemoryFile()
	mf.MarkAllUnevictable(c)
	if err := SyncDirtyAll(context.Background(), &c.cache, &c.dirty, uint64(c.attr.Size), mf, c.backingFile.WriteFromBlocksAt); err != nil {
		panic(fmt.Sprintf("Failed to writeback cached data: %v", err))
	}
	c.cache.DropAll(mf)
	c.dirty.RemoveAll()
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (c *CachingInodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	c.attrMu.Lock()
	attr := c.attr
	c.attrMu.Unlock()
	return attr, nil
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (c *CachingInodeOperations) SetPermissions(ctx context.Context, inode *fs.Inode, perms fs.FilePermissions) bool {
	c.attrMu.Lock()
	defer c.attrMu.Unlock()

	now := ktime.NowFromContext(ctx)
	masked := fs.AttrMask{Perms: true}
	if err := c.backingFile.SetMaskedAttributes(ctx, masked, fs.UnstableAttr{Perms: perms}); err != nil {
		return false
	}
	c.attr.Perms = perms
	c.touchStatusChangeTimeLocked(now)
	return true
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (c *CachingInodeOperations) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	if !owner.UID.Ok() && !owner.GID.Ok() {
		return nil
	}

	c.attrMu.Lock()
	defer c.attrMu.Unlock()

	now := ktime.NowFromContext(ctx)
	masked := fs.AttrMask{
		UID: owner.UID.Ok(),
		GID: owner.GID.Ok(),
	}
	if err := c.backingFile.SetMaskedAttributes(ctx, masked, fs.UnstableAttr{Owner: owner}); err != nil {
		return err
	}
	if owner.UID.Ok() {
		c.attr.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		c.attr.Owner.GID = owner.GID
	}
	c.touchStatusChangeTimeLocked(now)
	return nil
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (c *CachingInodeOperations) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	c.attrMu.Lock()
	defer c.attrMu.Unlock()

	// Replace requests to use the "system time" with the current time to
	// ensure that cached timestamps remain consistent with the remote
	// filesystem.
	now := ktime.NowFromContext(ctx)
	if ts.ATimeSetSystemTime {
		ts.ATime = now
	}
	if ts.MTimeSetSystemTime {
		ts.MTime = now
	}
	masked := fs.AttrMask{
		AccessTime:       !ts.ATimeOmit,
		ModificationTime: !ts.MTimeOmit,
	}
	if err := c.backingFile.SetMaskedAttributes(ctx, masked, fs.UnstableAttr{AccessTime: ts.ATime, ModificationTime: ts.MTime}); err != nil {
		return err
	}
	if !ts.ATimeOmit {
		c.attr.AccessTime = ts.ATime
	}
	if !ts.MTimeOmit {
		c.attr.ModificationTime = ts.MTime
	}
	c.touchStatusChangeTimeLocked(now)
	return nil
}

// Truncate implements fs.InodeOperations.Truncate.
func (c *CachingInodeOperations) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	c.attrMu.Lock()
	defer c.attrMu.Unlock()

	// c.attr.Size is protected by both c.attrMu and c.dataMu.
	c.dataMu.Lock()
	now := ktime.NowFromContext(ctx)
	masked := fs.AttrMask{Size: true}
	attr := fs.UnstableAttr{Size: size}
	if err := c.backingFile.SetMaskedAttributes(ctx, masked, attr); err != nil {
		c.dataMu.Unlock()
		return err
	}
	oldSize := c.attr.Size
	c.attr.Size = size
	c.touchModificationTimeLocked(now)

	// We drop c.dataMu here so that we can lock c.mapsMu and invalidate
	// mappings below. This allows concurrent calls to Read/Translate/etc.
	// These functions synchronize with an in-progress Truncate by refusing to
	// use cache contents beyond the new c.attr.Size. (We are still holding
	// c.attrMu, so we can't race with Truncate/Write.)
	c.dataMu.Unlock()

	// Nothing left to do unless shrinking the file.
	if size >= oldSize {
		return nil
	}

	oldpgend := fs.OffsetPageEnd(oldSize)
	newpgend := fs.OffsetPageEnd(size)

	// Invalidate past translations of truncated pages.
	if newpgend != oldpgend {
		c.mapsMu.Lock()
		c.mappings.Invalidate(memmap.MappableRange{newpgend, oldpgend}, memmap.InvalidateOpts{
			// Compare Linux's mm/truncate.c:truncate_setsize() =>
			// truncate_pagecache() =>
			// mm/memory.c:unmap_mapping_range(evencows=1).
			InvalidatePrivate: true,
		})
		c.mapsMu.Unlock()
	}

	// We are now guaranteed that there are no translations of truncated pages,
	// and can remove them from the cache. Since truncated pages have been
	// removed from the backing file, they should be dropped without being
	// written back.
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	c.cache.Truncate(uint64(size), c.mfp.MemoryFile())
	c.dirty.KeepClean(memmap.MappableRange{uint64(size), oldpgend})

	return nil
}

// Allocate implements fs.InodeOperations.Allocate.
func (c *CachingInodeOperations) Allocate(ctx context.Context, offset, length int64) error {
	newSize := offset + length

	// c.attr.Size is protected by both c.attrMu and c.dataMu.
	c.attrMu.Lock()
	defer c.attrMu.Unlock()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	if newSize <= c.attr.Size {
		return nil
	}

	now := ktime.NowFromContext(ctx)
	if err := c.backingFile.Allocate(ctx, offset, length); err != nil {
		return err
	}

	c.attr.Size = newSize
	c.touchModificationTimeLocked(now)
	return nil
}

// WriteOut implements fs.InodeOperations.WriteOut.
func (c *CachingInodeOperations) WriteOut(ctx context.Context, inode *fs.Inode) error {
	c.attrMu.Lock()

	// Write dirty pages back.
	c.dataMu.Lock()
	err := SyncDirtyAll(ctx, &c.cache, &c.dirty, uint64(c.attr.Size), c.mfp.MemoryFile(), c.backingFile.WriteFromBlocksAt)
	c.dataMu.Unlock()
	if err != nil {
		c.attrMu.Unlock()
		return err
	}

	// SyncDirtyAll above would have grown if needed. On shrinks, the backing
	// file is called directly, so size is never needs to be updated.
	c.dirtyAttr.Size = false

	// Write out cached attributes.
	if err := c.backingFile.SetMaskedAttributes(ctx, c.dirtyAttr, c.attr); err != nil {
		c.attrMu.Unlock()
		return err
	}
	c.dirtyAttr = fs.AttrMask{}

	c.attrMu.Unlock()

	// Fsync the remote file.
	return c.backingFile.Sync(ctx)
}

// IncLinks increases the link count and updates cached access time.
func (c *CachingInodeOperations) IncLinks(ctx context.Context) {
	c.attrMu.Lock()
	c.attr.Links++
	c.touchModificationTimeLocked(ktime.NowFromContext(ctx))
	c.attrMu.Unlock()
}

// DecLinks decreases the link count and updates cached access time.
func (c *CachingInodeOperations) DecLinks(ctx context.Context) {
	c.attrMu.Lock()
	c.attr.Links--
	c.touchModificationTimeLocked(ktime.NowFromContext(ctx))
	c.attrMu.Unlock()
}

// TouchAccessTime updates the cached access time in-place to the
// current time. It does not update status change time in-place. See
// mm/filemap.c:do_generic_file_read -> include/linux/h:file_accessed.
func (c *CachingInodeOperations) TouchAccessTime(ctx context.Context, inode *fs.Inode) {
	if inode.MountSource.Flags.NoAtime {
		return
	}

	c.attrMu.Lock()
	c.touchAccessTimeLocked(ktime.NowFromContext(ctx))
	c.attrMu.Unlock()
}

// touchAccesstimeLocked updates the cached access time in-place to the current
// time.
//
// Preconditions: c.attrMu is locked for writing.
func (c *CachingInodeOperations) touchAccessTimeLocked(now time.Time) {
	c.attr.AccessTime = now
	c.dirtyAttr.AccessTime = true
}

// TouchModificationTime updates the cached modification and status change time
// in-place to the current time.
func (c *CachingInodeOperations) TouchModificationTime(ctx context.Context) {
	c.attrMu.Lock()
	c.touchModificationTimeLocked(ktime.NowFromContext(ctx))
	c.attrMu.Unlock()
}

// touchModificationTimeLocked updates the cached modification and status
// change time in-place to the current time.
//
// Preconditions: c.attrMu is locked for writing.
func (c *CachingInodeOperations) touchModificationTimeLocked(now time.Time) {
	c.attr.ModificationTime = now
	c.dirtyAttr.ModificationTime = true
	c.attr.StatusChangeTime = now
	c.dirtyAttr.StatusChangeTime = true
}

// TouchStatusChangeTime updates the cached status change time in-place to the
// current time.
func (c *CachingInodeOperations) TouchStatusChangeTime(ctx context.Context) {
	c.attrMu.Lock()
	c.touchStatusChangeTimeLocked(ktime.NowFromContext(ctx))
	c.attrMu.Unlock()
}

// touchStatusChangeTimeLocked updates the cached status change time
// in-place to the current time.
//
// Preconditions: c.attrMu is locked for writing.
func (c *CachingInodeOperations) touchStatusChangeTimeLocked(now time.Time) {
	c.attr.StatusChangeTime = now
	c.dirtyAttr.StatusChangeTime = true
}

// UpdateUnstable updates the cached unstable attributes. Only non-dirty
// attributes are updated.
func (c *CachingInodeOperations) UpdateUnstable(attr fs.UnstableAttr) {
	// All attributes are protected by attrMu.
	c.attrMu.Lock()

	if !c.dirtyAttr.Usage {
		c.attr.Usage = attr.Usage
	}
	if !c.dirtyAttr.Perms {
		c.attr.Perms = attr.Perms
	}
	if !c.dirtyAttr.UID {
		c.attr.Owner.UID = attr.Owner.UID
	}
	if !c.dirtyAttr.GID {
		c.attr.Owner.GID = attr.Owner.GID
	}
	if !c.dirtyAttr.AccessTime {
		c.attr.AccessTime = attr.AccessTime
	}
	if !c.dirtyAttr.ModificationTime {
		c.attr.ModificationTime = attr.ModificationTime
	}
	if !c.dirtyAttr.StatusChangeTime {
		c.attr.StatusChangeTime = attr.StatusChangeTime
	}
	if !c.dirtyAttr.Links {
		c.attr.Links = attr.Links
	}

	// Size requires holding attrMu and dataMu.
	c.dataMu.Lock()
	if !c.dirtyAttr.Size {
		c.attr.Size = attr.Size
	}
	c.dataMu.Unlock()

	c.attrMu.Unlock()
}

// Read reads from frames and otherwise directly from the backing file
// into dst starting at offset until dst is full, EOF is reached, or an
// error is encountered.
//
// Read may partially fill dst and return a nil error.
func (c *CachingInodeOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}

	// Have we reached EOF? We check for this again in
	// inodeReadWriter.ReadToBlocks to avoid holding c.attrMu (which would
	// serialize reads) or c.dataMu (which would violate lock ordering), but
	// check here first (before calling into MM) since reading at EOF is
	// common: getting a return value of 0 from a read syscall is the only way
	// to detect EOF.
	//
	// TODO(jamieliu): Separate out c.attr.Size and use atomics instead of
	// c.dataMu.
	c.dataMu.RLock()
	size := c.attr.Size
	c.dataMu.RUnlock()
	if offset >= size {
		return 0, io.EOF
	}

	n, err := dst.CopyOutFrom(ctx, &inodeReadWriter{ctx, c, offset})
	// Compare Linux's mm/filemap.c:do_generic_file_read() => file_accessed().
	c.TouchAccessTime(ctx, file.Dirent.Inode)
	return n, err
}

// Write writes to frames and otherwise directly to the backing file
// from src starting at offset and until src is empty or an error is
// encountered.
//
// If Write partially fills src, a non-nil error is returned.
func (c *CachingInodeOperations) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// Hot path. Avoid defers.
	if src.NumBytes() == 0 {
		return 0, nil
	}

	c.attrMu.Lock()
	// Compare Linux's mm/filemap.c:__generic_file_write_iter() => file_update_time().
	c.touchModificationTimeLocked(ktime.NowFromContext(ctx))
	n, err := src.CopyInTo(ctx, &inodeReadWriter{ctx, c, offset})
	c.attrMu.Unlock()
	return n, err
}

type inodeReadWriter struct {
	ctx    context.Context
	c      *CachingInodeOperations
	offset int64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *inodeReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	// Hot path. Avoid defers.
	rw.c.dataMu.RLock()

	// Compute the range to read.
	if rw.offset >= rw.c.attr.Size {
		rw.c.dataMu.RUnlock()
		return 0, io.EOF
	}
	end := fs.ReadEndOffset(rw.offset, int64(dsts.NumBytes()), rw.c.attr.Size)
	if end == rw.offset { // dsts.NumBytes() == 0?
		rw.c.dataMu.RUnlock()
		return 0, nil
	}

	mem := rw.c.mfp.MemoryFile()
	var done uint64
	seg, gap := rw.c.cache.Find(uint64(rw.offset))
	for rw.offset < end {
		mr := memmap.MappableRange{uint64(rw.offset), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings from the cache.
			ims, err := mem.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Read)
			if err != nil {
				rw.c.dataMu.RUnlock()
				return done, err
			}

			// Copy from internal mappings.
			n, err := safemem.CopySeq(dsts, ims)
			done += n
			rw.offset += int64(n)
			dsts = dsts.DropFirst64(n)
			if err != nil {
				rw.c.dataMu.RUnlock()
				return done, err
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			// Read directly from the backing file.
			gapmr := gap.Range().Intersect(mr)
			dst := dsts.TakeFirst64(gapmr.Length())
			n, err := rw.c.backingFile.ReadToBlocksAt(rw.ctx, dst, gapmr.Start)
			done += n
			rw.offset += int64(n)
			dsts = dsts.DropFirst64(n)
			// Partial reads are fine. But we must stop reading.
			if n != dst.NumBytes() || err != nil {
				rw.c.dataMu.RUnlock()
				return done, err
			}

			// Continue.
			seg, gap = gap.NextSegment(), FileRangeGapIterator{}

		default:
			break
		}
	}
	rw.c.dataMu.RUnlock()
	return done, nil
}

// maybeGrowFile grows the file's size if data has been written past the old
// size.
//
// Preconditions: rw.c.attrMu and rw.c.dataMu bust be locked.
func (rw *inodeReadWriter) maybeGrowFile() {
	// If the write ends beyond the file's previous size, it causes the
	// file to grow.
	if rw.offset > rw.c.attr.Size {
		rw.c.attr.Size = rw.offset
		rw.c.dirtyAttr.Size = true
	}
	if rw.offset > rw.c.attr.Usage {
		// This is incorrect if CachingInodeOperations is caching a sparse
		// file. (In Linux, keeping inode::i_blocks up to date is the
		// filesystem's responsibility.)
		rw.c.attr.Usage = rw.offset
		rw.c.dirtyAttr.Usage = true
	}
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: rw.c.attrMu must be locked.
func (rw *inodeReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	// Hot path. Avoid defers.
	rw.c.dataMu.Lock()

	// Compute the range to write.
	end := fs.WriteEndOffset(rw.offset, int64(srcs.NumBytes()))
	if end == rw.offset { // srcs.NumBytes() == 0?
		rw.c.dataMu.Unlock()
		return 0, nil
	}

	mf := rw.c.mfp.MemoryFile()
	var done uint64
	seg, gap := rw.c.cache.Find(uint64(rw.offset))
	for rw.offset < end {
		mr := memmap.MappableRange{uint64(rw.offset), uint64(end)}
		switch {
		case seg.Ok() && seg.Start() < mr.End:
			// Get internal mappings from the cache.
			segMR := seg.Range().Intersect(mr)
			ims, err := mf.MapInternal(seg.FileRangeOf(segMR), usermem.Write)
			if err != nil {
				rw.maybeGrowFile()
				rw.c.dataMu.Unlock()
				return done, err
			}

			// Copy to internal mappings.
			n, err := safemem.CopySeq(ims, srcs)
			done += n
			rw.offset += int64(n)
			srcs = srcs.DropFirst64(n)
			rw.c.dirty.MarkDirty(segMR)
			if err != nil {
				rw.maybeGrowFile()
				rw.c.dataMu.Unlock()
				return done, err
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok() && gap.Start() < mr.End:
			// Write directly to the backing file.
			gapmr := gap.Range().Intersect(mr)
			src := srcs.TakeFirst64(gapmr.Length())
			n, err := rw.c.backingFile.WriteFromBlocksAt(rw.ctx, src, gapmr.Start)
			done += n
			rw.offset += int64(n)
			srcs = srcs.DropFirst64(n)
			// Partial writes are fine. But we must stop writing.
			if n != src.NumBytes() || err != nil {
				rw.maybeGrowFile()
				rw.c.dataMu.Unlock()
				return done, err
			}

			// Continue.
			seg, gap = gap.NextSegment(), FileRangeGapIterator{}

		default:
			break
		}
	}
	rw.maybeGrowFile()
	rw.c.dataMu.Unlock()
	return done, nil
}

// useHostPageCache returns true if c uses c.backingFile.FD() for all file I/O
// and memory mappings, and false if c.cache may contain data cached from
// c.backingFile.
func (c *CachingInodeOperations) useHostPageCache() bool {
	return !c.forcePageCache && c.backingFile.FD() >= 0
}

// AddMapping implements memmap.Mappable.AddMapping.
func (c *CachingInodeOperations) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	// Hot path. Avoid defers.
	c.mapsMu.Lock()
	mapped := c.mappings.AddMapping(ms, ar, offset, writable)
	// Do this unconditionally since whether we have c.backingFile.FD() >= 0
	// can change across save/restore.
	for _, r := range mapped {
		c.hostFileMapper.IncRefOn(r)
	}
	if !c.useHostPageCache() {
		// c.Evict() will refuse to evict memory-mapped pages, so tell the
		// MemoryFile to not bother trying.
		mf := c.mfp.MemoryFile()
		for _, r := range mapped {
			mf.MarkUnevictable(c, pgalloc.EvictableRange{r.Start, r.End})
		}
	}
	if c.useHostPageCache() && !usage.IncrementalMappedAccounting {
		for _, r := range mapped {
			usage.MemoryAccounting.Inc(r.Length(), usage.Mapped)
		}
	}
	c.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (c *CachingInodeOperations) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	// Hot path. Avoid defers.
	c.mapsMu.Lock()
	unmapped := c.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		c.hostFileMapper.DecRefOn(r)
	}
	if c.useHostPageCache() {
		if !usage.IncrementalMappedAccounting {
			for _, r := range unmapped {
				usage.MemoryAccounting.Dec(r.Length(), usage.Mapped)
			}
		}
		c.mapsMu.Unlock()
		return
	}

	// Pages that are no longer referenced by any application memory mappings
	// are now considered unused; allow MemoryFile to evict them when
	// necessary.
	mf := c.mfp.MemoryFile()
	c.dataMu.Lock()
	for _, r := range unmapped {
		// Since these pages are no longer mapped, they are no longer
		// concurrently dirtyable by a writable memory mapping.
		c.dirty.AllowClean(r)
		mf.MarkEvictable(c, pgalloc.EvictableRange{r.Start, r.End})
	}
	c.dataMu.Unlock()
	c.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (c *CachingInodeOperations) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return c.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (c *CachingInodeOperations) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	// Hot path. Avoid defer.
	if c.useHostPageCache() {
		return []memmap.Translation{
			{
				Source: optional,
				File:   c,
				Offset: optional.Start,
				Perms:  usermem.AnyAccess,
			},
		}, nil
	}

	c.dataMu.Lock()

	// Constrain translations to c.attr.Size (rounded up) to prevent
	// translation to pages that may be concurrently truncated.
	pgend := fs.OffsetPageEnd(c.attr.Size)
	var beyondEOF bool
	if required.End > pgend {
		if required.Start >= pgend {
			c.dataMu.Unlock()
			return nil, &memmap.BusError{io.EOF}
		}
		beyondEOF = true
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}

	mf := c.mfp.MemoryFile()
	cerr := c.cache.Fill(ctx, required, maxFillRange(required, optional), mf, usage.PageCache, c.backingFile.ReadToBlocksAt)

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := c.cache.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
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
			c.dirty.KeepDirty(segMR)
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

	c.dataMu.Unlock()

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
func (c *CachingInodeOperations) InvalidateUnsavable(ctx context.Context) error {
	// Whether we have a host fd (and consequently what platform.File is
	// mapped) can change across save/restore, so invalidate all translations
	// unconditionally.
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.mappings.InvalidateAll(memmap.InvalidateOpts{})

	// Sync the cache's contents so that if we have a host fd after restore,
	// the remote file's contents are coherent.
	mf := c.mfp.MemoryFile()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if err := SyncDirtyAll(ctx, &c.cache, &c.dirty, uint64(c.attr.Size), mf, c.backingFile.WriteFromBlocksAt); err != nil {
		return err
	}

	// Discard the cache so that it's not stored in saved state. This is safe
	// because per InvalidateUnsavable invariants, no new translations can have
	// been returned after we invalidated all existing translations above.
	c.cache.DropAll(mf)
	c.dirty.RemoveAll()

	return nil
}

// Evict implements pgalloc.EvictableMemoryUser.Evict.
func (c *CachingInodeOperations) Evict(ctx context.Context, er pgalloc.EvictableRange) {
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	mr := memmap.MappableRange{er.Start, er.End}
	mf := c.mfp.MemoryFile()
	// Only allow pages that are no longer memory-mapped to be evicted.
	for mgap := c.mappings.LowerBoundGap(mr.Start); mgap.Ok() && mgap.Start() < mr.End; mgap = mgap.NextGap() {
		mgapMR := mgap.Range().Intersect(mr)
		if mgapMR.Length() == 0 {
			continue
		}
		if err := SyncDirty(ctx, mgapMR, &c.cache, &c.dirty, uint64(c.attr.Size), mf, c.backingFile.WriteFromBlocksAt); err != nil {
			log.Warningf("Failed to writeback cached data %v: %v", mgapMR, err)
		}
		c.cache.Drop(mgapMR, mf)
		c.dirty.KeepClean(mgapMR)
	}
}

// IncRef implements platform.File.IncRef. This is used when we directly map an
// underlying host fd and CachingInodeOperations is used as the platform.File
// during translation.
func (c *CachingInodeOperations) IncRef(fr platform.FileRange) {
	// Hot path. Avoid defers.
	c.dataMu.Lock()
	seg, gap := c.refs.Find(fr.Start)
	for {
		switch {
		case seg.Ok() && seg.Start() < fr.End:
			seg = c.refs.Isolate(seg, fr)
			seg.SetValue(seg.Value() + 1)
			seg, gap = seg.NextNonEmpty()
		case gap.Ok() && gap.Start() < fr.End:
			newRange := gap.Range().Intersect(fr)
			if usage.IncrementalMappedAccounting {
				usage.MemoryAccounting.Inc(newRange.Length(), usage.Mapped)
			}
			seg, gap = c.refs.InsertWithoutMerging(gap, newRange, 1).NextNonEmpty()
		default:
			c.refs.MergeAdjacent(fr)
			c.dataMu.Unlock()
			return
		}
	}
}

// DecRef implements platform.File.DecRef. This is used when we directly map an
// underlying host fd and CachingInodeOperations is used as the platform.File
// during translation.
func (c *CachingInodeOperations) DecRef(fr platform.FileRange) {
	// Hot path. Avoid defers.
	c.dataMu.Lock()
	seg := c.refs.FindSegment(fr.Start)

	for seg.Ok() && seg.Start() < fr.End {
		seg = c.refs.Isolate(seg, fr)
		if old := seg.Value(); old == 1 {
			if usage.IncrementalMappedAccounting {
				usage.MemoryAccounting.Dec(seg.Range().Length(), usage.Mapped)
			}
			seg = c.refs.Remove(seg).NextSegment()
		} else {
			seg.SetValue(old - 1)
			seg = seg.NextSegment()
		}
	}
	c.refs.MergeAdjacent(fr)
	c.dataMu.Unlock()

}

// MapInternal implements platform.File.MapInternal. This is used when we
// directly map an underlying host fd and CachingInodeOperations is used as the
// platform.File during translation.
func (c *CachingInodeOperations) MapInternal(fr platform.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
	return c.hostFileMapper.MapInternal(fr, c.backingFile.FD(), at.Write)
}

// FD implements platform.File.FD. This is used when we directly map an
// underlying host fd and CachingInodeOperations is used as the platform.File
// during translation.
func (c *CachingInodeOperations) FD() int {
	return c.backingFile.FD()
}
