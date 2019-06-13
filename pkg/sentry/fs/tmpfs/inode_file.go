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

package tmpfs

import (
	"fmt"
	"io"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

var (
	opensRO  = metric.MustCreateNewUint64Metric("/in_memory_file/opens_ro", false /* sync */, "Number of times an in-memory file was opened in read-only mode.")
	opensW   = metric.MustCreateNewUint64Metric("/in_memory_file/opens_w", false /* sync */, "Number of times an in-memory file was opened in write mode.")
	reads    = metric.MustCreateNewUint64Metric("/in_memory_file/reads", false /* sync */, "Number of in-memory file reads.")
	readWait = metric.MustCreateNewUint64Metric("/in_memory_file/read_wait", false /* sync */, "Time waiting on in-memory file reads, in nanoseconds.")
)

// fileInodeOperations implements fs.InodeOperations for a regular tmpfs file.
// These files are backed by pages allocated from a platform.Memory, and may be
// directly mapped.
//
// Lock order: attrMu -> mapsMu -> dataMu.
//
// +stateify savable
type fileInodeOperations struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`

	fsutil.InodeSimpleExtendedAttributes

	// kernel is used to allocate memory that stores the file's contents.
	kernel *kernel.Kernel

	// memUsage is the default memory usage that will be reported by this file.
	memUsage usage.MemoryKind

	attrMu sync.Mutex `state:"nosave"`

	// attr contains the unstable metadata for the file.
	//
	// attr is protected by attrMu. attr.Size is protected by both attrMu
	// and dataMu; reading it requires locking either mutex, while mutating
	// it requires locking both.
	attr fs.UnstableAttr

	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks mappings of the file into memmap.MappingSpaces.
	//
	// mappings is protected by mapsMu.
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

	dataMu sync.RWMutex `state:"nosave"`

	// data maps offsets into the file to offsets into platform.Memory() that
	// store the file's data.
	//
	// data is protected by dataMu.
	data fsutil.FileRangeSet

	// seals represents file seals on this inode.
	//
	// Protected by dataMu.
	seals uint32
}

var _ fs.InodeOperations = (*fileInodeOperations)(nil)

// NewInMemoryFile returns a new file backed by Kernel.MemoryFile().
func NewInMemoryFile(ctx context.Context, usage usage.MemoryKind, uattr fs.UnstableAttr) fs.InodeOperations {
	return &fileInodeOperations{
		attr:     uattr,
		kernel:   kernel.KernelFromContext(ctx),
		memUsage: usage,
		seals:    linux.F_SEAL_SEAL,
	}
}

// NewMemfdInode creates a new inode backing a memfd. Memory used by the memfd
// is backed by platform memory.
func NewMemfdInode(ctx context.Context, allowSeals bool) *fs.Inode {
	// Per Linux, mm/shmem.c:__shmem_file_setup(), memfd inodes are set up with
	// S_IRWXUGO.
	perms := fs.PermMask{Read: true, Write: true, Execute: true}
	iops := NewInMemoryFile(ctx, usage.Tmpfs, fs.UnstableAttr{
		Owner: fs.FileOwnerFromContext(ctx),
		Perms: fs.FilePermissions{User: perms, Group: perms, Other: perms}}).(*fileInodeOperations)
	if allowSeals {
		iops.seals = 0
	}
	return fs.NewInode(iops, fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{}), fs.StableAttr{
		Type:      fs.RegularFile,
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
	})
}

// Release implements fs.InodeOperations.Release.
func (f *fileInodeOperations) Release(context.Context) {
	f.dataMu.Lock()
	defer f.dataMu.Unlock()
	f.data.DropAll(f.kernel.MemoryFile())
}

// Mappable implements fs.InodeOperations.Mappable.
func (f *fileInodeOperations) Mappable(*fs.Inode) memmap.Mappable {
	return f
}

// Rename implements fs.InodeOperations.Rename.
func (*fileInodeOperations) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// GetFile implements fs.InodeOperations.GetFile.
func (f *fileInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	if flags.Write {
		opensW.Increment()
	} else if flags.Read {
		opensRO.Increment()
	}
	flags.Pread = true
	flags.Pwrite = true
	return fs.NewFile(ctx, d, flags, &regularFileOperations{iops: f}), nil
}

// UnstableAttr returns unstable attributes of this tmpfs file.
func (f *fileInodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	f.attrMu.Lock()
	f.dataMu.RLock()
	attr := f.attr
	attr.Usage = int64(f.data.Span())
	f.dataMu.RUnlock()
	f.attrMu.Unlock()
	return attr, nil
}

// Check implements fs.InodeOperations.Check.
func (f *fileInodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (f *fileInodeOperations) SetPermissions(ctx context.Context, _ *fs.Inode, p fs.FilePermissions) bool {
	f.attrMu.Lock()
	f.attr.SetPermissions(ctx, p)
	f.attrMu.Unlock()
	return true
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (f *fileInodeOperations) SetTimestamps(ctx context.Context, _ *fs.Inode, ts fs.TimeSpec) error {
	f.attrMu.Lock()
	f.attr.SetTimestamps(ctx, ts)
	f.attrMu.Unlock()
	return nil
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (f *fileInodeOperations) SetOwner(ctx context.Context, _ *fs.Inode, owner fs.FileOwner) error {
	f.attrMu.Lock()
	f.attr.SetOwner(ctx, owner)
	f.attrMu.Unlock()
	return nil
}

// Truncate implements fs.InodeOperations.Truncate.
func (f *fileInodeOperations) Truncate(ctx context.Context, _ *fs.Inode, size int64) error {
	f.attrMu.Lock()
	defer f.attrMu.Unlock()

	f.dataMu.Lock()
	oldSize := f.attr.Size

	// Check if current seals allow truncation.
	switch {
	case size > oldSize && f.seals&linux.F_SEAL_GROW != 0: // Grow sealed
		fallthrough
	case oldSize > size && f.seals&linux.F_SEAL_SHRINK != 0: // Shrink sealed
		f.dataMu.Unlock()
		return syserror.EPERM
	}

	if oldSize != size {
		f.attr.Size = size
		// Update mtime and ctime.
		now := ktime.NowFromContext(ctx)
		f.attr.ModificationTime = now
		f.attr.StatusChangeTime = now
	}
	f.dataMu.Unlock()

	// Nothing left to do unless shrinking the file.
	if oldSize <= size {
		return nil
	}

	oldpgend := fs.OffsetPageEnd(oldSize)
	newpgend := fs.OffsetPageEnd(size)

	// Invalidate past translations of truncated pages.
	if newpgend != oldpgend {
		f.mapsMu.Lock()
		f.mappings.Invalidate(memmap.MappableRange{newpgend, oldpgend}, memmap.InvalidateOpts{
			// Compare Linux's mm/shmem.c:shmem_setattr() =>
			// mm/memory.c:unmap_mapping_range(evencows=1).
			InvalidatePrivate: true,
		})
		f.mapsMu.Unlock()
	}

	// We are now guaranteed that there are no translations of truncated pages,
	// and can remove them.
	f.dataMu.Lock()
	defer f.dataMu.Unlock()
	f.data.Truncate(uint64(size), f.kernel.MemoryFile())

	return nil
}

// Allocate implements fs.InodeOperations.Allocate.
func (f *fileInodeOperations) Allocate(ctx context.Context, _ *fs.Inode, offset, length int64) error {
	newSize := offset + length

	f.attrMu.Lock()
	defer f.attrMu.Unlock()
	f.dataMu.Lock()
	defer f.dataMu.Unlock()

	if newSize <= f.attr.Size {
		return nil
	}

	// Check if current seals allow growth.
	if f.seals&linux.F_SEAL_GROW != 0 {
		return syserror.EPERM
	}

	f.attr.Size = newSize

	now := ktime.NowFromContext(ctx)
	f.attr.ModificationTime = now
	f.attr.StatusChangeTime = now

	return nil
}

// AddLink implements fs.InodeOperations.AddLink.
func (f *fileInodeOperations) AddLink() {
	f.attrMu.Lock()
	f.attr.Links++
	f.attrMu.Unlock()
}

// DropLink implements fs.InodeOperations.DropLink.
func (f *fileInodeOperations) DropLink() {
	f.attrMu.Lock()
	f.attr.Links--
	f.attrMu.Unlock()
}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (f *fileInodeOperations) NotifyStatusChange(ctx context.Context) {
	f.attrMu.Lock()
	f.attr.StatusChangeTime = ktime.NowFromContext(ctx)
	f.attrMu.Unlock()
}

// IsVirtual implements fs.InodeOperations.IsVirtual.
func (*fileInodeOperations) IsVirtual() bool {
	return true
}

// StatFS implements fs.InodeOperations.StatFS.
func (*fileInodeOperations) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

func (f *fileInodeOperations) read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	var start time.Time
	if fs.RecordWaitTime {
		start = time.Now()
	}
	reads.Increment()
	// Zero length reads for tmpfs are no-ops.
	if dst.NumBytes() == 0 {
		fs.IncrementWait(readWait, start)
		return 0, nil
	}

	// Have we reached EOF? We check for this again in
	// fileReadWriter.ReadToBlocks to avoid holding f.attrMu (which would
	// serialize reads) or f.dataMu (which would violate lock ordering), but
	// check here first (before calling into MM) since reading at EOF is
	// common: getting a return value of 0 from a read syscall is the only way
	// to detect EOF.
	//
	// TODO(jamieliu): Separate out f.attr.Size and use atomics instead of
	// f.dataMu.
	f.dataMu.RLock()
	size := f.attr.Size
	f.dataMu.RUnlock()
	if offset >= size {
		fs.IncrementWait(readWait, start)
		return 0, io.EOF
	}

	n, err := dst.CopyOutFrom(ctx, &fileReadWriter{f, offset})
	if !file.Dirent.Inode.MountSource.Flags.NoAtime {
		// Compare Linux's mm/filemap.c:do_generic_file_read() => file_accessed().
		f.attrMu.Lock()
		f.attr.AccessTime = ktime.NowFromContext(ctx)
		f.attrMu.Unlock()
	}
	fs.IncrementWait(readWait, start)
	return n, err
}

func (f *fileInodeOperations) write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// Zero length writes for tmpfs are no-ops.
	if src.NumBytes() == 0 {
		return 0, nil
	}

	f.attrMu.Lock()
	defer f.attrMu.Unlock()
	// Compare Linux's mm/filemap.c:__generic_file_write_iter() => file_update_time().
	now := ktime.NowFromContext(ctx)
	f.attr.ModificationTime = now
	f.attr.StatusChangeTime = now
	return src.CopyInTo(ctx, &fileReadWriter{f, offset})
}

type fileReadWriter struct {
	f      *fileInodeOperations
	offset int64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *fileReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	rw.f.dataMu.RLock()
	defer rw.f.dataMu.RUnlock()

	// Compute the range to read.
	if rw.offset >= rw.f.attr.Size {
		return 0, io.EOF
	}
	end := fs.ReadEndOffset(rw.offset, int64(dsts.NumBytes()), rw.f.attr.Size)
	if end == rw.offset { // dsts.NumBytes() == 0?
		return 0, nil
	}

	mf := rw.f.kernel.MemoryFile()
	var done uint64
	seg, gap := rw.f.data.Find(uint64(rw.offset))
	for rw.offset < end {
		mr := memmap.MappableRange{uint64(rw.offset), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings.
			ims, err := mf.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Read)
			if err != nil {
				return done, err
			}

			// Copy from internal mappings.
			n, err := safemem.CopySeq(dsts, ims)
			done += n
			rw.offset += int64(n)
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
			rw.offset += int64(n)
			dsts = dsts.DropFirst64(n)
			if err != nil {
				return done, err
			}

			// Continue.
			seg, gap = gap.NextSegment(), fsutil.FileRangeGapIterator{}

		default:
			break
		}
	}
	return done, nil
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *fileReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	rw.f.dataMu.Lock()
	defer rw.f.dataMu.Unlock()

	// Compute the range to write.
	end := fs.WriteEndOffset(rw.offset, int64(srcs.NumBytes()))
	if end == rw.offset { // srcs.NumBytes() == 0?
		return 0, nil
	}

	// Check if seals prevent either file growth or all writes.
	switch {
	case rw.f.seals&linux.F_SEAL_WRITE != 0: // Write sealed
		return 0, syserror.EPERM
	case end > rw.f.attr.Size && rw.f.seals&linux.F_SEAL_GROW != 0: // Grow sealed
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
		if pgstart := int64(usermem.Addr(rw.f.attr.Size).RoundDown()); end > pgstart {
			end = pgstart
		}
		if end <= rw.offset {
			// Truncation would result in no data being written.
			return 0, syserror.EPERM
		}
	}

	defer func() {
		// If the write ends beyond the file's previous size, it causes the
		// file to grow.
		if rw.offset > rw.f.attr.Size {
			rw.f.attr.Size = rw.offset
		}
	}()

	mf := rw.f.kernel.MemoryFile()
	// Page-aligned mr for when we need to allocate memory. RoundUp can't
	// overflow since end is an int64.
	pgstartaddr := usermem.Addr(rw.offset).RoundDown()
	pgendaddr, _ := usermem.Addr(end).RoundUp()
	pgMR := memmap.MappableRange{uint64(pgstartaddr), uint64(pgendaddr)}

	var done uint64
	seg, gap := rw.f.data.Find(uint64(rw.offset))
	for rw.offset < end {
		mr := memmap.MappableRange{uint64(rw.offset), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings.
			ims, err := mf.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Write)
			if err != nil {
				return done, err
			}

			// Copy to internal mappings.
			n, err := safemem.CopySeq(ims, srcs)
			done += n
			rw.offset += int64(n)
			srcs = srcs.DropFirst64(n)
			if err != nil {
				return done, err
			}

			// Continue.
			seg, gap = seg.NextNonEmpty()

		case gap.Ok():
			// Allocate memory for the write.
			gapMR := gap.Range().Intersect(pgMR)
			fr, err := mf.Allocate(gapMR.Length(), rw.f.memUsage)
			if err != nil {
				return done, err
			}

			// Write to that memory as usual.
			seg, gap = rw.f.data.Insert(gap, gapMR, fr.Start), fsutil.FileRangeGapIterator{}

		default:
			break
		}
	}
	return done, nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (f *fileInodeOperations) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()

	f.dataMu.RLock()
	defer f.dataMu.RUnlock()

	// Reject writable mapping if F_SEAL_WRITE is set.
	if f.seals&linux.F_SEAL_WRITE != 0 && writable {
		return syserror.EPERM
	}

	f.mappings.AddMapping(ms, ar, offset, writable)
	if writable {
		pagesBefore := f.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		f.writableMappingPages += uint64(ar.Length() / usermem.PageSize)

		if f.writableMappingPages < pagesBefore {
			panic(fmt.Sprintf("Overflow while mapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, f.writableMappingPages))
		}
	}

	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (f *fileInodeOperations) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()

	f.mappings.RemoveMapping(ms, ar, offset, writable)

	if writable {
		pagesBefore := f.writableMappingPages

		// ar is guaranteed to be page aligned per memmap.Mappable.
		f.writableMappingPages -= uint64(ar.Length() / usermem.PageSize)

		if f.writableMappingPages > pagesBefore {
			panic(fmt.Sprintf("Underflow while unmapping potentially writable pages pointing to a tmpfs file. Before %v, after %v", pagesBefore, f.writableMappingPages))
		}
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (f *fileInodeOperations) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return f.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (f *fileInodeOperations) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	f.dataMu.Lock()
	defer f.dataMu.Unlock()

	// Constrain translations to f.attr.Size (rounded up) to prevent
	// translation to pages that may be concurrently truncated.
	pgend := fs.OffsetPageEnd(f.attr.Size)
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

	mf := f.kernel.MemoryFile()
	cerr := f.data.Fill(ctx, required, optional, mf, f.memUsage, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
		// Newly-allocated pages are zeroed, so we don't need to do anything.
		return dsts.NumBytes(), nil
	})

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := f.data.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   mf,
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
func (f *fileInodeOperations) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// GetSeals returns the current set of seals on a memfd inode.
func GetSeals(inode *fs.Inode) (uint32, error) {
	if f, ok := inode.InodeOperations.(*fileInodeOperations); ok {
		f.dataMu.RLock()
		defer f.dataMu.RUnlock()
		return f.seals, nil
	}
	// Not a memfd inode.
	return 0, syserror.EINVAL
}

// AddSeals adds new file seals to a memfd inode.
func AddSeals(inode *fs.Inode, val uint32) error {
	if f, ok := inode.InodeOperations.(*fileInodeOperations); ok {
		f.mapsMu.Lock()
		defer f.mapsMu.Unlock()
		f.dataMu.Lock()
		defer f.dataMu.Unlock()

		if f.seals&linux.F_SEAL_SEAL != 0 {
			// Seal applied which prevents addition of any new seals.
			return syserror.EPERM
		}

		// F_SEAL_WRITE can only be added if there are no active writable maps.
		if f.seals&linux.F_SEAL_WRITE == 0 && val&linux.F_SEAL_WRITE != 0 {
			if f.writableMappingPages > 0 {
				return syserror.EBUSY
			}
		}

		// Seals can only be added, never removed.
		f.seals |= val
		return nil
	}
	// Not a memfd inode.
	return syserror.EINVAL
}
