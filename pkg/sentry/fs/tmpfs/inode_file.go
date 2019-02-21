// Copyright 2018 Google LLC
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
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/metric"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

var (
	opensRO  = metric.MustCreateNewUint64Metric("/in_memory_file/opens_ro", false /* sync */, "Number of times an in-memory file was opened in read-only mode.")
	opensW   = metric.MustCreateNewUint64Metric("/in_memory_file/opens_w", false /* sync */, "Number of times an in-memory file was opened in write mode.")
	reads    = metric.MustCreateNewUint64Metric("/in_memory_file/reads", false /* sync */, "Number of in-memory file reads.")
	readWait = metric.MustCreateNewUint64Metric("/in_memory_file/read_wait", false /* sync */, "Time waiting on in-memory file reads, in nanoseconds.")
)

// fileInodeOperations implements fs.InodeOperations for a regular tmpfs file.
// These files are backed by FrameRegions allocated from a platform.Memory,
// and may be directly mapped.
//
// The tmpfs file memory is backed by FrameRegions, each of which is reference
// counted. frames maintains a single reference on each of the FrameRegions.
// Since these contain the contents of the file, the reference may only be
// decremented once this file is both deleted and all handles to the file have
// been closed.
//
// Mappable users may also call IncRefOn/DecRefOn, generally to indicate that
// they plan to use MapInto to map the file into an AddressSpace. These calls
// include an InvalidatorRegion associated with that reference. When the
// referenced portion of the file is removed (with Truncate), the associated
// InvalidatorRegion is invalidated.
//
// +stateify savable
type fileInodeOperations struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`

	fsutil.InodeSimpleExtendedAttributes

	// kernel is used to allocate platform memory that stores the file's contents.
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

	dataMu sync.RWMutex `state:"nosave"`

	// data maps offsets into the file to offsets into platform.Memory() that
	// store the file's data.
	//
	// data is protected by dataMu.
	data fsutil.FileRangeSet
}

var _ fs.InodeOperations = (*fileInodeOperations)(nil)

// NewInMemoryFile returns a new file backed by p.Memory().
func NewInMemoryFile(ctx context.Context, usage usage.MemoryKind, uattr fs.UnstableAttr) fs.InodeOperations {
	return &fileInodeOperations{
		attr:     uattr,
		kernel:   kernel.KernelFromContext(ctx),
		memUsage: usage,
	}
}

// Release implements fs.InodeOperations.Release.
func (f *fileInodeOperations) Release(context.Context) {
	f.dataMu.Lock()
	defer f.dataMu.Unlock()
	f.data.DropAll(f.kernel.Platform.Memory())
}

// Mappable implements fs.InodeOperations.Mappable.
func (f *fileInodeOperations) Mappable(*fs.Inode) memmap.Mappable {
	return f
}

// Rename implements fs.InodeOperations.Rename.
func (*fileInodeOperations) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return rename(ctx, oldParent, oldName, newParent, newName)
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
	f.data.Truncate(uint64(size), f.kernel.Platform.Memory())

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

func (f *fileInodeOperations) read(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
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
	// TODO: Separate out f.attr.Size and use atomics instead of
	// f.dataMu.
	f.dataMu.RLock()
	size := f.attr.Size
	f.dataMu.RUnlock()
	if offset >= size {
		fs.IncrementWait(readWait, start)
		return 0, io.EOF
	}

	n, err := dst.CopyOutFrom(ctx, &fileReadWriter{f, offset})
	// Compare Linux's mm/filemap.c:do_generic_file_read() => file_accessed().
	f.attrMu.Lock()
	f.attr.AccessTime = ktime.NowFromContext(ctx)
	f.attrMu.Unlock()
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

	mem := rw.f.kernel.Platform.Memory()
	var done uint64
	seg, gap := rw.f.data.Find(uint64(rw.offset))
	for rw.offset < end {
		mr := memmap.MappableRange{uint64(rw.offset), uint64(end)}
		switch {
		case seg.Ok():
			// Get internal mappings.
			ims, err := mem.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Read)
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

	defer func() {
		// If the write ends beyond the file's previous size, it causes the
		// file to grow.
		if rw.offset > rw.f.attr.Size {
			rw.f.attr.Size = rw.offset
		}
	}()

	mem := rw.f.kernel.Platform.Memory()
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
			ims, err := mem.MapInternal(seg.FileRangeOf(seg.Range().Intersect(mr)), usermem.Write)
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
			fr, err := mem.Allocate(gapMR.Length(), rw.f.memUsage)
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
	f.mappings.AddMapping(ms, ar, offset, writable)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (f *fileInodeOperations) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	f.mappings.RemoveMapping(ms, ar, offset, writable)
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

	mem := f.kernel.Platform.Memory()
	cerr := f.data.Fill(ctx, required, optional, mem, f.memUsage, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
		// Newly-allocated pages are zeroed, so we don't need to do anything.
		return dsts.NumBytes(), nil
	})

	var ts []memmap.Translation
	var translatedEnd uint64
	for seg := f.data.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   mem,
			Offset: seg.FileRangeOf(segMR).Start,
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
