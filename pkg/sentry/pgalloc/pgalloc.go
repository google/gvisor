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

// Package pgalloc contains the page allocator subsystem, which manages memory
// that may be mapped into application address spaces.
//
// Lock order:
//
// pgalloc.MemoryFile.mu
//   pgalloc.MemoryFile.mappingsMu
package pgalloc

import (
	"fmt"
	"math"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostmm"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// Direction describes how to allocate offsets from MemoryFile.
type Direction int

const (
	// BottomUp allocates offsets in increasing offsets.
	BottomUp Direction = iota
	// TopDown allocates offsets in decreasing offsets.
	TopDown
)

// String implements fmt.Stringer.
func (d Direction) String() string {
	switch d {
	case BottomUp:
		return "up"
	case TopDown:
		return "down"
	}
	panic(fmt.Sprintf("invalid direction: %d", d))
}

// MemoryFile is a memmap.File whose pages may be allocated to arbitrary
// users.
type MemoryFile struct {
	// opts holds options passed to NewMemoryFile. opts is immutable.
	opts MemoryFileOpts

	// MemoryFile owns a single backing file, which is modeled as follows:
	//
	// Each page in the file can be committed or uncommitted. A page is
	// committed if the host kernel is spending resources to store its contents
	// and uncommitted otherwise. This definition includes pages that the host
	// kernel has swapped; this is intentional, to ensure that accounting does
	// not change even if host kernel swapping behavior changes, and that
	// memory used by pseudo-swap mechanisms like zswap is still accounted.
	//
	// The initial contents of uncommitted pages are implicitly zero bytes. A
	// read or write to the contents of an uncommitted page causes it to be
	// committed. This is the only event that can cause a uncommitted page to
	// be committed.
	//
	// fallocate(FALLOC_FL_PUNCH_HOLE) (MemoryFile.Decommit) causes committed
	// pages to be uncommitted. This is the only event that can cause a
	// committed page to be uncommitted.
	//
	// Memory accounting is based on identifying the set of committed pages.
	// Since we do not have direct access to the MMU, tracking reads and writes
	// to uncommitted pages to detect commitment would introduce additional
	// page faults, which would be prohibitively expensive. Instead, we query
	// the host kernel to determine which pages are committed.

	// file is the backing file. The file pointer is immutable.
	file *os.File

	mu sync.Mutex

	// usage maps each page in the file to metadata for that page. Pages for
	// which no segment exists in usage are both unallocated (not in use) and
	// uncommitted.
	//
	// Since usage stores usageInfo objects by value, clients should usually
	// use usageIterator.ValuePtr() instead of usageIterator.Value() to get a
	// pointer to the usageInfo rather than a copy.
	//
	// usage must be kept maximally merged (that is, there should never be two
	// adjacent segments with the same values). At least markReclaimed depends
	// on this property.
	//
	// usage is protected by mu.
	usage usageSet

	// The UpdateUsage function scans all segments with knownCommitted set
	// to false, sees which pages are committed and creates corresponding
	// segments with knownCommitted set to true.
	//
	// In order to avoid unnecessary scans, usageExpected tracks the total
	// file blocks expected. This is used to elide the scan when this
	// matches the underlying file blocks.
	//
	// To track swapped pages, usageSwapped tracks the discrepency between
	// what is observed in core and what is reported by the file. When
	// usageSwapped is non-zero, a sweep will be performed at least every
	// second. The start of the last sweep is recorded in usageLast.
	//
	// All usage attributes are all protected by mu.
	usageExpected uint64
	usageSwapped  uint64
	usageLast     time.Time

	// fileSize is the size of the backing memory file in bytes. fileSize is
	// always a power-of-two multiple of chunkSize.
	//
	// fileSize is protected by mu.
	fileSize int64

	// Pages from the backing file are mapped into the local address space on
	// the granularity of large pieces called chunks. mappings is a []uintptr
	// that stores, for each chunk, the start address of a mapping of that
	// chunk in the current process' address space, or 0 if no such mapping
	// exists. Once a chunk is mapped, it is never remapped or unmapped until
	// the MemoryFile is destroyed.
	//
	// Mutating the mappings slice or its contents requires both holding
	// mappingsMu and using atomic memory operations. (The slice is mutated
	// whenever the file is expanded. Per the above, the only permitted
	// mutation of the slice's contents is the assignment of a mapping to a
	// chunk that was previously unmapped.) Reading the slice or its contents
	// only requires *either* holding mappingsMu or using atomic memory
	// operations. This allows MemoryFile.MapInternal to avoid locking in the
	// common case where chunk mappings already exist.
	mappingsMu sync.Mutex
	mappings   atomic.Value

	// destroyed is set by Destroy to instruct the reclaimer goroutine to
	// release resources and exit. destroyed is protected by mu.
	destroyed bool

	// reclaimable is true if usage may contain reclaimable pages. reclaimable
	// is protected by mu.
	reclaimable bool

	// reclaim is the collection of regions for reclaim. reclaim is protected
	// by mu.
	reclaim reclaimSet

	// reclaimCond is signaled (with mu locked) when reclaimable or destroyed
	// transitions from false to true.
	reclaimCond sync.Cond

	// evictable maps EvictableMemoryUsers to eviction state.
	//
	// evictable is protected by mu.
	evictable map[EvictableMemoryUser]*evictableMemoryUserInfo

	// evictionWG counts the number of goroutines currently performing evictions.
	evictionWG sync.WaitGroup

	// stopNotifyPressure stops memory cgroup pressure level
	// notifications used to drive eviction. stopNotifyPressure is
	// immutable.
	stopNotifyPressure func()
}

// MemoryFileOpts provides options to NewMemoryFile.
type MemoryFileOpts struct {
	// DelayedEviction controls the extent to which the MemoryFile may delay
	// eviction of evictable allocations.
	DelayedEviction DelayedEvictionType

	// If UseHostMemcgPressure is true, use host memory cgroup pressure level
	// notifications to determine when eviction is necessary. This option has
	// no effect unless DelayedEviction is DelayedEvictionEnabled.
	UseHostMemcgPressure bool

	// If ManualZeroing is true, MemoryFile must not assume that new pages
	// obtained from the host are zero-filled, such that MemoryFile must manually
	// zero newly-allocated pages.
	ManualZeroing bool
}

// DelayedEvictionType is the type of MemoryFileOpts.DelayedEviction.
type DelayedEvictionType int

const (
	// DelayedEvictionDefault has unspecified behavior.
	DelayedEvictionDefault DelayedEvictionType = iota

	// DelayedEvictionDisabled requires that evictable allocations are evicted
	// as soon as possible.
	DelayedEvictionDisabled

	// DelayedEvictionEnabled requests that the MemoryFile delay eviction of
	// evictable allocations until doing so is considered necessary to avoid
	// performance degradation due to host memory pressure, or OOM kills.
	//
	// As of this writing, the behavior of DelayedEvictionEnabled depends on
	// whether or not MemoryFileOpts.UseHostMemcgPressure is enabled:
	//
	// - If UseHostMemcgPressure is true, evictions are delayed until memory
	// pressure is indicated.
	//
	// - Otherwise, evictions are only delayed until the reclaimer goroutine
	// is out of work (pages to reclaim).
	DelayedEvictionEnabled

	// DelayedEvictionManual requires that evictable allocations are only
	// evicted when MemoryFile.StartEvictions() is called. This is extremely
	// dangerous outside of tests.
	DelayedEvictionManual
)

// usageInfo tracks usage information.
//
// +stateify savable
type usageInfo struct {
	// kind is the usage kind.
	kind usage.MemoryKind

	// knownCommitted is true if the tracked region is definitely committed.
	// (If it is false, the tracked region may or may not be committed.)
	knownCommitted bool

	refs uint64
}

// canCommit returns true if the tracked region can be committed.
func (u *usageInfo) canCommit() bool {
	// refs must be greater than 0 because we assume that reclaimable pages
	// (that aren't already known to be committed) are not committed. This
	// isn't necessarily true, even after the reclaimer does Decommit(),
	// because the kernel may subsequently back the hugepage-sized region
	// containing the decommitted page with a hugepage. However, it's
	// consistent with our treatment of unallocated pages, which have the same
	// property.
	return !u.knownCommitted && u.refs != 0
}

// An EvictableMemoryUser represents a user of MemoryFile-allocated memory that
// may be asked to deallocate that memory in the presence of memory pressure.
type EvictableMemoryUser interface {
	// Evict requests that the EvictableMemoryUser deallocate memory used by
	// er, which was registered as evictable by a previous call to
	// MemoryFile.MarkEvictable.
	//
	// Evict is not required to deallocate memory. In particular, since pgalloc
	// must call Evict without holding locks to avoid circular lock ordering,
	// it is possible that the passed range has already been marked as
	// unevictable by a racing call to MemoryFile.MarkUnevictable.
	// Implementations of EvictableMemoryUser must detect such races and handle
	// them by making Evict have no effect on unevictable ranges.
	//
	// After a call to Evict, the MemoryFile will consider the evicted range
	// unevictable (i.e. it will not call Evict on the same range again) until
	// informed otherwise by a subsequent call to MarkEvictable.
	Evict(ctx context.Context, er EvictableRange)
}

// An EvictableRange represents a range of uint64 offsets in an
// EvictableMemoryUser.
//
// In practice, most EvictableMemoryUsers will probably be implementations of
// memmap.Mappable, and EvictableRange therefore corresponds to
// memmap.MappableRange. However, this package cannot depend on the memmap
// package, since doing so would create a circular dependency.
//
// type EvictableRange <generated using go_generics>

// evictableMemoryUserInfo is the value type of MemoryFile.evictable.
type evictableMemoryUserInfo struct {
	// ranges tracks all evictable ranges for the given user.
	ranges evictableRangeSet

	// If evicting is true, there is a goroutine currently evicting all
	// evictable ranges for this user.
	evicting bool
}

const (
	chunkShift = 30
	chunkSize  = 1 << chunkShift // 1 GB
	chunkMask  = chunkSize - 1

	// maxPage is the highest 64-bit page.
	maxPage = math.MaxUint64 &^ (hostarch.PageSize - 1)
)

// NewMemoryFile creates a MemoryFile backed by the given file. If
// NewMemoryFile succeeds, ownership of file is transferred to the returned
// MemoryFile.
func NewMemoryFile(file *os.File, opts MemoryFileOpts) (*MemoryFile, error) {
	switch opts.DelayedEviction {
	case DelayedEvictionDefault:
		opts.DelayedEviction = DelayedEvictionEnabled
	case DelayedEvictionDisabled, DelayedEvictionManual:
		opts.UseHostMemcgPressure = false
	case DelayedEvictionEnabled:
		// ok
	default:
		return nil, fmt.Errorf("invalid MemoryFileOpts.DelayedEviction: %v", opts.DelayedEviction)
	}

	// Truncate the file to 0 bytes first to ensure that it's empty.
	if err := file.Truncate(0); err != nil {
		return nil, err
	}
	f := &MemoryFile{
		opts:      opts,
		file:      file,
		evictable: make(map[EvictableMemoryUser]*evictableMemoryUserInfo),
	}
	f.mappings.Store(make([]uintptr, 0))
	f.reclaimCond.L = &f.mu

	if f.opts.DelayedEviction == DelayedEvictionEnabled && f.opts.UseHostMemcgPressure {
		stop, err := hostmm.NotifyCurrentMemcgPressureCallback(func() {
			f.mu.Lock()
			startedAny := f.startEvictionsLocked()
			f.mu.Unlock()
			if startedAny {
				log.Debugf("pgalloc.MemoryFile performing evictions due to memcg pressure")
			}
		}, "low")
		if err != nil {
			return nil, fmt.Errorf("failed to configure memcg pressure level notifications: %v", err)
		}
		f.stopNotifyPressure = stop
	}

	go f.runReclaim() // S/R-SAFE: f.mu

	// The Linux kernel contains an optional feature called "Integrity
	// Measurement Architecture" (IMA). If IMA is enabled, it will checksum
	// binaries the first time they are mapped PROT_EXEC. This is bad news for
	// executable pages mapped from our backing file, which can grow to
	// terabytes in (sparse) size. If IMA attempts to checksum a file that
	// large, it will allocate all of the sparse pages and quickly exhaust all
	// memory.
	//
	// Work around IMA by immediately creating a temporary PROT_EXEC mapping,
	// while the backing file is still small. IMA will ignore any future
	// mappings.
	m, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		hostarch.PageSize,
		unix.PROT_EXEC,
		unix.MAP_SHARED,
		file.Fd(),
		0)
	if errno != 0 {
		// This isn't fatal (IMA may not even be in use). Log the error, but
		// don't return it.
		log.Warningf("Failed to pre-map MemoryFile PROT_EXEC: %v", errno)
	} else {
		if _, _, errno := unix.Syscall(
			unix.SYS_MUNMAP,
			m,
			hostarch.PageSize,
			0); errno != 0 {
			panic(fmt.Sprintf("failed to unmap PROT_EXEC MemoryFile mapping: %v", errno))
		}
	}

	return f, nil
}

// Destroy releases all resources used by f.
//
// Preconditions: All pages allocated by f have been freed.
//
// Postconditions: None of f's methods may be called after Destroy.
func (f *MemoryFile) Destroy() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = true
	f.reclaimCond.Signal()
}

// AllocOpts are options used in MemoryFile.Allocate.
type AllocOpts struct {
	Kind usage.MemoryKind
	Dir  Direction
}

// Allocate returns a range of initially-zeroed pages of the given length with
// the given accounting kind and a single reference held by the caller. When
// the last reference on an allocated page is released, ownership of the page
// is returned to the MemoryFile, allowing it to be returned by a future call
// to Allocate.
//
// Preconditions: length must be page-aligned and non-zero.
func (f *MemoryFile) Allocate(length uint64, opts AllocOpts) (memmap.FileRange, error) {
	if length == 0 || length%hostarch.PageSize != 0 {
		panic(fmt.Sprintf("invalid allocation length: %#x", length))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Align hugepage-and-larger allocations on hugepage boundaries to try
	// to take advantage of hugetmpfs.
	alignment := uint64(hostarch.PageSize)
	if length >= hostarch.HugePageSize {
		alignment = hostarch.HugePageSize
	}

	// Find a range in the underlying file.
	fr, ok := f.findAvailableRange(length, alignment, opts.Dir)
	if !ok {
		return memmap.FileRange{}, linuxerr.ENOMEM
	}

	// Expand the file if needed.
	if int64(fr.End) > f.fileSize {
		// Round the new file size up to be chunk-aligned.
		newFileSize := (int64(fr.End) + chunkMask) &^ chunkMask
		if err := f.file.Truncate(newFileSize); err != nil {
			return memmap.FileRange{}, err
		}
		f.fileSize = newFileSize
		f.mappingsMu.Lock()
		oldMappings := f.mappings.Load().([]uintptr)
		newMappings := make([]uintptr, newFileSize>>chunkShift)
		copy(newMappings, oldMappings)
		f.mappings.Store(newMappings)
		f.mappingsMu.Unlock()
	}

	if f.opts.ManualZeroing {
		if err := f.manuallyZero(fr); err != nil {
			return memmap.FileRange{}, err
		}
	}
	// Mark selected pages as in use.
	if !f.usage.Add(fr, usageInfo{
		kind: opts.Kind,
		refs: 1,
	}) {
		panic(fmt.Sprintf("allocating %v: failed to insert into usage set:\n%v", fr, &f.usage))
	}

	return fr, nil
}

// findAvailableRange returns an available range in the usageSet.
//
// Note that scanning for available slots takes place from end first backwards,
// then forwards. This heuristic has important consequence for how sequential
// mappings can be merged in the host VMAs, given that addresses for both
// application and sentry mappings are allocated top-down (from higher to
// lower addresses). The file is also grown expoentially in order to create
// space for mappings to be allocated downwards.
//
// Precondition: alignment must be a power of 2.
func (f *MemoryFile) findAvailableRange(length, alignment uint64, dir Direction) (memmap.FileRange, bool) {
	if dir == BottomUp {
		return findAvailableRangeBottomUp(&f.usage, length, alignment)
	}
	return findAvailableRangeTopDown(&f.usage, f.fileSize, length, alignment)
}

func findAvailableRangeTopDown(usage *usageSet, fileSize int64, length, alignment uint64) (memmap.FileRange, bool) {
	alignmentMask := alignment - 1

	// Search for space in existing gaps, starting at the current end of the
	// file and working backward.
	lastGap := usage.LastGap()
	gap := lastGap
	for {
		end := gap.End()
		if end > uint64(fileSize) {
			end = uint64(fileSize)
		}

		// Try to allocate from the end of this gap, with the start of the
		// allocated range aligned down to alignment.
		unalignedStart := end - length
		if unalignedStart > end {
			// Negative overflow: this and all preceding gaps are too small to
			// accommodate length.
			break
		}
		if start := unalignedStart &^ alignmentMask; start >= gap.Start() {
			return memmap.FileRange{start, start + length}, true
		}

		gap = gap.PrevLargeEnoughGap(length)
		if !gap.Ok() {
			break
		}
	}

	// Check that it's possible to fit this allocation at the end of a file of any size.
	min := lastGap.Start()
	min = (min + alignmentMask) &^ alignmentMask
	if min+length < min {
		// Overflow: allocation would exceed the range of uint64.
		return memmap.FileRange{}, false
	}

	// Determine the minimum file size required to fit this allocation at its end.
	for {
		newFileSize := 2 * fileSize
		if newFileSize <= fileSize {
			if fileSize != 0 {
				// Overflow: allocation would exceed the range of int64.
				return memmap.FileRange{}, false
			}
			newFileSize = chunkSize
		}
		fileSize = newFileSize

		unalignedStart := uint64(fileSize) - length
		if unalignedStart > uint64(fileSize) {
			// Negative overflow: fileSize is still inadequate.
			continue
		}
		if start := unalignedStart &^ alignmentMask; start >= min {
			return memmap.FileRange{start, start + length}, true
		}
	}
}

func findAvailableRangeBottomUp(usage *usageSet, length, alignment uint64) (memmap.FileRange, bool) {
	alignmentMask := alignment - 1
	for gap := usage.FirstGap(); gap.Ok(); gap = gap.NextLargeEnoughGap(length) {
		// Align the start address and check if allocation still fits in the gap.
		start := (gap.Start() + alignmentMask) &^ alignmentMask

		// File offsets are int64s. Since length must be strictly positive, end
		// cannot legitimately be 0.
		end := start + length
		if end < start || int64(end) <= 0 {
			return memmap.FileRange{}, false
		}
		if end <= gap.End() {
			return memmap.FileRange{start, end}, true
		}
	}

	// NextLargeEnoughGap should have returned a gap at the end.
	panic(fmt.Sprintf("NextLargeEnoughGap didn't return a gap at the end, length: %d", length))
}

// AllocateAndFill allocates memory of the given kind and fills it by calling
// r.ReadToBlocks() repeatedly until either length bytes are read or a non-nil
// error is returned. It returns the memory filled by r, truncated down to the
// nearest page. If this is shorter than length bytes due to an error returned
// by r.ReadToBlocks(), it returns that error.
//
// Preconditions:
// * length > 0.
// * length must be page-aligned.
func (f *MemoryFile) AllocateAndFill(length uint64, kind usage.MemoryKind, r safemem.Reader) (memmap.FileRange, error) {
	fr, err := f.Allocate(length, AllocOpts{Kind: kind})
	if err != nil {
		return memmap.FileRange{}, err
	}
	dsts, err := f.MapInternal(fr, hostarch.Write)
	if err != nil {
		f.DecRef(fr)
		return memmap.FileRange{}, err
	}
	n, err := safemem.ReadFullToBlocks(r, dsts)
	un := uint64(hostarch.Addr(n).RoundDown())
	if un < length {
		// Free unused memory and update fr to contain only the memory that is
		// still allocated.
		f.DecRef(memmap.FileRange{fr.Start + un, fr.End})
		fr.End = fr.Start + un
	}
	return fr, err
}

// fallocate(2) modes, defined in Linux's include/uapi/linux/falloc.h.
const (
	_FALLOC_FL_KEEP_SIZE  = 1
	_FALLOC_FL_PUNCH_HOLE = 2
)

// Decommit releases resources associated with maintaining the contents of the
// given pages. If Decommit succeeds, future accesses of the decommitted pages
// will read zeroes.
//
// Preconditions: fr.Length() > 0.
func (f *MemoryFile) Decommit(fr memmap.FileRange) error {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%hostarch.PageSize != 0 || fr.End%hostarch.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	if f.opts.ManualZeroing {
		// FALLOC_FL_PUNCH_HOLE may not zero pages if ManualZeroing is in
		// effect.
		if err := f.manuallyZero(fr); err != nil {
			return err
		}
	} else {
		if err := f.decommitFile(fr); err != nil {
			return err
		}
	}

	f.markDecommitted(fr)
	return nil
}

func (f *MemoryFile) manuallyZero(fr memmap.FileRange) error {
	return f.forEachMappingSlice(fr, func(bs []byte) {
		for i := range bs {
			bs[i] = 0
		}
	})
}

func (f *MemoryFile) decommitFile(fr memmap.FileRange) error {
	// "After a successful call, subsequent reads from this range will
	// return zeroes. The FALLOC_FL_PUNCH_HOLE flag must be ORed with
	// FALLOC_FL_KEEP_SIZE in mode ..." - fallocate(2)
	return unix.Fallocate(
		int(f.file.Fd()),
		_FALLOC_FL_PUNCH_HOLE|_FALLOC_FL_KEEP_SIZE,
		int64(fr.Start),
		int64(fr.Length()))
}

func (f *MemoryFile) markDecommitted(fr memmap.FileRange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Since we're changing the knownCommitted attribute, we need to merge
	// across the entire range to ensure that the usage tree is minimal.
	gap := f.usage.ApplyContiguous(fr, func(seg usageIterator) {
		val := seg.ValuePtr()
		if val.knownCommitted {
			// Drop the usageExpected appropriately.
			amount := seg.Range().Length()
			usage.MemoryAccounting.Dec(amount, val.kind)
			f.usageExpected -= amount
			val.knownCommitted = false
		}
	})
	if gap.Ok() {
		panic(fmt.Sprintf("Decommit(%v): attempted to decommit unallocated pages %v:\n%v", fr, gap.Range(), &f.usage))
	}
	f.usage.MergeRange(fr)
}

// IncRef implements memmap.File.IncRef.
func (f *MemoryFile) IncRef(fr memmap.FileRange) {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%hostarch.PageSize != 0 || fr.End%hostarch.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	gap := f.usage.ApplyContiguous(fr, func(seg usageIterator) {
		seg.ValuePtr().refs++
	})
	if gap.Ok() {
		panic(fmt.Sprintf("IncRef(%v): attempted to IncRef on unallocated pages %v:\n%v", fr, gap.Range(), &f.usage))
	}

	f.usage.MergeAdjacent(fr)
}

// DecRef implements memmap.File.DecRef.
func (f *MemoryFile) DecRef(fr memmap.FileRange) {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%hostarch.PageSize != 0 || fr.End%hostarch.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	var freed bool

	f.mu.Lock()
	defer f.mu.Unlock()

	for seg := f.usage.FindSegment(fr.Start); seg.Ok() && seg.Start() < fr.End; seg = seg.NextSegment() {
		seg = f.usage.Isolate(seg, fr)
		val := seg.ValuePtr()
		if val.refs == 0 {
			panic(fmt.Sprintf("DecRef(%v): 0 existing references on %v:\n%v", fr, seg.Range(), &f.usage))
		}
		val.refs--
		if val.refs == 0 {
			f.reclaim.Add(seg.Range(), reclaimSetValue{})
			freed = true
			// Reclassify memory as System, until it's freed by the reclaim
			// goroutine.
			if val.knownCommitted {
				usage.MemoryAccounting.Move(seg.Range().Length(), usage.System, val.kind)
			}
			val.kind = usage.System
		}
	}
	f.usage.MergeAdjacent(fr)

	if freed {
		f.reclaimable = true
		f.reclaimCond.Signal()
	}
}

// MapInternal implements memmap.File.MapInternal.
func (f *MemoryFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if !fr.WellFormed() || fr.Length() == 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}

	chunks := ((fr.End + chunkMask) >> chunkShift) - (fr.Start >> chunkShift)
	if chunks == 1 {
		// Avoid an unnecessary slice allocation.
		var seq safemem.BlockSeq
		err := f.forEachMappingSlice(fr, func(bs []byte) {
			seq = safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bs))
		})
		return seq, err
	}
	blocks := make([]safemem.Block, 0, chunks)
	err := f.forEachMappingSlice(fr, func(bs []byte) {
		blocks = append(blocks, safemem.BlockFromSafeSlice(bs))
	})
	return safemem.BlockSeqFromSlice(blocks), err
}

// forEachMappingSlice invokes fn on a sequence of byte slices that
// collectively map all bytes in fr.
func (f *MemoryFile) forEachMappingSlice(fr memmap.FileRange, fn func([]byte)) error {
	mappings := f.mappings.Load().([]uintptr)
	for chunkStart := fr.Start &^ chunkMask; chunkStart < fr.End; chunkStart += chunkSize {
		chunk := int(chunkStart >> chunkShift)
		m := atomic.LoadUintptr(&mappings[chunk])
		if m == 0 {
			var err error
			mappings, m, err = f.getChunkMapping(chunk)
			if err != nil {
				return err
			}
		}
		startOff := uint64(0)
		if chunkStart < fr.Start {
			startOff = fr.Start - chunkStart
		}
		endOff := uint64(chunkSize)
		if chunkStart+chunkSize > fr.End {
			endOff = fr.End - chunkStart
		}
		fn(unsafeSlice(m, chunkSize)[startOff:endOff])
	}
	return nil
}

func (f *MemoryFile) getChunkMapping(chunk int) ([]uintptr, uintptr, error) {
	f.mappingsMu.Lock()
	defer f.mappingsMu.Unlock()
	// Another thread may have replaced f.mappings altogether due to file
	// expansion.
	mappings := f.mappings.Load().([]uintptr)
	// Another thread may have already mapped the chunk.
	if m := mappings[chunk]; m != 0 {
		return mappings, m, nil
	}
	m, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		chunkSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
		f.file.Fd(),
		uintptr(chunk<<chunkShift))
	if errno != 0 {
		return nil, 0, errno
	}
	atomic.StoreUintptr(&mappings[chunk], m)
	return mappings, m, nil
}

// MarkEvictable allows f to request memory deallocation by calling
// user.Evict(er) in the future.
//
// Redundantly marking an already-evictable range as evictable has no effect.
func (f *MemoryFile) MarkEvictable(user EvictableMemoryUser, er EvictableRange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.evictable[user]
	if !ok {
		info = &evictableMemoryUserInfo{}
		f.evictable[user] = info
	}
	gap := info.ranges.LowerBoundGap(er.Start)
	for gap.Ok() && gap.Start() < er.End {
		gapER := gap.Range().Intersect(er)
		if gapER.Length() == 0 {
			gap = gap.NextGap()
			continue
		}
		gap = info.ranges.Insert(gap, gapER, evictableRangeSetValue{}).NextGap()
	}
	if !info.evicting {
		switch f.opts.DelayedEviction {
		case DelayedEvictionDisabled:
			// Kick off eviction immediately.
			f.startEvictionGoroutineLocked(user, info)
		case DelayedEvictionEnabled:
			if !f.opts.UseHostMemcgPressure {
				// Ensure that the reclaimer goroutine is running, so that it
				// can start eviction when necessary.
				f.reclaimCond.Signal()
			}
		}
	}
}

// MarkUnevictable informs f that user no longer considers er to be evictable,
// so the MemoryFile should no longer call user.Evict(er). Note that, per
// EvictableMemoryUser.Evict's documentation, user.Evict(er) may still be
// called even after MarkUnevictable returns due to race conditions, and
// implementations of EvictableMemoryUser must handle this possibility.
//
// Redundantly marking an already-unevictable range as unevictable has no
// effect.
func (f *MemoryFile) MarkUnevictable(user EvictableMemoryUser, er EvictableRange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.evictable[user]
	if !ok {
		return
	}
	seg := info.ranges.LowerBoundSegment(er.Start)
	for seg.Ok() && seg.Start() < er.End {
		seg = info.ranges.Isolate(seg, er)
		seg = info.ranges.Remove(seg).NextSegment()
	}
	// We can only remove info if there's no eviction goroutine running on its
	// behalf.
	if !info.evicting && info.ranges.IsEmpty() {
		delete(f.evictable, user)
	}
}

// MarkAllUnevictable informs f that user no longer considers any offsets to be
// evictable. It otherwise has the same semantics as MarkUnevictable.
func (f *MemoryFile) MarkAllUnevictable(user EvictableMemoryUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.evictable[user]
	if !ok {
		return
	}
	info.ranges.RemoveAll()
	// We can only remove info if there's no eviction goroutine running on its
	// behalf.
	if !info.evicting {
		delete(f.evictable, user)
	}
}

// ShouldCacheEvictable returns true if f is meaningfully delaying evictions of
// evictable memory, such that it may be advantageous to cache data in
// evictable memory. The value returned by ShouldCacheEvictable may change
// between calls.
func (f *MemoryFile) ShouldCacheEvictable() bool {
	return f.opts.DelayedEviction == DelayedEvictionManual || f.opts.UseHostMemcgPressure
}

// UpdateUsage ensures that the memory usage statistics in
// usage.MemoryAccounting are up to date.
func (f *MemoryFile) UpdateUsage() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// If the underlying usage matches where the usage tree already
	// represents, then we can just avoid the entire scan (we know it's
	// accurate).
	currentUsage, err := f.TotalUsage()
	if err != nil {
		return err
	}
	if currentUsage == f.usageExpected && f.usageSwapped == 0 {
		log.Debugf("UpdateUsage: skipped with usageSwapped=0.")
		return nil
	}
	// If the current usage matches the expected but there's swap
	// accounting, then ensure a scan takes place at least every second
	// (when requested).
	if currentUsage == f.usageExpected+f.usageSwapped && time.Now().Before(f.usageLast.Add(time.Second)) {
		log.Debugf("UpdateUsage: skipped with usageSwapped!=0.")
		return nil
	}
	// Linux updates usage values at CONFIG_HZ.
	if scanningAfter := time.Now().Sub(f.usageLast).Milliseconds(); scanningAfter < time.Second.Milliseconds()/linux.CLOCKS_PER_SEC {
		log.Debugf("UpdateUsage: skipped because previous scan happened %d ms back", scanningAfter)
		return nil
	}

	f.usageLast = time.Now()
	err = f.updateUsageLocked(currentUsage, mincore)
	log.Debugf("UpdateUsage: currentUsage=%d, usageExpected=%d, usageSwapped=%d.",
		currentUsage, f.usageExpected, f.usageSwapped)
	log.Debugf("UpdateUsage: took %v.", time.Since(f.usageLast))
	return err
}

// updateUsageLocked attempts to detect commitment of previous-uncommitted
// pages by invoking checkCommitted, which is a function that, for each page i
// in bs, sets committed[i] to 1 if the page is committed and 0 otherwise.
//
// Precondition: f.mu must be held; it may be unlocked and reacquired.
// +checklocks:f.mu
func (f *MemoryFile) updateUsageLocked(currentUsage uint64, checkCommitted func(bs []byte, committed []byte) error) error {
	// Track if anything changed to elide the merge. In the common case, we
	// expect all segments to be committed and no merge to occur.
	changedAny := false
	defer func() {
		if changedAny {
			f.usage.MergeAll()
		}

		// Adjust the swap usage to reflect reality.
		if f.usageExpected < currentUsage {
			// Since no pages may be marked decommitted while we hold mu, we
			// know that usage may have only increased since we got the last
			// current usage. Therefore, if usageExpected is still short of
			// currentUsage, we must assume that the difference is in pages
			// that have been swapped.
			newUsageSwapped := currentUsage - f.usageExpected
			if f.usageSwapped < newUsageSwapped {
				usage.MemoryAccounting.Inc(newUsageSwapped-f.usageSwapped, usage.System)
			} else {
				usage.MemoryAccounting.Dec(f.usageSwapped-newUsageSwapped, usage.System)
			}
			f.usageSwapped = newUsageSwapped
		} else if f.usageSwapped != 0 {
			// We have more usage accounted for than the file itself.
			// That's fine, we probably caught a race where pages were
			// being committed while the below loop was running. Just
			// report the higher number that we found and ignore swap.
			usage.MemoryAccounting.Dec(f.usageSwapped, usage.System)
			f.usageSwapped = 0
		}
	}()

	// Reused mincore buffer, will generally be <= 4096 bytes.
	var buf []byte

	// Iterate over all usage data. There will only be usage segments
	// present when there is an associated reference.
	for seg := f.usage.FirstSegment(); seg.Ok(); {
		if !seg.ValuePtr().canCommit() {
			seg = seg.NextSegment()
			continue
		}

		// Get the range for this segment. As we touch slices, the
		// Start value will be walked along.
		r := seg.Range()

		var checkErr error
		err := f.forEachMappingSlice(r,
			func(s []byte) {
				if checkErr != nil {
					return
				}

				// Ensure that we have sufficient buffer for the call
				// (one byte per page). The length of each slice must
				// be page-aligned.
				bufLen := len(s) / hostarch.PageSize
				if len(buf) < bufLen {
					buf = make([]byte, bufLen)
				}

				// Query for new pages in core.
				// NOTE(b/165896008): mincore (which is passed as checkCommitted)
				// by f.UpdateUsage() might take a really long time. So unlock f.mu
				// while checkCommitted runs.
				f.mu.Unlock() // +checklocksforce
				err := checkCommitted(s, buf)
				f.mu.Lock()
				if err != nil {
					checkErr = err
					return
				}

				// Scan each page and switch out segments.
				seg := f.usage.LowerBoundSegment(r.Start)
				for i := 0; i < bufLen; {
					if buf[i]&0x1 == 0 {
						i++
						continue
					}
					// Scan to the end of this committed range.
					j := i + 1
					for ; j < bufLen; j++ {
						if buf[j]&0x1 == 0 {
							break
						}
					}
					committedFR := memmap.FileRange{
						Start: r.Start + uint64(i*hostarch.PageSize),
						End:   r.Start + uint64(j*hostarch.PageSize),
					}
					// Advance seg to committedFR.Start.
					for seg.Ok() && seg.End() < committedFR.Start {
						seg = seg.NextSegment()
					}
					// Mark pages overlapping committedFR as committed.
					for seg.Ok() && seg.Start() < committedFR.End {
						if seg.ValuePtr().canCommit() {
							seg = f.usage.Isolate(seg, committedFR)
							seg.ValuePtr().knownCommitted = true
							amount := seg.Range().Length()
							usage.MemoryAccounting.Inc(amount, seg.ValuePtr().kind)
							f.usageExpected += amount
							changedAny = true
						}
						seg = seg.NextSegment()
					}
					// Continue scanning for committed pages.
					i = j + 1
				}

				// Advance r.Start.
				r.Start += uint64(len(s))
			})
		if checkErr != nil {
			return checkErr
		}
		if err != nil {
			return err
		}

		// Continue with the first segment after r.End.
		seg = f.usage.LowerBoundSegment(r.End)
	}

	return nil
}

// TotalUsage returns an aggregate usage for all memory statistics except
// Mapped (which is external to MemoryFile). This is generally much cheaper
// than UpdateUsage, but will not provide a fine-grained breakdown.
func (f *MemoryFile) TotalUsage() (uint64, error) {
	// Stat the underlying file to discover the underlying usage. stat(2)
	// always reports the allocated block count in units of 512 bytes. This
	// includes pages in the page cache and swapped pages.
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Blocks * 512), nil
}

// TotalSize returns the current size of the backing file in bytes, which is an
// upper bound on the amount of memory that can currently be allocated from the
// MemoryFile. The value returned by TotalSize is permitted to change.
func (f *MemoryFile) TotalSize() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return uint64(f.fileSize)
}

// File returns the backing file.
func (f *MemoryFile) File() *os.File {
	return f.file
}

// FD implements memmap.File.FD.
func (f *MemoryFile) FD() int {
	return int(f.file.Fd())
}

// String implements fmt.Stringer.String.
//
// Note that because f.String locks f.mu, calling f.String internally
// (including indirectly through the fmt package) risks recursive locking.
// Within the pgalloc package, use f.usage directly instead.
func (f *MemoryFile) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage.String()
}

// runReclaim implements the reclaimer goroutine, which continuously decommits
// reclaimable pages in order to reduce memory usage and make them available
// for allocation.
func (f *MemoryFile) runReclaim() {
	for {
		// N.B. We must call f.markReclaimed on the returned FrameRange.
		fr, ok := f.findReclaimable()
		if !ok {
			break
		}

		if f.opts.ManualZeroing {
			// If ManualZeroing is in effect, only hugepage-aligned regions may
			// be safely passed to decommitFile. Pages will be zeroed on
			// reallocation, so we don't need to perform any manual zeroing
			// here, whether or not decommitFile succeeds.
			if startAddr, ok := hostarch.Addr(fr.Start).HugeRoundUp(); ok {
				if endAddr := hostarch.Addr(fr.End).HugeRoundDown(); startAddr < endAddr {
					decommitFR := memmap.FileRange{uint64(startAddr), uint64(endAddr)}
					if err := f.decommitFile(decommitFR); err != nil {
						log.Warningf("Reclaim failed to decommit %v: %v", decommitFR, err)
					}
				}
			}
		} else {
			if err := f.decommitFile(fr); err != nil {
				log.Warningf("Reclaim failed to decommit %v: %v", fr, err)
				// Zero the pages manually. This won't reduce memory usage, but at
				// least ensures that the pages will be zero when reallocated.
				if err := f.manuallyZero(fr); err != nil {
					panic(fmt.Sprintf("Reclaim failed to decommit or zero %v: %v", fr, err))
				}
			}
		}
		f.markDecommitted(fr)
		f.markReclaimed(fr)
	}

	// We only get here if findReclaimable finds f.destroyed set and returns
	// false.
	f.mu.Lock()
	if !f.destroyed {
		f.mu.Unlock()
		panic("findReclaimable broke out of reclaim loop, but destroyed is no longer set")
	}
	f.file.Close()
	// Ensure that any attempts to use f.file.Fd() fail instead of getting a fd
	// that has possibly been reassigned.
	f.file = nil
	f.mappingsMu.Lock()
	defer f.mappingsMu.Unlock()
	mappings := f.mappings.Load().([]uintptr)
	for i, m := range mappings {
		if m != 0 {
			_, _, errno := unix.Syscall(unix.SYS_MUNMAP, m, chunkSize, 0)
			if errno != 0 {
				log.Warningf("Failed to unmap mapping %#x for MemoryFile chunk %d: %v", m, i, errno)
			}
		}
	}
	// Similarly, invalidate f.mappings. (atomic.Value.Store(nil) panics.)
	f.mappings.Store([]uintptr{})
	f.mu.Unlock()

	// This must be called without holding f.mu to avoid circular lock
	// ordering.
	if f.stopNotifyPressure != nil {
		f.stopNotifyPressure()
	}
}

// findReclaimable finds memory that has been marked for reclaim.
//
// Note that there returned range will be removed from tracking. It
// must be reclaimed (removed from f.usage) at this point.
func (f *MemoryFile) findReclaimable() (memmap.FileRange, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		for {
			if f.destroyed {
				return memmap.FileRange{}, false
			}
			if f.reclaimable {
				break
			}
			if f.opts.DelayedEviction == DelayedEvictionEnabled && !f.opts.UseHostMemcgPressure {
				// No work to do. Evict any pending evictable allocations to
				// get more reclaimable pages before going to sleep.
				f.startEvictionsLocked()
			}
			f.reclaimCond.Wait()
		}
		// Most allocations are done upwards, with exceptions being stacks and some
		// allocators that allocate top-down. Reclaim preserves this order to
		// minimize the cost of the search.
		if seg := f.reclaim.FirstSegment(); seg.Ok() {
			fr := seg.Range()
			f.reclaim.Remove(seg)
			return fr, true
		}
		// Nothing is reclaimable.
		f.reclaimable = false
	}
}

func (f *MemoryFile) markReclaimed(fr memmap.FileRange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seg := f.usage.FindSegment(fr.Start)
	// All of fr should be mapped to a single uncommitted reclaimable
	// segment accounted to System.
	if !seg.Ok() {
		panic(fmt.Sprintf("reclaimed pages %v include unreferenced pages:\n%v", fr, &f.usage))
	}
	if !seg.Range().IsSupersetOf(fr) {
		panic(fmt.Sprintf("reclaimed pages %v are not entirely contained in segment %v with state %v:\n%v", fr, seg.Range(), seg.Value(), &f.usage))
	}
	if got, want := seg.Value(), (usageInfo{
		kind:           usage.System,
		knownCommitted: false,
		refs:           0,
	}); got != want {
		panic(fmt.Sprintf("reclaimed pages %v in segment %v has incorrect state %v, wanted %v:\n%v", fr, seg.Range(), got, want, &f.usage))
	}
	// Deallocate reclaimed pages. Even though all of seg is reclaimable,
	// the caller of markReclaimed may not have decommitted it, so we can
	// only mark fr as reclaimed.
	f.usage.Remove(f.usage.Isolate(seg, fr))
}

// StartEvictions requests that f evict all evictable allocations. It does not
// wait for eviction to complete; for this, see MemoryFile.WaitForEvictions.
func (f *MemoryFile) StartEvictions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startEvictionsLocked()
}

// Preconditions: f.mu must be locked.
func (f *MemoryFile) startEvictionsLocked() bool {
	startedAny := false
	for user, info := range f.evictable {
		// Don't start multiple goroutines to evict the same user's
		// allocations.
		if !info.evicting {
			f.startEvictionGoroutineLocked(user, info)
			startedAny = true
		}
	}
	return startedAny
}

// Preconditions:
// * info == f.evictable[user].
// * !info.evicting.
// * f.mu must be locked.
func (f *MemoryFile) startEvictionGoroutineLocked(user EvictableMemoryUser, info *evictableMemoryUserInfo) {
	info.evicting = true
	f.evictionWG.Add(1)
	go func() { // S/R-SAFE: f.evictionWG
		defer f.evictionWG.Done()
		for {
			f.mu.Lock()
			info, ok := f.evictable[user]
			if !ok {
				// This shouldn't happen: only this goroutine is permitted
				// to delete this entry.
				f.mu.Unlock()
				panic(fmt.Sprintf("evictableMemoryUserInfo for EvictableMemoryUser %v deleted while eviction goroutine running", user))
			}
			if info.ranges.IsEmpty() {
				delete(f.evictable, user)
				f.mu.Unlock()
				return
			}
			// Evict from the end of info.ranges, under the assumption that
			// if ranges in user start being used again (and are
			// consequently marked unevictable), such uses are more likely
			// to start from the beginning of user.
			seg := info.ranges.LastSegment()
			er := seg.Range()
			info.ranges.Remove(seg)
			// user.Evict() must be called without holding f.mu to avoid
			// circular lock ordering.
			f.mu.Unlock()
			user.Evict(context.Background(), er)
		}
	}()
}

// WaitForEvictions blocks until f is no longer evicting any evictable
// allocations.
func (f *MemoryFile) WaitForEvictions() {
	f.evictionWG.Wait()
}

type usageSetFunctions struct{}

func (usageSetFunctions) MinKey() uint64 {
	return 0
}

func (usageSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (usageSetFunctions) ClearValue(val *usageInfo) {
}

func (usageSetFunctions) Merge(_ memmap.FileRange, val1 usageInfo, _ memmap.FileRange, val2 usageInfo) (usageInfo, bool) {
	return val1, val1 == val2
}

func (usageSetFunctions) Split(_ memmap.FileRange, val usageInfo, _ uint64) (usageInfo, usageInfo) {
	return val, val
}

// evictableRangeSetValue is the value type of evictableRangeSet.
type evictableRangeSetValue struct{}

type evictableRangeSetFunctions struct{}

func (evictableRangeSetFunctions) MinKey() uint64 {
	return 0
}

func (evictableRangeSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (evictableRangeSetFunctions) ClearValue(val *evictableRangeSetValue) {
}

func (evictableRangeSetFunctions) Merge(_ EvictableRange, _ evictableRangeSetValue, _ EvictableRange, _ evictableRangeSetValue) (evictableRangeSetValue, bool) {
	return evictableRangeSetValue{}, true
}

func (evictableRangeSetFunctions) Split(_ EvictableRange, _ evictableRangeSetValue, _ uint64) (evictableRangeSetValue, evictableRangeSetValue) {
	return evictableRangeSetValue{}, evictableRangeSetValue{}
}

// reclaimSetValue is the value type of reclaimSet.
type reclaimSetValue struct{}

type reclaimSetFunctions struct{}

func (reclaimSetFunctions) MinKey() uint64 {
	return 0
}

func (reclaimSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (reclaimSetFunctions) ClearValue(val *reclaimSetValue) {
}

func (reclaimSetFunctions) Merge(_ memmap.FileRange, _ reclaimSetValue, _ memmap.FileRange, _ reclaimSetValue) (reclaimSetValue, bool) {
	return reclaimSetValue{}, true
}

func (reclaimSetFunctions) Split(_ memmap.FileRange, _ reclaimSetValue, _ uint64) (reclaimSetValue, reclaimSetValue) {
	return reclaimSetValue{}, reclaimSetValue{}
}
