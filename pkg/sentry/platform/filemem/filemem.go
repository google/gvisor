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

// Package filemem provides a reusable implementation of platform.Memory.
//
// It enables memory to be sourced from a memfd file.
//
// Lock order:
//
// filemem.FileMem.mu
//   filemem.FileMem.mappingsMu
package filemem

import (
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// FileMem is a platform.Memory that allocates from a host file that it owns.
type FileMem struct {
	// Filemem models the backing file as follows:
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
	// fallocate(FALLOC_FL_PUNCH_HOLE) (FileMem.Decommit) causes committed
	// pages to be uncommitted. This is the only event that can cause a
	// committed page to be uncommitted.
	//
	// Filemem's accounting is based on identifying the set of committed pages.
	// Since filemem does not have direct access to the MMU, tracking reads and
	// writes to uncommitted pages to detect commitment would introduce
	// additional page faults, which would be prohibitively expensive. Instead,
	// filemem queries the host kernel to determine which pages are committed.

	// file is the backing memory file. The file pointer is immutable.
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

	// destroyed is set by Destroy to instruct the reclaimer goroutine to
	// release resources and exit. destroyed is protected by mu.
	destroyed bool

	// reclaimable is true if usage may contain reclaimable pages. reclaimable
	// is protected by mu.
	reclaimable bool

	// reclaimCond is signaled (with mu locked) when reclaimable or destroyed
	// transitions from false to true.
	reclaimCond sync.Cond

	// Filemem pages are mapped into the local address space on the granularity
	// of large pieces called chunks. mappings is a []uintptr that stores, for
	// each chunk, the start address of a mapping of that chunk in the current
	// process' address space, or 0 if no such mapping exists. Once a chunk is
	// mapped, it is never remapped or unmapped until the filemem is destroyed.
	//
	// Mutating the mappings slice or its contents requires both holding
	// mappingsMu and using atomic memory operations. (The slice is mutated
	// whenever the file is expanded. Per the above, the only permitted
	// mutation of the slice's contents is the assignment of a mapping to a
	// chunk that was previously unmapped.) Reading the slice or its contents
	// only requires *either* holding mappingsMu or using atomic memory
	// operations. This allows FileMem.AccessPhysical to avoid locking in the
	// common case where chunk mappings already exist.

	mappingsMu sync.Mutex
	mappings   atomic.Value
}

// usage tracks usage information.
type usageInfo struct {
	// kind is the usage kind.
	kind usage.MemoryKind

	// knownCommitted indicates whether this region is known to be
	// committed. If this is false, then the region may or may not have
	// been touched. If it is true however, then mincore (below) has
	// indicated that the page is present at least once.
	knownCommitted bool

	refs uint64
}

func (u *usageInfo) incRef() {
	u.refs++
}

func (u *usageInfo) decRef() {
	if u.refs == 0 {
		panic("DecRef at 0 refs!")
	}
	u.refs--
}

const (
	chunkShift = 24
	chunkSize  = 1 << chunkShift // 16 MB
	chunkMask  = chunkSize - 1

	initialSize = chunkSize
)

// newFromFile creates a FileMem backed by the given file.
func newFromFile(file *os.File) (*FileMem, error) {
	if err := file.Truncate(initialSize); err != nil {
		return nil, err
	}
	f := &FileMem{
		fileSize: initialSize,
		file:     file,
	}
	f.reclaimCond.L = &f.mu
	f.mappings.Store(make([]uintptr, initialSize/chunkSize))
	go f.runReclaim() // S/R-SAFE: f.mu

	// The Linux kernel contains an optional feature called "Integrity
	// Measurement Architecture" (IMA). If IMA is enabled, it will checksum
	// binaries the first time they are mapped PROT_EXEC. This is bad news for
	// executable pages mapped from FileMem, which can grow to terabytes in
	// (sparse) size. If IMA attempts to checksum a file that large, it will
	// allocate all of the sparse pages and quickly exhaust all memory.
	//
	// Work around IMA by immediately creating a temporary PROT_EXEC mapping,
	// while FileMem is still small. IMA will ignore any future mappings.
	m, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		usermem.PageSize,
		syscall.PROT_EXEC,
		syscall.MAP_SHARED,
		f.file.Fd(),
		0)
	if errno != 0 {
		// This isn't fatal to filemem (IMA may not even be in use). Log the
		// error, but don't return it.
		log.Warningf("Failed to pre-map FileMem PROT_EXEC: %v", errno)
	} else {
		syscall.Syscall(
			syscall.SYS_MUNMAP,
			m,
			usermem.PageSize,
			0)
	}

	return f, nil
}

// New creates a FileMem backed by a memfd file.
func New(name string) (*FileMem, error) {
	fd, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		return nil, err
	}
	return newFromFile(os.NewFile(uintptr(fd), name))
}

// Destroy implements platform.Memory.Destroy.
func (f *FileMem) Destroy() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = true
	f.reclaimCond.Signal()
}

// Allocate implements platform.Memory.Allocate.
func (f *FileMem) Allocate(length uint64, kind usage.MemoryKind) (platform.FileRange, error) {
	if length == 0 || length%usermem.PageSize != 0 {
		panic(fmt.Sprintf("invalid allocation length: %#x", length))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Align hugepage-and-larger allocations on hugepage boundaries to try
	// to take advantage of hugetmpfs.
	alignment := uint64(usermem.PageSize)
	if length >= usermem.HugePageSize {
		alignment = usermem.HugePageSize
	}

	start := findUnallocatedRange(&f.usage, length, alignment)
	end := start + length
	// File offsets are int64s. Since length must be strictly positive, end
	// cannot legitimately be 0.
	if end < start || int64(end) <= 0 {
		return platform.FileRange{}, syserror.ENOMEM
	}

	// Expand the file if needed. Double the file size on each expansion;
	// uncommitted pages have effectively no cost.
	fileSize := f.fileSize
	for int64(end) > fileSize {
		if fileSize >= 2*fileSize {
			// fileSize overflow.
			return platform.FileRange{}, syserror.ENOMEM
		}
		fileSize *= 2
	}
	if fileSize > f.fileSize {
		if err := f.file.Truncate(fileSize); err != nil {
			return platform.FileRange{}, err
		}
		f.fileSize = fileSize
		f.mappingsMu.Lock()
		oldMappings := f.mappings.Load().([]uintptr)
		newMappings := make([]uintptr, fileSize>>chunkShift)
		copy(newMappings, oldMappings)
		f.mappings.Store(newMappings)
		f.mappingsMu.Unlock()
	}

	// Mark selected pages as in use.
	fr := platform.FileRange{start, end}
	if !f.usage.Add(fr, usageInfo{
		kind: kind,
		refs: 1,
	}) {
		panic(fmt.Sprintf("allocating %v: failed to insert into f.usage:\n%v", fr, &f.usage))
	}
	return fr, nil
}

func findUnallocatedRange(usage *usageSet, length, alignment uint64) uint64 {
	alignMask := alignment - 1
	var start uint64
	for seg := usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		r := seg.Range()
		if start >= r.End {
			// start was rounded up to an alignment boundary from the end
			// of a previous segment.
			continue
		}
		// This segment represents allocated or reclaimable pages; only the
		// range from start to the segment's beginning is allocatable, and the
		// next allocatable range begins after the segment.
		if r.Start > start && r.Start-start >= length {
			break
		}
		start = (r.End + alignMask) &^ alignMask
	}
	return start
}

// fallocate(2) modes, defined in Linux's include/uapi/linux/falloc.h.
const (
	_FALLOC_FL_KEEP_SIZE  = 1
	_FALLOC_FL_PUNCH_HOLE = 2
)

// Decommit implements platform.Memory.Decommit.
func (f *FileMem) Decommit(fr platform.FileRange) error {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%usermem.PageSize != 0 || fr.End%usermem.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	// "After a successful call, subsequent reads from this range will
	// return zeroes. The FALLOC_FL_PUNCH_HOLE flag must be ORed with
	// FALLOC_FL_KEEP_SIZE in mode ..." - fallocate(2)
	err := syscall.Fallocate(
		int(f.file.Fd()),
		_FALLOC_FL_PUNCH_HOLE|_FALLOC_FL_KEEP_SIZE,
		int64(fr.Start),
		int64(fr.Length()))
	if err != nil {
		return err
	}
	f.markDecommitted(fr)
	return nil
}

func (f *FileMem) markDecommitted(fr platform.FileRange) {
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

// runReclaim implements the reclaimer goroutine, which continuously decommits
// reclaimable frames in order to reduce memory usage.
func (f *FileMem) runReclaim() {
	for {
		fr, ok := f.findReclaimable()
		if !ok {
			break
		}

		if err := f.Decommit(fr); err != nil {
			log.Warningf("Reclaim failed to decommit %v: %v", fr, err)
			// Zero the frames manually. This won't reduce memory usage, but at
			// least ensures that the frames will be zero when reallocated.
			f.forEachMappingSlice(fr, func(bs []byte) {
				for i := range bs {
					bs[i] = 0
				}
			})
			// Pretend the frames were decommitted even though they weren't,
			// since the memory accounting implementation has no idea how to
			// deal with this.
			f.markDecommitted(fr)
		}
		f.markReclaimed(fr)
	}
	// We only get here if findReclaimable finds f.destroyed set and returns
	// false.
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.destroyed {
		panic("findReclaimable broke out of reclaim loop, but f.destroyed is no longer set")
	}
	f.file.Close()
	// Ensure that any attempts to use f.file.Fd() fail instead of getting a fd
	// that has possibly been reassigned.
	f.file = nil
	mappings := f.mappings.Load().([]uintptr)
	for i, m := range mappings {
		if m != 0 {
			_, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, m, chunkSize, 0)
			if errno != 0 {
				log.Warningf("Failed to unmap mapping %#x for filemem chunk %d: %v", m, i, errno)
			}
		}
	}
	// Similarly, invalidate f.mappings. (atomic.Value.Store(nil) panics.)
	f.mappings.Store([]uintptr{})
}

func (f *FileMem) findReclaimable() (platform.FileRange, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		for {
			if f.destroyed {
				return platform.FileRange{}, false
			}
			if f.reclaimable {
				break
			}
			f.reclaimCond.Wait()
		}
		// Allocate returns the first usable range in offset order and is
		// currently a linear scan, so reclaiming from the beginning of the
		// file minimizes the expected latency of Allocate.
		for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			if seg.ValuePtr().refs == 0 {
				return seg.Range(), true
			}
		}
		f.reclaimable = false
	}
}

func (f *FileMem) markReclaimed(fr platform.FileRange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seg := f.usage.FindSegment(fr.Start)
	// All of fr should be mapped to a single uncommitted reclaimable segment
	// accounted to System.
	if !seg.Ok() {
		panic(fmt.Sprintf("Reclaimed pages %v include unreferenced pages:\n%v", fr, &f.usage))
	}
	if !seg.Range().IsSupersetOf(fr) {
		panic(fmt.Sprintf("Reclaimed pages %v are not entirely contained in segment %v with state %v:\n%v", fr, seg.Range(), seg.Value(), &f.usage))
	}
	if got, want := seg.Value(), (usageInfo{
		kind:           usage.System,
		knownCommitted: false,
		refs:           0,
	}); got != want {
		panic(fmt.Sprintf("Reclaimed pages %v in segment %v has incorrect state %v, wanted %v:\n%v", fr, seg.Range(), got, want, &f.usage))
	}
	// Deallocate reclaimed pages. Even though all of seg is reclaimable, the
	// caller of markReclaimed may not have decommitted it, so we can only mark
	// fr as reclaimed.
	f.usage.Remove(f.usage.Isolate(seg, fr))
}

// MapInto implements platform.File.MapInto.
func (f *FileMem) MapInto(as platform.AddressSpace, addr usermem.Addr, fr platform.FileRange, at usermem.AccessType, precommit bool) error {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%usermem.PageSize != 0 || fr.End%usermem.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}
	return as.MapFile(addr, int(f.file.Fd()), fr, at, precommit)
}

// MapInternal implements platform.File.MapInternal.
func (f *FileMem) MapInternal(fr platform.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
	if !fr.WellFormed() || fr.Length() == 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}
	if at.Execute {
		return safemem.BlockSeq{}, syserror.EACCES
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

// IncRef implements platform.File.IncRef.
func (f *FileMem) IncRef(fr platform.FileRange) {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%usermem.PageSize != 0 || fr.End%usermem.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	gap := f.usage.ApplyContiguous(fr, func(seg usageIterator) {
		seg.ValuePtr().incRef()
	})
	if gap.Ok() {
		panic(fmt.Sprintf("IncRef(%v): attempted to IncRef on unallocated pages %v:\n%v", fr, gap.Range(), &f.usage))
	}
}

// DecRef implements platform.File.DecRef.
func (f *FileMem) DecRef(fr platform.FileRange) {
	if !fr.WellFormed() || fr.Length() == 0 || fr.Start%usermem.PageSize != 0 || fr.End%usermem.PageSize != 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}

	var freed bool

	f.mu.Lock()
	defer f.mu.Unlock()

	for seg := f.usage.FindSegment(fr.Start); seg.Ok() && seg.Start() < fr.End; seg = seg.NextSegment() {
		seg = f.usage.Isolate(seg, fr)
		val := seg.ValuePtr()
		val.decRef()
		if val.refs == 0 {
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

// Flush implements platform.Mappable.Flush.
func (f *FileMem) Flush(ctx context.Context) error {
	return nil
}

// forEachMappingSlice invokes fn on a sequence of byte slices that
// collectively map all bytes in fr.
func (f *FileMem) forEachMappingSlice(fr platform.FileRange, fn func([]byte)) error {
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

func (f *FileMem) getChunkMapping(chunk int) ([]uintptr, uintptr, error) {
	f.mappingsMu.Lock()
	defer f.mappingsMu.Unlock()
	// Another thread may have replaced f.mappings altogether due to file
	// expansion.
	mappings := f.mappings.Load().([]uintptr)
	// Another thread may have already mapped the chunk.
	if m := mappings[chunk]; m != 0 {
		return mappings, m, nil
	}
	m, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		chunkSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
		f.file.Fd(),
		uintptr(chunk<<chunkShift))
	if errno != 0 {
		return nil, 0, errno
	}
	atomic.StoreUintptr(&mappings[chunk], m)
	return mappings, m, nil
}

// UpdateUsage implements platform.Memory.UpdateUsage.
func (f *FileMem) UpdateUsage() error {
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
// Precondition: f.mu must be held.
func (f *FileMem) updateUsageLocked(currentUsage uint64, checkCommitted func(bs []byte, committed []byte) error) error {
	// Track if anything changed to elide the merge. In the common case, we
	// expect all segments to be committed and no merge to occur.
	changedAny := false
	defer func() {
		if changedAny {
			f.usage.MergeAll()
		}

		// Adjust the swap usage to reflect reality.
		if f.usageExpected < currentUsage {
			// Since no pages may be decommitted while we hold usageMu, we
			// know that usage may have only increased since we got the
			// last current usage. Therefore, if usageExpected is still
			// short of currentUsage, we must assume that the difference is
			// in pages that have been swapped.
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
			// being committed while the above loop was running. Just
			// report the higher number that we found and ignore swap.
			usage.MemoryAccounting.Dec(f.usageSwapped, usage.System)
			f.usageSwapped = 0
		}
	}()

	// Reused mincore buffer, will generally be <= 4096 bytes.
	var buf []byte

	// Iterate over all usage data. There will only be usage segments
	// present when there is an associated reference.
	for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		val := seg.Value()

		// Already known to be committed; ignore.
		if val.knownCommitted {
			continue
		}

		// Assume that reclaimable pages (that aren't already known to be
		// committed) are not committed. This isn't necessarily true, even
		// after the reclaimer does Decommit(), because the kernel may
		// subsequently back the hugepage-sized region containing the
		// decommitted page with a hugepage. However, it's consistent with our
		// treatment of unallocated pages, which have the same property.
		if val.refs == 0 {
			continue
		}

		// Get the range for this segment. As we touch slices, the
		// Start value will be walked along.
		r := seg.Range()

		var checkErr error
		err := f.forEachMappingSlice(r, func(s []byte) {
			if checkErr != nil {
				return
			}

			// Ensure that we have sufficient buffer for the call
			// (one byte per page). The length of each slice must
			// be page-aligned.
			bufLen := len(s) / usermem.PageSize
			if len(buf) < bufLen {
				buf = make([]byte, bufLen)
			}

			// Query for new pages in core.
			if err := checkCommitted(s, buf); err != nil {
				checkErr = err
				return
			}

			// Scan each page and switch out segments.
			populatedRun := false
			populatedRunStart := 0
			for i := 0; i <= bufLen; i++ {
				// We run past the end of the slice here to
				// simplify the logic and only set populated if
				// we're still looking at elements.
				populated := false
				if i < bufLen {
					populated = buf[i]&0x1 != 0
				}

				switch {
				case populated == populatedRun:
					// Keep the run going.
					continue
				case populated && !populatedRun:
					// Begin the run.
					populatedRun = true
					populatedRunStart = i
					// Keep going.
					continue
				case !populated && populatedRun:
					// Finish the run by changing this segment.
					runRange := platform.FileRange{
						Start: r.Start + uint64(populatedRunStart*usermem.PageSize),
						End:   r.Start + uint64(i*usermem.PageSize),
					}
					seg = f.usage.Isolate(seg, runRange)
					seg.ValuePtr().knownCommitted = true
					// Advance the segment only if we still
					// have work to do in the context of
					// the original segment from the for
					// loop. Otherwise, the for loop itself
					// will advance the segment
					// appropriately.
					if runRange.End != r.End {
						seg = seg.NextSegment()
					}
					amount := runRange.Length()
					usage.MemoryAccounting.Inc(amount, val.kind)
					f.usageExpected += amount
					changedAny = true
					populatedRun = false
				}
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
	}

	return nil
}

// TotalUsage implements platform.Memory.TotalUsage.
func (f *FileMem) TotalUsage() (uint64, error) {
	// Stat the underlying file to discover the underlying usage. stat(2)
	// always reports the allocated block count in units of 512 bytes. This
	// includes pages in the page cache and swapped pages.
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.file.Fd()), &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Blocks * 512), nil
}

// TotalSize implements platform.Memory.TotalSize.
func (f *FileMem) TotalSize() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return uint64(f.fileSize)
}

// File returns the memory file used by f.
func (f *FileMem) File() *os.File {
	return f.file
}

// String implements fmt.Stringer.String.
//
// Note that because f.String locks f.mu, calling f.String internally
// (including indirectly through the fmt package) risks recursive locking.
// Within the filemem package, use f.usage directly instead.
func (f *FileMem) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage.String()
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

func (usageSetFunctions) Merge(_ platform.FileRange, val1 usageInfo, _ platform.FileRange, val2 usageInfo) (usageInfo, bool) {
	return val1, val1 == val2
}

func (usageSetFunctions) Split(_ platform.FileRange, val usageInfo, _ uint64) (usageInfo, usageInfo) {
	return val, val
}
