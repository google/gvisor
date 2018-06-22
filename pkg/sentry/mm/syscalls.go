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

package mm

import (
	"fmt"
	mrand "math/rand"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// HandleUserFault handles an application page fault. sp is the faulting
// application thread's stack pointer.
//
// Preconditions: mm.as != nil.
func (mm *MemoryManager) HandleUserFault(ctx context.Context, addr usermem.Addr, at usermem.AccessType, sp usermem.Addr) error {
	ar, ok := addr.RoundDown().ToRange(usermem.PageSize)
	if !ok {
		return syserror.EFAULT
	}

	// Don't bother trying existingPMAsLocked; in most cases, if we did have
	// existing pmas, we wouldn't have faulted.

	// Ensure that we have a usable vma. Here and below, since we are only
	// asking for a single page, there is no possibility of partial success,
	// and any error is immediately fatal.
	mm.mappingMu.RLock()
	vseg, _, err := mm.getVMAsLocked(ctx, ar, at, false)
	if err != nil {
		mm.mappingMu.RUnlock()
		return err
	}

	// Ensure that we have a usable pma.
	mm.activeMu.Lock()
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, pmaOpts{
		breakCOW: at.Write,
	})
	mm.mappingMu.RUnlock()
	if err != nil {
		mm.activeMu.Unlock()
		return err
	}

	// Downgrade to a read-lock on activeMu since we don't need to mutate pmas
	// anymore.
	mm.activeMu.DowngradeLock()

	// Map the faulted page into the active AddressSpace.
	err = mm.mapASLocked(pseg, ar, false)
	mm.activeMu.RUnlock()
	return err
}

// MMap establishes a memory mapping.
func (mm *MemoryManager) MMap(ctx context.Context, opts memmap.MMapOpts) (usermem.Addr, error) {
	if opts.Length == 0 {
		return 0, syserror.EINVAL
	}
	length, ok := usermem.Addr(opts.Length).RoundUp()
	if !ok {
		return 0, syserror.ENOMEM
	}
	opts.Length = uint64(length)

	if opts.Mappable != nil {
		// Offset must be aligned.
		if usermem.Addr(opts.Offset).RoundDown() != usermem.Addr(opts.Offset) {
			return 0, syserror.EINVAL
		}
		// Offset + length must not overflow.
		if end := opts.Offset + opts.Length; end < opts.Offset {
			return 0, syserror.ENOMEM
		}
	} else {
		opts.Offset = 0
		if !opts.Private {
			if opts.MappingIdentity != nil {
				return 0, syserror.EINVAL
			}
			m, err := NewSharedAnonMappable(opts.Length, platform.FromContext(ctx))
			if err != nil {
				return 0, err
			}
			opts.MappingIdentity = m
			opts.Mappable = m
		}
	}

	if opts.Addr.RoundDown() != opts.Addr {
		// MAP_FIXED requires addr to be page-aligned; non-fixed mappings
		// don't.
		if opts.Fixed {
			return 0, syserror.EINVAL
		}
		opts.Addr = opts.Addr.RoundDown()
	}

	if !opts.MaxPerms.SupersetOf(opts.Perms) {
		return 0, syserror.EACCES
	}
	if opts.Unmap && !opts.Fixed {
		return 0, syserror.EINVAL
	}
	if opts.GrowsDown && opts.Mappable != nil {
		return 0, syserror.EINVAL
	}

	// Get the new vma.
	mm.mappingMu.Lock()
	vseg, ar, err := mm.createVMALocked(ctx, opts)
	if err != nil {
		mm.mappingMu.Unlock()
		return 0, err
	}

	switch {
	case opts.Precommit:
		// Get pmas and map with precommit as requested.
		mm.populateAndUnlock(ctx, vseg, ar, true)

	case opts.Mappable == nil && length <= privateAllocUnit:
		// NOTE: Get pmas and map eagerly in the hope
		// that doing so will save on future page faults. We only do this for
		// anonymous mappings, since otherwise the cost of
		// memmap.Mappable.Translate is unknown; and only for small mappings,
		// to avoid needing to allocate large amounts of memory that we may
		// subsequently need to checkpoint.
		mm.populateAndUnlock(ctx, vseg, ar, false)

	default:
		mm.mappingMu.Unlock()
	}

	return ar.Start, nil
}

// Preconditions: mm.mappingMu must be locked for writing.
//
// Postconditions: mm.mappingMu will be unlocked.
func (mm *MemoryManager) populateAndUnlock(ctx context.Context, vseg vmaIterator, ar usermem.AddrRange, precommit bool) {
	if !vseg.ValuePtr().effectivePerms.Any() {
		// Linux doesn't populate inaccessible pages. See
		// mm/gup.c:populate_vma_page_range.
		mm.mappingMu.Unlock()
		return
	}

	mm.activeMu.Lock()

	// Even if we get a new pma, we can't actually map it if we don't have an
	// AddressSpace.
	if mm.as == nil {
		mm.activeMu.Unlock()
		mm.mappingMu.Unlock()
		return
	}

	// Ensure that we have usable pmas.
	mm.mappingMu.DowngradeLock()
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, pmaOpts{})
	mm.mappingMu.RUnlock()
	if err != nil {
		// mm/util.c:vm_mmap_pgoff() ignores the error, if any, from
		// mm/gup.c:mm_populate(). If it matters, we'll get it again when
		// userspace actually tries to use the failing page.
		mm.activeMu.Unlock()
		return
	}

	// Downgrade to a read-lock on activeMu since we don't need to mutate pmas
	// anymore.
	mm.activeMu.DowngradeLock()

	// As above, errors are silently ignored.
	mm.mapASLocked(pseg, ar, precommit)
	mm.activeMu.RUnlock()
}

// MapStack allocates the initial process stack.
func (mm *MemoryManager) MapStack(ctx context.Context) (usermem.AddrRange, error) {
	// maxStackSize is the maximum supported process stack size in bytes.
	//
	// This limit exists because stack growing isn't implemented, so the entire
	// process stack must be mapped up-front.
	const maxStackSize = 128 << 20

	stackSize := limits.FromContext(ctx).Get(limits.Stack)
	r, ok := usermem.Addr(stackSize.Cur).RoundUp()
	sz := uint64(r)
	if !ok {
		// RLIM_INFINITY rounds up to 0.
		sz = linux.DefaultStackSoftLimit
	} else if sz > maxStackSize {
		ctx.Warningf("Capping stack size from RLIMIT_STACK of %v down to %v.", sz, maxStackSize)
		sz = maxStackSize
	} else if sz == 0 {
		return usermem.AddrRange{}, syserror.ENOMEM
	}
	szaddr := usermem.Addr(sz)
	ctx.Debugf("Allocating stack with size of %v bytes", sz)

	// Determine the stack's desired location. Unlike Linux, address
	// randomization can't be disabled.
	stackEnd := mm.layout.MaxAddr - usermem.Addr(mrand.Int63n(int64(mm.layout.MaxStackRand))).RoundDown()
	if stackEnd < szaddr {
		return usermem.AddrRange{}, syserror.ENOMEM
	}
	stackStart := stackEnd - szaddr
	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	_, ar, err := mm.createVMALocked(ctx, memmap.MMapOpts{
		Length:    sz,
		Addr:      stackStart,
		Perms:     usermem.ReadWrite,
		MaxPerms:  usermem.AnyAccess,
		Private:   true,
		GrowsDown: true,
		Hint:      "[stack]",
	})
	return ar, err
}

// MUnmap implements the semantics of Linux's munmap(2).
func (mm *MemoryManager) MUnmap(ctx context.Context, addr usermem.Addr, length uint64) error {
	if addr != addr.RoundDown() {
		return syserror.EINVAL
	}
	if length == 0 {
		return syserror.EINVAL
	}
	la, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return syserror.EINVAL
	}
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return syserror.EINVAL
	}

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	mm.unmapLocked(ctx, ar)
	return nil
}

// MRemapOpts specifies options to MRemap.
type MRemapOpts struct {
	// Move controls whether MRemap moves the remapped mapping to a new address.
	Move MRemapMoveMode

	// NewAddr is the new address for the remapping. NewAddr is ignored unless
	// Move is MMRemapMustMove.
	NewAddr usermem.Addr
}

// MRemapMoveMode controls MRemap's moving behavior.
type MRemapMoveMode int

const (
	// MRemapNoMove prevents MRemap from moving the remapped mapping.
	MRemapNoMove MRemapMoveMode = iota

	// MRemapMayMove allows MRemap to move the remapped mapping.
	MRemapMayMove

	// MRemapMustMove requires MRemap to move the remapped mapping to
	// MRemapOpts.NewAddr, replacing any existing mappings in the remapped
	// range.
	MRemapMustMove
)

// MRemap implements the semantics of Linux's mremap(2).
func (mm *MemoryManager) MRemap(ctx context.Context, oldAddr usermem.Addr, oldSize uint64, newSize uint64, opts MRemapOpts) (usermem.Addr, error) {
	// "Note that old_address has to be page aligned." - mremap(2)
	if oldAddr.RoundDown() != oldAddr {
		return 0, syserror.EINVAL
	}

	// Linux treats an old_size that rounds up to 0 as 0, which is otherwise a
	// valid size. However, new_size can't be 0 after rounding.
	oldSizeAddr, _ := usermem.Addr(oldSize).RoundUp()
	oldSize = uint64(oldSizeAddr)
	newSizeAddr, ok := usermem.Addr(newSize).RoundUp()
	if !ok || newSizeAddr == 0 {
		return 0, syserror.EINVAL
	}
	newSize = uint64(newSizeAddr)

	oldEnd, ok := oldAddr.AddLength(oldSize)
	if !ok {
		return 0, syserror.EINVAL
	}

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()

	// All cases require that a vma exists at oldAddr.
	vseg := mm.vmas.FindSegment(oldAddr)
	if !vseg.Ok() {
		return 0, syserror.EFAULT
	}

	// Behavior matrix:
	//
	// Move     | oldSize = 0 | oldSize < newSize | oldSize = newSize | oldSize > newSize
	// ---------+-------------+-------------------+-------------------+------------------
	//   NoMove | ENOMEM [1]  | Grow in-place     | No-op             | Shrink in-place
	//  MayMove | Copy [1]    | Grow in-place or  | No-op             | Shrink in-place
	//          |             |   move            |                   |
	// MustMove | Copy        | Move and grow     | Move              | Shrink and move
	//
	// [1] In-place growth is impossible because the vma at oldAddr already
	// occupies at least part of the destination. Thus the NoMove case always
	// fails and the MayMove case always falls back to copying.

	if opts.Move != MRemapMustMove {
		// Handle no-ops and in-place shrinking. These cases don't care if
		// [oldAddr, oldEnd) maps to a single vma, or is even mapped at all
		// (aside from oldAddr).
		if newSize <= oldSize {
			if newSize < oldSize {
				// If oldAddr+oldSize didn't overflow, oldAddr+newSize can't
				// either.
				newEnd := oldAddr + usermem.Addr(newSize)
				mm.unmapLocked(ctx, usermem.AddrRange{newEnd, oldEnd})
			}
			return oldAddr, nil
		}

		// Handle in-place growing.

		// Check that oldEnd maps to the same vma as oldAddr.
		if vseg.End() < oldEnd {
			return 0, syserror.EFAULT
		}
		// "Grow" the existing vma by creating a new mergeable one.
		vma := vseg.ValuePtr()
		var newOffset uint64
		if vma.mappable != nil {
			newOffset = vseg.mappableRange().End
		}
		_, _, err := mm.createVMALocked(ctx, memmap.MMapOpts{
			Length:          newSize - oldSize,
			MappingIdentity: vma.id,
			Mappable:        vma.mappable,
			Offset:          newOffset,
			Addr:            oldEnd,
			Fixed:           true,
			Perms:           vma.realPerms,
			MaxPerms:        vma.maxPerms,
			Private:         vma.private,
			GrowsDown:       vma.growsDown,
			Hint:            vma.hint,
		})
		if err == nil {
			return oldAddr, nil
		}
		// In-place growth failed. In the MRemapMayMove case, fall through to
		// copying/moving below.
		if opts.Move == MRemapNoMove {
			return 0, err
		}
	}

	// Find a location for the new mapping.
	var newAR usermem.AddrRange
	switch opts.Move {
	case MRemapMayMove:
		newAddr, err := mm.findAvailableLocked(newSize, findAvailableOpts{})
		if err != nil {
			return 0, err
		}
		newAR, _ = newAddr.ToRange(newSize)

	case MRemapMustMove:
		newAddr := opts.NewAddr
		if newAddr.RoundDown() != newAddr {
			return 0, syserror.EINVAL
		}
		var ok bool
		newAR, ok = newAddr.ToRange(newSize)
		if !ok {
			return 0, syserror.EINVAL
		}
		if (usermem.AddrRange{oldAddr, oldEnd}).Overlaps(newAR) {
			return 0, syserror.EINVAL
		}

		// Unmap any mappings at the destination.
		mm.unmapLocked(ctx, newAR)

		// If the sizes specify shrinking, unmap everything between the new and
		// old sizes at the source. Unmapping before the following checks is
		// correct: compare Linux's mm/mremap.c:mremap_to() => do_munmap(),
		// vma_to_resize().
		if newSize < oldSize {
			oldNewEnd := oldAddr + usermem.Addr(newSize)
			mm.unmapLocked(ctx, usermem.AddrRange{oldNewEnd, oldEnd})
			oldEnd = oldNewEnd
		}

		// unmapLocked may have invalidated vseg; look it up again.
		vseg = mm.vmas.FindSegment(oldAddr)
	}

	oldAR := usermem.AddrRange{oldAddr, oldEnd}

	// Check that oldEnd maps to the same vma as oldAddr.
	if vseg.End() < oldEnd {
		return 0, syserror.EFAULT
	}

	// Check against RLIMIT_AS.
	newUsageAS := mm.usageAS - uint64(oldAR.Length()) + uint64(newAR.Length())
	if limitAS := limits.FromContext(ctx).Get(limits.AS).Cur; newUsageAS > limitAS {
		return 0, syserror.ENOMEM
	}

	if vma := vseg.ValuePtr(); vma.mappable != nil {
		// Check that offset+length does not overflow.
		if vma.off+uint64(newAR.Length()) < vma.off {
			return 0, syserror.EINVAL
		}
		// Inform the Mappable, if any, of the new mapping.
		if err := vma.mappable.CopyMapping(ctx, mm, oldAR, newAR, vseg.mappableOffsetAt(oldAR.Start)); err != nil {
			return 0, err
		}
	}

	if oldSize == 0 {
		// Handle copying.
		//
		// We can't use createVMALocked because it calls Mappable.AddMapping,
		// whereas we've already called Mappable.CopyMapping (which is
		// consistent with Linux). Call vseg.Value() (rather than
		// vseg.ValuePtr()) to make a copy of the vma.
		vma := vseg.Value()
		if vma.mappable != nil {
			vma.off = vseg.mappableOffsetAt(oldAR.Start)
		}
		if vma.id != nil {
			vma.id.IncRef()
		}
		mm.vmas.Add(newAR, vma)
		return newAR.Start, nil
	}

	// Handle moving.
	//
	// Remove the existing vma before inserting the new one to minimize
	// iterator invalidation. We do this directly (instead of calling
	// removeVMAsLocked) because:
	//
	// 1. We can't drop the reference on vma.id, which will be transferred to
	// the new vma.
	//
	// 2. We can't call vma.mappable.RemoveMapping, because pmas are still at
	// oldAR, so calling RemoveMapping could cause us to miss an invalidation
	// overlapping oldAR.
	//
	// Call vseg.Value() (rather than vseg.ValuePtr()) first to make a copy of
	// the vma.
	vseg = mm.vmas.Isolate(vseg, oldAR)
	vma := vseg.Value()
	mm.vmas.Remove(vseg)

	// Insert the new vma, transferring the reference on vma.id.
	mm.vmas.Add(newAR, vma)

	// Move pmas. This is technically optional for non-private pmas, which
	// could just go through memmap.Mappable.Translate again, but it's required
	// for private pmas.
	mm.activeMu.Lock()
	mm.movePMAsLocked(oldAR, newAR)
	mm.activeMu.Unlock()

	// Now that pmas have been moved to newAR, we can notify vma.mappable that
	// oldAR is no longer mapped.
	if vma.mappable != nil {
		vma.mappable.RemoveMapping(ctx, mm, oldAR, vma.off)
	}

	return newAR.Start, nil
}

// MProtect implements the semantics of Linux's mprotect(2).
func (mm *MemoryManager) MProtect(addr usermem.Addr, length uint64, realPerms usermem.AccessType, growsDown bool) error {
	if addr.RoundDown() != addr {
		return syserror.EINVAL
	}
	if length == 0 {
		return nil
	}
	rlength, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return syserror.ENOMEM
	}
	ar, ok := addr.ToRange(uint64(rlength))
	if !ok {
		return syserror.ENOMEM
	}
	effectivePerms := realPerms.Effective()

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	// Non-growsDown mprotect requires that all of ar is mapped, and stops at
	// the first non-empty gap. growsDown mprotect requires that the first vma
	// be growsDown, but does not require it to extend all the way to ar.Start;
	// vmas after the first must be contiguous but need not be growsDown, like
	// the non-growsDown case.
	vseg := mm.vmas.LowerBoundSegment(ar.Start)
	if !vseg.Ok() {
		return syserror.ENOMEM
	}
	if growsDown {
		if !vseg.ValuePtr().growsDown {
			return syserror.EINVAL
		}
		if ar.End <= vseg.Start() {
			return syserror.ENOMEM
		}
		ar.Start = vseg.Start()
	} else {
		if ar.Start < vseg.Start() {
			return syserror.ENOMEM
		}
	}

	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()
	defer func() {
		mm.vmas.MergeRange(ar)
		mm.vmas.MergeAdjacent(ar)
		mm.pmas.MergeRange(ar)
		mm.pmas.MergeAdjacent(ar)
	}()
	pseg := mm.pmas.LowerBoundSegment(ar.Start)
	var didUnmapAS bool
	for {
		// Check for permission validity before splitting vmas, for consistency
		// with Linux.
		if !vseg.ValuePtr().maxPerms.SupersetOf(effectivePerms) {
			return syserror.EACCES
		}
		vseg = mm.vmas.Isolate(vseg, ar)

		// Update vma permissions.
		vma := vseg.ValuePtr()
		vma.realPerms = realPerms
		vma.effectivePerms = effectivePerms

		// Propagate vma permission changes to pmas.
		for pseg.Ok() && pseg.Start() < vseg.End() {
			if pseg.Range().Overlaps(vseg.Range()) {
				pseg = mm.pmas.Isolate(pseg, vseg.Range())
				if !effectivePerms.SupersetOf(pseg.ValuePtr().vmaEffectivePerms) && !didUnmapAS {
					// Unmap all of ar, not just vseg.Range(), to minimize host
					// syscalls.
					mm.unmapASLocked(ar)
					didUnmapAS = true
				}
				pseg.ValuePtr().vmaEffectivePerms = effectivePerms
			}
			pseg = pseg.NextSegment()
		}

		// Continue to the next vma.
		if ar.End <= vseg.End() {
			return nil
		}
		vseg, _ = vseg.NextNonEmpty()
		if !vseg.Ok() {
			return syserror.ENOMEM
		}
	}
}

// BrkSetup sets mm's brk address to addr and its brk size to 0.
func (mm *MemoryManager) BrkSetup(ctx context.Context, addr usermem.Addr) {
	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	// Unmap the existing brk.
	if mm.brk.Length() != 0 {
		mm.unmapLocked(ctx, mm.brk)
	}
	mm.brk = usermem.AddrRange{addr, addr}
}

// Brk implements the semantics of Linux's brk(2), except that it returns an
// error on failure.
func (mm *MemoryManager) Brk(ctx context.Context, addr usermem.Addr) (usermem.Addr, error) {
	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()

	if addr < mm.brk.Start {
		return mm.brk.End, syserror.EINVAL
	}

	// TODO: This enforces RLIMIT_DATA, but is slightly more
	// permissive than the usual data limit. In particular, this only
	// limits the size of the heap; a true RLIMIT_DATA limits the size of
	// heap + data + bss. The segment sizes need to be plumbed from the
	// loader package to fully enforce RLIMIT_DATA.
	if uint64(addr-mm.brk.Start) > limits.FromContext(ctx).Get(limits.Data).Cur {
		return mm.brk.End, syserror.ENOMEM
	}

	oldbrkpg, _ := mm.brk.End.RoundUp()
	newbrkpg, ok := addr.RoundUp()
	if !ok {
		return mm.brk.End, syserror.EFAULT
	}

	switch {
	case newbrkpg < oldbrkpg:
		mm.unmapLocked(ctx, usermem.AddrRange{newbrkpg, oldbrkpg})

	case oldbrkpg < newbrkpg:
		_, _, err := mm.createVMALocked(ctx, memmap.MMapOpts{
			Length: uint64(newbrkpg - oldbrkpg),
			Addr:   oldbrkpg,
			Fixed:  true,
			// Compare Linux's
			// arch/x86/include/asm/page_types.h:VM_DATA_DEFAULT_FLAGS.
			Perms:    usermem.ReadWrite,
			MaxPerms: usermem.AnyAccess,
			Private:  true,
			Hint:     "[heap]",
		})
		if err != nil {
			return mm.brk.End, err
		}
	}

	mm.brk.End = addr
	return addr, nil
}

// Decommit implements the semantics of Linux's madvise(MADV_DONTNEED).
func (mm *MemoryManager) Decommit(addr usermem.Addr, length uint64) error {
	ar, ok := addr.ToRange(length)
	if !ok {
		return syserror.EINVAL
	}

	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()

	// Linux's mm/madvise.c:madvise_dontneed() => mm/memory.c:zap_page_range()
	// is analogous to our mm.invalidateLocked(ar, true, true). We inline this
	// here, with the special case that we synchronously decommit
	// uniquely-owned (non-copy-on-write) pages for private anonymous vma,
	// which is the common case for MADV_DONTNEED. Invalidating these pmas, and
	// allowing them to be reallocated when touched again, increases pma
	// fragmentation, which may significantly reduce performance for
	// non-vectored I/O implementations. Also, decommitting synchronously
	// ensures that Decommit immediately reduces host memory usage.
	var didUnmapAS bool
	pseg := mm.pmas.LowerBoundSegment(ar.Start)
	vseg := mm.vmas.LowerBoundSegment(ar.Start)
	mem := mm.p.Memory()
	for pseg.Ok() && pseg.Start() < ar.End {
		pma := pseg.ValuePtr()
		if pma.private && !mm.isPMACopyOnWriteLocked(pseg) {
			psegAR := pseg.Range().Intersect(ar)
			vseg = vseg.seekNextLowerBound(psegAR.Start)
			if checkInvariants {
				if !vseg.Ok() {
					panic(fmt.Sprintf("no vma after %#x", psegAR.Start))
				}
				if psegAR.Start < vseg.Start() {
					panic(fmt.Sprintf("no vma in [%#x, %#x)", psegAR.Start, vseg.Start()))
				}
			}
			if vseg.Range().IsSupersetOf(psegAR) && vseg.ValuePtr().mappable == nil {
				if err := mem.Decommit(pseg.fileRangeOf(psegAR)); err == nil {
					pseg = pseg.NextSegment()
					continue
				}
				// If an error occurs, fall through to the general
				// invalidation case below.
			}
		}
		pseg = mm.pmas.Isolate(pseg, ar)
		pma = pseg.ValuePtr()
		if !didUnmapAS {
			// Unmap all of ar, not just pseg.Range(), to minimize host
			// syscalls. AddressSpace mappings must be removed before
			// mm.decPrivateRef().
			mm.unmapASLocked(ar)
			didUnmapAS = true
		}
		if pma.private {
			mm.decPrivateRef(pseg.fileRange())
		}
		pma.file.DecRef(pseg.fileRange())
		mm.removeRSSLocked(pseg.Range())

		pseg = mm.pmas.Remove(pseg).NextSegment()
	}

	// "If there are some parts of the specified address space that are not
	// mapped, the Linux version of madvise() ignores them and applies the call
	// to the rest (but returns ENOMEM from the system call, as it should)." -
	// madvise(2)
	if mm.vmas.SpanRange(ar) != ar.Length() {
		return syserror.ENOMEM
	}
	return nil
}

// Sync implements the semantics of Linux's msync(MS_SYNC).
func (mm *MemoryManager) Sync(ctx context.Context, addr usermem.Addr, length uint64) error {
	ar, ok := addr.ToRange(length)
	if !ok {
		return syserror.ENOMEM
	}

	mm.mappingMu.RLock()
	// Can't defer mm.mappingMu.RUnlock(); see below.
	vseg := mm.vmas.LowerBoundSegment(ar.Start)
	if !vseg.Ok() {
		mm.mappingMu.RUnlock()
		return syserror.ENOMEM
	}
	var unmapped bool
	lastEnd := ar.Start
	for {
		if !vseg.Ok() {
			mm.mappingMu.RUnlock()
			unmapped = true
			break
		}
		if lastEnd < vseg.Start() {
			unmapped = true
		}
		lastEnd = vseg.End()
		vma := vseg.ValuePtr()
		// It's only possible to have dirtied the Mappable through a shared
		// mapping. Don't check if the mapping is writable, because mprotect
		// may have changed this, and also because Linux doesn't.
		if id := vma.id; id != nil && vma.mappable != nil && !vma.private {
			// We can't call memmap.MappingIdentity.Msync while holding
			// mm.mappingMu since it may take fs locks that precede it in the
			// lock order.
			id.IncRef()
			mr := vseg.mappableRangeOf(vseg.Range().Intersect(ar))
			mm.mappingMu.RUnlock()
			err := id.Msync(ctx, mr)
			id.DecRef()
			if err != nil {
				return err
			}
			if lastEnd >= ar.End {
				break
			}
			mm.mappingMu.RLock()
			vseg = mm.vmas.LowerBoundSegment(lastEnd)
		} else {
			if lastEnd >= ar.End {
				mm.mappingMu.RUnlock()
				break
			}
			vseg = vseg.NextSegment()
		}
	}

	if unmapped {
		return syserror.ENOMEM
	}
	return nil
}

// VirtualMemorySize returns the combined length in bytes of all mappings in
// mm.
func (mm *MemoryManager) VirtualMemorySize() uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return uint64(mm.usageAS)
}

// VirtualMemorySizeRange returns the combined length in bytes of all mappings
// in ar in mm.
func (mm *MemoryManager) VirtualMemorySizeRange(ar usermem.AddrRange) uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return uint64(mm.vmas.SpanRange(ar))
}

// ResidentSetSize returns the value advertised as mm's RSS in bytes.
func (mm *MemoryManager) ResidentSetSize() uint64 {
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	return uint64(mm.curRSS)
}

// MaxResidentSetSize returns the value advertised as mm's max RSS in bytes.
func (mm *MemoryManager) MaxResidentSetSize() uint64 {
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	return uint64(mm.maxRSS)
}
