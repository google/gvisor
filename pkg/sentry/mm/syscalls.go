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

package mm

import (
	"fmt"
	mrand "math/rand"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// HandleUserFault handles an application page fault. sp is the faulting
// application thread's stack pointer.
//
// Preconditions: mm.as != nil.
func (mm *MemoryManager) HandleUserFault(ctx context.Context, addr hostarch.Addr, at hostarch.AccessType, sp hostarch.Addr) error {
	ar, ok := addr.RoundDown().ToRange(hostarch.PageSize)
	if !ok {
		return linuxerr.EFAULT
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
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, at)
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
func (mm *MemoryManager) MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error) {
	if opts.Length == 0 {
		return 0, linuxerr.EINVAL
	}
	length, ok := hostarch.Addr(opts.Length).RoundUp()
	if !ok {
		return 0, linuxerr.ENOMEM
	}
	opts.Length = uint64(length)

	if opts.Mappable != nil {
		// Offset must be aligned.
		if hostarch.Addr(opts.Offset).RoundDown() != hostarch.Addr(opts.Offset) {
			return 0, linuxerr.EINVAL
		}
		// Offset + length must not overflow.
		if end := opts.Offset + opts.Length; end < opts.Offset {
			return 0, linuxerr.EOVERFLOW
		}
	} else {
		opts.Offset = 0
	}

	if opts.Addr.RoundDown() != opts.Addr {
		// MAP_FIXED requires addr to be page-aligned; non-fixed mappings
		// don't.
		if opts.Fixed {
			return 0, linuxerr.EINVAL
		}
		opts.Addr = opts.Addr.RoundDown()
	}

	if !opts.MaxPerms.SupersetOf(opts.Perms) {
		return 0, linuxerr.EACCES
	}
	if opts.Unmap && !opts.Fixed {
		return 0, linuxerr.EINVAL
	}
	if opts.GrowsDown && opts.Mappable != nil {
		return 0, linuxerr.EINVAL
	}

	// Get the new vma.
	var droppedIDs []memmap.MappingIdentity
	mm.mappingMu.Lock()
	if opts.MLockMode < mm.defMLockMode {
		opts.MLockMode = mm.defMLockMode
	}
	vseg, ar, droppedIDs, err := mm.createVMALocked(ctx, opts, droppedIDs)
	if err != nil {
		mm.mappingMu.Unlock()
		return 0, err
	}

	// TODO(jamieliu): In Linux, VM_LOCKONFAULT (which may be set on the new
	// vma by mlockall(MCL_FUTURE|MCL_ONFAULT) => mm_struct::def_flags) appears
	// to effectively disable MAP_POPULATE by unsetting FOLL_POPULATE in
	// mm/util.c:vm_mmap_pgoff() => mm/gup.c:__mm_populate() =>
	// populate_vma_page_range(). Confirm this behavior.
	switch {
	case opts.Precommit || opts.MLockMode == memmap.MLockEager:
		// Get pmas and map with precommit as requested.
		mm.populateVMAAndUnlock(ctx, vseg, ar, true)

	case opts.Mappable == nil && length <= privateAllocUnit:
		// NOTE(b/63077076, b/63360184): Get pmas and map eagerly in the hope
		// that doing so will save on future page faults. We only do this for
		// anonymous mappings, since otherwise the cost of
		// memmap.Mappable.Translate is unknown; and only for small mappings,
		// to avoid needing to allocate large amounts of memory that we may
		// subsequently need to checkpoint.
		mm.populateVMAAndUnlock(ctx, vseg, ar, false)

	default:
		mm.mappingMu.Unlock()
	}

	for _, id := range droppedIDs {
		id.DecRef(ctx)
	}

	return ar.Start, nil
}

// populateVMA obtains pmas for addresses in ar in the given vma, and maps them
// into mm.as if it is active.
//
// Preconditions:
//   - mm.mappingMu must be locked.
//   - vseg.Range().IsSupersetOf(ar).
func (mm *MemoryManager) populateVMA(ctx context.Context, vseg vmaIterator, ar hostarch.AddrRange, precommit bool) {
	if !vseg.ValuePtr().effectivePerms.Any() {
		// Linux doesn't populate inaccessible pages. See
		// mm/gup.c:populate_vma_page_range.
		return
	}

	mm.activeMu.Lock()
	// Can't defer mm.activeMu.Unlock(); see below.

	// Even if we get new pmas, we can't actually map them if we don't have an
	// AddressSpace.
	if mm.as == nil {
		mm.activeMu.Unlock()
		return
	}

	// Ensure that we have usable pmas.
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, hostarch.NoAccess)
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

// populateVMAAndUnlock is equivalent to populateVMA, but also unconditionally
// unlocks mm.mappingMu. In cases where populateVMAAndUnlock is usable, it is
// preferable to populateVMA since it unlocks mm.mappingMu before performing
// expensive operations that don't require it to be locked.
//
// Preconditions:
//   - mm.mappingMu must be locked for writing.
//   - vseg.Range().IsSupersetOf(ar).
//
// Postconditions: mm.mappingMu will be unlocked.
// +checklocksrelease:mm.mappingMu
func (mm *MemoryManager) populateVMAAndUnlock(ctx context.Context, vseg vmaIterator, ar hostarch.AddrRange, precommit bool) {
	// See populateVMA above for commentary.
	if !vseg.ValuePtr().effectivePerms.Any() {
		mm.mappingMu.Unlock()
		return
	}

	mm.activeMu.Lock()

	if mm.as == nil {
		mm.activeMu.Unlock()
		mm.mappingMu.Unlock()
		return
	}

	// mm.mappingMu doesn't need to be write-locked for getPMAsLocked, and it
	// isn't needed at all for mapASLocked.
	mm.mappingMu.DowngradeLock()
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, hostarch.NoAccess)
	mm.mappingMu.RUnlock()
	if err != nil {
		mm.activeMu.Unlock()
		return
	}

	mm.activeMu.DowngradeLock()
	mm.mapASLocked(pseg, ar, precommit)
	mm.activeMu.RUnlock()
}

// MapStack allocates the initial process stack.
func (mm *MemoryManager) MapStack(ctx context.Context) (hostarch.AddrRange, error) {
	// maxStackSize is the maximum supported process stack size in bytes.
	//
	// This limit exists because stack growing isn't implemented, so the entire
	// process stack must be mapped up-front.
	const maxStackSize = 128 << 20

	stackSize := limits.FromContext(ctx).Get(limits.Stack)
	r, ok := hostarch.Addr(stackSize.Cur).RoundUp()
	sz := uint64(r)
	if !ok {
		// RLIM_INFINITY rounds up to 0.
		sz = linux.DefaultStackSoftLimit
	} else if sz > maxStackSize {
		ctx.Warningf("Capping stack size from RLIMIT_STACK of %v down to %v.", sz, maxStackSize)
		sz = maxStackSize
	} else if sz == 0 {
		return hostarch.AddrRange{}, linuxerr.ENOMEM
	}
	szaddr := hostarch.Addr(sz)
	ctx.Debugf("Allocating stack with size of %v bytes", sz)

	// Determine the stack's desired location. Unlike Linux, address
	// randomization can't be disabled.
	stackEnd := mm.layout.MaxAddr - hostarch.Addr(mrand.Int63n(int64(mm.layout.MaxStackRand))).RoundDown()
	if stackEnd < szaddr {
		return hostarch.AddrRange{}, linuxerr.ENOMEM
	}
	stackStart := stackEnd - szaddr
	var droppedIDs []memmap.MappingIdentity
	var ar hostarch.AddrRange
	var err error
	mm.mappingMu.Lock()
	_, ar, droppedIDs, err = mm.createVMALocked(ctx, memmap.MMapOpts{
		Length:    sz,
		Addr:      stackStart,
		Perms:     hostarch.ReadWrite,
		MaxPerms:  hostarch.AnyAccess,
		Private:   true,
		GrowsDown: true,
		MLockMode: mm.defMLockMode,
		Hint:      "[stack]",
	}, droppedIDs)
	mm.mappingMu.Unlock()
	for _, id := range droppedIDs {
		id.DecRef(ctx)
	}
	return ar, err
}

// MUnmap implements the semantics of Linux's munmap(2).
func (mm *MemoryManager) MUnmap(ctx context.Context, addr hostarch.Addr, length uint64) error {
	if addr != addr.RoundDown() {
		return linuxerr.EINVAL
	}
	if length == 0 {
		return linuxerr.EINVAL
	}
	la, ok := hostarch.Addr(length).RoundUp()
	if !ok {
		return linuxerr.EINVAL
	}
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return linuxerr.EINVAL
	}

	var droppedIDs []memmap.MappingIdentity
	mm.mappingMu.Lock()
	_, droppedIDs = mm.unmapLocked(ctx, ar, droppedIDs)
	mm.mappingMu.Unlock()

	for _, id := range droppedIDs {
		id.DecRef(ctx)
	}

	return nil
}

// MRemapOpts specifies options to MRemap.
type MRemapOpts struct {
	// Move controls whether MRemap moves the remapped mapping to a new address.
	Move MRemapMoveMode

	// NewAddr is the new address for the remapping. NewAddr is ignored unless
	// Move is MMRemapMustMove.
	NewAddr hostarch.Addr
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
func (mm *MemoryManager) MRemap(ctx context.Context, oldAddr hostarch.Addr, oldSize uint64, newSize uint64, opts MRemapOpts) (hostarch.Addr, error) {
	// "Note that old_address has to be page aligned." - mremap(2)
	if oldAddr.RoundDown() != oldAddr {
		return 0, linuxerr.EINVAL
	}

	// Linux treats an old_size that rounds up to 0 as 0, which is otherwise a
	// valid size. However, new_size can't be 0 after rounding.
	oldSizeAddr, _ := hostarch.Addr(oldSize).RoundUp()
	oldSize = uint64(oldSizeAddr)
	newSizeAddr, ok := hostarch.Addr(newSize).RoundUp()
	if !ok || newSizeAddr == 0 {
		return 0, linuxerr.EINVAL
	}
	newSize = uint64(newSizeAddr)

	oldEnd, ok := oldAddr.AddLength(oldSize)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	var droppedIDs []memmap.MappingIdentity
	// This must run after mm.mappingMu.Unlock().
	defer func() {
		for _, id := range droppedIDs {
			id.DecRef(ctx)
		}
	}()

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()

	// All cases require that a vma exists at oldAddr.
	vseg := mm.vmas.FindSegment(oldAddr)
	if !vseg.Ok() {
		return 0, linuxerr.EFAULT
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

	if vma := vseg.ValuePtr(); newSize > oldSize && vma.mlockMode != memmap.MLockNone {
		// Check against RLIMIT_MEMLOCK. Unlike mmap, mlock, and mlockall,
		// mremap in Linux does not check mm/mlock.c:can_do_mlock() and
		// therefore does not return EPERM if RLIMIT_MEMLOCK is 0 and
		// !CAP_IPC_LOCK.
		mlockLimit := limits.FromContext(ctx).Get(limits.MemoryLocked).Cur
		if creds := auth.CredentialsFromContext(ctx); !creds.HasCapabilityIn(linux.CAP_IPC_LOCK, creds.UserNamespace.Root()) {
			if newLockedAS := mm.lockedAS - oldSize + newSize; newLockedAS > mlockLimit {
				return 0, linuxerr.EAGAIN
			}
		}
	}

	if opts.Move != MRemapMustMove {
		// Handle no-ops and in-place shrinking. These cases don't care if
		// [oldAddr, oldEnd) maps to a single vma, or is even mapped at all
		// (aside from oldAddr).
		if newSize <= oldSize {
			if newSize < oldSize {
				// If oldAddr+oldSize didn't overflow, oldAddr+newSize can't
				// either.
				newEnd := oldAddr + hostarch.Addr(newSize)
				_, droppedIDs = mm.unmapLocked(ctx, hostarch.AddrRange{newEnd, oldEnd}, droppedIDs)
			}
			return oldAddr, nil
		}

		// Handle in-place growing.

		// Check that oldEnd maps to the same vma as oldAddr.
		if vseg.End() < oldEnd {
			return 0, linuxerr.EFAULT
		}
		// "Grow" the existing vma by creating a new mergeable one.
		vma := vseg.ValuePtr()
		var newOffset uint64
		if vma.mappable != nil {
			newOffset = vseg.mappableRange().End
		}
		var vseg vmaIterator
		var ar hostarch.AddrRange
		var err error
		vseg, ar, droppedIDs, err = mm.createVMALocked(ctx, memmap.MMapOpts{
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
			MLockMode:       vma.mlockMode,
			Hint:            vma.hint,
		}, droppedIDs)
		if err == nil {
			if vma.mlockMode == memmap.MLockEager {
				mm.populateVMA(ctx, vseg, ar, true)
			}
			return oldAddr, nil
		}
		// In-place growth failed. In the MRemapMayMove case, fall through to
		// copying/moving below.
		if opts.Move == MRemapNoMove {
			return 0, err
		}
	}

	// Find a location for the new mapping.
	var newAR hostarch.AddrRange
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
			return 0, linuxerr.EINVAL
		}
		var ok bool
		newAR, ok = newAddr.ToRange(newSize)
		if !ok {
			return 0, linuxerr.EINVAL
		}
		if (hostarch.AddrRange{oldAddr, oldEnd}).Overlaps(newAR) {
			return 0, linuxerr.EINVAL
		}

		// Check that the new region is valid.
		_, err := mm.findAvailableLocked(newSize, findAvailableOpts{
			Addr:  newAddr,
			Fixed: true,
			Unmap: true,
		})
		if err != nil {
			return 0, err
		}

		// Unmap any mappings at the destination.
		_, droppedIDs = mm.unmapLocked(ctx, newAR, droppedIDs)

		// If the sizes specify shrinking, unmap everything between the new and
		// old sizes at the source. Unmapping before the following checks is
		// correct: compare Linux's mm/mremap.c:mremap_to() => do_munmap(),
		// vma_to_resize().
		if newSize < oldSize {
			oldNewEnd := oldAddr + hostarch.Addr(newSize)
			_, droppedIDs = mm.unmapLocked(ctx, hostarch.AddrRange{oldNewEnd, oldEnd}, droppedIDs)
			oldEnd = oldNewEnd
		}

		// unmapLocked may have invalidated vseg; look it up again.
		vseg = mm.vmas.FindSegment(oldAddr)
	}

	oldAR := hostarch.AddrRange{oldAddr, oldEnd}

	// Check that oldEnd maps to the same vma as oldAddr.
	if vseg.End() < oldEnd {
		return 0, linuxerr.EFAULT
	}

	// Check against RLIMIT_AS.
	newUsageAS := mm.usageAS - uint64(oldAR.Length()) + uint64(newAR.Length())
	if limitAS := limits.FromContext(ctx).Get(limits.AS).Cur; newUsageAS > limitAS {
		return 0, linuxerr.ENOMEM
	}

	if vma := vseg.ValuePtr(); vma.mappable != nil {
		// Check that offset+length does not overflow.
		if vma.off+uint64(newAR.Length()) < vma.off {
			return 0, linuxerr.EINVAL
		}
		// Inform the Mappable, if any, of the new mapping.
		if err := vma.mappable.CopyMapping(ctx, mm, oldAR, newAR, vseg.mappableOffsetAt(oldAR.Start), vma.canWriteMappableLocked()); err != nil {
			return 0, err
		}
	}

	if oldSize == 0 {
		// Handle copying.
		//
		// We can't use createVMALocked because it calls Mappable.AddMapping,
		// whereas we've already called Mappable.CopyMapping (which is
		// consistent with Linux).
		vma := vseg.ValuePtr().copy()
		if vma.mappable != nil {
			vma.off = vseg.mappableOffsetAt(oldAR.Start)
		}
		if vma.id != nil {
			vma.id.IncRef()
		}
		vseg := mm.vmas.Insert(mm.vmas.FindGap(newAR.Start), newAR, vma)
		mm.usageAS += uint64(newAR.Length())
		if vma.isPrivateDataLocked() {
			mm.dataAS += uint64(newAR.Length())
		}
		if vma.mlockMode != memmap.MLockNone {
			mm.lockedAS += uint64(newAR.Length())
			if vma.mlockMode == memmap.MLockEager {
				mm.populateVMA(ctx, vseg, newAR, true)
			}
		}
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
	vseg = mm.vmas.Isolate(vseg, oldAR)
	vma := vseg.ValuePtr().copy()
	mm.vmas.Remove(vseg)
	vseg = mm.vmas.Insert(mm.vmas.FindGap(newAR.Start), newAR, vma)
	mm.usageAS = mm.usageAS - uint64(oldAR.Length()) + uint64(newAR.Length())
	if vma.isPrivateDataLocked() {
		mm.dataAS = mm.dataAS - uint64(oldAR.Length()) + uint64(newAR.Length())
	}
	if vma.mlockMode != memmap.MLockNone {
		mm.lockedAS = mm.lockedAS - uint64(oldAR.Length()) + uint64(newAR.Length())
	}

	// Move pmas. This is technically optional for non-private pmas, which
	// could just go through memmap.Mappable.Translate again, but it's required
	// for private pmas.
	mm.activeMu.Lock()
	mm.movePMAsLocked(oldAR, newAR)
	mm.activeMu.Unlock()

	// Now that pmas have been moved to newAR, we can notify vma.mappable that
	// oldAR is no longer mapped.
	if vma.mappable != nil {
		vma.mappable.RemoveMapping(ctx, mm, oldAR, vma.off, vma.canWriteMappableLocked())
	}

	if vma.mlockMode == memmap.MLockEager {
		mm.populateVMA(ctx, vseg, newAR, true)
	}

	return newAR.Start, nil
}

// MProtect implements the semantics of Linux's mprotect(2).
func (mm *MemoryManager) MProtect(addr hostarch.Addr, length uint64, realPerms hostarch.AccessType, growsDown bool) error {
	if addr.RoundDown() != addr {
		return linuxerr.EINVAL
	}
	if length == 0 {
		return nil
	}
	rlength, ok := hostarch.Addr(length).RoundUp()
	if !ok {
		return linuxerr.ENOMEM
	}
	ar, ok := addr.ToRange(uint64(rlength))
	if !ok {
		return linuxerr.ENOMEM
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
		return linuxerr.ENOMEM
	}
	if growsDown {
		if !vseg.ValuePtr().growsDown {
			return linuxerr.EINVAL
		}
		if ar.End <= vseg.Start() {
			return linuxerr.ENOMEM
		}
		ar.Start = vseg.Start()
	} else {
		if ar.Start < vseg.Start() {
			return linuxerr.ENOMEM
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
			return linuxerr.EACCES
		}
		vseg = mm.vmas.Isolate(vseg, ar)

		// Update vma permissions.
		vma := vseg.ValuePtr()
		vmaLength := vseg.Range().Length()
		if vma.isPrivateDataLocked() {
			mm.dataAS -= uint64(vmaLength)
		}

		vma.realPerms = realPerms
		vma.effectivePerms = effectivePerms
		if vma.isPrivateDataLocked() {
			mm.dataAS += uint64(vmaLength)
		}

		// Propagate vma permission changes to pmas.
		for pseg.Ok() && pseg.Start() < vseg.End() {
			if pseg.Range().Overlaps(vseg.Range()) {
				pseg = mm.pmas.Isolate(pseg, vseg.Range())
				pma := pseg.ValuePtr()
				if !effectivePerms.SupersetOf(pma.effectivePerms) && !didUnmapAS {
					// Unmap all of ar, not just vseg.Range(), to minimize host
					// syscalls.
					mm.unmapASLocked(ar)
					didUnmapAS = true
				}
				pma.effectivePerms = effectivePerms.Intersect(pma.translatePerms)
				if pma.needCOW {
					pma.effectivePerms.Write = false
				}
			}
			pseg = pseg.NextSegment()
		}

		// Continue to the next vma.
		if ar.End <= vseg.End() {
			return nil
		}
		vseg, _ = vseg.NextNonEmpty()
		if !vseg.Ok() {
			return linuxerr.ENOMEM
		}
	}
}

// BrkSetup sets mm's brk address to addr and its brk size to 0.
func (mm *MemoryManager) BrkSetup(ctx context.Context, addr hostarch.Addr) {
	var droppedIDs []memmap.MappingIdentity
	mm.mappingMu.Lock()
	// Unmap the existing brk.
	if mm.brk.Length() != 0 {
		_, droppedIDs = mm.unmapLocked(ctx, mm.brk, droppedIDs)
	}
	mm.brk = hostarch.AddrRange{addr, addr}
	mm.mappingMu.Unlock()
	for _, id := range droppedIDs {
		id.DecRef(ctx)
	}
}

// Brk implements the semantics of Linux's brk(2), except that it returns an
// error on failure.
func (mm *MemoryManager) Brk(ctx context.Context, addr hostarch.Addr) (hostarch.Addr, error) {
	mm.mappingMu.Lock()
	// Can't defer mm.mappingMu.Unlock(); see below.

	if addr < mm.brk.Start {
		addr = mm.brk.End
		mm.mappingMu.Unlock()
		return addr, linuxerr.EINVAL
	}

	// TODO(gvisor.dev/issue/156): This enforces RLIMIT_DATA, but is
	// slightly more permissive than the usual data limit. In particular,
	// this only limits the size of the heap; a true RLIMIT_DATA limits the
	// size of heap + data + bss. The segment sizes need to be plumbed from
	// the loader package to fully enforce RLIMIT_DATA.
	if uint64(addr-mm.brk.Start) > limits.FromContext(ctx).Get(limits.Data).Cur {
		addr = mm.brk.End
		mm.mappingMu.Unlock()
		return addr, linuxerr.ENOMEM
	}

	oldbrkpg, _ := mm.brk.End.RoundUp()
	newbrkpg, ok := addr.RoundUp()
	if !ok {
		addr = mm.brk.End
		mm.mappingMu.Unlock()
		return addr, linuxerr.EFAULT
	}

	var vseg vmaIterator
	var ar hostarch.AddrRange
	var err error

	var droppedIDs []memmap.MappingIdentity
	// This must run after mm.mappingMu.Unlock().
	defer func() {
		for _, id := range droppedIDs {
			id.DecRef(ctx)
		}
	}()

	switch {
	case oldbrkpg < newbrkpg:
		vseg, ar, droppedIDs, err = mm.createVMALocked(ctx, memmap.MMapOpts{
			Length: uint64(newbrkpg - oldbrkpg),
			Addr:   oldbrkpg,
			Fixed:  true,
			// Compare Linux's
			// arch/x86/include/asm/page_types.h:VM_DATA_DEFAULT_FLAGS.
			Perms:    hostarch.ReadWrite,
			MaxPerms: hostarch.AnyAccess,
			Private:  true,
			// Linux: mm/mmap.c:sys_brk() => do_brk_flags() includes
			// mm->def_flags.
			MLockMode: mm.defMLockMode,
			Hint:      "[heap]",
		}, droppedIDs)
		if err != nil {
			addr = mm.brk.End
			mm.mappingMu.Unlock()
			return addr, err
		}
		mm.brk.End = addr
		if mm.defMLockMode == memmap.MLockEager {
			mm.populateVMAAndUnlock(ctx, vseg, ar, true)
		} else {
			mm.mappingMu.Unlock()
		}

	case newbrkpg < oldbrkpg:
		_, droppedIDs = mm.unmapLocked(ctx, hostarch.AddrRange{newbrkpg, oldbrkpg}, droppedIDs)
		fallthrough

	default:
		mm.brk.End = addr
		mm.mappingMu.Unlock()
	}

	return addr, nil
}

// MLock implements the semantics of Linux's mlock()/mlock2()/munlock(),
// depending on mode.
func (mm *MemoryManager) MLock(ctx context.Context, addr hostarch.Addr, length uint64, mode memmap.MLockMode) error {
	// Linux allows this to overflow.
	la, _ := hostarch.Addr(length + addr.PageOffset()).RoundUp()
	ar, ok := addr.RoundDown().ToRange(uint64(la))
	if !ok {
		return linuxerr.EINVAL
	}

	mm.mappingMu.Lock()
	// Can't defer mm.mappingMu.Unlock(); see below.

	if mode != memmap.MLockNone {
		// Check against RLIMIT_MEMLOCK.
		if creds := auth.CredentialsFromContext(ctx); !creds.HasCapabilityIn(linux.CAP_IPC_LOCK, creds.UserNamespace.Root()) {
			mlockLimit := limits.FromContext(ctx).Get(limits.MemoryLocked).Cur
			if mlockLimit == 0 {
				mm.mappingMu.Unlock()
				return linuxerr.EPERM
			}
			if newLockedAS := mm.lockedAS + uint64(ar.Length()) - mm.mlockedBytesRangeLocked(ar); newLockedAS > mlockLimit {
				mm.mappingMu.Unlock()
				return linuxerr.ENOMEM
			}
		}
	}

	// Check this after RLIMIT_MEMLOCK for consistency with Linux.
	if ar.Length() == 0 {
		mm.mappingMu.Unlock()
		return nil
	}

	// Apply the new mlock mode to vmas.
	var unmapped bool
	vseg := mm.vmas.FindSegment(ar.Start)
	for {
		if !vseg.Ok() {
			unmapped = true
			break
		}
		vseg = mm.vmas.Isolate(vseg, ar)
		vma := vseg.ValuePtr()
		prevMode := vma.mlockMode
		vma.mlockMode = mode
		if mode != memmap.MLockNone && prevMode == memmap.MLockNone {
			mm.lockedAS += uint64(vseg.Range().Length())
		} else if mode == memmap.MLockNone && prevMode != memmap.MLockNone {
			mm.lockedAS -= uint64(vseg.Range().Length())
		}
		if ar.End <= vseg.End() {
			break
		}
		vseg, _ = vseg.NextNonEmpty()
	}
	mm.vmas.MergeRange(ar)
	mm.vmas.MergeAdjacent(ar)
	if unmapped {
		mm.mappingMu.Unlock()
		return linuxerr.ENOMEM
	}

	if mode == memmap.MLockEager {
		// Ensure that we have usable pmas. Since we didn't return ENOMEM
		// above, ar must be fully covered by vmas, so we can just use
		// NextSegment below.
		mm.activeMu.Lock()
		mm.mappingMu.DowngradeLock()
		for vseg := mm.vmas.FindSegment(ar.Start); vseg.Ok() && vseg.Start() < ar.End; vseg = vseg.NextSegment() {
			if !vseg.ValuePtr().effectivePerms.Any() {
				// Linux: mm/gup.c:__get_user_pages() returns EFAULT in this
				// case, which is converted to ENOMEM by mlock.
				mm.activeMu.Unlock()
				mm.mappingMu.RUnlock()
				return linuxerr.ENOMEM
			}
			_, _, err := mm.getPMAsLocked(ctx, vseg, vseg.Range().Intersect(ar), hostarch.NoAccess)
			if err != nil {
				mm.activeMu.Unlock()
				mm.mappingMu.RUnlock()
				// Linux: mm/mlock.c:__mlock_posix_error_return()
				if linuxerr.Equals(linuxerr.EFAULT, err) {
					return linuxerr.ENOMEM
				}
				if linuxerr.Equals(linuxerr.ENOMEM, err) {
					return linuxerr.EAGAIN
				}
				return err
			}
		}

		// Map pmas into the active AddressSpace, if we have one.
		mm.mappingMu.RUnlock()
		if mm.as != nil {
			mm.activeMu.DowngradeLock()
			err := mm.mapASLocked(mm.pmas.LowerBoundSegment(ar.Start), ar, true /* precommit */)
			mm.activeMu.RUnlock()
			if err != nil {
				return err
			}
		} else {
			mm.activeMu.Unlock()
		}
	} else {
		mm.mappingMu.Unlock()
	}

	return nil
}

// MLockAllOpts holds options to MLockAll.
type MLockAllOpts struct {
	// If Current is true, change the memory-locking behavior of all mappings
	// to Mode. If Future is true, upgrade the memory-locking behavior of all
	// future mappings to Mode. At least one of Current or Future must be true.
	Current bool
	Future  bool
	Mode    memmap.MLockMode
}

// MLockAll implements the semantics of Linux's mlockall()/munlockall(),
// depending on opts.
func (mm *MemoryManager) MLockAll(ctx context.Context, opts MLockAllOpts) error {
	if !opts.Current && !opts.Future {
		return linuxerr.EINVAL
	}

	mm.mappingMu.Lock()
	// Can't defer mm.mappingMu.Unlock(); see below.

	if opts.Current {
		if opts.Mode != memmap.MLockNone {
			// Check against RLIMIT_MEMLOCK.
			if creds := auth.CredentialsFromContext(ctx); !creds.HasCapabilityIn(linux.CAP_IPC_LOCK, creds.UserNamespace.Root()) {
				mlockLimit := limits.FromContext(ctx).Get(limits.MemoryLocked).Cur
				if mlockLimit == 0 {
					mm.mappingMu.Unlock()
					return linuxerr.EPERM
				}
				if uint64(mm.vmas.Span()) > mlockLimit {
					mm.mappingMu.Unlock()
					return linuxerr.ENOMEM
				}
			}
		}
		for vseg := mm.vmas.FirstSegment(); vseg.Ok(); vseg = vseg.NextSegment() {
			vma := vseg.ValuePtr()
			prevMode := vma.mlockMode
			vma.mlockMode = opts.Mode
			if opts.Mode != memmap.MLockNone && prevMode == memmap.MLockNone {
				mm.lockedAS += uint64(vseg.Range().Length())
			} else if opts.Mode == memmap.MLockNone && prevMode != memmap.MLockNone {
				mm.lockedAS -= uint64(vseg.Range().Length())
			}
		}
	}

	if opts.Future {
		mm.defMLockMode = opts.Mode
	}

	if opts.Current && opts.Mode == memmap.MLockEager {
		// Linux: mm/mlock.c:sys_mlockall() => include/linux/mm.h:mm_populate()
		// ignores the return value of __mm_populate(), so all errors below are
		// ignored.
		//
		// Try to get usable pmas.
		mm.activeMu.Lock()
		mm.mappingMu.DowngradeLock()
		for vseg := mm.vmas.FirstSegment(); vseg.Ok(); vseg = vseg.NextSegment() {
			if vseg.ValuePtr().effectivePerms.Any() {
				mm.getPMAsLocked(ctx, vseg, vseg.Range(), hostarch.NoAccess)
			}
		}

		// Map all pmas into the active AddressSpace, if we have one.
		mm.mappingMu.RUnlock()
		if mm.as != nil {
			mm.activeMu.DowngradeLock()
			mm.mapASLocked(mm.pmas.FirstSegment(), mm.applicationAddrRange(), true /* precommit */)
			mm.activeMu.RUnlock()
		} else {
			mm.activeMu.Unlock()
		}
	} else {
		mm.mappingMu.Unlock()
	}
	return nil
}

// NumaPolicy implements the semantics of Linux's get_mempolicy(MPOL_F_ADDR).
func (mm *MemoryManager) NumaPolicy(addr hostarch.Addr) (linux.NumaPolicy, uint64, error) {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	vseg := mm.vmas.FindSegment(addr)
	if !vseg.Ok() {
		return 0, 0, linuxerr.EFAULT
	}
	vma := vseg.ValuePtr()
	return vma.numaPolicy, vma.numaNodemask, nil
}

// SetNumaPolicy implements the semantics of Linux's mbind().
func (mm *MemoryManager) SetNumaPolicy(addr hostarch.Addr, length uint64, policy linux.NumaPolicy, nodemask uint64) error {
	if !addr.IsPageAligned() {
		return linuxerr.EINVAL
	}
	// Linux allows this to overflow.
	la, _ := hostarch.Addr(length).RoundUp()
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return linuxerr.EINVAL
	}
	if ar.Length() == 0 {
		return nil
	}

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	defer func() {
		mm.vmas.MergeRange(ar)
		mm.vmas.MergeAdjacent(ar)
	}()
	vseg := mm.vmas.LowerBoundSegment(ar.Start)
	lastEnd := ar.Start
	for {
		if !vseg.Ok() || lastEnd < vseg.Start() {
			// "EFAULT: ... there was an unmapped hole in the specified memory
			// range specified [sic] by addr and len." - mbind(2)
			return linuxerr.EFAULT
		}
		vseg = mm.vmas.Isolate(vseg, ar)
		vma := vseg.ValuePtr()
		vma.numaPolicy = policy
		vma.numaNodemask = nodemask
		lastEnd = vseg.End()
		if ar.End <= lastEnd {
			return nil
		}
		vseg, _ = vseg.NextNonEmpty()
	}
}

// SetDontFork implements the semantics of madvise MADV_DONTFORK.
func (mm *MemoryManager) SetDontFork(addr hostarch.Addr, length uint64, dontfork bool) error {
	ar, ok := addr.ToRange(length)
	if !ok {
		return linuxerr.EINVAL
	}

	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()
	defer func() {
		mm.vmas.MergeRange(ar)
		mm.vmas.MergeAdjacent(ar)
	}()

	for vseg := mm.vmas.LowerBoundSegment(ar.Start); vseg.Ok() && vseg.Start() < ar.End; vseg = vseg.NextSegment() {
		vseg = mm.vmas.Isolate(vseg, ar)
		vma := vseg.ValuePtr()
		vma.dontfork = dontfork
	}

	if mm.vmas.SpanRange(ar) != ar.Length() {
		return linuxerr.ENOMEM
	}
	return nil
}

// Decommit implements the semantics of Linux's madvise(MADV_DONTNEED).
func (mm *MemoryManager) Decommit(addr hostarch.Addr, length uint64) error {
	ar, ok := addr.ToRange(length)
	if !ok {
		return linuxerr.EINVAL
	}

	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()

	// This is invalidateLocked(invalidatePrivate=true, invalidateShared=true),
	// with the additional wrinkle that we must refuse to invalidate pmas under
	// mlocked vmas.
	var didUnmapAS bool
	pseg := mm.pmas.LowerBoundSegment(ar.Start)
	for vseg := mm.vmas.LowerBoundSegment(ar.Start); vseg.Ok() && vseg.Start() < ar.End; vseg = vseg.NextSegment() {
		vma := vseg.ValuePtr()
		if vma.mlockMode != memmap.MLockNone {
			return linuxerr.EINVAL
		}
		vsegAR := vseg.Range().Intersect(ar)
		// pseg should already correspond to either this vma or a later one,
		// since there can't be a pma without a corresponding vma.
		if checkInvariants {
			if pseg.Ok() && pseg.End() <= vsegAR.Start {
				panic(fmt.Sprintf("pma %v precedes vma %v", pseg.Range(), vsegAR))
			}
		}
		for pseg.Ok() && pseg.Start() < vsegAR.End {
			pseg = mm.pmas.Isolate(pseg, vsegAR)
			pma := pseg.ValuePtr()
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
	}

	// "If there are some parts of the specified address space that are not
	// mapped, the Linux version of madvise() ignores them and applies the call
	// to the rest (but returns ENOMEM from the system call, as it should)." -
	// madvise(2)
	if mm.vmas.SpanRange(ar) != ar.Length() {
		return linuxerr.ENOMEM
	}
	return nil
}

// MSyncOpts holds options to MSync.
type MSyncOpts struct {
	// Sync has the semantics of MS_SYNC.
	Sync bool

	// Invalidate has the semantics of MS_INVALIDATE.
	Invalidate bool
}

// MSync implements the semantics of Linux's msync().
func (mm *MemoryManager) MSync(ctx context.Context, addr hostarch.Addr, length uint64, opts MSyncOpts) error {
	if addr != addr.RoundDown() {
		return linuxerr.EINVAL
	}
	if length == 0 {
		return nil
	}
	la, ok := hostarch.Addr(length).RoundUp()
	if !ok {
		return linuxerr.ENOMEM
	}
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return linuxerr.ENOMEM
	}

	mm.mappingMu.RLock()
	// Can't defer mm.mappingMu.RUnlock(); see below.
	vseg := mm.vmas.LowerBoundSegment(ar.Start)
	if !vseg.Ok() {
		mm.mappingMu.RUnlock()
		return linuxerr.ENOMEM
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
		if opts.Invalidate && vma.mlockMode != memmap.MLockNone {
			mm.mappingMu.RUnlock()
			return linuxerr.EBUSY
		}
		// It's only possible to have dirtied the Mappable through a shared
		// mapping. Don't check if the mapping is writable, because mprotect
		// may have changed this, and also because Linux doesn't.
		if id := vma.id; opts.Sync && id != nil && vma.mappable != nil && !vma.private {
			// We can't call memmap.MappingIdentity.Msync while holding
			// mm.mappingMu since it may take fs locks that precede it in the
			// lock order.
			id.IncRef()
			mr := vseg.mappableRangeOf(vseg.Range().Intersect(ar))
			mm.mappingMu.RUnlock()
			err := id.Msync(ctx, mr)
			id.DecRef(ctx)
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
		return linuxerr.ENOMEM
	}
	return nil
}

// GetSharedFutexKey is used by kernel.Task.GetSharedKey.
func (mm *MemoryManager) GetSharedFutexKey(ctx context.Context, addr hostarch.Addr) (futex.Key, error) {
	ar, ok := addr.ToRange(4) // sizeof(int32).
	if !ok {
		return futex.Key{}, linuxerr.EFAULT
	}

	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	vseg, _, err := mm.getVMAsLocked(ctx, ar, hostarch.Read, false)
	if err != nil {
		return futex.Key{}, err
	}
	vma := vseg.ValuePtr()

	if vma.private {
		return futex.Key{
			Kind:   futex.KindSharedPrivate,
			Offset: uint64(addr),
		}, nil
	}

	if vma.id != nil {
		vma.id.IncRef()
	}
	return futex.Key{
		Kind:            futex.KindSharedMappable,
		Mappable:        vma.mappable,
		MappingIdentity: vma.id,
		Offset:          vseg.mappableOffsetAt(addr),
	}, nil
}

// VirtualMemorySize returns the combined length in bytes of all mappings in
// mm.
func (mm *MemoryManager) VirtualMemorySize() uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return mm.usageAS
}

// VirtualMemorySizeRange returns the combined length in bytes of all mappings
// in ar in mm.
func (mm *MemoryManager) VirtualMemorySizeRange(ar hostarch.AddrRange) uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return uint64(mm.vmas.SpanRange(ar))
}

// ResidentSetSize returns the value advertised as mm's RSS in bytes.
func (mm *MemoryManager) ResidentSetSize() uint64 {
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	return mm.curRSS
}

// MaxResidentSetSize returns the value advertised as mm's max RSS in bytes.
func (mm *MemoryManager) MaxResidentSetSize() uint64 {
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	return mm.maxRSS
}

// VirtualDataSize returns the size of private data segments in mm.
func (mm *MemoryManager) VirtualDataSize() uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return mm.dataAS
}

// EnableMembarrierPrivate causes future calls to IsMembarrierPrivateEnabled to
// return true.
func (mm *MemoryManager) EnableMembarrierPrivate() {
	mm.membarrierPrivateEnabled.Store(1)
}

// IsMembarrierPrivateEnabled returns true if mm.EnableMembarrierPrivate() has
// previously been called.
func (mm *MemoryManager) IsMembarrierPrivateEnabled() bool {
	return mm.membarrierPrivateEnabled.Load() != 0
}

// EnableMembarrierRSeq causes future calls to IsMembarrierRSeqEnabled to
// return true.
func (mm *MemoryManager) EnableMembarrierRSeq() {
	mm.membarrierRSeqEnabled.Store(1)
}

// IsMembarrierRSeqEnabled returns true if mm.EnableMembarrierRSeq() has
// previously been called.
func (mm *MemoryManager) IsMembarrierRSeqEnabled() bool {
	return mm.membarrierRSeqEnabled.Load() != 0
}
