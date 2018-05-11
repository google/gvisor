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

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Preconditions: mm.mappingMu must be locked for writing. opts must be valid
// as defined by the checks in MMap.
func (mm *MemoryManager) createVMALocked(ctx context.Context, opts memmap.MMapOpts) (vmaIterator, usermem.AddrRange, error) {
	if opts.MaxPerms != opts.MaxPerms.Effective() {
		panic(fmt.Sprintf("Non-effective MaxPerms %s cannot be enforced", opts.MaxPerms))
	}

	// Find a useable range.
	addr, err := mm.findAvailableLocked(opts.Length, findAvailableOpts{
		Addr:     opts.Addr,
		Fixed:    opts.Fixed,
		Unmap:    opts.Unmap,
		Map32Bit: opts.Map32Bit,
	})
	if err != nil {
		return vmaIterator{}, usermem.AddrRange{}, err
	}
	ar, _ := addr.ToRange(opts.Length)

	// Check against RLIMIT_AS.
	newUsageAS := mm.usageAS + opts.Length
	if opts.Unmap {
		newUsageAS -= uint64(mm.vmas.SpanRange(ar))
	}
	if limitAS := limits.FromContext(ctx).Get(limits.AS).Cur; newUsageAS > limitAS {
		return vmaIterator{}, usermem.AddrRange{}, syserror.ENOMEM
	}

	// Remove overwritten mappings. This ordering is consistent with Linux:
	// compare Linux's mm/mmap.c:mmap_region() => do_munmap(),
	// file->f_op->mmap().
	var vgap vmaGapIterator
	if opts.Unmap {
		vgap = mm.unmapLocked(ctx, ar)
	} else {
		vgap = mm.vmas.FindGap(ar.Start)
	}

	// Inform the Mappable, if any, of the new mapping.
	if opts.Mappable != nil {
		if err := opts.Mappable.AddMapping(ctx, mm, ar, opts.Offset); err != nil {
			return vmaIterator{}, usermem.AddrRange{}, err
		}
	}

	// Take a reference on opts.MappingIdentity before inserting the vma since
	// vma merging can drop the reference.
	if opts.MappingIdentity != nil {
		opts.MappingIdentity.IncRef()
	}

	// Finally insert the vma.
	vseg := mm.vmas.Insert(vgap, ar, vma{
		mappable:       opts.Mappable,
		off:            opts.Offset,
		realPerms:      opts.Perms,
		effectivePerms: opts.Perms.Effective(),
		maxPerms:       opts.MaxPerms,
		private:        opts.Private,
		growsDown:      opts.GrowsDown,
		id:             opts.MappingIdentity,
		hint:           opts.Hint,
	})
	mm.usageAS += opts.Length

	return vseg, ar, nil
}

type findAvailableOpts struct {
	// These fields are equivalent to those in memmap.MMapOpts, except that:
	//
	// - Addr must be page-aligned.
	//
	// - Unmap allows existing guard pages in the returned range.

	Addr     usermem.Addr
	Fixed    bool
	Unmap    bool
	Map32Bit bool
}

// map32Start/End are the bounds to which MAP_32BIT mappings are constrained,
// and are equivalent to Linux's MAP32_BASE and MAP32_MAX respectively.
const (
	map32Start = 0x40000000
	map32End   = 0x80000000
)

// findAvailableLocked finds an allocatable range.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) findAvailableLocked(length uint64, opts findAvailableOpts) (usermem.Addr, error) {
	if opts.Fixed {
		opts.Map32Bit = false
	}
	allowedAR := mm.applicationAddrRange()
	if opts.Map32Bit {
		allowedAR = allowedAR.Intersect(usermem.AddrRange{map32Start, map32End})
	}

	// Does the provided suggestion work?
	if ar, ok := opts.Addr.ToRange(length); ok {
		if allowedAR.IsSupersetOf(ar) {
			if opts.Unmap {
				return ar.Start, nil
			}
			// Check for the presence of an existing vma or guard page.
			if vgap := mm.vmas.FindGap(ar.Start); vgap.Ok() && vgap.availableRange().IsSupersetOf(ar) {
				return ar.Start, nil
			}
		}
	}

	// Fixed mappings accept only the requested address.
	if opts.Fixed {
		return 0, syserror.ENOMEM
	}

	// Prefer hugepage alignment if a hugepage or more is requested.
	alignment := uint64(usermem.PageSize)
	if length >= usermem.HugePageSize {
		alignment = usermem.HugePageSize
	}

	if opts.Map32Bit {
		return mm.findLowestAvailableLocked(length, alignment, allowedAR)
	}
	if mm.layout.DefaultDirection == arch.MmapBottomUp {
		return mm.findLowestAvailableLocked(length, alignment, usermem.AddrRange{mm.layout.BottomUpBase, mm.layout.MaxAddr})
	}
	return mm.findHighestAvailableLocked(length, alignment, usermem.AddrRange{mm.layout.MinAddr, mm.layout.TopDownBase})
}

func (mm *MemoryManager) applicationAddrRange() usermem.AddrRange {
	return usermem.AddrRange{mm.layout.MinAddr, mm.layout.MaxAddr}
}

// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) findLowestAvailableLocked(length, alignment uint64, bounds usermem.AddrRange) (usermem.Addr, error) {
	for gap := mm.vmas.LowerBoundGap(bounds.Start); gap.Ok() && gap.Start() < bounds.End; gap = gap.NextGap() {
		if gr := gap.availableRange().Intersect(bounds); uint64(gr.Length()) >= length {
			// Can we shift up to match the alignment?
			if offset := uint64(gr.Start) % alignment; offset != 0 {
				if uint64(gr.Length()) >= length+alignment-offset {
					// Yes, we're aligned.
					return gr.Start + usermem.Addr(alignment-offset), nil
				}
			}

			// Either aligned perfectly, or can't align it.
			return gr.Start, nil
		}
	}
	return 0, syserror.ENOMEM
}

// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) findHighestAvailableLocked(length, alignment uint64, bounds usermem.AddrRange) (usermem.Addr, error) {
	for gap := mm.vmas.UpperBoundGap(bounds.End); gap.Ok() && gap.End() > bounds.Start; gap = gap.PrevGap() {
		if gr := gap.availableRange().Intersect(bounds); uint64(gr.Length()) >= length {
			// Can we shift down to match the alignment?
			start := gr.End - usermem.Addr(length)
			if offset := uint64(start) % alignment; offset != 0 {
				if gr.Start <= start-usermem.Addr(offset) {
					// Yes, we're aligned.
					return start - usermem.Addr(offset), nil
				}
			}

			// Either aligned perfectly, or can't align it.
			return start, nil
		}
	}
	return 0, syserror.ENOMEM
}

// getVMAsLocked ensures that vmas exist for all addresses in ar, and support
// access of type (at, ignorePermissions). It returns:
//
// - An iterator to the vma containing ar.Start. If no vma contains ar.Start,
// the iterator is unspecified.
//
// - An iterator to the gap after the last vma containing an address in ar. If
// vmas exist for no addresses in ar, the iterator is to a gap that begins
// before ar.Start.
//
// - An error that is non-nil if vmas exist for only a subset of ar.
//
// Preconditions: mm.mappingMu must be locked for reading; it may be
// temporarily unlocked. ar.Length() != 0.
func (mm *MemoryManager) getVMAsLocked(ctx context.Context, ar usermem.AddrRange, at usermem.AccessType, ignorePermissions bool) (vmaIterator, vmaGapIterator, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	// Inline mm.vmas.LowerBoundSegment so that we have the preceding gap if
	// !vbegin.Ok().
	vbegin, vgap := mm.vmas.Find(ar.Start)
	if !vbegin.Ok() {
		vbegin = vgap.NextSegment()
		// vseg.Ok() is checked before entering the following loop.
	} else {
		vgap = vbegin.PrevGap()
	}

	addr := ar.Start
	vseg := vbegin
	for vseg.Ok() {
		// Loop invariants: vgap = vseg.PrevGap(); addr < vseg.End().
		vma := vseg.ValuePtr()
		if addr < vseg.Start() {
			// TODO: Implement vma.growsDown here.
			return vbegin, vgap, syserror.EFAULT
		}

		perms := vma.effectivePerms
		if ignorePermissions {
			perms = vma.maxPerms
		}
		if !perms.SupersetOf(at) {
			return vbegin, vgap, syserror.EPERM
		}

		addr = vseg.End()
		vgap = vseg.NextGap()
		if addr >= ar.End {
			return vbegin, vgap, nil
		}
		vseg = vgap.NextSegment()
	}

	// Ran out of vmas before ar.End.
	return vbegin, vgap, syserror.EFAULT
}

// getVecVMAsLocked ensures that vmas exist for all addresses in ars, and
// support access to type of (at, ignorePermissions). It returns the subset of
// ars for which vmas exist. If this is not equal to ars, it returns a non-nil
// error explaining why.
//
// Preconditions: mm.mappingMu must be locked for reading; it may be
// temporarily unlocked.
//
// Postconditions: ars is not mutated.
func (mm *MemoryManager) getVecVMAsLocked(ctx context.Context, ars usermem.AddrRangeSeq, at usermem.AccessType, ignorePermissions bool) (usermem.AddrRangeSeq, error) {
	for arsit := ars; !arsit.IsEmpty(); arsit = arsit.Tail() {
		ar := arsit.Head()
		if ar.Length() == 0 {
			continue
		}
		if _, vend, err := mm.getVMAsLocked(ctx, ar, at, ignorePermissions); err != nil {
			return truncatedAddrRangeSeq(ars, arsit, vend.Start()), err
		}
	}
	return ars, nil
}

// vma extension will not shrink the number of unmapped bytes between the start
// of a growsDown vma and the end of its predecessor non-growsDown vma below
// guardBytes.
//
// guardBytes is equivalent to Linux's stack_guard_gap after upstream
// 1be7107fbe18 "mm: larger stack guard gap, between vmas".
const guardBytes = 256 * usermem.PageSize

// unmapLocked unmaps all addresses in ar and returns the resulting gap in
// mm.vmas.
//
// Preconditions: mm.mappingMu must be locked for writing. ar.Length() != 0.
// ar must be page-aligned.
func (mm *MemoryManager) unmapLocked(ctx context.Context, ar usermem.AddrRange) vmaGapIterator {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	// AddressSpace mappings and pmas must be invalidated before
	// mm.removeVMAsLocked() => memmap.Mappable.RemoveMapping().
	mm.Invalidate(ar, memmap.InvalidateOpts{InvalidatePrivate: true})
	return mm.removeVMAsLocked(ctx, ar)
}

// removeVMAsLocked removes vmas for addresses in ar and returns the resulting
// gap in mm.vmas. It does not remove pmas or AddressSpace mappings; clients
// must do so before calling removeVMAsLocked.
//
// Preconditions: mm.mappingMu must be locked for writing. ar.Length() != 0. ar
// must be page-aligned.
func (mm *MemoryManager) removeVMAsLocked(ctx context.Context, ar usermem.AddrRange) vmaGapIterator {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	vseg, vgap := mm.vmas.Find(ar.Start)
	if vgap.Ok() {
		vseg = vgap.NextSegment()
	}
	for vseg.Ok() && vseg.Start() < ar.End {
		vseg = mm.vmas.Isolate(vseg, ar)
		vmaAR := vseg.Range()
		vma := vseg.ValuePtr()
		if vma.mappable != nil {
			vma.mappable.RemoveMapping(ctx, mm, vmaAR, vma.off)
		}
		if vma.id != nil {
			vma.id.DecRef()
		}
		mm.usageAS -= uint64(vmaAR.Length())
		vgap = mm.vmas.Remove(vseg)
		vseg = vgap.NextSegment()
	}
	return vgap
}

// vmaSetFunctions implements segment.Functions for vmaSet.
type vmaSetFunctions struct{}

func (vmaSetFunctions) MinKey() usermem.Addr {
	return 0
}

func (vmaSetFunctions) MaxKey() usermem.Addr {
	return ^usermem.Addr(0)
}

func (vmaSetFunctions) ClearValue(vma *vma) {
	vma.mappable = nil
	vma.id = nil
	vma.hint = ""
}

func (vmaSetFunctions) Merge(ar1 usermem.AddrRange, vma1 vma, ar2 usermem.AddrRange, vma2 vma) (vma, bool) {
	if vma1.mappable != vma2.mappable ||
		(vma1.mappable != nil && vma1.off+uint64(ar1.Length()) != vma2.off) ||
		vma1.realPerms != vma2.realPerms ||
		vma1.maxPerms != vma2.maxPerms ||
		vma1.private != vma2.private ||
		vma1.growsDown != vma2.growsDown ||
		vma1.id != vma2.id ||
		vma1.hint != vma2.hint {
		return vma{}, false
	}

	if vma2.id != nil {
		vma2.id.DecRef()
	}
	return vma1, true
}

func (vmaSetFunctions) Split(ar usermem.AddrRange, v vma, split usermem.Addr) (vma, vma) {
	v2 := v
	if v2.mappable != nil {
		v2.off += uint64(split - ar.Start)
	}
	if v2.id != nil {
		v2.id.IncRef()
	}
	return v, v2
}

// Preconditions: vseg.ValuePtr().mappable != nil. vseg.Range().Contains(addr).
func (vseg vmaIterator) mappableOffsetAt(addr usermem.Addr) uint64 {
	if checkInvariants {
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if vseg.ValuePtr().mappable == nil {
			panic("Mappable offset is meaningless for anonymous vma")
		}
		if !vseg.Range().Contains(addr) {
			panic(fmt.Sprintf("addr %v out of bounds %v", addr, vseg.Range()))
		}
	}

	vma := vseg.ValuePtr()
	vstart := vseg.Start()
	return vma.off + uint64(addr-vstart)
}

// Preconditions: vseg.ValuePtr().mappable != nil.
func (vseg vmaIterator) mappableRange() memmap.MappableRange {
	return vseg.mappableRangeOf(vseg.Range())
}

// Preconditions: vseg.ValuePtr().mappable != nil.
// vseg.Range().IsSupersetOf(ar). ar.Length() != 0.
func (vseg vmaIterator) mappableRangeOf(ar usermem.AddrRange) memmap.MappableRange {
	if checkInvariants {
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if vseg.ValuePtr().mappable == nil {
			panic("MappableRange is meaningless for anonymous vma")
		}
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !vseg.Range().IsSupersetOf(ar) {
			panic(fmt.Sprintf("ar %v out of bounds %v", ar, vseg.Range()))
		}
	}

	vma := vseg.ValuePtr()
	vstart := vseg.Start()
	return memmap.MappableRange{vma.off + uint64(ar.Start-vstart), vma.off + uint64(ar.End-vstart)}
}

// Preconditions: vseg.ValuePtr().mappable != nil.
// vseg.mappableRange().IsSupersetOf(mr). mr.Length() != 0.
func (vseg vmaIterator) addrRangeOf(mr memmap.MappableRange) usermem.AddrRange {
	if checkInvariants {
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if vseg.ValuePtr().mappable == nil {
			panic("MappableRange is meaningless for anonymous vma")
		}
		if !mr.WellFormed() || mr.Length() <= 0 {
			panic(fmt.Sprintf("invalid mr: %v", mr))
		}
		if !vseg.mappableRange().IsSupersetOf(mr) {
			panic(fmt.Sprintf("mr %v out of bounds %v", mr, vseg.mappableRange()))
		}
	}

	vma := vseg.ValuePtr()
	vstart := vseg.Start()
	return usermem.AddrRange{vstart + usermem.Addr(mr.Start-vma.off), vstart + usermem.Addr(mr.End-vma.off)}
}

// seekNextLowerBound returns mm.vmas.LowerBoundSegment(addr), but does so by
// scanning linearly forward from vseg.
//
// Preconditions: mm.mappingMu must be locked. addr >= vseg.Start().
func (vseg vmaIterator) seekNextLowerBound(addr usermem.Addr) vmaIterator {
	if checkInvariants {
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if addr < vseg.Start() {
			panic(fmt.Sprintf("can't seek forward to %#x from %#x", addr, vseg.Start()))
		}
	}
	for vseg.Ok() && addr >= vseg.End() {
		vseg = vseg.NextSegment()
	}
	return vseg
}

// availableRange returns the subset of vgap.Range() in which new vmas may be
// created without MMapOpts.Unmap == true.
func (vgap vmaGapIterator) availableRange() usermem.AddrRange {
	ar := vgap.Range()
	next := vgap.NextSegment()
	if !next.Ok() || !next.ValuePtr().growsDown {
		return ar
	}
	// Exclude guard pages.
	if ar.Length() < guardBytes {
		return usermem.AddrRange{ar.Start, ar.Start}
	}
	ar.End -= guardBytes
	return ar
}
