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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// existingPMAsLocked checks that pmas exist for all addresses in ar, and
// support access of type (at, ignorePermissions). If so, it returns an
// iterator to the pma containing ar.Start. Otherwise it returns a terminal
// iterator.
//
// Preconditions: mm.activeMu must be locked. ar.Length() != 0.
func (mm *MemoryManager) existingPMAsLocked(ar usermem.AddrRange, at usermem.AccessType, ignorePermissions bool, needInternalMappings bool) pmaIterator {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	first := mm.pmas.FindSegment(ar.Start)
	pseg := first
	for pseg.Ok() {
		pma := pseg.ValuePtr()
		perms := pma.effectivePerms
		if ignorePermissions {
			perms = pma.maxPerms
		}
		if !perms.SupersetOf(at) {
			return pmaIterator{}
		}
		if needInternalMappings && pma.internalMappings.IsEmpty() {
			return pmaIterator{}
		}

		if ar.End <= pseg.End() {
			return first
		}
		pseg, _ = pseg.NextNonEmpty()
	}

	// Ran out of pmas before reaching ar.End.
	return pmaIterator{}
}

// existingVecPMAsLocked returns true if pmas exist for all addresses in ars,
// and support access of type (at, ignorePermissions).
//
// Preconditions: mm.activeMu must be locked.
func (mm *MemoryManager) existingVecPMAsLocked(ars usermem.AddrRangeSeq, at usermem.AccessType, ignorePermissions bool, needInternalMappings bool) bool {
	for ; !ars.IsEmpty(); ars = ars.Tail() {
		if ar := ars.Head(); ar.Length() != 0 && !mm.existingPMAsLocked(ar, at, ignorePermissions, needInternalMappings).Ok() {
			return false
		}
	}
	return true
}

// getPMAsLocked ensures that pmas exist for all addresses in ar, and support
// access of type at. It returns:
//
// - An iterator to the pma containing ar.Start. If no pma contains ar.Start,
// the iterator is unspecified.
//
// - An iterator to the gap after the last pma containing an address in ar. If
// pmas exist for no addresses in ar, the iterator is to a gap that begins
// before ar.Start.
//
// - An error that is non-nil if pmas exist for only a subset of ar.
//
// Preconditions: mm.mappingMu must be locked. mm.activeMu must be locked for
// writing. ar.Length() != 0. vseg.Range().Contains(ar.Start). vmas must exist
// for all addresses in ar, and support accesses of type at (i.e. permission
// checks must have been performed against vmas).
func (mm *MemoryManager) getPMAsLocked(ctx context.Context, vseg vmaIterator, ar usermem.AddrRange, at usermem.AccessType) (pmaIterator, pmaGapIterator, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if !vseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial vma %v does not cover start of ar %v", vseg.Range(), ar))
		}
	}

	// Page-align ar so that all AddrRanges are aligned.
	end, ok := ar.End.RoundUp()
	var alignerr error
	if !ok {
		end = ar.End.RoundDown()
		alignerr = syserror.EFAULT
	}
	ar = usermem.AddrRange{ar.Start.RoundDown(), end}

	pstart, pend, perr := mm.getPMAsInternalLocked(ctx, vseg, ar, at)
	if pend.Start() <= ar.Start {
		return pmaIterator{}, pend, perr
	}
	// getPMAsInternalLocked may not have returned pstart due to iterator
	// invalidation.
	if !pstart.Ok() {
		pstart = mm.findOrSeekPrevUpperBoundPMA(ar.Start, pend)
	}
	if perr != nil {
		return pstart, pend, perr
	}
	return pstart, pend, alignerr
}

// getVecPMAsLocked ensures that pmas exist for all addresses in ars, and
// support access of type at. It returns the subset of ars for which pmas
// exist. If this is not equal to ars, it returns a non-nil error explaining
// why.
//
// Preconditions: mm.mappingMu must be locked. mm.activeMu must be locked for
// writing. vmas must exist for all addresses in ars, and support accesses of
// type at (i.e. permission checks must have been performed against vmas).
func (mm *MemoryManager) getVecPMAsLocked(ctx context.Context, ars usermem.AddrRangeSeq, at usermem.AccessType) (usermem.AddrRangeSeq, error) {
	for arsit := ars; !arsit.IsEmpty(); arsit = arsit.Tail() {
		ar := arsit.Head()
		if ar.Length() == 0 {
			continue
		}
		if checkInvariants {
			if !ar.WellFormed() {
				panic(fmt.Sprintf("invalid ar: %v", ar))
			}
		}

		// Page-align ar so that all AddrRanges are aligned.
		end, ok := ar.End.RoundUp()
		var alignerr error
		if !ok {
			end = ar.End.RoundDown()
			alignerr = syserror.EFAULT
		}
		ar = usermem.AddrRange{ar.Start.RoundDown(), end}

		_, pend, perr := mm.getPMAsInternalLocked(ctx, mm.vmas.FindSegment(ar.Start), ar, at)
		if perr != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), perr
		}
		if alignerr != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), alignerr
		}
	}

	return ars, nil
}

// getPMAsInternalLocked is equivalent to getPMAsLocked, with the following
// exceptions:
//
// - getPMAsInternalLocked returns a pmaIterator on a best-effort basis (that
// is, the returned iterator may be terminal, even if a pma that contains
// ar.Start exists). Returning this iterator on a best-effort basis allows
// callers that require it to use it when it's cheaply available, while also
// avoiding the overhead of retrieving it when it's not.
//
// - getPMAsInternalLocked additionally requires that ar is page-aligned.
//
// getPMAsInternalLocked is an implementation helper for getPMAsLocked and
// getVecPMAsLocked; other clients should call one of those instead.
func (mm *MemoryManager) getPMAsInternalLocked(ctx context.Context, vseg vmaIterator, ar usermem.AddrRange, at usermem.AccessType) (pmaIterator, pmaGapIterator, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !vseg.Ok() {
			panic("terminal vma iterator")
		}
		if !vseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial vma %v does not cover start of ar %v", vseg.Range(), ar))
		}
	}

	mf := mm.mfp.MemoryFile()
	// Limit the range we allocate to ar, aligned to privateAllocUnit.
	maskAR := privateAligned(ar)
	didUnmapAS := false
	// The range in which we iterate vmas and pmas is still limited to ar, to
	// ensure that we don't allocate or COW-break a pma we don't need.
	pseg, pgap := mm.pmas.Find(ar.Start)
	pstart := pseg
	for {
		// Get pmas for this vma.
		vsegAR := vseg.Range().Intersect(ar)
		vma := vseg.ValuePtr()
	pmaLoop:
		for {
			switch {
			case pgap.Ok() && pgap.Start() < vsegAR.End:
				// Need a pma here.
				optAR := vseg.Range().Intersect(pgap.Range())
				if checkInvariants {
					if optAR.Length() <= 0 {
						panic(fmt.Sprintf("vseg %v and pgap %v do not overlap", vseg, pgap))
					}
				}
				if vma.mappable == nil {
					// Private anonymous mappings get pmas by allocating.
					allocAR := optAR.Intersect(maskAR)
					fr, err := mf.Allocate(uint64(allocAR.Length()), usage.Anonymous)
					if err != nil {
						return pstart, pgap, err
					}
					if checkInvariants {
						if !fr.WellFormed() || fr.Length() != uint64(allocAR.Length()) {
							panic(fmt.Sprintf("Allocate(%v) returned invalid FileRange %v", allocAR.Length(), fr))
						}
					}
					mm.addRSSLocked(allocAR)
					mm.incPrivateRef(fr)
					mf.IncRef(fr)
					pseg, pgap = mm.pmas.Insert(pgap, allocAR, pma{
						file:           mf,
						off:            fr.Start,
						translatePerms: usermem.AnyAccess,
						effectivePerms: vma.effectivePerms,
						maxPerms:       vma.maxPerms,
						// Since we just allocated this memory and have the
						// only reference, the new pma does not need
						// copy-on-write.
						private: true,
					}).NextNonEmpty()
					pstart = pmaIterator{} // iterators invalidated
				} else {
					// Other mappings get pmas by translating.
					optMR := vseg.mappableRangeOf(optAR)
					reqAR := optAR.Intersect(ar)
					reqMR := vseg.mappableRangeOf(reqAR)
					perms := at
					if vma.private {
						// This pma will be copy-on-write; don't require write
						// permission, but do require read permission to
						// facilitate the copy.
						//
						// If at.Write is true, we will need to break
						// copy-on-write immediately, which occurs after
						// translation below.
						perms.Read = true
						perms.Write = false
					}
					ts, err := vma.mappable.Translate(ctx, reqMR, optMR, perms)
					if checkInvariants {
						if err := memmap.CheckTranslateResult(reqMR, optMR, perms, ts, err); err != nil {
							panic(fmt.Sprintf("Mappable(%T).Translate(%v, %v, %v): %v", vma.mappable, reqMR, optMR, perms, err))
						}
					}
					// Install a pma for each translation.
					if len(ts) == 0 {
						return pstart, pgap, err
					}
					pstart = pmaIterator{} // iterators invalidated
					for _, t := range ts {
						newpmaAR := vseg.addrRangeOf(t.Source)
						newpma := pma{
							file:           t.File,
							off:            t.Offset,
							translatePerms: t.Perms,
							effectivePerms: vma.effectivePerms.Intersect(t.Perms),
							maxPerms:       vma.maxPerms.Intersect(t.Perms),
						}
						if vma.private {
							newpma.effectivePerms.Write = false
							newpma.maxPerms.Write = false
							newpma.needCOW = true
						}
						mm.addRSSLocked(newpmaAR)
						t.File.IncRef(t.FileRange())
						// This is valid because memmap.Mappable.Translate is
						// required to return Translations in increasing
						// Translation.Source order.
						pseg = mm.pmas.Insert(pgap, newpmaAR, newpma)
						pgap = pseg.NextGap()
					}
					// The error returned by Translate is only significant if
					// it occurred before ar.End.
					if err != nil && vseg.addrRangeOf(ts[len(ts)-1].Source).End < ar.End {
						return pstart, pgap, err
					}
					// Rewind pseg to the first pma inserted and continue the
					// loop to check if we need to break copy-on-write.
					pseg, pgap = mm.findOrSeekPrevUpperBoundPMA(vseg.addrRangeOf(ts[0].Source).Start, pgap), pmaGapIterator{}
					continue
				}

			case pseg.Ok() && pseg.Start() < vsegAR.End:
				oldpma := pseg.ValuePtr()
				if at.Write && mm.isPMACopyOnWriteLocked(vseg, pseg) {
					// Break copy-on-write by copying.
					if checkInvariants {
						if !oldpma.maxPerms.Read {
							panic(fmt.Sprintf("pma %v needs to be copied for writing, but is not readable: %v", pseg.Range(), oldpma))
						}
					}
					// The majority of copy-on-write breaks on executable pages
					// come from:
					//
					// - The ELF loader, which must zero out bytes on the last
					// page of each segment after the end of the segment.
					//
					// - gdb's use of ptrace to insert breakpoints.
					//
					// Neither of these cases has enough spatial locality to
					// benefit from copying nearby pages, so if the vma is
					// executable, only copy the pages required.
					var copyAR usermem.AddrRange
					if vseg.ValuePtr().effectivePerms.Execute {
						copyAR = pseg.Range().Intersect(ar)
					} else {
						copyAR = pseg.Range().Intersect(maskAR)
					}
					// Get internal mappings from the pma to copy from.
					if err := pseg.getInternalMappingsLocked(); err != nil {
						return pstart, pseg.PrevGap(), err
					}
					// Copy contents.
					fr, err := mf.AllocateAndFill(uint64(copyAR.Length()), usage.Anonymous, &safemem.BlockSeqReader{mm.internalMappingsLocked(pseg, copyAR)})
					if _, ok := err.(safecopy.BusError); ok {
						// If we got SIGBUS during the copy, deliver SIGBUS to
						// userspace (instead of SIGSEGV) if we're breaking
						// copy-on-write due to application page fault.
						err = &memmap.BusError{err}
					}
					if fr.Length() == 0 {
						return pstart, pseg.PrevGap(), err
					}
					// Unmap all of maskAR, not just copyAR, to minimize host
					// syscalls. AddressSpace mappings must be removed before
					// mm.decPrivateRef().
					if !didUnmapAS {
						mm.unmapASLocked(maskAR)
						didUnmapAS = true
					}
					// Replace the pma with a copy in the part of the address
					// range where copying was successful. This doesn't change
					// RSS.
					copyAR.End = copyAR.Start + usermem.Addr(fr.Length())
					if copyAR != pseg.Range() {
						pseg = mm.pmas.Isolate(pseg, copyAR)
						pstart = pmaIterator{} // iterators invalidated
					}
					oldpma = pseg.ValuePtr()
					if oldpma.private {
						mm.decPrivateRef(pseg.fileRange())
					}
					oldpma.file.DecRef(pseg.fileRange())
					mm.incPrivateRef(fr)
					mf.IncRef(fr)
					oldpma.file = mf
					oldpma.off = fr.Start
					oldpma.translatePerms = usermem.AnyAccess
					oldpma.effectivePerms = vma.effectivePerms
					oldpma.maxPerms = vma.maxPerms
					oldpma.needCOW = false
					oldpma.private = true
					oldpma.internalMappings = safemem.BlockSeq{}
					// Try to merge the pma with its neighbors.
					if prev := pseg.PrevSegment(); prev.Ok() {
						if merged := mm.pmas.Merge(prev, pseg); merged.Ok() {
							pseg = merged
							pstart = pmaIterator{} // iterators invalidated
						}
					}
					if next := pseg.NextSegment(); next.Ok() {
						if merged := mm.pmas.Merge(pseg, next); merged.Ok() {
							pseg = merged
							pstart = pmaIterator{} // iterators invalidated
						}
					}
					// The error returned by AllocateAndFill is only
					// significant if it occurred before ar.End.
					if err != nil && pseg.End() < ar.End {
						return pstart, pseg.NextGap(), err
					}
					// Ensure pseg and pgap are correct for the next iteration
					// of the loop.
					pseg, pgap = pseg.NextNonEmpty()
				} else if !oldpma.translatePerms.SupersetOf(at) {
					// Get new pmas (with sufficient permissions) by calling
					// memmap.Mappable.Translate again.
					if checkInvariants {
						if oldpma.private {
							panic(fmt.Sprintf("private pma %v has non-maximal pma.translatePerms: %v", pseg.Range(), oldpma))
						}
					}
					// Allow the entire pma to be replaced.
					optAR := pseg.Range()
					optMR := vseg.mappableRangeOf(optAR)
					reqAR := optAR.Intersect(ar)
					reqMR := vseg.mappableRangeOf(reqAR)
					perms := oldpma.translatePerms.Union(at)
					ts, err := vma.mappable.Translate(ctx, reqMR, optMR, perms)
					if checkInvariants {
						if err := memmap.CheckTranslateResult(reqMR, optMR, perms, ts, err); err != nil {
							panic(fmt.Sprintf("Mappable(%T).Translate(%v, %v, %v): %v", vma.mappable, reqMR, optMR, perms, err))
						}
					}
					// Remove the part of the existing pma covered by new
					// Translations, then insert new pmas. This doesn't change
					// RSS. Note that we don't need to call unmapASLocked: any
					// existing AddressSpace mappings are still valid (though
					// less permissive than the new pmas indicate) until
					// Invalidate is called, and will be replaced by future
					// calls to mapASLocked.
					if len(ts) == 0 {
						return pstart, pseg.PrevGap(), err
					}
					transMR := memmap.MappableRange{ts[0].Source.Start, ts[len(ts)-1].Source.End}
					transAR := vseg.addrRangeOf(transMR)
					pseg = mm.pmas.Isolate(pseg, transAR)
					pseg.ValuePtr().file.DecRef(pseg.fileRange())
					pgap = mm.pmas.Remove(pseg)
					pstart = pmaIterator{} // iterators invalidated
					for _, t := range ts {
						newpmaAR := vseg.addrRangeOf(t.Source)
						newpma := pma{
							file:           t.File,
							off:            t.Offset,
							translatePerms: t.Perms,
							effectivePerms: vma.effectivePerms.Intersect(t.Perms),
							maxPerms:       vma.maxPerms.Intersect(t.Perms),
						}
						if vma.private {
							newpma.effectivePerms.Write = false
							newpma.maxPerms.Write = false
							newpma.needCOW = true
						}
						t.File.IncRef(t.FileRange())
						pseg = mm.pmas.Insert(pgap, newpmaAR, newpma)
						pgap = pseg.NextGap()
					}
					// The error returned by Translate is only significant if
					// it occurred before ar.End.
					if err != nil && pseg.End() < ar.End {
						return pstart, pgap, err
					}
					// Ensure pseg and pgap are correct for the next iteration
					// of the loop.
					if pgap.Range().Length() == 0 {
						pseg, pgap = pgap.NextSegment(), pmaGapIterator{}
					} else {
						pseg = pmaIterator{}
					}
				} else {
					// We have a usable pma; continue.
					pseg, pgap = pseg.NextNonEmpty()
				}

			default:
				break pmaLoop
			}
		}
		// Go to the next vma.
		if ar.End <= vseg.End() {
			if pgap.Ok() {
				return pstart, pgap, nil
			}
			return pstart, pseg.PrevGap(), nil
		}
		vseg = vseg.NextSegment()
	}
}

const (
	// When memory is allocated for a private pma, align the allocated address
	// range to a privateAllocUnit boundary when possible. Larger values of
	// privateAllocUnit may reduce page faults by allowing fewer, larger pmas
	// to be mapped, but may result in larger amounts of wasted memory in the
	// presence of fragmentation. privateAllocUnit must be a power-of-2
	// multiple of usermem.PageSize.
	privateAllocUnit = usermem.HugePageSize

	privateAllocMask = privateAllocUnit - 1
)

func privateAligned(ar usermem.AddrRange) usermem.AddrRange {
	aligned := usermem.AddrRange{ar.Start &^ privateAllocMask, ar.End}
	if end := (ar.End + privateAllocMask) &^ privateAllocMask; end >= ar.End {
		aligned.End = end
	}
	if checkInvariants {
		if !aligned.IsSupersetOf(ar) {
			panic(fmt.Sprintf("aligned AddrRange %#v is not a superset of ar %#v", aligned, ar))
		}
	}
	return aligned
}

// isPMACopyOnWriteLocked returns true if the contents of the pma represented
// by pseg must be copied to a new private pma to be written to.
//
// If the pma is a copy-on-write private pma, and holds the only reference on
// the memory it maps, isPMACopyOnWriteLocked will take ownership of the memory
// and update the pma to indicate that it does not require copy-on-write.
//
// Preconditions: vseg.Range().IsSupersetOf(pseg.Range()). mm.mappingMu must be
// locked. mm.activeMu must be locked for writing.
func (mm *MemoryManager) isPMACopyOnWriteLocked(vseg vmaIterator, pseg pmaIterator) bool {
	pma := pseg.ValuePtr()
	if !pma.needCOW {
		return false
	}
	if !pma.private {
		return true
	}
	// If we have the only reference on private memory to be copied, just take
	// ownership of it instead of copying. If we do hold the only reference,
	// additional references can only be taken by mm.Fork(), which is excluded
	// by mm.activeMu, so this isn't racy.
	mm.privateRefs.mu.Lock()
	defer mm.privateRefs.mu.Unlock()
	fr := pseg.fileRange()
	// This check relies on mm.privateRefs.refs being kept fully merged.
	rseg := mm.privateRefs.refs.FindSegment(fr.Start)
	if rseg.Ok() && rseg.Value() == 1 && fr.End <= rseg.End() {
		pma.needCOW = false
		// pma.private => pma.translatePerms == usermem.AnyAccess
		vma := vseg.ValuePtr()
		pma.effectivePerms = vma.effectivePerms
		pma.maxPerms = vma.maxPerms
		return false
	}
	return true
}

// Invalidate implements memmap.MappingSpace.Invalidate.
func (mm *MemoryManager) Invalidate(ar usermem.AddrRange, opts memmap.InvalidateOpts) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()
	if mm.captureInvalidations {
		mm.capturedInvalidations = append(mm.capturedInvalidations, invalidateArgs{ar, opts})
		return
	}
	mm.invalidateLocked(ar, opts.InvalidatePrivate, true)
}

// invalidateLocked removes pmas and AddressSpace mappings of those pmas for
// addresses in ar.
//
// Preconditions: mm.activeMu must be locked for writing. ar.Length() != 0. ar
// must be page-aligned.
func (mm *MemoryManager) invalidateLocked(ar usermem.AddrRange, invalidatePrivate, invalidateShared bool) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	var didUnmapAS bool
	pseg := mm.pmas.LowerBoundSegment(ar.Start)
	for pseg.Ok() && pseg.Start() < ar.End {
		pma := pseg.ValuePtr()
		if (invalidatePrivate && pma.private) || (invalidateShared && !pma.private) {
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
			mm.removeRSSLocked(pseg.Range())
			pma.file.DecRef(pseg.fileRange())
			pseg = mm.pmas.Remove(pseg).NextSegment()
		} else {
			pseg = pseg.NextSegment()
		}
	}
}

// Pin returns the platform.File ranges currently mapped by addresses in ar in
// mm, acquiring a reference on the returned ranges which the caller must
// release by calling Unpin. If not all addresses are mapped, Pin returns a
// non-nil error. Note that Pin may return both a non-empty slice of
// PinnedRanges and a non-nil error.
//
// Pin does not prevent mapped ranges from changing, making it unsuitable for
// most I/O. It should only be used in contexts that would use get_user_pages()
// in the Linux kernel.
//
// Preconditions: ar.Length() != 0. ar must be page-aligned.
func (mm *MemoryManager) Pin(ctx context.Context, ar usermem.AddrRange, at usermem.AccessType, ignorePermissions bool) ([]PinnedRange, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	// Ensure that we have usable vmas.
	mm.mappingMu.RLock()
	vseg, vend, verr := mm.getVMAsLocked(ctx, ar, at, ignorePermissions)
	if vendaddr := vend.Start(); vendaddr < ar.End {
		if vendaddr <= ar.Start {
			mm.mappingMu.RUnlock()
			return nil, verr
		}
		ar.End = vendaddr
	}

	// Ensure that we have usable pmas.
	mm.activeMu.Lock()
	pseg, pend, perr := mm.getPMAsLocked(ctx, vseg, ar, at)
	mm.mappingMu.RUnlock()
	if pendaddr := pend.Start(); pendaddr < ar.End {
		if pendaddr <= ar.Start {
			mm.activeMu.Unlock()
			return nil, perr
		}
		ar.End = pendaddr
	}

	// Gather pmas.
	var prs []PinnedRange
	for pseg.Ok() && pseg.Start() < ar.End {
		psar := pseg.Range().Intersect(ar)
		f := pseg.ValuePtr().file
		fr := pseg.fileRangeOf(psar)
		f.IncRef(fr)
		prs = append(prs, PinnedRange{
			Source: psar,
			File:   f,
			Offset: fr.Start,
		})
		pseg = pseg.NextSegment()
	}
	mm.activeMu.Unlock()

	// Return the first error in order of progress through ar.
	if perr != nil {
		return prs, perr
	}
	return prs, verr
}

// PinnedRanges are returned by MemoryManager.Pin.
type PinnedRange struct {
	// Source is the corresponding range of addresses.
	Source usermem.AddrRange

	// File is the mapped file.
	File platform.File

	// Offset is the offset into File at which this PinnedRange begins.
	Offset uint64
}

// FileRange returns the platform.File offsets mapped by pr.
func (pr PinnedRange) FileRange() platform.FileRange {
	return platform.FileRange{pr.Offset, pr.Offset + uint64(pr.Source.Length())}
}

// Unpin releases the reference held by prs.
func Unpin(prs []PinnedRange) {
	for i := range prs {
		prs[i].File.DecRef(prs[i].FileRange())
	}
}

// movePMAsLocked moves all pmas in oldAR to newAR.
//
// Preconditions: mm.activeMu must be locked for writing. oldAR.Length() != 0.
// oldAR.Length() <= newAR.Length(). !oldAR.Overlaps(newAR).
// mm.pmas.IsEmptyRange(newAR). oldAR and newAR must be page-aligned.
func (mm *MemoryManager) movePMAsLocked(oldAR, newAR usermem.AddrRange) {
	if checkInvariants {
		if !oldAR.WellFormed() || oldAR.Length() <= 0 || !oldAR.IsPageAligned() {
			panic(fmt.Sprintf("invalid oldAR: %v", oldAR))
		}
		if !newAR.WellFormed() || newAR.Length() <= 0 || !newAR.IsPageAligned() {
			panic(fmt.Sprintf("invalid newAR: %v", newAR))
		}
		if oldAR.Length() > newAR.Length() {
			panic(fmt.Sprintf("old address range %v may contain pmas that will not fit in new address range %v", oldAR, newAR))
		}
		if oldAR.Overlaps(newAR) {
			panic(fmt.Sprintf("old and new address ranges overlap: %v, %v", oldAR, newAR))
		}
		// mm.pmas.IsEmptyRange is checked by mm.pmas.Insert.
	}

	type movedPMA struct {
		oldAR usermem.AddrRange
		pma   pma
	}
	var movedPMAs []movedPMA
	pseg := mm.pmas.LowerBoundSegment(oldAR.Start)
	for pseg.Ok() && pseg.Start() < oldAR.End {
		pseg = mm.pmas.Isolate(pseg, oldAR)
		movedPMAs = append(movedPMAs, movedPMA{
			oldAR: pseg.Range(),
			pma:   pseg.Value(),
		})
		pseg = mm.pmas.Remove(pseg).NextSegment()
		// No RSS change is needed since we're re-inserting the same pmas
		// below.
	}

	off := newAR.Start - oldAR.Start
	pgap := mm.pmas.FindGap(newAR.Start)
	for i := range movedPMAs {
		mpma := &movedPMAs[i]
		pmaNewAR := usermem.AddrRange{mpma.oldAR.Start + off, mpma.oldAR.End + off}
		pgap = mm.pmas.Insert(pgap, pmaNewAR, mpma.pma).NextGap()
	}

	mm.unmapASLocked(oldAR)
}

// getPMAInternalMappingsLocked ensures that pmas for all addresses in ar have
// cached internal mappings. It returns:
//
// - An iterator to the gap after the last pma with internal mappings
// containing an address in ar. If internal mappings exist for no addresses in
// ar, the iterator is to a gap that begins before ar.Start.
//
// - An error that is non-nil if internal mappings exist for only a subset of
// ar.
//
// Preconditions: mm.activeMu must be locked for writing.
// pseg.Range().Contains(ar.Start). pmas must exist for all addresses in ar.
// ar.Length() != 0.
//
// Postconditions: getPMAInternalMappingsLocked does not invalidate iterators
// into mm.pmas.
func (mm *MemoryManager) getPMAInternalMappingsLocked(pseg pmaIterator, ar usermem.AddrRange) (pmaGapIterator, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !pseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial pma %v does not cover start of ar %v", pseg.Range(), ar))
		}
	}

	for {
		if err := pseg.getInternalMappingsLocked(); err != nil {
			return pseg.PrevGap(), err
		}
		if ar.End <= pseg.End() {
			return pseg.NextGap(), nil
		}
		pseg, _ = pseg.NextNonEmpty()
	}
}

// getVecPMAInternalMappingsLocked ensures that pmas for all addresses in ars
// have cached internal mappings. It returns the subset of ars for which
// internal mappings exist. If this is not equal to ars, it returns a non-nil
// error explaining why.
//
// Preconditions: mm.activeMu must be locked for writing. pmas must exist for
// all addresses in ar.
//
// Postconditions: getVecPMAInternalMappingsLocked does not invalidate iterators
// into mm.pmas.
func (mm *MemoryManager) getVecPMAInternalMappingsLocked(ars usermem.AddrRangeSeq) (usermem.AddrRangeSeq, error) {
	for arsit := ars; !arsit.IsEmpty(); arsit = arsit.Tail() {
		ar := arsit.Head()
		if ar.Length() == 0 {
			continue
		}
		if pend, err := mm.getPMAInternalMappingsLocked(mm.pmas.FindSegment(ar.Start), ar); err != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), err
		}
	}
	return ars, nil
}

// internalMappingsLocked returns internal mappings for addresses in ar.
//
// Preconditions: mm.activeMu must be locked. Internal mappings must have been
// previously established for all addresses in ar. ar.Length() != 0.
// pseg.Range().Contains(ar.Start).
func (mm *MemoryManager) internalMappingsLocked(pseg pmaIterator, ar usermem.AddrRange) safemem.BlockSeq {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !pseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial pma %v does not cover start of ar %v", pseg.Range(), ar))
		}
	}

	if ar.End <= pseg.End() {
		// Since only one pma is involved, we can use pma.internalMappings
		// directly, avoiding a slice allocation.
		offset := uint64(ar.Start - pseg.Start())
		return pseg.ValuePtr().internalMappings.DropFirst64(offset).TakeFirst64(uint64(ar.Length()))
	}

	var ims []safemem.Block
	for {
		pr := pseg.Range().Intersect(ar)
		for pims := pseg.ValuePtr().internalMappings.DropFirst64(uint64(pr.Start - pseg.Start())).TakeFirst64(uint64(pr.Length())); !pims.IsEmpty(); pims = pims.Tail() {
			ims = append(ims, pims.Head())
		}
		if ar.End <= pseg.End() {
			break
		}
		pseg = pseg.NextSegment()
	}
	return safemem.BlockSeqFromSlice(ims)
}

// vecInternalMappingsLocked returns internal mappings for addresses in ars.
//
// Preconditions: mm.activeMu must be locked. Internal mappings must have been
// previously established for all addresses in ars.
func (mm *MemoryManager) vecInternalMappingsLocked(ars usermem.AddrRangeSeq) safemem.BlockSeq {
	var ims []safemem.Block
	for ; !ars.IsEmpty(); ars = ars.Tail() {
		ar := ars.Head()
		if ar.Length() == 0 {
			continue
		}
		for pims := mm.internalMappingsLocked(mm.pmas.FindSegment(ar.Start), ar); !pims.IsEmpty(); pims = pims.Tail() {
			ims = append(ims, pims.Head())
		}
	}
	return safemem.BlockSeqFromSlice(ims)
}

// incPrivateRef acquires a reference on private pages in fr.
func (mm *MemoryManager) incPrivateRef(fr platform.FileRange) {
	mm.privateRefs.mu.Lock()
	defer mm.privateRefs.mu.Unlock()
	refSet := &mm.privateRefs.refs
	seg, gap := refSet.Find(fr.Start)
	for {
		switch {
		case seg.Ok() && seg.Start() < fr.End:
			seg = refSet.Isolate(seg, fr)
			seg.SetValue(seg.Value() + 1)
			seg, gap = seg.NextNonEmpty()
		case gap.Ok() && gap.Start() < fr.End:
			seg, gap = refSet.InsertWithoutMerging(gap, gap.Range().Intersect(fr), 1).NextNonEmpty()
		default:
			refSet.MergeAdjacent(fr)
			return
		}
	}
}

// decPrivateRef releases a reference on private pages in fr.
func (mm *MemoryManager) decPrivateRef(fr platform.FileRange) {
	var freed []platform.FileRange

	mm.privateRefs.mu.Lock()
	refSet := &mm.privateRefs.refs
	seg := refSet.LowerBoundSegment(fr.Start)
	for seg.Ok() && seg.Start() < fr.End {
		seg = refSet.Isolate(seg, fr)
		if old := seg.Value(); old == 1 {
			freed = append(freed, seg.Range())
			seg = refSet.Remove(seg).NextSegment()
		} else {
			seg.SetValue(old - 1)
			seg = seg.NextSegment()
		}
	}
	refSet.MergeAdjacent(fr)
	mm.privateRefs.mu.Unlock()

	mf := mm.mfp.MemoryFile()
	for _, fr := range freed {
		mf.DecRef(fr)
	}
}

// addRSSLocked updates the current and maximum resident set size of a
// MemoryManager to reflect the insertion of a pma at ar.
//
// Preconditions: mm.activeMu must be locked for writing.
func (mm *MemoryManager) addRSSLocked(ar usermem.AddrRange) {
	mm.curRSS += uint64(ar.Length())
	if mm.curRSS > mm.maxRSS {
		mm.maxRSS = mm.curRSS
	}
}

// removeRSSLocked updates the current resident set size of a MemoryManager to
// reflect the removal of a pma at ar.
//
// Preconditions: mm.activeMu must be locked for writing.
func (mm *MemoryManager) removeRSSLocked(ar usermem.AddrRange) {
	mm.curRSS -= uint64(ar.Length())
}

// pmaSetFunctions implements segment.Functions for pmaSet.
type pmaSetFunctions struct{}

func (pmaSetFunctions) MinKey() usermem.Addr {
	return 0
}

func (pmaSetFunctions) MaxKey() usermem.Addr {
	return ^usermem.Addr(0)
}

func (pmaSetFunctions) ClearValue(pma *pma) {
	pma.file = nil
	pma.internalMappings = safemem.BlockSeq{}
}

func (pmaSetFunctions) Merge(ar1 usermem.AddrRange, pma1 pma, ar2 usermem.AddrRange, pma2 pma) (pma, bool) {
	if pma1.file != pma2.file ||
		pma1.off+uint64(ar1.Length()) != pma2.off ||
		pma1.translatePerms != pma2.translatePerms ||
		pma1.effectivePerms != pma2.effectivePerms ||
		pma1.maxPerms != pma2.maxPerms ||
		pma1.needCOW != pma2.needCOW ||
		pma1.private != pma2.private {
		return pma{}, false
	}

	// Discard internal mappings instead of trying to merge them, since merging
	// them requires an allocation and getting them again from the
	// platform.File might not.
	pma1.internalMappings = safemem.BlockSeq{}
	return pma1, true
}

func (pmaSetFunctions) Split(ar usermem.AddrRange, p pma, split usermem.Addr) (pma, pma) {
	newlen1 := uint64(split - ar.Start)
	p2 := p
	p2.off += newlen1
	if !p.internalMappings.IsEmpty() {
		p.internalMappings = p.internalMappings.TakeFirst64(newlen1)
		p2.internalMappings = p2.internalMappings.DropFirst64(newlen1)
	}
	return p, p2
}

// findOrSeekPrevUpperBoundPMA returns mm.pmas.UpperBoundSegment(addr), but may do
// so by scanning linearly backward from pgap.
//
// Preconditions: mm.activeMu must be locked. addr <= pgap.Start().
func (mm *MemoryManager) findOrSeekPrevUpperBoundPMA(addr usermem.Addr, pgap pmaGapIterator) pmaIterator {
	if checkInvariants {
		if !pgap.Ok() {
			panic("terminal pma iterator")
		}
		if addr > pgap.Start() {
			panic(fmt.Sprintf("can't seek backward to %#x from %#x", addr, pgap.Start()))
		}
	}
	// Optimistically check if pgap.PrevSegment() is the PMA we're looking for,
	// which is the case if findOrSeekPrevUpperBoundPMA is called to find the
	// start of a range containing only a single PMA.
	if pseg := pgap.PrevSegment(); pseg.Start() <= addr {
		return pseg
	}
	return mm.pmas.UpperBoundSegment(addr)
}

// getInternalMappingsLocked ensures that pseg.ValuePtr().internalMappings is
// non-empty.
//
// Preconditions: mm.activeMu must be locked for writing.
func (pseg pmaIterator) getInternalMappingsLocked() error {
	pma := pseg.ValuePtr()
	if pma.internalMappings.IsEmpty() {
		// This must use maxPerms (instead of perms) because some permission
		// constraints are only visible to vmas; for example, mappings of
		// read-only files have vma.maxPerms.Write unset, but this may not be
		// visible to the memmap.Mappable.
		perms := pma.maxPerms
		// We will never execute application code through an internal mapping.
		perms.Execute = false
		ims, err := pma.file.MapInternal(pseg.fileRange(), perms)
		if err != nil {
			return err
		}
		pma.internalMappings = ims
	}
	return nil
}

func (pseg pmaIterator) fileRange() platform.FileRange {
	return pseg.fileRangeOf(pseg.Range())
}

// Preconditions: pseg.Range().IsSupersetOf(ar). ar.Length != 0.
func (pseg pmaIterator) fileRangeOf(ar usermem.AddrRange) platform.FileRange {
	if checkInvariants {
		if !pseg.Ok() {
			panic("terminal pma iterator")
		}
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !pseg.Range().IsSupersetOf(ar) {
			panic(fmt.Sprintf("ar %v out of bounds %v", ar, pseg.Range()))
		}
	}

	pma := pseg.ValuePtr()
	pstart := pseg.Start()
	return platform.FileRange{pma.off + uint64(ar.Start-pstart), pma.off + uint64(ar.End-pstart)}
}
