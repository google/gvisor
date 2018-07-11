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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

type pmaOpts struct {
	// If breakCOW is true, pmas must not be copy-on-write.
	breakCOW bool
}

// existingPMAsLocked checks that pmas exist for all addresses in ar, and
// support access of type (at, ignorePermissions). If so, it returns an
// iterator to the pma containing ar.Start. Otherwise it returns a terminal
// iterator.
//
// Preconditions: mm.activeMu must be locked. ar.Length() != 0.
func (mm *MemoryManager) existingPMAsLocked(ar usermem.AddrRange, at usermem.AccessType, ignorePermissions bool, opts pmaOpts, needInternalMappings bool) pmaIterator {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
	}

	first := mm.pmas.FindSegment(ar.Start)
	pseg := first
	for pseg.Ok() {
		pma := pseg.ValuePtr()
		perms := pma.vmaEffectivePerms
		if ignorePermissions {
			perms = pma.vmaMaxPerms
		}
		if !perms.SupersetOf(at) {
			// These are the vma's permissions, so the caller will get an error
			// when they try to get new pmas.
			return pmaIterator{}
		}
		if opts.breakCOW && pma.needCOW {
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
func (mm *MemoryManager) existingVecPMAsLocked(ars usermem.AddrRangeSeq, at usermem.AccessType, ignorePermissions bool, opts pmaOpts, needInternalMappings bool) bool {
	for ; !ars.IsEmpty(); ars = ars.Tail() {
		if ar := ars.Head(); ar.Length() != 0 && !mm.existingPMAsLocked(ar, at, ignorePermissions, opts, needInternalMappings).Ok() {
			return false
		}
	}
	return true
}

// getPMAsLocked ensures that pmas exist for all addresses in ar, subject to
// opts. It returns:
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
// for all addresses in ar.
func (mm *MemoryManager) getPMAsLocked(ctx context.Context, vseg vmaIterator, ar usermem.AddrRange, opts pmaOpts) (pmaIterator, pmaGapIterator, error) {
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

	pstart, pend, perr := mm.ensurePMAsLocked(ctx, vseg, ar)
	if pend.Start() <= ar.Start {
		return pmaIterator{}, pend, perr
	}
	// ensurePMAsLocked may not have pstart due to iterator invalidation. We
	// need it, either to return it immediately or to pass to
	// breakCopyOnWriteLocked.
	if !pstart.Ok() {
		pstart = mm.findOrSeekPrevUpperBoundPMA(ar.Start, pend)
	}

	var cowerr error
	if opts.breakCOW {
		var invalidated bool
		pend, invalidated, cowerr = mm.breakCopyOnWriteLocked(pstart, ar)
		if pend.Start() <= ar.Start {
			return pmaIterator{}, pend, cowerr
		}
		if invalidated {
			pstart = mm.findOrSeekPrevUpperBoundPMA(ar.Start, pend)
		}
	}

	if cowerr != nil {
		return pstart, pend, cowerr
	}
	if perr != nil {
		return pstart, pend, perr
	}
	return pstart, pend, alignerr
}

// getVecPMAsLocked ensures that pmas exist for all addresses in ars. It
// returns the subset of ars for which pmas exist. If this is not equal to ars,
// it returns a non-nil error explaining why.
//
// Preconditions: mm.mappingMu must be locked. mm.activeMu must be locked for
// writing. vmas must exist for all addresses in ars.
func (mm *MemoryManager) getVecPMAsLocked(ctx context.Context, ars usermem.AddrRangeSeq, opts pmaOpts) (usermem.AddrRangeSeq, error) {
	for arsit := ars; !arsit.IsEmpty(); arsit = arsit.Tail() {
		ar := arsit.Head()
		if ar.Length() == 0 {
			continue
		}

		// Page-align ar so that all AddrRanges are aligned.
		end, ok := ar.End.RoundUp()
		var alignerr error
		if !ok {
			end = ar.End.RoundDown()
			alignerr = syserror.EFAULT
		}
		ar = usermem.AddrRange{ar.Start.RoundDown(), end}

		pstart, pend, perr := mm.ensurePMAsLocked(ctx, mm.vmas.FindSegment(ar.Start), ar)
		if pend.Start() <= ar.Start {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), perr
		}

		var cowerr error
		if opts.breakCOW {
			if !pstart.Ok() {
				pstart = mm.findOrSeekPrevUpperBoundPMA(ar.Start, pend)
			}
			pend, _, cowerr = mm.breakCopyOnWriteLocked(pstart, ar)
		}

		if cowerr != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), cowerr
		}
		if perr != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), perr
		}
		if alignerr != nil {
			return truncatedAddrRangeSeq(ars, arsit, pend.Start()), alignerr
		}
	}

	return ars, nil
}

// ensurePMAsLocked ensures that pmas exist for all addresses in ar. It returns:
//
// - An iterator to the pma containing ar.Start, on a best-effort basis (that
// is, the returned iterator may be terminal, even if such a pma exists).
// Returning this iterator on a best-effort basis allows callers that require
// it to use it when it's cheaply available, while also avoiding the overhead
// of retrieving it when it's not.
//
// - An iterator to the gap after the last pma containing an address in ar. If
// pmas exist for no addresses in ar, the iterator is to a gap that begins
// before ar.Start.
//
// - An error that is non-nil if pmas exist for only a subset of ar.
//
// Preconditions: mm.mappingMu must be locked. mm.activeMu must be locked for
// writing. ar.Length() != 0. ar must be page-aligned.
// vseg.Range().Contains(ar.Start). vmas must exist for all addresses in ar.
func (mm *MemoryManager) ensurePMAsLocked(ctx context.Context, vseg vmaIterator, ar usermem.AddrRange) (pmaIterator, pmaGapIterator, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !vseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial vma %v does not cover start of ar %v", vseg.Range(), ar))
		}
	}

	pstart, pgap := mm.pmas.Find(ar.Start)
	if pstart.Ok() {
		pgap = pstart.NextGap()
	}
	for pgap.Start() < ar.End {
		if pgap.Range().Length() == 0 {
			pgap = pgap.NextGap()
			continue
		}
		// A single pgap might be spanned by multiple vmas. Insert pmas to
		// cover the first (vma, pgap) pair.
		pgapAR := pgap.Range().Intersect(ar)
		vseg = vseg.seekNextLowerBound(pgapAR.Start)
		if checkInvariants {
			if !vseg.Ok() {
				panic(fmt.Sprintf("no vma after %#x", pgapAR.Start))
			}
			if pgapAR.Start < vseg.Start() {
				panic(fmt.Sprintf("no vma in [%#x, %#x)", pgapAR.Start, vseg.Start()))
			}
		}
		var err error
		pgap, err = mm.insertPMAsLocked(ctx, vseg, pgap, ar)
		// insertPMAsLocked most likely invalidated iterators, so pstart is now
		// unknown.
		pstart = pmaIterator{}
		if err != nil {
			return pstart, pgap, err
		}
	}
	return pstart, pgap, nil
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

// insertPMAsLocked inserts pmas into pgap corresponding to the vma iterated by
// vseg, spanning at least ar. It returns:
//
// - An iterator to the gap after the last pma containing an address in ar. If
// pmas exist for no addresses in ar, the iterator is to a gap that begins
// before ar.Start.
//
// - An error that is non-nil if pmas exist for only a subset of ar.
//
// Preconditions: mm.mappingMu must be locked. mm.activeMu must be locked for
// writing. vseg.Range().Intersect(pgap.Range()).Intersect(ar).Length() != 0.
// ar must be page-aligned.
func (mm *MemoryManager) insertPMAsLocked(ctx context.Context, vseg vmaIterator, pgap pmaGapIterator, ar usermem.AddrRange) (pmaGapIterator, error) {
	optAR := vseg.Range().Intersect(pgap.Range())
	if checkInvariants {
		if optAR.Length() <= 0 {
			panic(fmt.Sprintf("vseg %v and pgap %v do not overlap", vseg, pgap))
		}
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar %v", ar))
		}
	}
	vma := vseg.ValuePtr()

	// Private anonymous mappings get pmas by allocating.
	if vma.mappable == nil {
		// Limit the range we allocate to ar, aligned to privateAllocUnit.
		maskAR := privateAligned(ar)
		allocAR := optAR.Intersect(maskAR)
		mem := mm.p.Memory()
		fr, err := mem.Allocate(uint64(allocAR.Length()), usage.Anonymous)
		if err != nil {
			return pgap, err
		}
		mm.incPrivateRef(fr)

		if checkInvariants {
			if !fr.WellFormed() || fr.Length() != uint64(allocAR.Length()) {
				panic(fmt.Sprintf("Allocate(%v) returned invalid FileRange %v", allocAR.Length(), fr))
			}
		}

		mm.addRSSLocked(allocAR)
		mem.IncRef(fr)

		return mm.pmas.Insert(pgap, allocAR, pma{
			file:              mem,
			off:               fr.Start,
			vmaEffectivePerms: vma.effectivePerms,
			vmaMaxPerms:       vma.maxPerms,
			private:           true,
			// Since we just allocated this memory and have the only reference,
			// the new pma does not need copy-on-write.
		}).NextGap(), nil
	}

	// Other mappings get pmas by translating. Limit the required range
	// to ar.
	optMR := vseg.mappableRangeOf(optAR)
	reqAR := optAR.Intersect(ar)
	reqMR := vseg.mappableRangeOf(reqAR)
	perms := vma.maxPerms
	if vma.private {
		perms.Write = false
	}
	ts, err := vma.mappable.Translate(ctx, reqMR, optMR, perms)
	if checkInvariants {
		if err := memmap.CheckTranslateResult(reqMR, optMR, ts, err); err != nil {
			panic(fmt.Sprintf("Mappable(%T).Translate(%v, %v): %v", vma.mappable, reqMR, optMR, err))
		}
	}

	// Install a pma for each Translation.
	for _, t := range ts {
		// This is valid because memmap.Mappable.Translate is required to
		// return Translations in increasing Translation.Source order.
		addrRange := vseg.addrRangeOf(t.Source)
		mm.addRSSLocked(addrRange)
		pseg := mm.pmas.Insert(pgap, addrRange, pma{
			file:              t.File,
			off:               t.Offset,
			vmaEffectivePerms: vma.effectivePerms,
			vmaMaxPerms:       vma.maxPerms,
			needCOW:           vma.private,
		})
		// The new pseg may have been merged with existing segments, only take a
		// ref on the inserted range.
		t.File.IncRef(pseg.fileRangeOf(addrRange))
		pgap = pseg.NextGap()
	}

	// Even if Translate returned an error, if we got to ar.End,
	// insertPMAsLocked succeeded.
	if ar.End <= pgap.Start() {
		return pgap, nil
	}
	return pgap, err
}

// breakCopyOnWriteLocked ensures that pmas in ar are not copy-on-write. It
// returns:
//
// - An iterator to the gap after the last non-COW pma containing an address in
// ar. If non-COW pmas exist for no addresses in ar, the iterator is to a gap
// that begins before ar.Start.
//
// - A boolean that is true if iterators into mm.pmas may have been
// invalidated.
//
// - An error that is non-nil if non-COW pmas exist for only a subset of ar.
//
// Preconditions: mm.activeMu must be locked for writing. ar.Length() != 0. ar
// must be page-aligned. pseg.Range().Contains(ar.Start). pmas must exist for
// all addresses in ar.
func (mm *MemoryManager) breakCopyOnWriteLocked(pseg pmaIterator, ar usermem.AddrRange) (pmaGapIterator, bool, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() <= 0 || !ar.IsPageAligned() {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !pseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial pma %v does not cover start of ar %v", pseg.Range(), ar))
		}
	}

	// Limit the range we copy to ar, aligned to privateAllocUnit.
	maskAR := privateAligned(ar)
	var invalidatedIterators, didUnmapAS bool
	mem := mm.p.Memory()
	for {
		if mm.isPMACopyOnWriteLocked(pseg) {
			// Determine the range to copy.
			copyAR := pseg.Range().Intersect(maskAR)

			// Get internal mappings from the pma to copy from.
			if err := pseg.getInternalMappingsLocked(); err != nil {
				return pseg.PrevGap(), invalidatedIterators, err
			}

			// Copy contents.
			fr, err := platform.AllocateAndFill(mem, uint64(copyAR.Length()), usage.Anonymous, &safemem.BlockSeqReader{mm.internalMappingsLocked(pseg, copyAR)})
			if _, ok := err.(safecopy.BusError); ok {
				// If we got SIGBUS during the copy, deliver SIGBUS to
				// userspace (instead of SIGSEGV) if we're breaking
				// copy-on-write due to application page fault.
				err = &memmap.BusError{err}
			}
			if fr.Length() == 0 {
				return pseg.PrevGap(), invalidatedIterators, err
			}
			mm.incPrivateRef(fr)
			mem.IncRef(fr)

			// Unmap all of maskAR, not just copyAR, to minimize host syscalls.
			// AddressSpace mappings must be removed before mm.decPrivateRef().
			if !didUnmapAS {
				mm.unmapASLocked(maskAR)
				didUnmapAS = true
			}

			// Replace the pma with a copy in the part of the address range
			// where copying was successful.
			copyAR.End = copyAR.Start + usermem.Addr(fr.Length())
			if copyAR != pseg.Range() {
				pseg = mm.pmas.Isolate(pseg, copyAR)
				invalidatedIterators = true
			}
			pma := pseg.ValuePtr()
			if pma.private {
				mm.decPrivateRef(pseg.fileRange())
			}
			pma.file.DecRef(pseg.fileRange())

			pma.file = mem
			pma.off = fr.Start
			pma.private = true
			pma.needCOW = false
			pma.internalMappings = safemem.BlockSeq{}

			// Try to merge pma with its neighbors.
			if prev := pseg.PrevSegment(); prev.Ok() {
				if merged := mm.pmas.Merge(prev, pseg); merged.Ok() {
					pseg = merged
					invalidatedIterators = true
				}
			}
			if next := pseg.NextSegment(); next.Ok() {
				if merged := mm.pmas.Merge(pseg, next); merged.Ok() {
					pseg = merged
					invalidatedIterators = true
				}
			}

			// If an error occurred after ar.End, breakCopyOnWriteLocked still
			// did its job, so discard the error.
			if err != nil && pseg.End() < ar.End {
				return pseg.NextGap(), invalidatedIterators, err
			}
		}
		// This checks against ar.End, not maskAR.End, so we will never break
		// COW on a pma that does not intersect ar.
		if ar.End <= pseg.End() {
			return pseg.NextGap(), invalidatedIterators, nil
		}
		pseg = pseg.NextSegment()
	}
}

// Preconditions: mm.activeMu must be locked for writing.
func (mm *MemoryManager) isPMACopyOnWriteLocked(pseg pmaIterator) bool {
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
	pseg, pend, perr := mm.getPMAsLocked(ctx, vseg, ar, pmaOpts{
		breakCOW: at.Write,
	})
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
// oldAR.Length() == newAR.Length(). !oldAR.Overlaps(newAR).
// mm.pmas.IsEmptyRange(newAR). oldAR and newAR must be page-aligned.
func (mm *MemoryManager) movePMAsLocked(oldAR, newAR usermem.AddrRange) {
	if checkInvariants {
		if !oldAR.WellFormed() || oldAR.Length() <= 0 || !oldAR.IsPageAligned() {
			panic(fmt.Sprintf("invalid oldAR: %v", oldAR))
		}
		if !newAR.WellFormed() || newAR.Length() <= 0 || !newAR.IsPageAligned() {
			panic(fmt.Sprintf("invalid newAR: %v", newAR))
		}
		if oldAR.Length() != newAR.Length() {
			panic(fmt.Sprintf("old and new address ranges have different lengths: %v, %v", oldAR, newAR))
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
		mm.removeRSSLocked(pseg.Range())
		pseg = mm.pmas.Remove(pseg).NextSegment()
	}

	off := newAR.Start - oldAR.Start
	pgap := mm.pmas.FindGap(newAR.Start)
	for i := range movedPMAs {
		mpma := &movedPMAs[i]
		pmaNewAR := usermem.AddrRange{mpma.oldAR.Start + off, mpma.oldAR.End + off}
		mm.addRSSLocked(pmaNewAR)
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

	mem := mm.p.Memory()
	for _, fr := range freed {
		mem.DecRef(fr)
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
		pma1.vmaEffectivePerms != pma2.vmaEffectivePerms ||
		pma1.vmaMaxPerms != pma2.vmaMaxPerms ||
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
		// Internal mappings are used for ignorePermissions accesses,
		// so we need to use vma.maxPerms instead of
		// vma.effectivePerms. However, we will never execute
		// application code through an internal mapping, and we don't
		// actually need a writable mapping if copy-on-write is in
		// effect. (But get a writable mapping anyway if the pma is
		// private, so that if breakCopyOnWriteLocked =>
		// isPMACopyOnWriteLocked takes ownership of the pma instead of
		// copying, it doesn't need to get a new mapping.)
		perms := pma.vmaMaxPerms
		perms.Execute = false
		if pma.needCOW && !pma.private {
			perms.Write = false
		}
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
