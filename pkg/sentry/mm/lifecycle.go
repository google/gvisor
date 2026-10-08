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

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// NewMemoryManager returns a new MemoryManager with no mappings and 1 user.
func NewMemoryManager(p platform.Platform, mf *pgalloc.MemoryFile) (*MemoryManager, error) {
	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		return nil, err
	}
	return &MemoryManager{
		p:           p,
		mf:          mf,
		haveASIO:    p.SupportsAddressSpaceIO(),
		users:       atomicbitops.FromInt32(1),
		as:          as,
		auxv:        arch.Auxv{},
		dumpability: atomicbitops.FromInt32(int32(UserDumpable)),
		aioManager:  aioManager{contexts: make(map[uint64]*AIOContext)},
	}, nil
}

// SetMmapLayout initializes mm's layout from the given arch.Context64.
//
// Preconditions: mm contains no mappings and is not used concurrently.
func (mm *MemoryManager) SetMmapLayout(ac *arch.Context64, r *limits.LimitSet) (arch.MmapLayout, error) {
	layout, err := ac.NewMmapLayout(mm.p.MinUserAddress(), mm.p.MaxUserAddress(), r)
	if err != nil {
		return arch.MmapLayout{}, err
	}
	mm.layout = layout
	return layout, nil
}

// isolatePMAToVMALocked advances vseg to the vma containing pseg.Start(), and
// splits pseg at that vma's boundaries so that it lies entirely within it. It
// returns the updated iterators. If there is a remainder to the pma, it
// becomes the one following the returned one. The returned vseg can be used
// to find the vma of the pma.
//
// Preconditions:
//   - A vma must contain pseg.Start(), and vseg must not be after it.
//
// +checklocksread:mm.mappingMu
// +checklocks:mm.activeMu
func (mm *MemoryManager) isolatePMAToVMALocked(pseg pmaIterator, vseg vmaIterator) (pmaIterator, vmaIterator) {
	vseg = vseg.seekNextLowerBound(pseg.Start())
	if checkInvariants {
		if !vseg.Ok() {
			panic(fmt.Sprintf("no vma covers pma range %v", pseg.Range()))
		}
		if pseg.Start() < vseg.Start() {
			panic(fmt.Sprintf("vma %v ran ahead of pma %v", vseg.Range(), pseg.Range()))
		}
	}
	return mm.pmas.Isolate(pseg, vseg.Range()), vseg
}

// abortForkLocked releases the references and mappings established for a
// MemoryManager under construction by Fork, when Fork fails while copying
// pmas, similar to Linux's copy_page_range() fail. It returns the updated
// aborted mappings via droppedIDs.
//
// Preconditions:
//   - mm must not yet be visible outside of Fork.
//
// +checklocks:mm.activeMu
func (mm *MemoryManager) abortForkLocked(ctx context.Context, droppedIDs []memmap.MappingIdentity) []memmap.MappingIdentity {
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		pseg.ValuePtr().file.DecRef(pseg.fileRange())
	}
	mm.pmas.RemoveAll()
	// Fork still exclusively owns mm2's VMA and mapping-accounting
	// state. AddMapping only exposes its activeMu-protected
	// invalidation state.
	_, droppedIDs = mm.removeVMAsLocked(ctx, mm.applicationAddrRange(), droppedIDs) // +checklocksignore
	mm.as.Release()
	return droppedIDs
}

// Fork creates a copy of mm with 1 user, as for Linux syscalls fork() or
// clone() (without CLONE_VM).
//
// +checklocksexclude:mm.metadataMu
// +checklocksexclude:mm.mappingMu
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) Fork(ctx context.Context) (*MemoryManager, error) {
	// Systrap cares about the GS register: see systrap.go/NewAddressSpace.
	mm.activeMu.RLock()
	gsInUse := mm.gsInUse
	mm.activeMu.RUnlock()

	as, err := mm.p.NewAddressSpace(platform.AddressSpaceOptions{
		DisableSyscallPatching: gsInUse,
	})
	if err != nil {
		return nil, err
	}

	mm.AddressSpace().PreFork()
	defer mm.AddressSpace().PostFork()
	mm.metadataMu.Lock()
	defer mm.metadataMu.Unlock()

	var droppedIDs []memmap.MappingIdentity
	// This must run after {mm,mm2}.mappingMu.Unlock().
	defer func() {
		for _, id := range droppedIDs {
			id.DecRef(ctx)
		}
	}()

	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	mm2 := &MemoryManager{
		p:        mm.p,
		mf:       mm.mf,
		haveASIO: mm.haveASIO,
		layout:   mm.layout,
		users:    atomicbitops.FromInt32(1),
		as:       as,
		brk:      mm.brk,
		usageAS:  mm.usageAS,
		dataAS:   mm.dataAS,
		// "The child does not inherit its parent's memory locks (mlock(2),
		// mlockall(2))." - fork(2). So lockedAS is 0 and defMLockMode is
		// MLockNone, both of which are zero values. vma.mlockMode is reset
		// when copied below.
		captureInvalidations: true,
		argv:                 mm.argv,
		envv:                 mm.envv,
		auxv:                 append(arch.Auxv(nil), mm.auxv...),
		// IncRef'd below, once we know that there isn't an error.
		executable:        mm.executable,
		dumpability:       atomicbitops.FromInt32(mm.dumpability.Load()),
		aioManager:        aioManager{contexts: make(map[uint64]*AIOContext)},
		vdsoSigReturnAddr: mm.vdsoSigReturnAddr,
	}

	// Copy vmas.
	dontforks := false
	var eagerForkARs []hostarch.AddrRange
	dstvgap := mm2.vmas.FirstGap()
	for srcvseg := mm.vmas.FirstSegment(); srcvseg.Ok(); srcvseg = srcvseg.NextSegment() {
		vma := srcvseg.ValuePtr().copy()
		vmaAR := srcvseg.Range()

		if vma.dontfork {
			length := uint64(vmaAR.Length())
			mm2.usageAS -= length
			if vma.isPrivateDataLocked() {
				mm2.dataAS -= length
			}
			dontforks = true
			continue
		}
		if vma.eagerForkCopy {
			eagerForkARs = append(eagerForkARs, vmaAR)
		}

		// Inform the Mappable, if any, of the new mapping.
		if vma.mappable != nil {
			if err := vma.mappable.AddMapping(ctx, mm2, vmaAR, vma.off, vma.canWriteMappableLocked()); err != nil {
				// Fork still exclusively owns mm2's VMA and mapping-accounting
				// state. AddMapping only exposes its activeMu-protected
				// invalidation state.
				_, droppedIDs = mm2.removeVMAsLocked(ctx, mm2.applicationAddrRange(), droppedIDs) // +checklocksignore
				as.Release()
				return nil, err
			}
		}
		if vma.id != nil {
			vma.id.IncRef()
		}
		vma.mlockMode = memmap.MLockNone
		dstvgap = mm2.vmas.Insert(dstvgap, vmaAR, vma).NextGap()
		// We don't need to update mm2.usageAS since we copied it from mm
		// above.
	}

	// Copy pmas. We have to lock mm.activeMu for writing to make existing
	// private pmas copy-on-write. We also have to lock mm2.activeMu since
	// after copying vmas above, memmap.Mappables may call mm2.Invalidate. We
	// only copy private pmas, since in the common case where fork(2) is
	// immediately followed by execve(2), copying non-private pmas that can be
	// regenerated by calling memmap.Mappable.Translate is a waste of time.
	// (Linux does the same; compare kernel/fork.c:dup_mmap() =>
	// mm/memory.c:copy_page_range().)
	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()
	mm2.activeMu.NestedLock(activeLockForked)
	defer mm2.activeMu.NestedUnlock(activeLockForked)
	mm2.gsInUse = gsInUse
	if dontforks || mm.hasPinned {
		defer mm.pmas.MergeInsideRange(mm.applicationAddrRange())
	}
	srcvseg := mm.vmas.FirstSegment()
	dstpgap := mm2.pmas.FirstGap()
	var unmapAR hostarch.AddrRange
	defer func() {
		if unmapAR.Length() != 0 {
			mm.unmapASLocked(unmapAR)
		}
	}()
	memCgID := pgalloc.MemoryCgroupIDFromContext(ctx)
	for srcpseg := mm.pmas.FirstSegment(); srcpseg.Ok(); srcpseg = srcpseg.NextSegment() {
		pma := srcpseg.ValuePtr()
		if !pma.private {
			continue
		}

		// Skip eager fork ranges that end before srcpseg. Since pmas are
		// visited in increasing order, they can't overlap any later pmas.
		for len(eagerForkARs) != 0 && eagerForkARs[0].End <= srcpseg.Start() {
			eagerForkARs = eagerForkARs[1:]
		}

		eager := len(eagerForkARs) != 0 && eagerForkARs[0].Overlaps(srcpseg.Range())
		if dontforks || eager {
			srcpseg, srcvseg = mm.isolatePMAToVMALocked(srcpseg, srcvseg)
			srcvma := srcvseg.ValuePtr()
			if srcvma.dontfork {
				continue
			}

			pma = srcpseg.ValuePtr()
			if srcvma.eagerForkCopy {
				var err error
				if dstpgap, err = mm.forkCopyPMALocked(mm2, srcpseg, dstpgap, memCgID); err != nil {
					// Dropped IDs need to be updated so that deferred
					// ref decrements are done correctly.
					droppedIDs = mm2.abortForkLocked(ctx, droppedIDs)
					return nil, err
				}
				continue
			}
		}

		if mm.hasPinned && !pma.needCOW {
			// Pinned pages must not be made copy-on-write: breaking
			// copy-on-write moves the writing process to a new copy of the
			// page, while any DMA registered against the original page
			// continues to target it, causing the two to diverge. Instead,
			// give the child a copy of possibly-pinned pages immediately,
			// leaving the parent's mappings unchanged; compare Linux's
			// mm/memory.c:copy_present_ptes() => folio_needs_cow_for_dma().
			// Since Pin() breaks copy-on-write on the pinned range,
			// possibly-pinned pages are exactly those in private
			// non-copy-on-write pmas with more than one reference.
			if sfr, ok := mm.mf.FirstSharedRange(srcpseg.fileRange()); ok {
				sar := hostarch.AddrRange{
					Start: srcpseg.Start() + hostarch.Addr(sfr.Start-pma.off),
					End:   srcpseg.Start() + hostarch.Addr(sfr.End-pma.off),
				}
				if sar.Start > srcpseg.Start() {
					// Isolate the pages preceding sar and fall through to
					// make only those copy-on-write; the remainder of the
					// pma is revisited on the next iteration.
					srcpseg = mm.pmas.Isolate(
						srcpseg,
						hostarch.AddrRange{
							Start: srcpseg.Start(),
							End:   sar.Start},
					)
					pma = srcpseg.ValuePtr()
				} else {
					// Copy the possibly-pinned pages for the child now.
					srcpseg = mm.pmas.Isolate(srcpseg, sar)
					var err error
					dstpgap, err = mm.forkCopyPMALocked(mm2, srcpseg, dstpgap, memCgID)
					if err != nil {
						droppedIDs = mm2.abortForkLocked(ctx, droppedIDs)
						return nil, err
					}
					continue
				}
			}
		}

		if !pma.needCOW {
			pma.needCOW = true
			if pma.effectivePerms.Write {
				// We don't want to unmap the whole address space, even though
				// doing so would reduce calls to unmapASLocked(), because mm
				// will most likely continue to be used after the fork, so
				// unmapping pmas unnecessarily will result in extra page
				// faults. But we do want to merge consecutive AddrRanges
				// across pma boundaries.
				if unmapAR.End == srcpseg.Start() {
					unmapAR.End = srcpseg.End()
				} else {
					if unmapAR.Length() != 0 {
						mm.unmapASLocked(unmapAR)
					}
					unmapAR = srcpseg.Range()
				}
				pma.effectivePerms.Write = false
			}
			pma.maxPerms.Write = false
		}
		fr := srcpseg.fileRange()
		// srcpseg.ValuePtr().file == mm.mf since pma.private == true.
		mm.mf.IncRef(fr, memCgID)
		addrRange := srcpseg.Range()
		mm2.addRSSLocked(addrRange)
		dstpgap = mm2.pmas.Insert(dstpgap, addrRange, *pma).NextGap()
	}

	// Between when we call memmap.Mappable.AddMapping while copying vmas and
	// when we lock mm2.activeMu to copy pmas, calls to mm2.Invalidate() are
	// ineffective because the pmas they invalidate haven't yet been copied,
	// possibly allowing mm2 to get invalidated translations:
	//
	// Invalidating Mappable            mm.Fork
	// ---------------------            -------
	//
	// mm2.Invalidate()
	//                                  mm.activeMu.Lock()
	// mm.Invalidate() /* blocks */
	//                                  mm2.activeMu.Lock()
	//                                  (mm copies invalidated pma to mm2)
	//
	// This would technically be both safe (since we only copy private pmas,
	// which will still hold a reference on their memory) and consistent with
	// Linux, but we avoid it anyway by setting mm2.captureInvalidations during
	// construction, causing calls to mm2.Invalidate() to be captured in
	// mm2.capturedInvalidations, to be replayed after pmas are copied - i.e.
	// here.
	mm2.captureInvalidations = false
	for _, invArgs := range mm2.capturedInvalidations {
		mm2.invalidateLocked(invArgs.ar, invArgs.opts.InvalidatePrivate, true)
	}
	mm2.capturedInvalidations = nil

	if mm2.executable != nil {
		mm2.executable.IncRef()
		mm2.executable.DenyWriteAccess()
	}
	return mm2, nil
}

// forkCopyPMALocked copies the contents of the private pma represented by
// srcpseg in mm into newly-allocated memory, and inserts a pma mapping that
// memory into mm2 at the same address range, as Fork requires for pages that
// may be pinned for DMA. It returns the gap after the inserted pma.
//
// Preconditions:
//   - srcpseg.ValuePtr().private == true.
//   - dstpgap must be the gap in mm2.pmas at which the new pma should be
//     inserted.
//
// +checklocks:mm.activeMu
// +checklocks:mm2.activeMu
func (mm *MemoryManager) forkCopyPMALocked(mm2 *MemoryManager, srcpseg pmaIterator, dstpgap pmaGapIterator, memCgID uint32) (pmaGapIterator, error) {
	if err := srcpseg.getInternalMappingsLocked(); err != nil {
		return dstpgap, err
	}
	copyAR := srcpseg.Range()
	reader := safemem.BlockSeqReader{Blocks: mm.internalMappingsLocked(srcpseg, copyAR)}
	huge := mm.mf.HugepagesEnabled() && copyAR.IsHugePageAligned()
	fr, err := mm.mf.Allocate(uint64(copyAR.Length()), pgalloc.AllocOpts{
		Kind:       usage.Anonymous,
		MemCgID:    memCgID,
		Mode:       pgalloc.AllocateAndWritePopulate,
		Huge:       huge,
		ReaderFunc: reader.ReadToBlocks,
	})
	if err != nil {
		if _, ok := err.(safecopy.BusError); ok {
			// Compare Linux's mm/memory.c:copy_present_page() =>
			// copy_mc_user_highpage().
			err = linuxerr.EHWPOISON
		}
		if fr.Length() != 0 {
			mm.mf.DecRef(fr)
		}
		return dstpgap, err
	}
	newpma := srcpseg.Value()
	newpma.off = fr.Start
	newpma.huge = huge
	newpma.internalMappings = safemem.BlockSeq{}
	mm2.addRSSLocked(copyAR)
	return mm2.pmas.Insert(dstpgap, copyAR, newpma).NextGap(), nil
}

// IncUsers increments mm's user count and returns true. If the user count is
// already 0, IncUsers does nothing and returns false.
func (mm *MemoryManager) IncUsers() bool {
	for {
		users := mm.users.Load()
		if users == 0 {
			return false
		}
		if mm.users.CompareAndSwap(users, users+1) {
			return true
		}
	}
}

// DecUsers decrements mm's user count. If the user count reaches 0, all
// mappings in mm are unmapped.
//
// +checklocksexclude:mm.aioManager.mu
// +checklocksexclude:mm.metadataMu
// +checklocksexclude:mm.activeMu
// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) DecUsers(ctx context.Context) {
	if users := mm.users.Add(-1); users > 0 {
		return
	} else if users < 0 {
		panic(fmt.Sprintf("Invalid MemoryManager.users: %d", users))
	}

	mm.destroyAIOManager(ctx)

	mm.metadataMu.Lock()
	exe := mm.executable
	mm.executable = nil
	mm.metadataMu.Unlock()
	if exe != nil {
		exe.AllowWriteAccess()
		exe.DecRef(ctx)
	}

	mm.activeMu.Lock()
	// Make sure the AddressSpace is returned.
	if mm.as != nil {
		mm.as.Release()
		mm.as = nil
	}
	mm.activeMu.Unlock()

	var droppedIDs []memmap.MappingIdentity
	mm.mappingMu.Lock()
	// If mm is being dropped before mm.SetMmapLayout was called,
	// mm.applicationAddrRange() will be empty.
	if ar := mm.applicationAddrRange(); ar.Length() != 0 {
		_, droppedIDs = mm.unmapLocked(ctx, ar, droppedIDs)
	}
	mm.mappingMu.Unlock()

	for _, id := range droppedIDs {
		id.DecRef(ctx)
	}
}
