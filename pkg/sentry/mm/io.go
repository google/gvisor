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

package mm

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// There are two supported ways to copy data to/from application virtual
// memory:
//
// 1. Internally-mapped copying: Determine the platform.File that backs the
// copied-to/from virtual address, obtain a mapping of its pages, and read or
// write to the mapping.
//
// 2. AddressSpace copying: If platform.Platform.SupportsAddressSpaceIO() is
// true, AddressSpace permissions are applicable, and an AddressSpace is
// available, copy directly through the AddressSpace, handling faults as
// needed.
//
// (Given that internally-mapped copying requires that backing memory is always
// implemented using a host file descriptor, we could also preadv/pwritev to it
// instead. But this would incur a host syscall for each use of the mapped
// page, whereas mmap is a one-time cost.)
//
// The fixed overhead of internally-mapped copying is expected to be higher
// than that of AddressSpace copying since the former always needs to translate
// addresses, whereas the latter only needs to do so when faults occur.
// However, the throughput of internally-mapped copying is expected to be
// somewhat higher than that of AddressSpace copying due to the high cost of
// page faults and because implementations of the latter usually rely on
// safecopy, which doesn't use AVX registers. So we prefer to use AddressSpace
// copying (when available) for smaller copies, and switch to internally-mapped
// copying once a size threshold is exceeded.
const (
	// copyMapMinBytes is the size threshold for switching to internally-mapped
	// copying in CopyOut, CopyIn, and ZeroOut.
	copyMapMinBytes = 32 << 10 // 32 KB

	// rwMapMinBytes is the size threshold for switching to internally-mapped
	// copying in CopyOutFrom and CopyInTo. It's lower than copyMapMinBytes
	// since AddressSpace copying in this case requires additional buffering;
	// see CopyOutFrom for details.
	rwMapMinBytes = 512
)

// CheckIORange is similar to usermem.Addr.ToRange, but applies bounds checks
// consistent with Linux's arch/x86/include/asm/uaccess.h:access_ok().
//
// Preconditions: length >= 0.
func (mm *MemoryManager) CheckIORange(addr usermem.Addr, length int64) (usermem.AddrRange, bool) {
	// Note that access_ok() constrains end even if length == 0.
	ar, ok := addr.ToRange(uint64(length))
	return ar, (ok && ar.End <= mm.layout.MaxAddr)
}

// checkIOVec applies bound checks consistent with Linux's
// arch/x86/include/asm/uaccess.h:access_ok() to ars.
func (mm *MemoryManager) checkIOVec(ars usermem.AddrRangeSeq) bool {
	for !ars.IsEmpty() {
		ar := ars.Head()
		if _, ok := mm.CheckIORange(ar.Start, int64(ar.Length())); !ok {
			return false
		}
		ars = ars.Tail()
	}
	return true
}

func (mm *MemoryManager) asioEnabled(opts usermem.IOOpts) bool {
	return mm.haveASIO && !opts.IgnorePermissions && opts.AddressSpaceActive
}

// translateIOError converts errors to EFAULT, as is usually reported for all
// I/O errors originating from MM in Linux.
func translateIOError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if logIOErrors {
		ctx.Debugf("MM I/O error: %v", err)
	}
	return syserror.EFAULT
}

// CopyOut implements usermem.IO.CopyOut.
func (mm *MemoryManager) CopyOut(ctx context.Context, addr usermem.Addr, src []byte, opts usermem.IOOpts) (int, error) {
	ar, ok := mm.CheckIORange(addr, int64(len(src)))
	if !ok {
		return 0, syserror.EFAULT
	}

	if len(src) == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && len(src) < copyMapMinBytes {
		return mm.asCopyOut(ctx, addr, src)
	}

	// Go through internal mappings.
	n64, err := mm.withInternalMappings(ctx, ar, usermem.Write, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		n, err := safemem.CopySeq(ims, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(src)))
		return n, translateIOError(ctx, err)
	})
	return int(n64), err
}

func (mm *MemoryManager) asCopyOut(ctx context.Context, addr usermem.Addr, src []byte) (int, error) {
	var done int
	for {
		n, err := mm.as.CopyOut(addr+usermem.Addr(done), src[done:])
		done += n
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(len(src)))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, usermem.Write); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// CopyIn implements usermem.IO.CopyIn.
func (mm *MemoryManager) CopyIn(ctx context.Context, addr usermem.Addr, dst []byte, opts usermem.IOOpts) (int, error) {
	ar, ok := mm.CheckIORange(addr, int64(len(dst)))
	if !ok {
		return 0, syserror.EFAULT
	}

	if len(dst) == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && len(dst) < copyMapMinBytes {
		return mm.asCopyIn(ctx, addr, dst)
	}

	// Go through internal mappings.
	n64, err := mm.withInternalMappings(ctx, ar, usermem.Read, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		n, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(dst)), ims)
		return n, translateIOError(ctx, err)
	})
	return int(n64), err
}

func (mm *MemoryManager) asCopyIn(ctx context.Context, addr usermem.Addr, dst []byte) (int, error) {
	var done int
	for {
		n, err := mm.as.CopyIn(addr+usermem.Addr(done), dst[done:])
		done += n
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(len(dst)))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, usermem.Read); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// ZeroOut implements usermem.IO.ZeroOut.
func (mm *MemoryManager) ZeroOut(ctx context.Context, addr usermem.Addr, toZero int64, opts usermem.IOOpts) (int64, error) {
	ar, ok := mm.CheckIORange(addr, toZero)
	if !ok {
		return 0, syserror.EFAULT
	}

	if toZero == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && toZero < copyMapMinBytes {
		return mm.asZeroOut(ctx, addr, toZero)
	}

	// Go through internal mappings.
	return mm.withInternalMappings(ctx, ar, usermem.Write, opts.IgnorePermissions, func(dsts safemem.BlockSeq) (uint64, error) {
		n, err := safemem.ZeroSeq(dsts)
		return n, translateIOError(ctx, err)
	})
}

func (mm *MemoryManager) asZeroOut(ctx context.Context, addr usermem.Addr, toZero int64) (int64, error) {
	var done int64
	for {
		n, err := mm.as.ZeroOut(addr+usermem.Addr(done), uintptr(toZero-done))
		done += int64(n)
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(toZero))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, usermem.Write); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// CopyOutFrom implements usermem.IO.CopyOutFrom.
func (mm *MemoryManager) CopyOutFrom(ctx context.Context, ars usermem.AddrRangeSeq, src safemem.Reader, opts usermem.IOOpts) (int64, error) {
	if !mm.checkIOVec(ars) {
		return 0, syserror.EFAULT
	}

	if ars.NumBytes() == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && ars.NumBytes() < rwMapMinBytes {
		// We have to introduce a buffered copy, instead of just passing a
		// safemem.BlockSeq representing addresses in the AddressSpace to src.
		// This is because usermem.IO.CopyOutFrom() guarantees that it calls
		// src.ReadToBlocks() at most once, which is incompatible with handling
		// faults between calls. In the future, this is probably best resolved
		// by introducing a CopyOutFrom variant or option that allows it to
		// call src.ReadToBlocks() any number of times.
		//
		// This issue applies to CopyInTo as well.
		buf := make([]byte, int(ars.NumBytes()))
		bufN, bufErr := src.ReadToBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)))
		var done int64
		for done < int64(bufN) {
			ar := ars.Head()
			cplen := int64(ar.Length())
			if cplen > int64(bufN)-done {
				cplen = int64(bufN) - done
			}
			n, err := mm.asCopyOut(ctx, ar.Start, buf[int(done):int(done+cplen)])
			done += int64(n)
			if err != nil {
				return done, err
			}
			ars = ars.Tail()
		}
		// Do not convert errors returned by src to EFAULT.
		return done, bufErr
	}

	// Go through internal mappings.
	return mm.withVecInternalMappings(ctx, ars, usermem.Write, opts.IgnorePermissions, src.ReadToBlocks)
}

// CopyInTo implements usermem.IO.CopyInTo.
func (mm *MemoryManager) CopyInTo(ctx context.Context, ars usermem.AddrRangeSeq, dst safemem.Writer, opts usermem.IOOpts) (int64, error) {
	if !mm.checkIOVec(ars) {
		return 0, syserror.EFAULT
	}

	if ars.NumBytes() == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && ars.NumBytes() < rwMapMinBytes {
		buf := make([]byte, int(ars.NumBytes()))
		var done int
		var bufErr error
		for !ars.IsEmpty() {
			ar := ars.Head()
			var n int
			n, bufErr = mm.asCopyIn(ctx, ar.Start, buf[done:done+int(ar.Length())])
			done += n
			if bufErr != nil {
				break
			}
			ars = ars.Tail()
		}
		n, err := dst.WriteFromBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:done])))
		if err != nil {
			return int64(n), err
		}
		// Do not convert errors returned by dst to EFAULT.
		return int64(n), bufErr
	}

	// Go through internal mappings.
	return mm.withVecInternalMappings(ctx, ars, usermem.Read, opts.IgnorePermissions, dst.WriteFromBlocks)
}

// SwapUint32 implements usermem.IO.SwapUint32.
func (mm *MemoryManager) SwapUint32(ctx context.Context, addr usermem.Addr, new uint32, opts usermem.IOOpts) (uint32, error) {
	ar, ok := mm.CheckIORange(addr, 4)
	if !ok {
		return 0, syserror.EFAULT
	}

	// Do AddressSpace IO if applicable.
	if mm.haveASIO && opts.AddressSpaceActive && !opts.IgnorePermissions {
		for {
			old, err := mm.as.SwapUint32(addr, new)
			if err == nil {
				return old, nil
			}
			if f, ok := err.(platform.SegmentationFault); ok {
				if err := mm.handleASIOFault(ctx, f.Addr, ar, usermem.ReadWrite); err != nil {
					return 0, err
				}
				continue
			}
			return 0, translateIOError(ctx, err)
		}
	}

	// Go through internal mappings.
	var old uint32
	_, err := mm.withInternalMappings(ctx, ar, usermem.ReadWrite, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBlocks() != 1 || ims.NumBytes() != 4 {
			// Atomicity is unachievable across mappings.
			return 0, syserror.EFAULT
		}
		im := ims.Head()
		var err error
		old, err = safemem.SwapUint32(im, new)
		if err != nil {
			return 0, translateIOError(ctx, err)
		}
		return 4, nil
	})
	return old, err
}

// CompareAndSwapUint32 implements usermem.IO.CompareAndSwapUint32.
func (mm *MemoryManager) CompareAndSwapUint32(ctx context.Context, addr usermem.Addr, old, new uint32, opts usermem.IOOpts) (uint32, error) {
	ar, ok := mm.CheckIORange(addr, 4)
	if !ok {
		return 0, syserror.EFAULT
	}

	// Do AddressSpace IO if applicable.
	if mm.haveASIO && opts.AddressSpaceActive && !opts.IgnorePermissions {
		for {
			prev, err := mm.as.CompareAndSwapUint32(addr, old, new)
			if err == nil {
				return prev, nil
			}
			if f, ok := err.(platform.SegmentationFault); ok {
				if err := mm.handleASIOFault(ctx, f.Addr, ar, usermem.ReadWrite); err != nil {
					return 0, err
				}
				continue
			}
			return 0, translateIOError(ctx, err)
		}
	}

	// Go through internal mappings.
	var prev uint32
	_, err := mm.withInternalMappings(ctx, ar, usermem.ReadWrite, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBlocks() != 1 || ims.NumBytes() != 4 {
			// Atomicity is unachievable across mappings.
			return 0, syserror.EFAULT
		}
		im := ims.Head()
		var err error
		prev, err = safemem.CompareAndSwapUint32(im, old, new)
		if err != nil {
			return 0, translateIOError(ctx, err)
		}
		return 4, nil
	})
	return prev, err
}

// handleASIOFault handles a page fault at address addr for an AddressSpaceIO
// operation spanning ioar.
//
// Preconditions: mm.as != nil. ioar.Length() != 0. ioar.Contains(addr).
func (mm *MemoryManager) handleASIOFault(ctx context.Context, addr usermem.Addr, ioar usermem.AddrRange, at usermem.AccessType) error {
	// Try to map all remaining pages in the I/O operation. This RoundUp can't
	// overflow because otherwise it would have been caught by CheckIORange.
	end, _ := ioar.End.RoundUp()
	ar := usermem.AddrRange{addr.RoundDown(), end}

	// Don't bother trying existingPMAsLocked; in most cases, if we did have
	// existing pmas, we wouldn't have faulted.

	// Ensure that we have usable vmas. Here and below, only return early if we
	// can't map the first (faulting) page; failure to map later pages are
	// silently ignored. This maximizes partial success.
	mm.mappingMu.RLock()
	vseg, vend, err := mm.getVMAsLocked(ctx, ar, at, false)
	if vendaddr := vend.Start(); vendaddr < ar.End {
		if vendaddr <= ar.Start {
			mm.mappingMu.RUnlock()
			return translateIOError(ctx, err)
		}
		ar.End = vendaddr
	}

	// Ensure that we have usable pmas.
	mm.activeMu.Lock()
	pseg, pend, err := mm.getPMAsLocked(ctx, vseg, ar, pmaOpts{
		breakCOW: at.Write,
	})
	mm.mappingMu.RUnlock()
	if pendaddr := pend.Start(); pendaddr < ar.End {
		if pendaddr <= ar.Start {
			mm.activeMu.Unlock()
			return translateIOError(ctx, err)
		}
		ar.End = pendaddr
	}

	// Downgrade to a read-lock on activeMu since we don't need to mutate pmas
	// anymore.
	mm.activeMu.DowngradeLock()

	err = mm.mapASLocked(pseg, ar, false)
	mm.activeMu.RUnlock()
	return translateIOError(ctx, err)
}

// withInternalMappings ensures that pmas exist for all addresses in ar,
// support access of type (at, ignorePermissions), and have internal mappings
// cached. It then calls f with mm.activeMu locked for reading, passing
// internal mappings for the subrange of ar for which this property holds.
//
// withInternalMappings takes a function returning uint64 since many safemem
// functions have this property, but returns an int64 since this is usually
// more useful for usermem.IO methods.
//
// Preconditions: 0 < ar.Length() <= math.MaxInt64.
func (mm *MemoryManager) withInternalMappings(ctx context.Context, ar usermem.AddrRange, at usermem.AccessType, ignorePermissions bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	po := pmaOpts{
		breakCOW: at.Write,
	}

	// If pmas are already available, we can do IO without touching mm.vmas or
	// mm.mappingMu.
	mm.activeMu.RLock()
	if pseg := mm.existingPMAsLocked(ar, at, ignorePermissions, po, true /* needInternalMappings */); pseg.Ok() {
		n, err := f(mm.internalMappingsLocked(pseg, ar))
		mm.activeMu.RUnlock()
		// Do not convert errors returned by f to EFAULT.
		return int64(n), err
	}
	mm.activeMu.RUnlock()

	// Ensure that we have usable vmas.
	mm.mappingMu.RLock()
	vseg, vend, verr := mm.getVMAsLocked(ctx, ar, at, ignorePermissions)
	if vendaddr := vend.Start(); vendaddr < ar.End {
		if vendaddr <= ar.Start {
			mm.mappingMu.RUnlock()
			return 0, translateIOError(ctx, verr)
		}
		ar.End = vendaddr
	}

	// Ensure that we have usable pmas.
	mm.activeMu.Lock()
	pseg, pend, perr := mm.getPMAsLocked(ctx, vseg, ar, po)
	mm.mappingMu.RUnlock()
	if pendaddr := pend.Start(); pendaddr < ar.End {
		if pendaddr <= ar.Start {
			mm.activeMu.Unlock()
			return 0, translateIOError(ctx, perr)
		}
		ar.End = pendaddr
	}
	imend, imerr := mm.getPMAInternalMappingsLocked(pseg, ar)
	mm.activeMu.DowngradeLock()
	if imendaddr := imend.Start(); imendaddr < ar.End {
		if imendaddr <= ar.Start {
			mm.activeMu.RUnlock()
			return 0, translateIOError(ctx, imerr)
		}
		ar.End = imendaddr
	}

	// Do I/O.
	un, err := f(mm.internalMappingsLocked(pseg, ar))
	mm.activeMu.RUnlock()
	n := int64(un)

	// Return the first error in order of progress through ar.
	if err != nil {
		// Do not convert errors returned by f to EFAULT.
		return n, err
	}
	if imerr != nil {
		return n, translateIOError(ctx, imerr)
	}
	if perr != nil {
		return n, translateIOError(ctx, perr)
	}
	return n, translateIOError(ctx, verr)
}

// withVecInternalMappings ensures that pmas exist for all addresses in ars,
// support access of type (at, ignorePermissions), and have internal mappings
// cached. It then calls f with mm.activeMu locked for reading, passing
// internal mappings for the subset of ars for which this property holds.
//
// Preconditions: !ars.IsEmpty().
func (mm *MemoryManager) withVecInternalMappings(ctx context.Context, ars usermem.AddrRangeSeq, at usermem.AccessType, ignorePermissions bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// withInternalMappings is faster than withVecInternalMappings because of
	// iterator plumbing (this isn't generally practical in the vector case due
	// to iterator invalidation between AddrRanges). Use it if possible.
	if ars.NumRanges() == 1 {
		return mm.withInternalMappings(ctx, ars.Head(), at, ignorePermissions, f)
	}

	po := pmaOpts{
		breakCOW: at.Write,
	}

	// If pmas are already available, we can do IO without touching mm.vmas or
	// mm.mappingMu.
	mm.activeMu.RLock()
	if mm.existingVecPMAsLocked(ars, at, ignorePermissions, po, true /* needInternalMappings */) {
		n, err := f(mm.vecInternalMappingsLocked(ars))
		mm.activeMu.RUnlock()
		// Do not convert errors returned by f to EFAULT.
		return int64(n), err
	}
	mm.activeMu.RUnlock()

	// Ensure that we have usable vmas.
	mm.mappingMu.RLock()
	vars, verr := mm.getVecVMAsLocked(ctx, ars, at, ignorePermissions)
	if vars.NumBytes() == 0 {
		mm.mappingMu.RUnlock()
		return 0, translateIOError(ctx, verr)
	}

	// Ensure that we have usable pmas.
	mm.activeMu.Lock()
	pars, perr := mm.getVecPMAsLocked(ctx, vars, po)
	mm.mappingMu.RUnlock()
	if pars.NumBytes() == 0 {
		mm.activeMu.Unlock()
		return 0, translateIOError(ctx, perr)
	}
	imars, imerr := mm.getVecPMAInternalMappingsLocked(pars)
	mm.activeMu.DowngradeLock()
	if imars.NumBytes() == 0 {
		mm.activeMu.RUnlock()
		return 0, translateIOError(ctx, imerr)
	}

	// Do I/O.
	un, err := f(mm.vecInternalMappingsLocked(imars))
	mm.activeMu.RUnlock()
	n := int64(un)

	// Return the first error in order of progress through ars.
	if err != nil {
		// Do not convert errors from f to EFAULT.
		return n, err
	}
	if imerr != nil {
		return n, translateIOError(ctx, imerr)
	}
	if perr != nil {
		return n, translateIOError(ctx, perr)
	}
	return n, translateIOError(ctx, verr)
}

// truncatedAddrRangeSeq returns a copy of ars, but with the end truncated to
// at most address end on AddrRange arsit.Head(). It is used in vector I/O paths to
// truncate usermem.AddrRangeSeq when errors occur.
//
// Preconditions: !arsit.IsEmpty(). end <= arsit.Head().End.
func truncatedAddrRangeSeq(ars, arsit usermem.AddrRangeSeq, end usermem.Addr) usermem.AddrRangeSeq {
	ar := arsit.Head()
	if end <= ar.Start {
		return ars.TakeFirst64(ars.NumBytes() - arsit.NumBytes())
	}
	return ars.TakeFirst64(ars.NumBytes() - arsit.NumBytes() + int64(end-ar.Start))
}
