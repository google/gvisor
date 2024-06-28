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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// There are two supported ways to copy data to/from application virtual
// memory:
//
// 1. Internally-mapped copying: Determine the memmap.File that backs the
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

// CheckIORange is similar to hostarch.Addr.ToRange, but applies bounds checks
// consistent with Linux's arch/x86/include/asm/uaccess.h:access_ok().
//
// Preconditions: length >= 0.
func (mm *MemoryManager) CheckIORange(addr hostarch.Addr, length int64) (hostarch.AddrRange, bool) {
	// Note that access_ok() constrains end even if length == 0.
	ar, ok := addr.ToRange(uint64(length))
	return ar, (ok && ar.End <= mm.layout.MaxAddr)
}

// checkIOVec applies bound checks consistent with Linux's
// arch/x86/include/asm/uaccess.h:access_ok() to ars.
func (mm *MemoryManager) checkIOVec(ars hostarch.AddrRangeSeq) bool {
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
	return linuxerr.EFAULT
}

// CopyOut implements usermem.IO.CopyOut.
func (mm *MemoryManager) CopyOut(ctx context.Context, addr hostarch.Addr, src []byte, opts usermem.IOOpts) (int, error) {
	ar, ok := mm.CheckIORange(addr, int64(len(src)))
	if !ok {
		return 0, linuxerr.EFAULT
	}

	if len(src) == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && len(src) < copyMapMinBytes {
		return mm.asCopyOut(ctx, addr, src)
	}

	// Go through internal mappings.
	// NOTE(gvisor.dev/issue/10331): Using mm.withInternalMappings() here means
	// that if we encounter any memmap.BufferedIOFallbackErrs, this copy will
	// traverse an unnecessary layer of buffering. This can be fixed by
	// inlining mm.withInternalMappings() and passing src subslices directly to
	// memmap.File.BufferWriteAt().
	n64, err := mm.withInternalMappings(ctx, ar, hostarch.Write, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		n, err := safemem.CopySeq(ims, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(src)))
		return n, translateIOError(ctx, err)
	})
	return int(n64), err
}

func (mm *MemoryManager) asCopyOut(ctx context.Context, addr hostarch.Addr, src []byte) (int, error) {
	var done int
	for {
		n, err := mm.as.CopyOut(addr+hostarch.Addr(done), src[done:])
		done += n
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(len(src)))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.Write); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// CopyIn implements usermem.IO.CopyIn.
func (mm *MemoryManager) CopyIn(ctx context.Context, addr hostarch.Addr, dst []byte, opts usermem.IOOpts) (int, error) {
	ar, ok := mm.CheckIORange(addr, int64(len(dst)))
	if !ok {
		return 0, linuxerr.EFAULT
	}

	if len(dst) == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && len(dst) < copyMapMinBytes {
		return mm.asCopyIn(ctx, addr, dst)
	}

	// Go through internal mappings.
	// NOTE(gvisor.dev/issue/10331): Using mm.withInternalMappings() here means
	// that if we encounter any memmap.BufferedIOFallbackErrs, this copy will
	// traverse an unnecessary layer of buffering. This can be fixed by
	// inlining mm.withInternalMappings() and passing dst subslices directly to
	// memmap.File.BufferReadAt().
	n64, err := mm.withInternalMappings(ctx, ar, hostarch.Read, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		n, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(dst)), ims)
		return n, translateIOError(ctx, err)
	})
	return int(n64), err
}

func (mm *MemoryManager) asCopyIn(ctx context.Context, addr hostarch.Addr, dst []byte) (int, error) {
	var done int
	for {
		n, err := mm.as.CopyIn(addr+hostarch.Addr(done), dst[done:])
		done += n
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(len(dst)))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.Read); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// ZeroOut implements usermem.IO.ZeroOut.
func (mm *MemoryManager) ZeroOut(ctx context.Context, addr hostarch.Addr, toZero int64, opts usermem.IOOpts) (int64, error) {
	ar, ok := mm.CheckIORange(addr, toZero)
	if !ok {
		return 0, linuxerr.EFAULT
	}

	if toZero == 0 {
		return 0, nil
	}

	// Do AddressSpace IO if applicable.
	if mm.asioEnabled(opts) && toZero < copyMapMinBytes {
		return mm.asZeroOut(ctx, addr, toZero)
	}

	// Go through internal mappings.
	return mm.withInternalMappings(ctx, ar, hostarch.Write, opts.IgnorePermissions, func(dsts safemem.BlockSeq) (uint64, error) {
		n, err := safemem.ZeroSeq(dsts)
		return n, translateIOError(ctx, err)
	})
}

func (mm *MemoryManager) asZeroOut(ctx context.Context, addr hostarch.Addr, toZero int64) (int64, error) {
	var done int64
	for {
		n, err := mm.as.ZeroOut(addr+hostarch.Addr(done), uintptr(toZero-done))
		done += int64(n)
		if err == nil {
			return done, nil
		}
		if f, ok := err.(platform.SegmentationFault); ok {
			ar, _ := addr.ToRange(uint64(toZero))
			if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.Write); err != nil {
				return done, err
			}
			continue
		}
		return done, translateIOError(ctx, err)
	}
}

// CopyOutFrom implements usermem.IO.CopyOutFrom.
func (mm *MemoryManager) CopyOutFrom(ctx context.Context, ars hostarch.AddrRangeSeq, src safemem.Reader, opts usermem.IOOpts) (int64, error) {
	if !mm.checkIOVec(ars) {
		return 0, linuxerr.EFAULT
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
	return mm.withVecInternalMappings(ctx, ars, hostarch.Write, opts.IgnorePermissions, src.ReadToBlocks)
}

// CopyInTo implements usermem.IO.CopyInTo.
func (mm *MemoryManager) CopyInTo(ctx context.Context, ars hostarch.AddrRangeSeq, dst safemem.Writer, opts usermem.IOOpts) (int64, error) {
	if !mm.checkIOVec(ars) {
		return 0, linuxerr.EFAULT
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
	return mm.withVecInternalMappings(ctx, ars, hostarch.Read, opts.IgnorePermissions, dst.WriteFromBlocks)
}

// EnsurePMAsExist attempts to ensure that PMAs exist for the given addr with the
// requested length. It returns the length to which it was able to either
// initialize PMAs for, or ascertain that PMAs exist for. If this length is
// smaller than the requested length it returns an error explaining why.
func (mm *MemoryManager) EnsurePMAsExist(ctx context.Context, addr hostarch.Addr, length int64, opts usermem.IOOpts) (int64, error) {
	ar, ok := mm.CheckIORange(addr, length)
	if !ok {
		return 0, linuxerr.EFAULT
	}
	n64, err := mm.withInternalMappings(ctx, ar, hostarch.Write, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		return uint64(ims.NumBytes()), nil
	})
	return int64(n64), err
}

// SwapUint32 implements usermem.IO.SwapUint32.
func (mm *MemoryManager) SwapUint32(ctx context.Context, addr hostarch.Addr, new uint32, opts usermem.IOOpts) (uint32, error) {
	ar, ok := mm.CheckIORange(addr, 4)
	if !ok {
		return 0, linuxerr.EFAULT
	}

	// Do AddressSpace IO if applicable.
	if mm.haveASIO && opts.AddressSpaceActive && !opts.IgnorePermissions {
		for {
			old, err := mm.as.SwapUint32(addr, new)
			if err == nil {
				return old, nil
			}
			if f, ok := err.(platform.SegmentationFault); ok {
				if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.ReadWrite); err != nil {
					return 0, err
				}
				continue
			}
			return 0, translateIOError(ctx, err)
		}
	}

	// Go through internal mappings.
	var old uint32
	_, err := mm.withInternalMappings(ctx, ar, hostarch.ReadWrite, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBlocks() != 1 || ims.NumBytes() != 4 {
			// Atomicity is unachievable across mappings.
			return 0, linuxerr.EFAULT
		}
		im := ims.Head()
		var err error
		old, err = safemem.SwapUint32(im, new)
		if err != nil {
			return 0, translateIOError(ctx, err)
		}
		// Return the number of bytes read.
		return 4, nil
	})
	return old, err
}

// CompareAndSwapUint32 implements usermem.IO.CompareAndSwapUint32.
func (mm *MemoryManager) CompareAndSwapUint32(ctx context.Context, addr hostarch.Addr, old, new uint32, opts usermem.IOOpts) (uint32, error) {
	ar, ok := mm.CheckIORange(addr, 4)
	if !ok {
		return 0, linuxerr.EFAULT
	}

	// Do AddressSpace IO if applicable.
	if mm.haveASIO && opts.AddressSpaceActive && !opts.IgnorePermissions {
		for {
			prev, err := mm.as.CompareAndSwapUint32(addr, old, new)
			if err == nil {
				return prev, nil
			}
			if f, ok := err.(platform.SegmentationFault); ok {
				if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.ReadWrite); err != nil {
					return 0, err
				}
				continue
			}
			return 0, translateIOError(ctx, err)
		}
	}

	// Go through internal mappings.
	var prev uint32
	_, err := mm.withInternalMappings(ctx, ar, hostarch.ReadWrite, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBlocks() != 1 || ims.NumBytes() != 4 {
			// Atomicity is unachievable across mappings.
			return 0, linuxerr.EFAULT
		}
		im := ims.Head()
		var err error
		prev, err = safemem.CompareAndSwapUint32(im, old, new)
		if err != nil {
			return 0, translateIOError(ctx, err)
		}
		// Return the number of bytes read.
		return 4, nil
	})
	return prev, err
}

// LoadUint32 implements usermem.IO.LoadUint32.
func (mm *MemoryManager) LoadUint32(ctx context.Context, addr hostarch.Addr, opts usermem.IOOpts) (uint32, error) {
	ar, ok := mm.CheckIORange(addr, 4)
	if !ok {
		return 0, linuxerr.EFAULT
	}

	// Do AddressSpace IO if applicable.
	if mm.haveASIO && opts.AddressSpaceActive && !opts.IgnorePermissions {
		for {
			val, err := mm.as.LoadUint32(addr)
			if err == nil {
				return val, nil
			}
			if f, ok := err.(platform.SegmentationFault); ok {
				if err := mm.handleASIOFault(ctx, f.Addr, ar, hostarch.Read); err != nil {
					return 0, err
				}
				continue
			}
			return 0, translateIOError(ctx, err)
		}
	}

	// Go through internal mappings.
	var val uint32
	_, err := mm.withInternalMappings(ctx, ar, hostarch.Read, opts.IgnorePermissions, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBlocks() != 1 || ims.NumBytes() != 4 {
			// Atomicity is unachievable across mappings.
			return 0, linuxerr.EFAULT
		}
		im := ims.Head()
		var err error
		val, err = safemem.LoadUint32(im)
		if err != nil {
			return 0, translateIOError(ctx, err)
		}
		// Return the number of bytes read.
		return 4, nil
	})
	return val, err
}

// handleASIOFault handles a page fault at address addr for an AddressSpaceIO
// operation spanning ioar.
//
// Preconditions:
//   - mm.as != nil.
//   - ioar.Length() != 0.
//   - ioar.Contains(addr).
func (mm *MemoryManager) handleASIOFault(ctx context.Context, addr hostarch.Addr, ioar hostarch.AddrRange, at hostarch.AccessType) error {
	// Try to map all remaining pages in the I/O operation. This RoundUp can't
	// overflow because otherwise it would have been caught by CheckIORange.
	end, _ := ioar.End.RoundUp()
	ar := hostarch.AddrRange{addr.RoundDown(), end}

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
	pseg, pend, err := mm.getPMAsLocked(ctx, vseg, ar, at, true /* callerIndirectCommit */)
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

	err = mm.mapASLocked(pseg, ar, memmap.PlatformEffectDefault)
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
func (mm *MemoryManager) withInternalMappings(ctx context.Context, ar hostarch.AddrRange, at hostarch.AccessType, ignorePermissions bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// If pmas are already available, we can do IO without touching mm.vmas or
	// mm.mappingMu.
	mm.activeMu.RLock()
	if pseg := mm.existingPMAsLocked(ar, at, ignorePermissions, true /* needInternalMappings */); pseg.Ok() {
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
	pseg, pend, perr := mm.getPMAsLocked(ctx, vseg, ar, at, true /* callerIndirectCommit */)
	mm.mappingMu.RUnlock()
	if pendaddr := pend.Start(); pendaddr < ar.End {
		if pendaddr <= ar.Start {
			mm.activeMu.Unlock()
			return 0, translateIOError(ctx, perr)
		}
		ar.End = pendaddr
	}
	imbs, t, imerr := mm.getIOMappingsLocked(pseg, ar, at)
	mm.activeMu.DowngradeLock()
	if imlen := imbs.NumBytes(); imlen < uint64(ar.Length()) {
		if imlen == 0 {
			t.flush(0, nil)
			mm.activeMu.RUnlock()
			return 0, translateIOError(ctx, imerr)
		}
		ar.End = ar.Start + hostarch.Addr(imlen)
	}

	// Do I/O.
	un, err := t.flush(f(imbs))
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
func (mm *MemoryManager) withVecInternalMappings(ctx context.Context, ars hostarch.AddrRangeSeq, at hostarch.AccessType, ignorePermissions bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// withInternalMappings is faster than withVecInternalMappings because of
	// iterator plumbing (this isn't generally practical in the vector case due
	// to iterator invalidation between AddrRanges). Use it if possible.
	if ars.NumRanges() == 1 {
		return mm.withInternalMappings(ctx, ars.Head(), at, ignorePermissions, f)
	}

	// If pmas are already available, we can do IO without touching mm.vmas or
	// mm.mappingMu.
	mm.activeMu.RLock()
	if mm.existingVecPMAsLocked(ars, at, ignorePermissions, true /* needInternalMappings */) {
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
	pars, perr := mm.getVecPMAsLocked(ctx, vars, at, true /* callerIndirectCommit */)
	mm.mappingMu.RUnlock()
	if pars.NumBytes() == 0 {
		mm.activeMu.Unlock()
		return 0, translateIOError(ctx, perr)
	}
	imbs, t, imerr := mm.getVecIOMappingsLocked(pars, at)
	mm.activeMu.DowngradeLock()
	if imbs.NumBytes() == 0 {
		t.flush(0, nil)
		mm.activeMu.RUnlock()
		return 0, translateIOError(ctx, imerr)
	}

	// Do I/O.
	un, err := t.flush(f(imbs))
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

// getIOMappingsLocked returns internal mappings appropriate for I/O for
// addresses in ar. If mappings are only available for a strict subset of ar,
// the returned error is non-nil.
//
// ioBufTracker.flush() must be called on the returned ioBufTracker when the
// returned mappings are no longer in use, and its return value indicates the
// number of bytes actually completed after buffer flushing. Returned mappings
// are valid until either mm.activeMu is unlocked or ioBufTracker.flush() is
// called.
//
// Preconditions:
//   - mm.activeMu must be locked for writing.
//   - pseg.Range().Contains(ar.Start).
//   - pmas must exist for all addresses in ar.
//   - ar.Length() != 0.
//
// Postconditions: getIOMappingsLocked does not invalidate iterators into mm.pmas.
func (mm *MemoryManager) getIOMappingsLocked(pseg pmaIterator, ar hostarch.AddrRange, at hostarch.AccessType) (safemem.BlockSeq, *ioBufTracker, error) {
	if checkInvariants {
		if !ar.WellFormed() || ar.Length() == 0 {
			panic(fmt.Sprintf("invalid ar: %v", ar))
		}
		if !pseg.Range().Contains(ar.Start) {
			panic(fmt.Sprintf("initial pma %v does not cover start of ar %v", pseg.Range(), ar))
		}
	}

	if ar.End <= pseg.End() {
		// Since only one pma is involved, we can use pma.internalMappings
		// directly, avoiding a slice allocation.
		if err := pseg.getInternalMappingsLocked(); err != nil {
			if _, ok := err.(memmap.BufferedIOFallbackErr); ok {
				goto slowPath
			}
			return safemem.BlockSeq{}, nil, err
		}
		offset := uint64(ar.Start - pseg.Start())
		return pseg.ValuePtr().internalMappings.DropFirst64(offset).TakeFirst64(uint64(ar.Length())), nil, nil
	}

slowPath:
	ims, t, _, err := mm.getIOMappingsTrackedLocked(pseg, ar, at, nil, nil, 0)
	return safemem.BlockSeqFromSlice(ims), t, err
}

// getVecIOMappingsLocked returns internal mappings appropriate for I/O for
// addresses in ars. If mappings are only available for a strict subset of ar,
// the returned error is non-nil.
//
// ioBufTracker.flush() must be called on the returned ioBufTracker when the
// returned mappings are no longer in use, and its return value indicates the
// number of bytes actually completed after buffer flushing. Returned mappings
// are valid until either mm.activeMu is unlocked or ioBufTracker.flush() is
// called.
//
// Preconditions:
//   - mm.activeMu must be locked for writing.
//   - pmas must exist for all addresses in ar.
//
// Postconditions: getVecIOMappingsLocked does not invalidate iterators into
// mm.pmas
func (mm *MemoryManager) getVecIOMappingsLocked(ars hostarch.AddrRangeSeq, at hostarch.AccessType) (safemem.BlockSeq, *ioBufTracker, error) {
	if ars.NumRanges() == 1 {
		ar := ars.Head()
		return mm.getIOMappingsLocked(mm.pmas.FindSegment(ar.Start), ar, at)
	}

	var ims []safemem.Block
	var t *ioBufTracker
	unbufBytes := uint64(0)
	for arsit := ars; !arsit.IsEmpty(); arsit = arsit.Tail() {
		ar := arsit.Head()
		if ar.Length() == 0 {
			continue
		}
		var err error
		ims, t, unbufBytes, err = mm.getIOMappingsTrackedLocked(mm.pmas.FindSegment(ar.Start), ar, at, ims, t, unbufBytes)
		if err != nil {
			return safemem.BlockSeqFromSlice(ims), t, err
		}
	}
	return safemem.BlockSeqFromSlice(ims), t, nil
}

// getIOMappingsTrackedLocked collects internal mappings appropriate for I/O
// for addresses in ar, appends them to ims, and returns an updated slice. If
// mappings are only available for a strict subset of ar, the returned error is
// non-nil.
//
// If any iterated memmap.Files require buffering for I/O, they are recorded in
// an ioBufTracker. Since the ioBufTracker pointer is initially nil (to
// minimize overhead for the common case where no memmap.files require
// buffering for I/O), getIOMappingsTrackedLocked returns an updated
// ioBufTracker pointer.
//
// unbufBytes is the number of bytes of unbuffered mappings that have been
// appended to ims since the last buffered mapping; getIOMappingsTrackedLocked
// also returns an updated value for unbufBytes.
//
// Returned mappings are valid until either mm.activeMu is unlocked or
// ioBufTracker.flush() is called.
//
// Preconditions:
//   - mm.activeMu must be locked for writing.
//   - pseg.Range().Contains(ar.Start).
//   - pmas must exist for all addresses in ar.
//   - ar.Length() != 0.
//
// Postconditions: getIOMappingsTrackedLocked does not invalidate iterators
// into mm.pmas.
func (mm *MemoryManager) getIOMappingsTrackedLocked(pseg pmaIterator, ar hostarch.AddrRange, at hostarch.AccessType, ims []safemem.Block, t *ioBufTracker, unbufBytes uint64) ([]safemem.Block, *ioBufTracker, uint64, error) {
	for {
		pmaAR := ar.Intersect(pseg.Range())
		if err := pseg.getInternalMappingsLocked(); err == nil {
			// Iterate the subset of the PMA's cached internal mappings that
			// correspond to pmaAR, and append them to ims.
			for pims := pseg.ValuePtr().internalMappings.DropFirst64(uint64(pmaAR.Start - pseg.Start())).TakeFirst64(uint64(pmaAR.Length())); !pims.IsEmpty(); pims = pims.Tail() {
				ims = append(ims, pims.Head())
			}
			unbufBytes += uint64(pmaAR.Length())
		} else if _, ok := err.(memmap.BufferedIOFallbackErr); !ok {
			return ims, t, unbufBytes, err
		} else {
			// Fall back to buffered I/O as instructed.
			if t == nil {
				t = getIOBufTracker(at.Write)
			}
			buf := getByteSlicePtr(int(pmaAR.Length()))
			pma := pseg.ValuePtr()
			off := pseg.fileRangeOf(pmaAR).Start
			// If the caller will read from the buffer, fill it from the file;
			// otherwise leave it zeroed.
			if at.Read || at.Execute {
				var n uint64
				n, err = pma.file.BufferReadAt(off, *buf)
				*buf = (*buf)[:n]
			} else {
				err = nil
			}
			if len(*buf) != 0 {
				ims = append(ims, safemem.BlockFromSafeSlice(*buf))
				t.bufs = append(t.bufs, ioBuf{
					unbufBytesBefore: unbufBytes,
					file:             pma.file,
					off:              off,
					buf:              buf,
				})
				unbufBytes = 0
			}
			if err != nil {
				return ims, t, unbufBytes, err
			}
		}
		if ar.End <= pseg.End() {
			return ims, t, unbufBytes, nil
		}
		pseg, _ = pseg.NextNonEmpty()
	}
}

type ioBuf struct {
	unbufBytesBefore uint64
	file             memmap.File
	off              uint64
	buf              *[]byte
}

type ioBufTracker struct {
	write bool
	bufs  []ioBuf
}

var ioBufTrackerPool = sync.Pool{
	New: func() any {
		return &ioBufTracker{}
	},
}

func getIOBufTracker(write bool) *ioBufTracker {
	t := ioBufTrackerPool.Get().(*ioBufTracker)
	t.write = write
	return t
}

func putIOBufTracker(t *ioBufTracker) {
	for i := range t.bufs {
		t.bufs[i].file = nil
		putByteSlicePtr(t.bufs[i].buf)
		t.bufs[i].buf = nil
	}
	t.bufs = t.bufs[:0]
	ioBufTrackerPool.Put(t)
}

func (t *ioBufTracker) flush(prevN uint64, prevErr error) (uint64, error) {
	if t == nil {
		return prevN, prevErr
	}
	return t.flushSlow(prevN, prevErr)
}

func (t *ioBufTracker) flushSlow(prevN uint64, prevErr error) (uint64, error) {
	defer putIOBufTracker(t)
	if !t.write {
		return prevN, prevErr
	}
	// Flush dirty buffers to underlying memmap.Files.
	rem := prevN
	done := uint64(0)
	for i := range t.bufs {
		buf := &t.bufs[i]
		if rem <= buf.unbufBytesBefore {
			// The write ended before reaching buf.buf.
			break
		}
		rem -= buf.unbufBytesBefore
		done += buf.unbufBytesBefore
		n, err := buf.file.BufferWriteAt(buf.off, (*buf.buf)[:min(len(*buf.buf), int(rem))])
		rem -= n
		done += n
		if err != nil {
			return done, err
		}
	}
	// All buffers covered by prevN were written back successfully.
	return prevN, prevErr
}

var byteSlicePtrPool sync.Pool

// getByteSlicePtr returns a pointer to a byte slice with the given length. The
// slice is either newly-allocated or recycled from a previous call to
// putByteSlicePtr. The pointer should be passed to putByteSlicePtr when the
// slice is no longer in use.
func getByteSlicePtr(l int) *[]byte {
	a := byteSlicePtrPool.Get()
	if a == nil {
		s := make([]byte, l)
		return &s
	}
	sp := a.(*[]byte)
	s := *sp
	if l <= cap(s) {
		s = s[:l]
	} else {
		s = make([]byte, l)
	}
	*sp = s
	return sp
}

// putByteSlicePtr marks all of the given's slice capacity reusable by a future
// call to getByteSlicePtr.
func putByteSlicePtr(s *[]byte) {
	byteSlicePtrPool.Put(s)
}

// truncatedAddrRangeSeq returns a copy of ars, but with the end truncated to
// at most address end on AddrRange arsit.Head(). It is used in vector I/O paths to
// truncate hostarch.AddrRangeSeq when errors occur.
//
// Preconditions:
//   - !arsit.IsEmpty().
//   - end <= arsit.Head().End.
func truncatedAddrRangeSeq(ars, arsit hostarch.AddrRangeSeq, end hostarch.Addr) hostarch.AddrRangeSeq {
	ar := arsit.Head()
	if end <= ar.Start {
		return ars.TakeFirst64(ars.NumBytes() - arsit.NumBytes())
	}
	return ars.TakeFirst64(ars.NumBytes() - arsit.NumBytes() + int64(end-ar.Start))
}
