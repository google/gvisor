// Copyright 2024 The gVisor Authors.
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

package nvproxy

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MapInternal implements memmap.File.MapInternal.
func (mf *frontendFDMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}

	mf.mmapMu.Lock()
	defer mf.mmapMu.Unlock()
	if mf.mmapInternal == 0 {
		if mf.mmapLength == 0 {
			// This shouldn't be possible.
			log.Traceback("nvproxy: frontendFDMemmapFile.MapInternal() called before NV_ESC_RM_MAP_MEMORY or NV_ESC_RM_ALLOC_MEMORY+NV01_MEMORY_SYSTEM")
			return safemem.BlockSeq{}, linuxerr.EINVAL
		}
		// Nvidia kernel driver:
		// kernel-open/nvidia/nv-mmap.c:nvidia_mmap_helper() requires vm_pgoff
		// == 0 (so we must pass offset 0 here), and conditionally requires
		// NV_VMA_SIZE(vma) == mmap_context->mmap_size (so we pass length
		// mmapLength here).
		m, _, errno := unix.Syscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(mf.mmapLength), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(mf.hostFD), 0 /* offset */)
		if errno != 0 {
			return safemem.BlockSeq{}, errno
		}
		mf.mmapInternal = m
	}
	mappedFR := memmap.FileRange{0, hostarch.MustPageRoundUp(mf.mmapLength)}
	if !mappedFR.IsSupersetOf(fr) {
		return safemem.BlockSeq{}, linuxerr.EINVAL
	}
	// mmap_context::prot is determined internally during NV_ESC_RM_MAP_MEMORY
	// (see
	// src/nvidia/arch/nvalloc/unix/src/osapi.c:RmCreateMmapContextLocked());
	// nvidia_mmap_helper() propagates this to vm_area_struct::vm_page_prot, so
	// PROT_WRITE on a read-only mapping will succeed at mmap time but fault at
	// write time. Thus, these mappings should use safecopy (i.e.
	// BlockFromUnsafePointer rather than BlockFromSafePointer).
	return safemem.BlockSeqOf(safemem.BlockFromUnsafePointer(unsafe.Pointer(mf.mmapInternal+uintptr(fr.Start)), int(fr.Length()))), nil
}

// isClosed returns true if mf has been closed, after which it no longer maps
// memory.
func (mf *frontendFDMemmapFile) isClosed() bool {
	mf.mmapMu.Lock()
	defer mf.mmapMu.Unlock()
	return mf.closed
}

// storeUint32s makes stores in order to the memory that mf maps, at offsets
// from off. Each store is a single 32-bit write, made visible before the
// next. A store that faults, as one to a mapping without write access does,
// or that is not 4-byte aligned, ends the sequence.
func (mf *frontendFDMemmapFile) storeUint32s(off uint64, stores []uint32Store) {
	mf.mmapMu.Lock()
	defer mf.mmapMu.Unlock()
	if mf.closed || mf.mmapLength == 0 || off > mf.mmapLength || !canSwapUint32(mf.memType) {
		return
	}
	if mf.mmapInternal == 0 {
		// See MapInternal.
		m, _, errno := unix.Syscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(mf.mmapLength), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(mf.hostFD), 0 /* offset */)
		if errno != 0 {
			if log.IsLogging(log.Debug) {
				log.Debugf("nvproxy: failed to map memory for a timed semaphore release: %v", errno)
			}
			return
		}
		mf.mmapInternal = m
	}
	for _, s := range stores {
		if s.off+4 > mf.mmapLength-off {
			return
		}
		p := unsafe.Pointer(mf.mmapInternal + uintptr(off+s.off))
		// SwapUint32 is a single 32-bit store, where CopyOut may store
		// smaller pieces. An unaligned structure, which RM would write with
		// unaligned stores, is not written.
		if uintptr(p)%4 != 0 {
			return
		}
		if _, err := safecopy.SwapUint32(p, s.value); err != nil {
			if log.IsLogging(log.Debug) {
				log.Debugf("nvproxy: failed to write a timed semaphore release: %v", err)
			}
			return
		}
	}
}
