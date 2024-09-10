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
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MapInternal implements memmap.File.MapInternal.
func (mf *frontendFDMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}

	mf.fd.mmapMu.Lock()
	defer mf.fd.mmapMu.Unlock()
	if mf.fd.mmapInternal == 0 {
		if mf.fd.mmapLength == 0 {
			// This shouldn't be possible.
			log.Traceback("nvproxy: frontendFDMemmapFile.MapInternal() called before NV_ESC_RM_MAP_MEMORY")
			return safemem.BlockSeq{}, linuxerr.EINVAL
		}
		// Nvidia kernel driver:
		// kernel-open/nvidia/nv-mmap.c:nvidia_mmap_helper() requires vm_pgoff
		// == 0 (so we must pass offset 0 here), and conditionally requires
		// NV_VMA_SIZE(vma) == mmap_context->mmap_size (so we pass length
		// mmapLength here).
		m, _, errno := unix.Syscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(mf.fd.mmapLength), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(mf.fd.hostFD), 0 /* offset */)
		if errno != 0 {
			return safemem.BlockSeq{}, errno
		}
		mf.fd.mmapInternal = m
	}
	mappedFR := memmap.FileRange{0, mf.fd.mmapLength}
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
	return safemem.BlockSeqOf(safemem.BlockFromUnsafePointer(unsafe.Pointer(mf.fd.mmapInternal+uintptr(fr.Start)), int(fr.Length()))), nil
}
