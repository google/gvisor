// Copyright 2023 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *frontendFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	// Nvidia kernel driver: kernel-open/nvidia/nv-mmap.c:nvidia_mmap_helper()
	// requires vm_pgoff == 0, so trying to lazily fault any subset of the
	// mapping that doesn't include the beginning will fail.
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *frontendFD) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *frontendFD) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *frontendFD) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (fd *frontendFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   &fd.memmapFile,
			Offset: optional.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (fd *frontendFD) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// +stateify savable
type frontendFDMemmapFile struct {
	memmap.NoBufferedIOFallback

	fd *frontendFD
}

// IncRef implements memmap.File.IncRef.
func (mf *frontendFDMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {
}

// DecRef implements memmap.File.DecRef.
func (mf *frontendFDMemmapFile) DecRef(fr memmap.FileRange) {
}

// MemoryType implements memmap.File.MemoryType.
func (mf *frontendFDMemmapFile) MemoryType() hostarch.MemoryType {
	mf.fd.mmapMu.Lock()
	defer mf.fd.mmapMu.Unlock()
	return mf.fd.mmapMemType
}

// DataFD implements memmap.File.DataFD.
func (mf *frontendFDMemmapFile) DataFD(fr memmap.FileRange) (int, error) {
	return mf.FD(), nil
}

// FD implements memmap.File.FD.
func (mf *frontendFDMemmapFile) FD() int {
	return int(mf.fd.hostFD)
}

func getMemoryType(ctx context.Context, mapDev *frontendDevice, cachingType uint32) hostarch.MemoryType {
	// Compare kernel-open/nvidia/nv-mmap.c:nvidia_mmap_helper() =>
	// nv_encode_caching(). Each NVOS33_FLAGS_CACHING_TYPE_* corresponds
	// directly to a NV_MEMORY_*; this is checked by asserts in
	// src/nvidia/src/kernel/rmapi/mapping_cpu.c.
	if !mapDev.isCtlDevice() {
		// NOTE(gvisor.dev/issue/11436): In the !NV_IS_CTL_DEVICE() branch of
		// nvidia_mmap_helper(), mmap_context->caching is only honored if
		// IS_FB_OFFSET() and !IS_UD_OFFSET(). We can get the information we
		// need for IS_FB_OFFSET() from NV_ESC_CARD_INFO, but there doesn't
		// seem to be any way for us to replicate IS_UD_OFFSET(). So we must
		// conservatively specify uncacheable, which applies in all other
		// cases. This is unfortunate since it prevents us from using
		// write-combining on framebuffer memory. Empirically, mappings of
		// framebuffer memory seem to be fairly common, but none of our tests
		// result in any IS_UD_OFFSET (USERD?) mappings.
		if log.IsLogging(log.Debug) {
			ctx.Debugf("nvproxy: inferred memory type %v for mapping of %s", hostarch.MemoryTypeUncached, mapDev.basename())
		}
		return hostarch.MemoryTypeUncached
	}
	var memType hostarch.MemoryType
	switch cachingType {
	case nvgpu.NVOS33_FLAGS_CACHING_TYPE_CACHED, nvgpu.NVOS33_FLAGS_CACHING_TYPE_WRITEBACK:
		// Note that nv_encode_caching() doesn't actually handle
		// NV_MEMORY_WRITEBACK, so this case should fail during host mmap.
		memType = hostarch.MemoryTypeWriteBack
	case nvgpu.NVOS33_FLAGS_CACHING_TYPE_WRITECOMBINED, nvgpu.NVOS33_FLAGS_CACHING_TYPE_DEFAULT:
		// NOTE(gvisor.dev/issue/11436): In the NV_IS_CTL_DEVICE() branch of
		// nvidia_mmap_helper(), memory_type is never
		// NV_MEMORY_TYPE_FRAMEBUFFER, so this corresponds to
		// kernel-open/common/inc/nv-pgprot.h:NV_PGPROT_WRITE_COMBINED(). On
		// ARM64, NV_PGPROT_WRITE_COMBINED() => NV_PGPROT_UNCACHED() implicitly
		// uses MT_NORMAL (equivalent to our MemoryTypeWriteBack) rather than
		// MT_NORMAL_NC when nvos_is_chipset_io_coherent() =>
		// PDB_PROP_CL_IS_CHIPSET_IO_COHERENT is true, which seems to be the
		// case on most systems. We should clarify whether this is an
		// optimization or required for correctness (cf. Armv8-M Architecture
		// Reference Manual Sec. B7.16 "Mismatched memory attributes"), and
		// subsequently whether to replicate it.
		memType = hostarch.MemoryTypeWriteCombine
	case nvgpu.NVOS33_FLAGS_CACHING_TYPE_UNCACHED, nvgpu.NVOS33_FLAGS_CACHING_TYPE_UNCACHED_WEAK:
		// NOTE(gvisor.dev/issue/11436): On ARM64, nv_encode_caching()
		// distinguishes between NV_PGPROT_UNCACHED() => MT_NORMAL/MT_NORMAL_NC
		// and NV_PGPROT_UNCACHED_DEVICE() => MT_DEVICE_nGnRnE; in context, the
		// former is used in the !peer_io (NV_MEMORY_TYPE_SYSTEM) case and the
		// latter is used in the peer_io (NV_MEMORY_TYPE_DEVICE_MMIO) case. As
		// above, we should clarify whether we need to replicate this behavior.
		memType = hostarch.MemoryTypeUncached
	default:
		ctx.Warningf("nvproxy: unknown caching type %d", cachingType)
		memType = hostarch.MemoryTypeUncached
	}
	if log.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: inferred memory type %v for caching type %d", memType, cachingType)
	}
	return memType
}
