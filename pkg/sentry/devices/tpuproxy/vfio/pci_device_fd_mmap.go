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

package vfio

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *pciDeviceFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *pciDeviceFD) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	fd.mapsMu.Lock()
	mapped := fd.mappings.AddMapping(ms, ar, offset, writable)
	for _, r := range mapped {
		fd.memmapFile.pfm.IncRefOn(r)
	}
	fd.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *pciDeviceFD) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	fd.mapsMu.Lock()
	unmapped := fd.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		fd.memmapFile.pfm.DecRefOn(r)
	}
	fd.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *pciDeviceFD) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return fd.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (fd *pciDeviceFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
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
func (fd *pciDeviceFD) InvalidateUnsavable(ctx context.Context) error {
	fd.mapsMu.Lock()
	defer fd.mapsMu.Unlock()
	fd.mappings.InvalidateAll(memmap.InvalidateOpts{InvalidatePrivate: true})
	return nil
}

// pciDeviceFdMemmapFile implements memmap.File for /dev/vfio/[0-9]+.
//
// +stateify savable
type pciDeviceFdMemmapFile struct {
	// FIXME(jamieliu): This is consistent with legacy behavior, but not
	// clearly correct; drivers/vfio/pci/vfio_pci_core.c:vfio_pci_core_mmap()
	// uses pgprot_noncached(), which would correspond to our
	// MemoryTypeUncached.
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback

	fd  *pciDeviceFD
	pfm fsutil.PreciseHostFileMapper
}

// IncRef implements memmap.File.IncRef.
func (mf *pciDeviceFdMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {
}

// DecRef implements memmap.File.DecRef.
func (mf *pciDeviceFdMemmapFile) DecRef(fr memmap.FileRange) {
}

// MapInternal implements memmap.File.MapInternal.
func (mf *pciDeviceFdMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	return mf.pfm.MapInternal(fr, int(mf.fd.hostFD), at.Write)
}

// DataFD implements memmap.File.DataFD.
func (mf *pciDeviceFdMemmapFile) DataFD(fr memmap.FileRange) (int, error) {
	return mf.FD(), nil
}

// FD implements memmap.File.FD.
func (mf *pciDeviceFdMemmapFile) FD() int {
	return int(mf.fd.hostFD)
}
