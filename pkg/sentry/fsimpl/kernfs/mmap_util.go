// Copyright 2020 The gVisor Authors.
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

package kernfs

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
)

// inodePlatformFile implements memmap.File. It exists solely because inode
// cannot implement both kernfs.Inode.IncRef and memmap.File.IncRef.
//
// +stateify savable
type inodePlatformFile struct {
	// hostFD contains the host fd that this file was originally created from,
	// which must be available at time of restore.
	//
	// This field is initialized at creation time and is immutable.
	// inodePlatformFile does not own hostFD and hence should not close it.
	hostFD int

	// fdRefsMu protects fdRefs.
	fdRefsMu sync.Mutex `state:"nosave"`

	// fdRefs counts references on memmap.File offsets. It is used solely for
	// memory accounting.
	fdRefs fsutil.FrameRefSet

	// fileMapper caches mappings of the host file represented by this inode.
	fileMapper fsutil.HostFileMapper

	// fileMapperInitOnce is used to lazily initialize fileMapper.
	fileMapperInitOnce sync.Once `state:"nosave"`
}

var _ memmap.File = (*inodePlatformFile)(nil)

// IncRef implements memmap.File.IncRef.
func (i *inodePlatformFile) IncRef(fr memmap.FileRange) {
	i.fdRefsMu.Lock()
	i.fdRefs.IncRefAndAccount(fr)
	i.fdRefsMu.Unlock()
}

// DecRef implements memmap.File.DecRef.
func (i *inodePlatformFile) DecRef(fr memmap.FileRange) {
	i.fdRefsMu.Lock()
	i.fdRefs.DecRefAndAccount(fr)
	i.fdRefsMu.Unlock()
}

// MapInternal implements memmap.File.MapInternal.
func (i *inodePlatformFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	return i.fileMapper.MapInternal(fr, i.hostFD, at.Write)
}

// FD implements memmap.File.FD.
func (i *inodePlatformFile) FD() int {
	return i.hostFD
}

// CachedMappable implements memmap.Mappable. This utility can be embedded in a
// kernfs.Inode that represents a host file  to make the inode mappable.
// CachedMappable caches the mappings of the host file. CachedMappable must be
// initialized (via Init) with a hostFD before use.
//
// +stateify savable
type CachedMappable struct {
	// mapsMu protects mappings.
	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks mappings of hostFD into memmap.MappingSpaces.
	mappings memmap.MappingSet

	// pf implements memmap.File for mappings backed by a host fd.
	pf inodePlatformFile
}

var _ memmap.Mappable = (*CachedMappable)(nil)

// Init initializes i.pf. This must be called before using CachedMappable.
func (i *CachedMappable) Init(hostFD int) {
	i.pf.hostFD = hostFD
}

// AddMapping implements memmap.Mappable.AddMapping.
func (i *CachedMappable) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	i.mapsMu.Lock()
	mapped := i.mappings.AddMapping(ms, ar, offset, writable)
	for _, r := range mapped {
		i.pf.fileMapper.IncRefOn(r)
	}
	i.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (i *CachedMappable) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	i.mapsMu.Lock()
	unmapped := i.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		i.pf.fileMapper.DecRefOn(r)
	}
	i.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (i *CachedMappable) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return i.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (i *CachedMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	mr := optional
	return []memmap.Translation{
		{
			Source: mr,
			File:   &i.pf,
			Offset: mr.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (i *CachedMappable) InvalidateUnsavable(ctx context.Context) error {
	// We expect the same host fd across save/restore, so all translations
	// should be valid.
	return nil
}

// InvalidateRange invalidates the passed range on i.mappings.
func (i *CachedMappable) InvalidateRange(r memmap.MappableRange) {
	i.mapsMu.Lock()
	i.mappings.Invalidate(r, memmap.InvalidateOpts{
		// Compare Linux's mm/truncate.c:truncate_setsize() =>
		// truncate_pagecache() =>
		// mm/memory.c:unmap_mapping_range(evencows=1).
		InvalidatePrivate: true,
	})
	i.mapsMu.Unlock()
}

// InitFileMapperOnce initializes the host file mapper. It ensures that the
// file mapper is initialized just once.
func (i *CachedMappable) InitFileMapperOnce() {
	i.pf.fileMapperInitOnce.Do(i.pf.fileMapper.Init)
}
