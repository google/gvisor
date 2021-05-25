// Copyright 2019 The gVisor Authors.
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

package fsutil

import (
	"math"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// HostMappable implements memmap.Mappable and memmap.File over a
// CachedFileObject.
//
// Lock order (compare the lock order model in mm/mm.go):
//   truncateMu ("fs locks")
//     mu ("memmap.Mappable locks not taken by Translate")
//       ("memmap.File locks")
//   	     backingFile ("CachedFileObject locks")
//
// +stateify savable
type HostMappable struct {
	hostFileMapper *HostFileMapper

	backingFile CachedFileObject

	mu sync.Mutex `state:"nosave"`

	// mappings tracks mappings of the cached file object into
	// memmap.MappingSpaces so it can invalidated upon save. Protected by mu.
	mappings memmap.MappingSet

	// truncateMu protects writes and truncations. See Truncate() for details.
	truncateMu sync.RWMutex `state:"nosave"`
}

// NewHostMappable creates a new mappable that maps directly to host FD.
func NewHostMappable(backingFile CachedFileObject) *HostMappable {
	return &HostMappable{
		hostFileMapper: NewHostFileMapper(),
		backingFile:    backingFile,
	}
}

// AddMapping implements memmap.Mappable.AddMapping.
func (h *HostMappable) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	// Hot path. Avoid defers.
	h.mu.Lock()
	mapped := h.mappings.AddMapping(ms, ar, offset, writable)
	for _, r := range mapped {
		h.hostFileMapper.IncRefOn(r)
	}
	h.mu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (h *HostMappable) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	// Hot path. Avoid defers.
	h.mu.Lock()
	unmapped := h.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		h.hostFileMapper.DecRefOn(r)
	}
	h.mu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (h *HostMappable) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return h.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (h *HostMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   h,
			Offset: optional.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (h *HostMappable) InvalidateUnsavable(_ context.Context) error {
	h.mu.Lock()
	h.mappings.InvalidateAll(memmap.InvalidateOpts{})
	h.mu.Unlock()
	return nil
}

// NotifyChangeFD must be called after the file description represented by
// CachedFileObject.FD() changes.
func (h *HostMappable) NotifyChangeFD() error {
	// Update existing sentry mappings to refer to the new file description.
	if err := h.hostFileMapper.RegenerateMappings(h.backingFile.FD()); err != nil {
		return err
	}

	// Shoot down existing application mappings of the old file description;
	// they will be remapped with the new file description on demand.
	h.mu.Lock()
	defer h.mu.Unlock()

	h.mappings.InvalidateAll(memmap.InvalidateOpts{})
	return nil
}

// MapInternal implements memmap.File.MapInternal.
func (h *HostMappable) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	return h.hostFileMapper.MapInternal(fr, h.backingFile.FD(), at.Write)
}

// FD implements memmap.File.FD.
func (h *HostMappable) FD() int {
	return h.backingFile.FD()
}

// IncRef implements memmap.File.IncRef.
func (h *HostMappable) IncRef(fr memmap.FileRange) {
	mr := memmap.MappableRange{Start: fr.Start, End: fr.End}
	h.hostFileMapper.IncRefOn(mr)
}

// DecRef implements memmap.File.DecRef.
func (h *HostMappable) DecRef(fr memmap.FileRange) {
	mr := memmap.MappableRange{Start: fr.Start, End: fr.End}
	h.hostFileMapper.DecRefOn(mr)
}

// Truncate truncates the file, invalidating any mapping that may have been
// removed after the size change.
//
// Truncation and writes are synchronized to prevent races where writes make the
// file grow between truncation and invalidation below:
//   T1: Calls SetMaskedAttributes and stalls
//   T2: Appends to file causing it to grow
//   T2: Writes to mapped pages and COW happens
//   T1: Continues and wronly invalidates the page mapped in step above.
func (h *HostMappable) Truncate(ctx context.Context, newSize int64, uattr fs.UnstableAttr) error {
	h.truncateMu.Lock()
	defer h.truncateMu.Unlock()

	mask := fs.AttrMask{Size: true}
	attr := fs.UnstableAttr{Size: newSize}

	// Truncating a file clears privilege bits.
	if uattr.Perms.HasSetUIDOrGID() {
		mask.Perms = true
		attr.Perms = uattr.Perms
		attr.Perms.DropSetUIDAndMaybeGID()
	}

	if err := h.backingFile.SetMaskedAttributes(ctx, mask, attr, false); err != nil {
		return err
	}

	// Invalidate COW mappings that may exist beyond the new size in case the file
	// is being shrunk. Other mappings don't need to be invalidated because
	// translate will just return identical mappings after invalidation anyway,
	// and SIGBUS will be raised and handled when the mappings are touched.
	//
	// Compare Linux's mm/truncate.c:truncate_setsize() =>
	// truncate_pagecache() =>
	// mm/memory.c:unmap_mapping_range(evencows=1).
	h.mu.Lock()
	defer h.mu.Unlock()
	mr := memmap.MappableRange{
		Start: fs.OffsetPageEnd(newSize),
		End:   fs.OffsetPageEnd(math.MaxInt64),
	}
	h.mappings.Invalidate(mr, memmap.InvalidateOpts{InvalidatePrivate: true})

	return nil
}

// Allocate reserves space in the backing file.
func (h *HostMappable) Allocate(ctx context.Context, offset int64, length int64) error {
	h.truncateMu.RLock()
	err := h.backingFile.Allocate(ctx, offset, length)
	h.truncateMu.RUnlock()
	return err
}

// Write writes to the file backing this mappable.
func (h *HostMappable) Write(ctx context.Context, src usermem.IOSequence, offset int64, uattr fs.UnstableAttr) (int64, error) {
	h.truncateMu.RLock()
	defer h.truncateMu.RUnlock()
	n, err := src.CopyInTo(ctx, &writer{ctx: ctx, hostMappable: h, off: offset})
	if n > 0 && uattr.Perms.HasSetUIDOrGID() {
		mask := fs.AttrMask{Perms: true}
		uattr.Perms.DropSetUIDAndMaybeGID()
		if err := h.backingFile.SetMaskedAttributes(ctx, mask, uattr, false); err != nil {
			return n, err
		}
	}
	return n, err
}

type writer struct {
	ctx          context.Context
	hostMappable *HostMappable
	off          int64
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (w *writer) WriteFromBlocks(src safemem.BlockSeq) (uint64, error) {
	n, err := w.hostMappable.backingFile.WriteFromBlocksAt(w.ctx, src, uint64(w.off))
	w.off += int64(n)
	return n, err
}
