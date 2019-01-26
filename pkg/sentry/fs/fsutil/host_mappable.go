// Copyright 2019 Google LLC
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// HostMappable implements memmap.Mappable and platform.File over an arbitrary
// host file descriptor.
//
// +stateify savable
type HostMappable struct {
	hostFileMapper *HostFileMapper

	mu sync.Mutex `state:"nosave"`

	// fd is the file descriptor to the host. Protected by mu.
	fd int `state:"nosave"`

	// mappings tracks mappings of the cached file object into
	// memmap.MappingSpaces so it can invalidated upon save. Protected by mu.
	mappings memmap.MappingSet
}

// NewHostMappable creates a new mappable that maps directly to host FD.
func NewHostMappable() *HostMappable {
	return &HostMappable{
		hostFileMapper: NewHostFileMapper(),
		fd:             -1,
	}
}

func (h *HostMappable) getFD() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd < 0 {
		panic("HostMappable FD isn't set")
	}
	return h.fd
}

// UpdateFD sets the host FD iff FD hasn't been set before or if there are
// no mappings.
func (h *HostMappable) UpdateFD(fd int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fd = fd
}

// AddMapping implements memmap.Mappable.AddMapping.
func (h *HostMappable) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
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
func (h *HostMappable) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	// Hot path. Avoid defers.
	h.mu.Lock()
	unmapped := h.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		h.hostFileMapper.DecRefOn(r)
	}
	h.mu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (h *HostMappable) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return h.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (h *HostMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   h,
			Offset: optional.Start,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (h *HostMappable) InvalidateUnsavable(ctx context.Context) error {
	h.mu.Lock()
	h.mappings.InvalidateAll(memmap.InvalidateOpts{})
	h.mu.Unlock()
	return nil
}

// MapInto implements platform.File.MapInto.
func (h *HostMappable) MapInto(as platform.AddressSpace, addr usermem.Addr, fr platform.FileRange, at usermem.AccessType, precommit bool) error {
	return as.MapFile(addr, h.getFD(), fr, at, precommit)
}

// MapInternal implements platform.File.MapInternal.
func (h *HostMappable) MapInternal(fr platform.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
	return h.hostFileMapper.MapInternal(fr, h.getFD(), at.Write)
}

// IncRef implements platform.File.IncRef.
func (h *HostMappable) IncRef(fr platform.FileRange) {
	mr := memmap.MappableRange{Start: fr.Start, End: fr.End}
	h.hostFileMapper.IncRefOn(mr)
}

// DecRef implements platform.File.DecRef.
func (h *HostMappable) DecRef(fr platform.FileRange) {
	mr := memmap.MappableRange{Start: fr.Start, End: fr.End}
	h.hostFileMapper.DecRefOn(mr)
}
