// Copyright 2026 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
)

// trackedMappings tracks mappings of a device FD whose memmap.File is not
// savable, so that InvalidateUnsavable can drop all pmas over it before save.
// Compare memmap.MappableNoTrackMappings.
//
// +stateify savable
type trackedMappings struct {
	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	set memmap.MappingSet
}

// AddMapping implements memmap.Mappable.AddMapping.
func (m *trackedMappings) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set.AddMapping(ms, ar, offset, writable)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (m *trackedMappings) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set.RemoveMapping(ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (m *trackedMappings) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return m.AddMapping(ctx, ms, dstAR, offset, writable)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (m *trackedMappings) InvalidateUnsavable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set.InvalidateAll(memmap.InvalidateOpts{InvalidatePrivate: true})
	return nil
}
