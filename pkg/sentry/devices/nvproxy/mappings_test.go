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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

type recordingMappingSpace struct {
	invalidated []hostarch.AddrRange
}

// Invalidate implements memmap.MappingSpace.Invalidate.
func (ms *recordingMappingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	ms.invalidated = append(ms.invalidated, ar)
}

func TestTrackedMappingsInvalidateUnsavable(t *testing.T) {
	ctx := context.Background()
	ms := &recordingMappingSpace{}
	var m trackedMappings

	kept := hostarch.AddrRange{Start: 0x10000, End: 0x12000}
	removed := hostarch.AddrRange{Start: 0x20000, End: 0x21000}
	if err := m.AddMapping(ctx, ms, kept, 0, true); err != nil {
		t.Fatalf("AddMapping(%v): %v", kept, err)
	}
	if err := m.AddMapping(ctx, ms, removed, 0x2000, false); err != nil {
		t.Fatalf("AddMapping(%v): %v", removed, err)
	}
	m.RemoveMapping(ctx, ms, removed, 0x2000, false)

	// Only live mappings are invalidated, and they stay tracked afterwards.
	for i := 0; i < 2; i++ {
		ms.invalidated = nil
		if err := m.InvalidateUnsavable(ctx); err != nil {
			t.Fatalf("InvalidateUnsavable #%d: %v", i, err)
		}
		if want := []hostarch.AddrRange{kept}; !reflect.DeepEqual(ms.invalidated, want) {
			t.Fatalf("InvalidateUnsavable #%d invalidated %v, want %v", i, ms.invalidated, want)
		}
	}
}
