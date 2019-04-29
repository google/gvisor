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

package memmap

import (
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type testMappingSpace struct {
	// Ideally we'd store the full ranges that were invalidated, rather
	// than individual calls to Invalidate, as they are an implementation
	// detail, but this is the simplest way for now.
	inv []usermem.AddrRange
}

func (n *testMappingSpace) reset() {
	n.inv = []usermem.AddrRange{}
}

func (n *testMappingSpace) Invalidate(ar usermem.AddrRange, opts InvalidateOpts) {
	n.inv = append(n.inv, ar)
}

func TestAddRemoveMapping(t *testing.T) {
	set := MappingSet{}
	ms := &testMappingSpace{}

	mapped := set.AddMapping(ms, usermem.AddrRange{0x10000, 0x12000}, 0x1000, true)
	if got, want := mapped, []MappableRange{{0x1000, 0x3000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("AddMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings (usermem.AddrRanges => memmap.MappableRange):
	// [0x10000, 0x12000) => [0x1000, 0x3000)
	t.Log(&set)

	mapped = set.AddMapping(ms, usermem.AddrRange{0x20000, 0x21000}, 0x2000, true)
	if len(mapped) != 0 {
		t.Errorf("AddMapping: got %+v, wanted []", mapped)
	}

	// Mappings:
	// [0x10000, 0x11000) => [0x1000, 0x2000)
	// [0x11000, 0x12000) and [0x20000, 0x21000) => [0x2000, 0x3000)
	t.Log(&set)

	mapped = set.AddMapping(ms, usermem.AddrRange{0x30000, 0x31000}, 0x4000, true)
	if got, want := mapped, []MappableRange{{0x4000, 0x5000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("AddMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x10000, 0x11000) => [0x1000, 0x2000)
	// [0x11000, 0x12000) and [0x20000, 0x21000) => [0x2000, 0x3000)
	// [0x30000, 0x31000) => [0x4000, 0x5000)
	t.Log(&set)

	mapped = set.AddMapping(ms, usermem.AddrRange{0x12000, 0x15000}, 0x3000, true)
	if got, want := mapped, []MappableRange{{0x3000, 0x4000}, {0x5000, 0x6000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("AddMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x10000, 0x11000) => [0x1000, 0x2000)
	// [0x11000, 0x12000) and [0x20000, 0x21000) => [0x2000, 0x3000)
	// [0x12000, 0x13000) => [0x3000, 0x4000)
	// [0x13000, 0x14000) and [0x30000, 0x31000) => [0x4000, 0x5000)
	// [0x14000, 0x15000) => [0x5000, 0x6000)
	t.Log(&set)

	unmapped := set.RemoveMapping(ms, usermem.AddrRange{0x10000, 0x11000}, 0x1000, true)
	if got, want := unmapped, []MappableRange{{0x1000, 0x2000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x11000, 0x12000) and [0x20000, 0x21000) => [0x2000, 0x3000)
	// [0x12000, 0x13000) => [0x3000, 0x4000)
	// [0x13000, 0x14000) and [0x30000, 0x31000) => [0x4000, 0x5000)
	// [0x14000, 0x15000) => [0x5000, 0x6000)
	t.Log(&set)

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x20000, 0x21000}, 0x2000, true)
	if len(unmapped) != 0 {
		t.Errorf("RemoveMapping: got %+v, wanted []", unmapped)
	}

	// Mappings:
	// [0x11000, 0x13000) => [0x2000, 0x4000)
	// [0x13000, 0x14000) and [0x30000, 0x31000) => [0x4000, 0x5000)
	// [0x14000, 0x15000) => [0x5000, 0x6000)
	t.Log(&set)

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x11000, 0x15000}, 0x2000, true)
	if got, want := unmapped, []MappableRange{{0x2000, 0x4000}, {0x5000, 0x6000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x30000, 0x31000) => [0x4000, 0x5000)
	t.Log(&set)

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x30000, 0x31000}, 0x4000, true)
	if got, want := unmapped, []MappableRange{{0x4000, 0x5000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}
}

func TestInvalidateWholeMapping(t *testing.T) {
	set := MappingSet{}
	ms := &testMappingSpace{}

	set.AddMapping(ms, usermem.AddrRange{0x10000, 0x11000}, 0, true)
	// Mappings:
	// [0x10000, 0x11000) => [0, 0x1000)
	t.Log(&set)
	set.Invalidate(MappableRange{0, 0x1000}, InvalidateOpts{})
	if got, want := ms.inv, []usermem.AddrRange{{0x10000, 0x11000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Invalidate: got %+v, wanted %+v", got, want)
	}
}

func TestInvalidatePartialMapping(t *testing.T) {
	set := MappingSet{}
	ms := &testMappingSpace{}

	set.AddMapping(ms, usermem.AddrRange{0x10000, 0x13000}, 0, true)
	// Mappings:
	// [0x10000, 0x13000) => [0, 0x3000)
	t.Log(&set)
	set.Invalidate(MappableRange{0x1000, 0x2000}, InvalidateOpts{})
	if got, want := ms.inv, []usermem.AddrRange{{0x11000, 0x12000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Invalidate: got %+v, wanted %+v", got, want)
	}
}

func TestInvalidateMultipleMappings(t *testing.T) {
	set := MappingSet{}
	ms := &testMappingSpace{}

	set.AddMapping(ms, usermem.AddrRange{0x10000, 0x11000}, 0, true)
	set.AddMapping(ms, usermem.AddrRange{0x20000, 0x21000}, 0x2000, true)
	// Mappings:
	// [0x10000, 0x11000) => [0, 0x1000)
	// [0x12000, 0x13000) => [0x2000, 0x3000)
	t.Log(&set)
	set.Invalidate(MappableRange{0, 0x3000}, InvalidateOpts{})
	if got, want := ms.inv, []usermem.AddrRange{{0x10000, 0x11000}, {0x20000, 0x21000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Invalidate: got %+v, wanted %+v", got, want)
	}
}

func TestInvalidateOverlappingMappings(t *testing.T) {
	set := MappingSet{}
	ms1 := &testMappingSpace{}
	ms2 := &testMappingSpace{}

	set.AddMapping(ms1, usermem.AddrRange{0x10000, 0x12000}, 0, true)
	set.AddMapping(ms2, usermem.AddrRange{0x20000, 0x22000}, 0x1000, true)
	// Mappings:
	// ms1:[0x10000, 0x12000) => [0, 0x2000)
	// ms2:[0x11000, 0x13000) => [0x1000, 0x3000)
	t.Log(&set)
	set.Invalidate(MappableRange{0x1000, 0x2000}, InvalidateOpts{})
	if got, want := ms1.inv, []usermem.AddrRange{{0x11000, 0x12000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Invalidate: ms1: got %+v, wanted %+v", got, want)
	}
	if got, want := ms2.inv, []usermem.AddrRange{{0x20000, 0x21000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Invalidate: ms1: got %+v, wanted %+v", got, want)
	}
}

func TestMixedWritableMappings(t *testing.T) {
	set := MappingSet{}
	ms := &testMappingSpace{}

	mapped := set.AddMapping(ms, usermem.AddrRange{0x10000, 0x12000}, 0x1000, true)
	if got, want := mapped, []MappableRange{{0x1000, 0x3000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("AddMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x10000, 0x12000) writable => [0x1000, 0x3000)
	t.Log(&set)

	mapped = set.AddMapping(ms, usermem.AddrRange{0x20000, 0x22000}, 0x2000, false)
	if got, want := mapped, []MappableRange{{0x3000, 0x4000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("AddMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x10000, 0x11000) writable => [0x1000, 0x2000)
	// [0x11000, 0x12000) writable and [0x20000, 0x21000) readonly => [0x2000, 0x3000)
	// [0x21000, 0x22000) readonly => [0x3000, 0x4000)
	t.Log(&set)

	// Unmap should fail because we specified the readonly map address range, but
	// asked to unmap a writable segment.
	unmapped := set.RemoveMapping(ms, usermem.AddrRange{0x20000, 0x21000}, 0x2000, true)
	if len(unmapped) != 0 {
		t.Errorf("RemoveMapping: got %+v, wanted []", unmapped)
	}

	// Readonly mapping removed, but writable mapping still exists in the range,
	// so no mappable range fully unmapped.
	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x20000, 0x21000}, 0x2000, false)
	if len(unmapped) != 0 {
		t.Errorf("RemoveMapping: got %+v, wanted []", unmapped)
	}

	// Mappings:
	// [0x10000, 0x12000) writable => [0x1000, 0x3000)
	// [0x21000, 0x22000) readonly => [0x3000, 0x4000)
	t.Log(&set)

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x11000, 0x12000}, 0x2000, true)
	if got, want := unmapped, []MappableRange{{0x2000, 0x3000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x10000, 0x12000) writable => [0x1000, 0x3000)
	// [0x21000, 0x22000) readonly => [0x3000, 0x4000)
	t.Log(&set)

	// Unmap should fail since writable bit doesn't match.
	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x10000, 0x12000}, 0x1000, false)
	if len(unmapped) != 0 {
		t.Errorf("RemoveMapping: got %+v, wanted []", unmapped)
	}

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x10000, 0x12000}, 0x1000, true)
	if got, want := unmapped, []MappableRange{{0x1000, 0x2000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}

	// Mappings:
	// [0x21000, 0x22000) readonly => [0x3000, 0x4000)
	t.Log(&set)

	unmapped = set.RemoveMapping(ms, usermem.AddrRange{0x21000, 0x22000}, 0x3000, false)
	if got, want := unmapped, []MappableRange{{0x3000, 0x4000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemoveMapping: got %+v, wanted %+v", got, want)
	}
}
