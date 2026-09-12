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
	"testing"
)

// remappingFromDeviceInstances builds a DeviceRemapping that maps each old
// device instance in pairs to the new one beside it. Only DeviceInstance
// matters to composeIDMap().
func remappingFromDeviceInstances(pairs [][2]uint32) *DeviceRemapping {
	dr := &DeviceRemapping{
		NewDeviceByOld:            make(map[*DeviceRemapID]*DeviceRemapID),
		OldDeviceByMinor:          make(map[uint32]*DeviceRemapID),
		OldDeviceByDeviceInstance: make(map[uint32]*DeviceRemapID),
	}
	for _, pair := range pairs {
		oldID := &DeviceRemapID{DeviceInstance: pair[0]}
		newID := &DeviceRemapID{DeviceInstance: pair[1]}
		dr.NewDeviceByOld[oldID] = newID
		dr.OldDeviceByDeviceInstance[oldID.DeviceInstance] = oldID
	}
	return dr
}

func TestComposeIDMap(t *testing.T) {
	for _, test := range []struct {
		name  string
		prev  map[uint32]uint32
		pairs [][2]uint32
		want  map[uint32]uint32
	}{
		{
			name:  "first restore",
			prev:  nil,
			pairs: [][2]uint32{{0, 4}, {1, 7}},
			want:  map[uint32]uint32{4: 0, 7: 1},
		},
		{
			name:  "identity remapping still recorded",
			prev:  nil,
			pairs: [][2]uint32{{0, 0}, {1, 1}},
			want:  map[uint32]uint32{0: 0, 1: 1},
		},
		{
			// A sandbox booted on 0,1 was restored onto 4,7 and is now
			// restored onto 2,3: it must still report 0,1.
			name:  "second restore composes with the first",
			prev:  map[uint32]uint32{4: 0, 7: 1},
			pairs: [][2]uint32{{4, 2}, {7, 3}},
			want:  map[uint32]uint32{2: 0, 3: 1},
		},
		{
			// Overlapping old and new sets: the entry for the device that
			// kept its instance must not be clobbered by the one that took it.
			name:  "overlapping sets",
			prev:  map[uint32]uint32{2: 0, 3: 1},
			pairs: [][2]uint32{{2, 3}, {3, 5}},
			want:  map[uint32]uint32{3: 0, 5: 1},
		},
		{
			// An old device instance absent from prev was never remapped, so
			// it is its own guest instance.
			name:  "old instance missing from prev maps to itself",
			prev:  map[uint32]uint32{4: 0},
			pairs: [][2]uint32{{4, 6}, {9, 8}},
			want:  map[uint32]uint32{6: 0, 8: 9},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := composeIDMap(test.prev, test.pairs)
			if len(got) != len(test.want) {
				t.Fatalf("composeIDMap() = %v, want %v", got, test.want)
			}
			for host, wantGuest := range test.want {
				gotGuest, ok := got[host]
				if !ok {
					t.Errorf("composeIDMap() = %v, missing host device instance %d", got, host)
					continue
				}
				if gotGuest != wantGuest {
					t.Errorf("composeIDMap()[%d] = %d, want %d", host, gotGuest, wantGuest)
				}
			}
			// The input must not be mutated: it is the saved state of a
			// sandbox that may still be read by a concurrent log line.
			if test.prev != nil {
				if _, ok := test.prev[0xdead]; ok {
					t.Errorf("prev was mutated")
				}
			}
		})
	}
}

func TestFormatIDMapIsOrdered(t *testing.T) {
	m := map[uint32]uint32{7: 1, 2: 3, 4: 0}
	const want = "{2 -> 3, 4 -> 0, 7 -> 1}"
	for i := 0; i < 16; i++ {
		if got := formatIDMap(m); got != want {
			t.Fatalf("formatIDMap() = %q, want %q", got, want)
		}
	}
	if got, want := formatIDMap(nil), "{}"; got != want {
		t.Errorf("formatIDMap(nil) = %q, want %q", got, want)
	}
}

// TestRemapPairsCoversAllThreeIdentifiers pins that the device instance, gpuId
// and UUID mappings all come from the same DeviceRemapID pairs, in the same
// order.
func TestRemapPairsCoversAllThreeIdentifiers(t *testing.T) {
	dr := &DeviceRemapping{NewDeviceByOld: map[*DeviceRemapID]*DeviceRemapID{}}
	old0 := &DeviceRemapID{DeviceInstance: 0, GPUID: 0x1111, Minor: 2, UUID: "GPU-00000000-0000-0000-0000-000000000000"}
	new0 := &DeviceRemapID{DeviceInstance: 4, GPUID: 0x4444, Minor: 4, UUID: "GPU-44444444-0000-0000-0000-000000000000"}
	old1 := &DeviceRemapID{DeviceInstance: 1, GPUID: 0x2222, Minor: 3, UUID: "GPU-11111111-0000-0000-0000-000000000000"}
	new1 := &DeviceRemapID{DeviceInstance: 7, GPUID: 0x7777, Minor: 6, UUID: "GPU-77777777-0000-0000-0000-000000000000"}
	dr.NewDeviceByOld[old0] = new0
	dr.NewDeviceByOld[old1] = new1

	// Ordered by old device instance, so the result does not vary with map
	// iteration order.
	for i := 0; i < 16; i++ {
		devInsts, gpuIDs, uuids, minors, _ := remapPairs(dr)
		if want := [][2]uint32{{0, 4}, {1, 7}}; !equalPairs(devInsts, want) {
			t.Fatalf("remapPairs() device instances = %v, want %v", devInsts, want)
		}
		if want := [][2]uint32{{0x1111, 0x4444}, {0x2222, 0x7777}}; !equalPairs(gpuIDs, want) {
			t.Fatalf("remapPairs() gpuIds = %v, want %v", gpuIDs, want)
		}
		if len(uuids) != 2 || uuids[0][0] != old0.UUID || uuids[0][1] != new0.UUID {
			t.Fatalf("remapPairs() uuids = %v", uuids)
		}
		if want := [][2]uint32{{2, 4}, {3, 6}}; !equalPairs(minors, want) {
			t.Fatalf("remapPairs() minors = %v, want %v", minors, want)
		}
	}
}

func equalPairs(got, want [][2]uint32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestInvertIDMapDropsAmbiguousEntries(t *testing.T) {
	inv := invertIDMap(map[uint32]uint32{4: 0, 7: 1}, "test")
	if len(inv) != 2 || inv[0] != 4 || inv[1] != 7 {
		t.Errorf("invertIDMap() = %v, want {0:4, 1:7}", inv)
	}
	// Two hosts claiming the same guest: neither may be resolved inward.
	inv = invertIDMap(map[uint32]uint32{4: 0, 7: 0, 9: 3}, "test")
	if _, ok := inv[0]; ok {
		t.Errorf("invertIDMap() kept an ambiguous entry: %v", inv)
	}
	if inv[3] != 9 {
		t.Errorf("invertIDMap() dropped an unambiguous entry: %v", inv)
	}
}

func TestPermuteDeviceInstanceMask(t *testing.T) {
	m := map[uint32]uint32{4: 0, 7: 1}
	// Bits 4 and 7 set -> bits 0 and 1 set.
	if got, want := permuteDeviceInstanceMask(1<<4|1<<7, m), uint32(1<<0|1<<1); got != want {
		t.Errorf("permuteDeviceInstanceMask(0x90) = %#x, want %#x", got, want)
	}
	// A bit with no translation is carried through.
	if got, want := permuteDeviceInstanceMask(1<<4|1<<9, m), uint32(1<<0|1<<9); got != want {
		t.Errorf("permuteDeviceInstanceMask() = %#x, want %#x", got, want)
	}
	// An empty map is the identity.
	if got, want := permuteDeviceInstanceMask(0xdeadbeef, nil), uint32(0xdeadbeef); got != want {
		t.Errorf("permuteDeviceInstanceMask() = %#x, want %#x", got, want)
	}
	if got, want := permuteDeviceInstanceMask(0, m), uint32(0); got != want {
		t.Errorf("permuteDeviceInstanceMask(0) = %#x, want %#x", got, want)
	}
}

func TestComposeUUIDMap(t *testing.T) {
	const (
		a = "GPU-aaaaaaaa-0000-0000-0000-000000000000"
		b = "GPU-bbbbbbbb-0000-0000-0000-000000000000"
		c = "GPU-cccccccc-0000-0000-0000-000000000000"
	)
	first := composeUUIDMap(nil, [][2]string{{a, b}})
	if first[b] != a {
		t.Fatalf("composeUUIDMap() = %v, want {%s: %s}", first, b, a)
	}
	// Restored again onto a third device: still reports the original.
	second := composeUUIDMap(first, [][2]string{{b, c}})
	if second[c] != a {
		t.Errorf("composeUUIDMap() = %v, want {%s: %s}", second, c, a)
	}
	if _, ok := second[b]; ok {
		t.Errorf("composeUUIDMap() kept a stale host UUID: %v", second)
	}
}

func TestUUIDBinaryRoundTrip(t *testing.T) {
	const s = "GPU-0123456789abcdef-fedc-ba98-7654-3210deadbeef"
	if _, ok := uuidBinary(s); ok {
		t.Errorf("uuidBinary(%q) accepted a malformed UUID", s)
	}
	const good = "GPU-01234567-89ab-cdef-fedc-ba9876543210"
	bin, ok := uuidBinary(good)
	if !ok {
		t.Fatalf("uuidBinary(%q) failed", good)
	}
	if got := formatUUID(bin[:]); got != good {
		t.Errorf("formatUUID(uuidBinary(%q)) = %q", good, got)
	}
	if _, ok := uuidBinary("not a uuid"); ok {
		t.Errorf("uuidBinary() accepted junk")
	}
}

func TestFormatUUIDZero(t *testing.T) {
	var zero [16]byte
	if got := formatUUID(zero[:]); got != "<zero>" {
		t.Errorf("formatUUID(zero) = %q, want <zero>", got)
	}
	if got := formatUUID([]byte{1, 2}); got != "<short>" {
		t.Errorf("formatUUID(short) = %q, want <short>", got)
	}
}

// TestMinorMapComposesAcrossRestores pins the map that decides where a
// restored process's open of an old /dev/nvidia# is sent. A process restored
// twice still names the minor it saw on its original boot.
func TestMinorMapComposesAcrossRestores(t *testing.T) {
	// Booted on minors 2,3; restored onto 4,6.
	hostToGuest := composeIDMap(nil, [][2]uint32{{2, 4}, {3, 6}})
	guestToHost := invertIDMap(hostToGuest, "device minor")
	if guestToHost[2] != 4 || guestToHost[3] != 6 {
		t.Fatalf("after one restore guestToHostMinor = %v, want {2:4, 3:6}", guestToHost)
	}
	// Checkpointed again and restored onto 0,1. The process still opens
	// /dev/nvidia2 and /dev/nvidia3, which must now reach 0 and 1.
	hostToGuest = composeIDMap(hostToGuest, [][2]uint32{{4, 0}, {6, 1}})
	guestToHost = invertIDMap(hostToGuest, "device minor")
	if guestToHost[2] != 0 || guestToHost[3] != 1 {
		t.Errorf("after two restores guestToHostMinor = %v, want {2:0, 3:1}", guestToHost)
	}
	if _, ok := guestToHost[4]; ok {
		t.Errorf("guestToHostMinor kept a stale intermediate minor: %v", guestToHost)
	}
}

// TestMinorMapIdentityRemapIsHarmless pins that a restore onto the same minors
// leaves an open pointing at the minor the caller named.
func TestMinorMapIdentityRemapIsHarmless(t *testing.T) {
	hostToGuest := composeIDMap(nil, [][2]uint32{{2, 2}, {3, 3}})
	guestToHost := invertIDMap(hostToGuest, "device minor")
	if guestToHost[2] != 2 || guestToHost[3] != 3 {
		t.Errorf("guestToHostMinor = %v, want the identity", guestToHost)
	}
}
