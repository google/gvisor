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

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

func TestPackPCIAddrRoundTrip(t *testing.T) {
	for _, test := range []struct {
		domain             uint32
		bus, slot, funcNum uint8
		want               string
	}{
		{0x0000, 0x07, 0x00, 0x0, "0000:07:00.0"},
		{0x0000, 0xca, 0x00, 0x0, "0000:ca:00.0"},
		{0x1234, 0xff, 0x1f, 0x7, "1234:ff:1f.7"},
		{0, 0, 0, 0, "0000:00:00.0"},
	} {
		v := PackPCIAddr(test.domain, test.bus, test.slot, test.funcNum)
		d, b, s, f := UnpackPCIAddr(v)
		if d != test.domain || b != test.bus || s != test.slot || f != test.funcNum {
			t.Errorf("UnpackPCIAddr(PackPCIAddr(%#x,%#x,%#x,%#x)) = (%#x,%#x,%#x,%#x)", test.domain, test.bus, test.slot, test.funcNum, d, b, s, f)
		}
		if got := formatPCIAddr(v); got != test.want {
			t.Errorf("formatPCIAddr() = %q, want %q", got, test.want)
		}
	}
	// Distinct addresses must pack distinctly, or one GPU's address would map
	// onto another's.
	seen := make(map[uint64]struct{})
	for _, v := range []uint64{
		PackPCIAddr(0, 0x07, 0, 0),
		PackPCIAddr(0, 0x08, 0, 0),
		PackPCIAddr(0, 0, 0x07, 0),
		PackPCIAddr(1, 0, 0, 0),
	} {
		if _, ok := seen[v]; ok {
			t.Errorf("two distinct PCI addresses pack to %#x", v)
		}
		seen[v] = struct{}{}
	}
}

func TestMatchHostPCIAddr(t *testing.T) {
	a := PackPCIAddr(0, 0x07, 0x00, 0)
	b := PackPCIAddr(0, 0x0b, 0x00, 0)
	m := map[uint64]uint64{a: PackPCIAddr(0, 0x03, 0x00, 0), b: PackPCIAddr(0, 0x04, 0x00, 0)}

	// All three components, exact.
	if got, ok := matchHostPCIAddr(m, 0, true, 0x07, true, 0x00, true); !ok || got != a {
		t.Errorf("matchHostPCIAddr(full) = (%#x, %v), want (%#x, true)", got, ok, a)
	}
	// Bus alone is enough to pick one out here.
	if got, ok := matchHostPCIAddr(m, 0, false, 0x0b, true, 0, false); !ok || got != b {
		t.Errorf("matchHostPCIAddr(bus only) = (%#x, %v), want (%#x, true)", got, ok, b)
	}
	// Domain alone matches both: ambiguous, so no translation rather than a
	// guess at which GPU was meant.
	if _, ok := matchHostPCIAddr(m, 0, true, 0, false, 0, false); ok {
		t.Errorf("matchHostPCIAddr(ambiguous) reported a match")
	}
	// A device that is not ours matches nothing.
	if _, ok := matchHostPCIAddr(m, 0, true, 0x99, true, 0, true); ok {
		t.Errorf("matchHostPCIAddr(absent) reported a match")
	}
	// An empty map never matches.
	if _, ok := matchHostPCIAddr(nil, 0, true, 0x07, true, 0x00, true); ok {
		t.Errorf("matchHostPCIAddr(nil map) reported a match")
	}
}

// TestCardInfoFieldsSurviveRoundTrip pins that translateCardInfo edits the
// fields it means to: an entry is unmarshalled, three identities are changed,
// and everything else must come back unchanged.
func TestCardInfoFieldsSurviveRoundTrip(t *testing.T) {
	var ci nvgpu.IoctlCardInfo
	ci.Valid = 1
	ci.GPUID = 0xc400
	ci.MinorNumber = 5
	ci.PCIInfo.Domain = 0
	ci.PCIInfo.Bus = 0x0b
	ci.PCIInfo.Slot = 0x00
	ci.PCIInfo.Function = 0
	ci.PCIInfo.VendorID = 0x10de
	ci.PCIInfo.DeviceID = 0x2330
	ci.RegAddress = 0xdeadbeef00000000
	ci.FBSize = 0x123456789
	ci.InterruptLine = 0x42

	buf := make([]byte, ci.SizeBytes())
	ci.MarshalBytes(buf)

	var back nvgpu.IoctlCardInfo
	back.UnmarshalBytes(buf)
	back.GPUID = 0x400
	back.MinorNumber = 3
	back.PCIInfo.Bus = 0x07
	back.MarshalBytes(buf)

	var final nvgpu.IoctlCardInfo
	final.UnmarshalBytes(buf)
	if final.GPUID != 0x400 || final.MinorNumber != 3 || final.PCIInfo.Bus != 0x07 {
		t.Errorf("translated fields did not survive: gpuId=%#x minor=%d bus=%#x", final.GPUID, final.MinorNumber, final.PCIInfo.Bus)
	}
	if final.PCIInfo.VendorID != 0x10de || final.PCIInfo.DeviceID != 0x2330 {
		t.Errorf("PCI vendor/device ids were disturbed: %#x/%#x", final.PCIInfo.VendorID, final.PCIInfo.DeviceID)
	}
	if final.RegAddress != ci.RegAddress || final.FBSize != ci.FBSize || final.InterruptLine != ci.InterruptLine {
		t.Errorf("unrelated card info fields were disturbed")
	}
	if final.Valid != 1 {
		t.Errorf("Valid was disturbed")
	}
}

// TestBusGetInfoV2ParamsSize pins the modelled layout of
// NV2080_CTRL_BUS_GET_INFO_V2_PARAMS against the entry size nvgpu computes.
func TestBusGetInfoV2ParamsSize(t *testing.T) {
	if got, want := int(nvgpu.CtrlXxxInfoSize), 8; got != want {
		t.Fatalf("NVXXXX_CTRL_XXX_INFO is %d bytes, want %d ({NvU32 index, NvU32 data})", got, want)
	}
	if got, want := busGetInfoV2ParamsSize, 4+0x34*8; got != want {
		t.Errorf("busGetInfoV2ParamsSize = %d, want %d", got, want)
	}
	// The three PCI indices, from ctrl2080bus.h.
	if busInfoIndexBusNumber != 0x0f || busInfoIndexDeviceNumber != 0x10 || busInfoIndexDomainNumber != 0x2c {
		t.Errorf("bus info indices are %#x/%#x/%#x, want 0xf/0x10/0x2c", busInfoIndexBusNumber, busInfoIndexDeviceNumber, busInfoIndexDomainNumber)
	}
}

// TestRemapPairsSkipsUnrecordedPCIAddrs pins backward compatibility: a
// checkpoint written before nvproxy recorded PCI addresses yields no PCI
// mapping at all, rather than a mapping onto 0000:00:00.0.
func TestRemapPairsSkipsUnrecordedPCIAddrs(t *testing.T) {
	dr := &DeviceRemapping{NewDeviceByOld: map[*DeviceRemapID]*DeviceRemapID{}}
	oldDev := &DeviceRemapID{DeviceInstance: 1, Minor: 2} // no PCIAddrValid
	newDev := &DeviceRemapID{DeviceInstance: 6, Minor: 5, PCIBus: 0x0b, PCIAddrValid: true}
	dr.NewDeviceByOld[oldDev] = newDev

	_, _, _, _, pciAddrs := remapPairs(dr)
	if len(pciAddrs) != 0 {
		t.Errorf("remapPairs() produced %d PCI address pairs from an old checkpoint, want 0", len(pciAddrs))
	}

	// With both sides recorded, the pair appears.
	oldDev.PCIBus = 0x07
	oldDev.PCIAddrValid = true
	_, _, _, _, pciAddrs = remapPairs(dr)
	if len(pciAddrs) != 1 {
		t.Fatalf("remapPairs() produced %d PCI address pairs, want 1", len(pciAddrs))
	}
	if pciAddrs[0][0] != PackPCIAddr(0, 0x07, 0, 0) || pciAddrs[0][1] != PackPCIAddr(0, 0x0b, 0, 0) {
		t.Errorf("remapPairs() PCI pair = %s -> %s", formatPCIAddr(pciAddrs[0][0]), formatPCIAddr(pciAddrs[0][1]))
	}
}

// TestPCIAddrMapComposesAcrossRestores pins that a process restored twice
// still sees the PCI address of its original boot.
func TestPCIAddrMapComposesAcrossRestores(t *testing.T) {
	boot := PackPCIAddr(0, 0x07, 0, 0)
	first := PackPCIAddr(0, 0x0b, 0, 0)
	second := PackPCIAddr(0, 0x4e, 0, 0)

	m := composeMap[uint64](nil, [][2]uint64{{boot, first}})
	if m[first] != boot {
		t.Fatalf("after one restore %s maps to %s, want %s", formatPCIAddr(first), formatPCIAddr(m[first]), formatPCIAddr(boot))
	}
	m = composeMap(m, [][2]uint64{{first, second}})
	if m[second] != boot {
		t.Errorf("after two restores %s maps to %s, want %s", formatPCIAddr(second), formatPCIAddr(m[second]), formatPCIAddr(boot))
	}
	if _, ok := m[first]; ok {
		t.Errorf("a stale intermediate PCI address was kept: %v", m)
	}
	inv := invertMap(m, "PCI address")
	if inv[boot] != second {
		t.Errorf("guest-to-host PCI address = %s, want %s", formatPCIAddr(inv[boot]), formatPCIAddr(second))
	}
}

// TestDeviceRemapIDPCIAddrString pins how an unrecorded address is reported,
// so a log line cannot be read as "domain 0, bus 0".
func TestDeviceRemapIDPCIAddrString(t *testing.T) {
	id := &DeviceRemapID{}
	if got, want := id.PCIAddrString(), "<unrecorded>"; got != want {
		t.Errorf("PCIAddrString() = %q, want %q", got, want)
	}
	id = &DeviceRemapID{PCIDomain: 0, PCIBus: 0x0b, PCISlot: 0, PCIFunction: 0, PCIAddrValid: true}
	if got, want := id.PCIAddrString(), "0000:0b:00.0"; got != want {
		t.Errorf("PCIAddrString() = %q, want %q", got, want)
	}
}
