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

//go:build amd64
// +build amd64

package kvm

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

const (
	testELFMachineAMD64 = 62 // EM_X86_64
	testPFRX            = 5  // PF_R | PF_X
	testPFR             = 4  // PF_R
)

// amd64TestSiteOffsets are the .text offsets of the counter read sites that
// amd64TestSites emits, in the order they are recorded in .altinstructions.
var amd64TestSiteOffsets = []int{128, 134, 140}

// amd64TestSites populates .text of a makeTestVDSOELF image with three
// counter read sites and one decoy, and returns amd64TestSiteOffsets.
//
//	128: rdtscp; xchg %ax, %ax (0f 01 f9 66 90)
//	134: lfence; rdtsc         (0f ae e8 0f 31)
//	140: rdtsc; nopl (%rax)    (0f 31 0f 1f 00)
//	146: rdtsc; nopl (%rax)    (0f 31 0f 1f 00), not an alternatives site
func amd64TestSites(buf []byte) []int {
	copy(buf[128:133], []byte{0x0f, 0x01, 0xf9, 0x66, 0x90})
	buf[133] = 0x90
	copy(buf[134:139], []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31})
	buf[139] = 0x90
	copy(buf[140:145], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
	buf[145] = 0x90
	copy(buf[146:151], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
	buf[151] = 0xc3
	return amd64TestSiteOffsets
}

// checkAMD64Stubs verifies the stubs that patchVDSOTSCOffsetAMD64 emitted for
// the amd64TestSites sites.
func checkAMD64Stubs(t *testing.T, buf []byte, testOffset uint64) {
	t.Helper()
	sites := []struct {
		off      int
		wantHead []byte
	}{
		{128, []byte{0x0f, 0x01, 0xf9}},
		{134, []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31}},
		{140, []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31}},
	}
	wantLo := uint32(testOffset & 0xffffffff)
	wantHi := uint32(testOffset >> 32)

	for idx, s := range sites {
		if buf[s.off] != 0xe9 {
			t.Fatalf("site %d (off %d): expected JMP rel32 (0xe9), got %#x", idx, s.off, buf[s.off])
		}
		rel32 := int32(binary.LittleEndian.Uint32(buf[s.off+1 : s.off+5]))
		stubOff := (s.off + 5) + int(rel32)
		headLen := len(s.wantHead)
		if !bytes.Equal(buf[stubOff:stubOff+headLen], s.wantHead) {
			t.Errorf("site %d stub head: got %x, want %x", idx, buf[stubOff:stubOff+headLen], s.wantHead)
		}
		suf := buf[stubOff+headLen : stubOff+headLen+amd64StubSuffixLen]
		// subl $lo, %eax (2d <lo>)
		if suf[0] != 0x2d {
			t.Errorf("site %d subl opcode: got %#x", idx, suf[0])
		}
		if gotLo := binary.LittleEndian.Uint32(suf[1:5]); gotLo != wantLo {
			t.Errorf("site %d subl imm32: got %#x, want %#x", idx, gotLo, wantLo)
		}
		// sbbl $hi, %edx (81 da <hi>)
		if suf[5] != 0x81 || suf[6] != 0xda {
			t.Errorf("site %d sbbl opcode: got %x", idx, suf[5:7])
		}
		if gotHi := binary.LittleEndian.Uint32(suf[7:11]); gotHi != wantHi {
			t.Errorf("site %d sbbl imm32: got %#x, want %#x", idx, gotHi, wantHi)
		}
		// jmp rel32 (e9)
		if suf[11] != 0xe9 {
			t.Errorf("site %d jmp opcode: got %#x", idx, suf[11])
		}
		backRel32 := int32(binary.LittleEndian.Uint32(suf[12:16]))
		backTarget := (stubOff + headLen + amd64StubSuffixLen) + int(backRel32)
		if backTarget != s.off+5 {
			t.Errorf("site %d jmp back target: got %d, want %d", idx, backTarget, s.off+5)
		}
	}

	// The decoy at 146 matches the byte pattern but is not an alternatives
	// site, so it must be left alone.
	if want := []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00}; !bytes.Equal(buf[146:151], want) {
		t.Errorf("unanchored rdtsc at 146 was patched: got %x, want %x", buf[146:151], want)
	}
}

func TestPatchVDSOTSCOffsetAMD64(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)
	const totalStubsLen = amd64RDTSCPStubLen + 2*amd64LFenceRDTSCStubLen

	for _, tc := range []struct {
		name           string
		altSize        int
		wantStubOffset int
	}{
		// With only room for the entries, the stubs go to the zero tail.
		{"ZeroTail", 3 * testVDSOAltEntryLen, testVDSOTailStubOffset(totalStubsLen)},
		// With a large enough .altinstructions, the stubs overwrite it.
		{"DeadSection", 128, testVDSOAltOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, tc.altSize, amd64TestSiteOffsets)
			sites := amd64TestSites(buf)
			before := append([]byte(nil), buf...)

			patch, err := patchVDSOTSCOffsetAMD64(buf, testOffset)
			if err != nil {
				t.Fatalf("patchVDSOTSCOffsetAMD64 failed: %v", err)
			}
			if len(patch.sites) != len(sites) {
				t.Errorf("patched %d sites, want %d", len(patch.sites), len(sites))
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)
			checkAMD64Stubs(t, buf, testOffset)
		})
	}
}

func TestPatchVDSOTSCOffsetAMD64Errors(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)

	t.Run("NoAnchoredSite", func(t *testing.T) {
		// A valid pattern that no alternatives entry points at.
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, 8, []int{160})
		copy(buf[128:133], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only rdtsc site is not an alternatives site, got nil")
		}
	})

	t.Run("ShortSite", func(t *testing.T) {
		// A bare rdtsc with a 1-byte NOP is not a 5-byte site.
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, 8, []int{136})
		copy(buf[136:140], []byte{0x0f, 0x31, 0x90, 0xc3})
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error when no valid 5-byte rdtsc site is present, got nil")
		}
	})

	t.Run("NonExecutableSegment", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFR, 8, []int{128})
		copy(buf[128:133], []byte{0x0f, 0x01, 0xf9, 0x66, 0x90})
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error for non-executable PT_LOAD segment, got nil")
		}
	})

	t.Run("OffsetVaddrMismatch", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, 8, []int{128})
		copy(buf[128:133], []byte{0x0f, 0x01, 0xf9, 0x66, 0x90})
		binary.LittleEndian.PutUint64(buf[80:88], 0x1000) // p_vaddr
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error when p_offset != p_vaddr, got nil")
		}
	})
}

// hostVDSO returns a copy of the host [vdso] image, or nil if the host has no
// [vdso] mapping.
func hostVDSO(t *testing.T) []byte {
	t.Helper()
	var vdso []byte
	if err := applyVirtualRegions(func(vr virtualRegion) bool {
		if vr.filename != "[vdso]" {
			return false
		}
		vdso = append([]byte(nil), sliceFromAddr(vr.virtual, vr.length)...)
		return true
	}); err != nil {
		t.Fatalf("error scanning /proc/self/maps: %v", err)
	}
	return vdso
}

// TestPatchHostVDSOAMD64 patches a copy of the host's own [vdso] and checks
// that the patcher's assumptions hold for the running kernel.
func TestPatchHostVDSOAMD64(t *testing.T) {
	before := hostVDSO(t)
	if before == nil {
		t.Skip("no [vdso] mapping")
	}
	after := append([]byte(nil), before...)

	const testOffset = uint64(0x123456789abcdef0)
	patch, err := patchVDSOTSCOffsetAMD64(after, testOffset)
	if err != nil {
		t.Fatalf("patchVDSOTSCOffsetAMD64 on the host [vdso] failed: %v", err)
	}
	if len(patch.sites) == 0 {
		t.Fatalf("no counter read sites were patched in the host [vdso]")
	}
	checkVDSOPatchFootprint(t, before, after, patch, patch.stubOffset)

	// Every patched site must have been one of the three forms that
	// rdtsc_ordered() resolves to.
	for _, s := range patch.sites {
		b := before[s : s+amd64SiteLen]
		switch {
		case b[0] == 0x0f && b[1] == 0x01 && b[2] == 0xf9 && isAMD64NOP2(b[3], b[4]):
		case b[0] == 0x0f && b[1] == 0xae && b[2] == 0xe8 && b[3] == 0x0f && b[4] == 0x31:
		case b[0] == 0x0f && b[1] == 0x31 && isAMD64NOP3(b[2], b[3], b[4]):
		default:
			t.Errorf("site at %#x held %x before patching, which is not a counter read", s, b)
		}
	}

	// The stubs must have landed either in a dead section or in a
	// previously zero-filled region.
	f, err := elf.NewFile(bytes.NewReader(before))
	if err != nil {
		t.Fatalf("failed to parse the host [vdso]: %v", err)
	}
	inDeadSection := false
	for _, sec := range f.Sections {
		if vdsoDeadSections[sec.Name] && patch.stubOffset >= int(sec.Offset) && patch.stubOffset+patch.stubLen <= int(sec.Offset+sec.Size) {
			inDeadSection = true
		}
	}
	if !inDeadSection && !isAllZero(before[patch.stubOffset:patch.stubOffset+patch.stubLen]) {
		t.Errorf("stubs at [%#x, %#x) overwrote live data", patch.stubOffset, patch.stubOffset+patch.stubLen)
	}
	t.Logf("patched %d sites; stubs at %#x (dead section: %t)", len(patch.sites), patch.stubOffset, inDeadSection)
}
