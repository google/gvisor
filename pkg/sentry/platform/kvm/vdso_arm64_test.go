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

//go:build arm64
// +build arm64

package kvm

import (
	"encoding/binary"
	"testing"
)

const (
	testELFMachineARM64 = 183 // EM_AARCH64
	testPFRX            = 5   // PF_R | PF_X
	testPFR             = 4   // PF_R
)

// arm64TestSites populates .text of a makeTestVDSOELF image with two counter
// read sites.
//
//	128: isb
//	132: mrs x2, cntvct_el0
//	136: nop
//	140: mrs x0, cntvctss_el0
func arm64TestSites(buf []byte) {
	binary.LittleEndian.PutUint32(buf[128:132], 0xd5033fdf) // isb
	binary.LittleEndian.PutUint32(buf[132:136], 0xd53be042) // mrs x2, cntvct_el0 (rt=2)
	binary.LittleEndian.PutUint32(buf[136:140], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(buf[140:144], 0xd53be0c0) // mrs x0, cntvctss_el0 (rt=0)
}

// checkARM64Stub verifies the stub emitted for a site at siteOff whose
// original instruction read into rt using scratch register scratch.
func checkARM64Stub(t *testing.T, buf []byte, siteOff, litOff int, origInsn, rt, scratch uint32) {
	t.Helper()
	insn := binary.LittleEndian.Uint32(buf[siteOff : siteOff+4])
	if insn&0xfc000000 != 0x14000000 {
		t.Fatalf("expected B instruction at %d, got %#x", siteOff, insn)
	}
	rel := int32(insn&0x03ffffff) << 6 >> 6 // sign extend 26-bit
	stubOff := siteOff + int(rel<<2)

	want := []struct {
		name string
		insn uint32
	}{
		{"orig", origInsn},
		{"str scratch, [sp, #-16]!", 0xf81f0fe0 | scratch},
		{"ldr scratch, literal", uint32(0x58000000) | ((uint32(int32((litOff-(stubOff+8))>>2)) & 0x7ffff) << 5) | scratch},
		{"sub rt, rt, scratch", 0xcb000000 | (scratch << 16) | (rt << 5) | rt},
		{"ldr scratch, [sp], #16", 0xf84107e0 | scratch},
		{"b back", uint32(0x14000000) | (uint32(int32(siteOff+4-(stubOff+20))>>2) & 0x03ffffff)},
	}
	for i, w := range want {
		off := stubOff + 4*i
		if got := binary.LittleEndian.Uint32(buf[off : off+4]); got != w.insn {
			t.Errorf("stub for site %d, insn %d (%s): got %#x, want %#x", siteOff, i, w.name, got, w.insn)
		}
	}
}

func TestPatchVDSOTSCOffsetARM64(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)
	const totalStubsLen = arm64LiteralLen + 2*arm64StubLen

	for _, tc := range []struct {
		name           string
		altSize        int
		wantStubOffset int
	}{
		// Without a usable dead section, the stubs go to the zero tail.
		{"ZeroTail", 0, testVDSOTailStubOffset(totalStubsLen)},
		// With a large enough .altinstructions, the stubs overwrite it.
		{"DeadSection", 128, testVDSOAltOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, tc.altSize, nil)
			arm64TestSites(buf)
			before := append([]byte(nil), buf...)

			patch, err := patchVDSOTSCOffsetARM64(buf, testOffset)
			if err != nil {
				t.Fatalf("patchVDSOTSCOffsetARM64 failed: %v", err)
			}
			if len(patch.sites) != 2 {
				t.Errorf("patched %d sites, want 2", len(patch.sites))
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)

			litOff := patch.stubOffset
			if lit := binary.LittleEndian.Uint64(buf[litOff : litOff+8]); lit != testOffset {
				t.Fatalf("expected literal %#x at %d, got %#x", testOffset, litOff, lit)
			}
			// Site 0 reads into x2 and uses x0 as scratch; site 1 reads
			// into x0 and must therefore use x1.
			checkARM64Stub(t, buf, 132, litOff, 0xd53be042, 2, 0)
			checkARM64Stub(t, buf, 140, litOff, 0xd53be0c0, 0, 1)
		})
	}
}

func TestPatchVDSOTSCOffsetARM64Errors(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)

	t.Run("NoSite", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, 0, nil)
		binary.LittleEndian.PutUint32(buf[128:132], 0xd53be05f) // mrs xzr, cntvct_el0
		if _, err := patchVDSOTSCOffsetARM64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only counter read targets XZR, got nil")
		}
	})

	t.Run("NonExecutableSegment", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineARM64, testPFR, 0, nil)
		arm64TestSites(buf)
		if _, err := patchVDSOTSCOffsetARM64(buf, testOffset); err == nil {
			t.Errorf("expected error for non-executable PT_LOAD segment, got nil")
		}
	})

	t.Run("OffsetVaddrMismatch", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, 0, nil)
		arm64TestSites(buf)
		binary.LittleEndian.PutUint64(buf[80:88], 0x1000) // p_vaddr
		if _, err := patchVDSOTSCOffsetARM64(buf, testOffset); err == nil {
			t.Errorf("expected error when p_offset != p_vaddr, got nil")
		}
	})
}
