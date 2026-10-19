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
	"fmt"
	"slices"
	"testing"
)

const testELFMachineARM64 = 183 // EM_AARCH64

// checkARM64PatchDisasm verifies against objdump disassembly that each site in
// patch now branches to its own stub in after, and that the stub performs the
// counter read found at the site in before, subtracts the literal at
// patch.stubOffset from the destination register while preserving the
// scratch register, and branches back past the site. It also verifies that
// the literal holds tscOffset.
func checkARM64PatchDisasm(t *testing.T, before, after []byte, patch vdsoPatch, tscOffset uint64) {
	t.Helper()
	litOff := patch.stubOffset
	if lit := binary.LittleEndian.Uint64(after[litOff : litOff+arm64LiteralLen]); lit != tscOffset {
		t.Errorf("literal at %#x = %#x, want %#x", litOff, lit, tscOffset)
	}
	for i, site := range patch.sites {
		stubOff := patch.stubOffset + arm64LiteralLen + i*arm64StubLen
		if got, want := disasmARM64(t, after, site, site+patch.siteLen), []string{fmt.Sprintf("b %#x", stubOff)}; !slices.Equal(got, want) {
			t.Errorf("site %d at %#x disassembly: got %q, want %q", i, site, got, want)
		}
		orig := disasmARM64(t, before, site, site+patch.siteLen)
		var rt int
		if len(orig) != 1 {
			t.Errorf("site %d at %#x original disassembly: got %q, want one instruction", i, site, orig)
			continue
		}
		if _, err := fmt.Sscanf(orig[0], "mrs x%d,", &rt); err != nil {
			t.Errorf("site %d at %#x original disassembly %q is not an mrs into an X register: %v", i, site, orig[0], err)
			continue
		}
		scratch := 0
		if rt == 0 {
			scratch = 1
		}
		want := []string{
			orig[0],
			fmt.Sprintf("str x%d, [sp, #-16]!", scratch),
			fmt.Sprintf("ldr x%d, %#x", scratch, litOff),
			fmt.Sprintf("sub x%d, x%d, x%d", rt, rt, scratch),
			fmt.Sprintf("ldr x%d, [sp], #16", scratch),
			fmt.Sprintf("b %#x", site+patch.siteLen),
		}
		if got := disasmARM64(t, after, stubOff, stubOff+arm64StubLen); !slices.Equal(got, want) {
			t.Errorf("stub %d at %#x disassembly: got %q, want %q", i, stubOff, got, want)
		}
	}
	if end := patch.stubOffset + arm64LiteralLen + len(patch.sites)*arm64StubLen; end != patch.stubOffset+patch.stubLen {
		t.Errorf("stubs end at %#x, want %#x", end, patch.stubOffset+patch.stubLen)
	}
}

// arm64TestSites populates .text of a makeTestVDSOELF image with two counter
// read sites and returns their offsets.
//
//	128: isb
//	132: mrs x2, cntvct_el0
//	136: nop
//	140: mrs x0, cntvctss_el0
func arm64TestSites(buf []byte) []int {
	w := newARM64StubWriter(buf, testVDSOTextOff)
	w.isb()
	site0 := w.offset()
	w.mrsCNTVCT(2)
	w.nop()
	site1 := w.offset()
	w.mrsCNTVCTSS(0)
	return []int{site0, site1}
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
			sites := arm64TestSites(buf)
			before := append([]byte(nil), buf...)

			patch, err := patchVDSOTSCOffsetARM64(buf, testOffset)
			if err != nil {
				t.Fatalf("patchVDSOTSCOffsetARM64 failed: %v", err)
			}
			if !slices.Equal(patch.sites, sites) {
				t.Errorf("patched sites = %v, want %v", patch.sites, sites)
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)
			checkARM64PatchDisasm(t, before, buf, patch, testOffset)
		})
	}

	t.Run("NoSite", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, 0, nil)
		w := newARM64StubWriter(buf, testVDSOTextOff)
		w.mrsCNTVCT(arm64RegXZR)
		if _, err := patchVDSOTSCOffsetARM64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only counter read targets XZR, got nil")
		}
	})
}

// TestPatchHostVDSOARM64 patches a copy of the host's own [vdso] and checks
// that the patcher's assumptions hold for the running kernel.
func TestPatchHostVDSOARM64(t *testing.T) {
	before := hostVDSO(t)
	if before == nil {
		t.Skip("no [vdso] mapping")
	}
	after := append([]byte(nil), before...)

	const testOffset = uint64(0x123456789abcdef0)
	patch, err := patchVDSOTSCOffsetARM64(after, testOffset)
	if err != nil {
		t.Fatalf("patchVDSOTSCOffsetARM64 on the host [vdso] failed: %v", err)
	}
	if len(patch.sites) == 0 {
		t.Fatalf("no counter read sites were patched in the host [vdso]")
	}
	checkVDSOPatchFootprint(t, before, after, patch, patch.stubOffset)
	checkARM64PatchDisasm(t, before, after, patch, testOffset)
}
