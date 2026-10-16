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
	"fmt"
	"slices"
	"testing"
)

const testELFMachineAMD64 = 62 // EM_X86_64

// checkAMD64PatchDisasm verifies against objdump disassembly that each site in
// patch now jumps to its own stub in after, and that the stub performs the
// counter read found at the site in before, subtracts tscOffset from edx:eax
// and jumps back past the site.
func checkAMD64PatchDisasm(t *testing.T, before, after []byte, patch vdsoPatch, tscOffset uint64) {
	t.Helper()
	stubOff := patch.stubOffset
	for i, site := range patch.sites {
		if got, want := disasmAMD64(t, after, site, site+patch.siteLen), []string{fmt.Sprintf("jmp %#x", stubOff)}; !slices.Equal(got, want) {
			t.Errorf("site %d at %#x disassembly: got %q, want %q", i, site, got, want)
		}
		orig := disasmAMD64(t, before, site, site+patch.siteLen)
		want := []string{"lfence", "rdtsc"}
		stubLen := amd64LFenceRDTSCStubLen
		if len(orig) > 0 && orig[0] == "rdtscp" {
			want = []string{"rdtscp"}
			stubLen = amd64RDTSCPStubLen
		}
		want = append(want,
			fmt.Sprintf("sub $%#x,%%eax", uint32(tscOffset)),
			fmt.Sprintf("sbb $%#x,%%edx", uint32(tscOffset>>32)),
			fmt.Sprintf("jmp %#x", site+patch.siteLen))
		if got := disasmAMD64(t, after, stubOff, stubOff+stubLen); !slices.Equal(got, want) {
			t.Errorf("stub %d at %#x for site %q disassembly: got %q, want %q", i, stubOff, orig, got, want)
		}
		stubOff += stubLen
	}
	if stubOff != patch.stubOffset+patch.stubLen {
		t.Errorf("stubs end at %#x, want %#x", stubOff, patch.stubOffset+patch.stubLen)
	}
}

// amd64TestSiteOffsets are the .text offsets of the counter read sites that
// amd64TestSites emits, in the order they are recorded in .altinstructions.
var amd64TestSiteOffsets = []int{
	testVDSOTextOff,
	testVDSOTextOff + (amd64SiteLen + 1),
	testVDSOTextOff + 2*(amd64SiteLen+1),
}

// amd64TestSites populates .text of a makeTestVDSOELF image with three
// counter read sites and one unanchored decoy, and returns the offsets of the
// three anchored sites.
//
//	128: rdtscp; xchg %ax, %ax; nop
//	134: lfence; rdtsc; nop
//	140: rdtsc; nopl (%rax); nop
//	146: rdtsc; nopl (%rax); ret (not an alternatives site)
func amd64TestSites(buf []byte) []int {
	w := newAMD64StubWriter(buf, testVDSOTextOff)

	site0 := w.offset()
	w.rdtscp()
	w.nop2()
	w.nop1()

	site1 := w.offset()
	w.lfence()
	w.rdtsc()
	w.nop1()

	site2 := w.offset()
	w.rdtsc()
	w.nop3()
	w.nop1()

	// Unanchored decoy site.
	w.rdtsc()
	w.nop3()
	w.ret()

	return []int{site0, site1, site2}
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
			if !slices.Equal(patch.sites, sites) {
				t.Errorf("patched sites = %v, want %v", patch.sites, sites)
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)
			checkAMD64PatchDisasm(t, before, buf, patch, testOffset)
		})
	}

	t.Run("NoAnchoredSite", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, 8, []int{testVDSOTextOff + 32})
		w := newAMD64StubWriter(buf, testVDSOTextOff)
		w.rdtsc()
		w.nop3()
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only rdtsc site is not an alternatives site, got nil")
		}
	})
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
	checkAMD64PatchDisasm(t, before, after, patch, testOffset)
}
