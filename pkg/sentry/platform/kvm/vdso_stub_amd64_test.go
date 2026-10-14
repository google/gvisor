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
	"math"
	"slices"
	"testing"
)

// disasmAMD64 disassembles buf[startOff:endOff] as x86-64 instructions at
// image offset startOff.
func disasmAMD64(t *testing.T, buf []byte, startOff, endOff int) []string {
	t.Helper()
	return disasmBytes(t, "i386:x86-64", buf, startOff, endOff)
}

// TestMatchAMD64RDTSCOrderedSite verifies against objdump disassembly that
// amd64StubWriter emits the expected site instructions and
// matchAMD64RDTSCOrderedSite recognizes only valid 5-byte rdtsc_ordered()
// forms.
func TestMatchAMD64RDTSCOrderedSite(t *testing.T) {
	emit := func(fn func(w *amd64StubWriter)) []byte {
		buf := make([]byte, 16)
		w := newAMD64StubWriter(buf, 0)
		fn(&w)
		return buf[:w.offset()]
	}

	for _, tc := range []struct {
		name       string
		bytes      []byte
		wantDisasm []string
		wantRDTSCP bool
		wantOK     bool
	}{
		{
			name:       "RDTSCP_XchgAX",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtscp(); w.nop2() }),
			wantDisasm: []string{"rdtscp", "xchg %ax,%ax"},
			wantRDTSCP: true,
			wantOK:     true,
		},
		{
			name:       "RDTSCP_TwoNOPs",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtscp(); w.nop1(); w.nop1() }),
			wantDisasm: []string{"rdtscp", "nop", "nop"},
			wantRDTSCP: true,
			wantOK:     true,
		},
		{
			name:       "LFenceRDTSC",
			bytes:      emit(func(w *amd64StubWriter) { w.lfence(); w.rdtsc() }),
			wantDisasm: []string{"lfence", "rdtsc"},
			wantRDTSCP: false,
			wantOK:     true,
		},
		{
			name:       "RDTSC_NOPL",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtsc(); w.nop3() }),
			wantDisasm: []string{"rdtsc", "nopl (%rax)"},
			wantRDTSCP: false,
			wantOK:     true,
		},
		{
			name:       "RDTSC_K8NOP3",
			bytes:      []byte{0x0f, 0x31, 0x66, 0x66, 0x90},
			wantDisasm: []string{"rdtsc", "data16 xchg %ax,%ax"},
			wantRDTSCP: false,
			wantOK:     true,
		},
		{
			name:       "RDTSC_ThreeNOPs",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtsc(); w.nop1(); w.nop1(); w.nop1() }),
			wantDisasm: []string{"rdtsc", "nop", "nop", "nop"},
			wantRDTSCP: false,
			wantOK:     true,
		},
		{
			name:       "ShortSlice",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtscp(); w.nop1() }),
			wantDisasm: []string{"rdtscp", "nop"},
			wantRDTSCP: false,
			wantOK:     false,
		},
		{
			name:       "RDTSC_ShortNOP",
			bytes:      emit(func(w *amd64StubWriter) { w.rdtsc(); w.nop1(); w.ret(); w.nop1() }),
			wantDisasm: []string{"rdtsc", "nop", "ret", "nop"},
			wantRDTSCP: false,
			wantOK:     false,
		},
		{
			name:       "Unrelated",
			bytes:      []byte{0x48, 0x89, 0xe5, 0x90, 0x90},
			wantDisasm: []string{"mov %rsp,%rbp", "nop", "nop"},
			wantRDTSCP: false,
			wantOK:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if gotDisasm := disasmAMD64(t, tc.bytes, 0, len(tc.bytes)); !slices.Equal(gotDisasm, tc.wantDisasm) {
				t.Errorf("disasmAMD64(%x) = %q, want %q", tc.bytes, gotDisasm, tc.wantDisasm)
			}
			gotRDTSCP, gotOK := matchAMD64RDTSCOrderedSite(tc.bytes)
			if gotOK != tc.wantOK || gotRDTSCP != tc.wantRDTSCP {
				t.Errorf("matchAMD64RDTSCOrderedSite(%x) = (%v, %v), want (%v, %v)", tc.bytes, gotRDTSCP, gotOK, tc.wantRDTSCP, tc.wantOK)
			}
		})
	}
}

// TestAMD64StubWriter verifies against objdump disassembly that
// patchAMD64JmpRel32 and amd64StubWriter emit valid jump sites and TSC
// adjustment stubs.
func TestAMD64StubWriter(t *testing.T) {
	buf := make([]byte, 4096)

	// Emit an RDTSCP stub at 0xfbd for a site at 0x80.
	const (
		site0Off = 0x80
		stub0Off = 0xfbd
	)
	w0 := newAMD64StubWriter(buf, stub0Off)
	w0.rdtscp()
	w0.sublEAX(0x9abcdef0)
	w0.sbblEDX(0x12345678)
	if err := w0.jmpRel32(site0Off + amd64SiteLen); err != nil {
		t.Fatalf("w0.jmpRel32 failed: %v", err)
	}
	if w0.offset() != stub0Off+amd64RDTSCPStubLen {
		t.Fatalf("w0.offset() = %#x, want %#x", w0.offset(), stub0Off+amd64RDTSCPStubLen)
	}
	if err := patchAMD64JmpRel32(buf, site0Off, stub0Off); err != nil {
		t.Fatalf("patchAMD64JmpRel32 failed: %v", err)
	}

	if got, want := disasmAMD64(t, buf, site0Off, site0Off+amd64SiteLen), []string{"jmp 0xfbd"}; !slices.Equal(got, want) {
		t.Errorf("site 0 disassembly: got %q, want %q", got, want)
	}
	wantStub0 := []string{
		"rdtscp",
		"sub $0x9abcdef0,%eax",
		"sbb $0x12345678,%edx",
		"jmp 0x85",
	}
	if got := disasmAMD64(t, buf, stub0Off, w0.offset()); !slices.Equal(got, wantStub0) {
		t.Errorf("stub 0 disassembly: got %q, want %q", got, wantStub0)
	}

	// Emit an LFENCE; RDTSC stub immediately following stub 0 for a site at 0x86.
	const site1Off = 0x86
	stub1Off := w0.offset()
	w1 := newAMD64StubWriter(buf, stub1Off)
	w1.lfence()
	w1.rdtsc()
	w1.sublEAX(0x9abcdef0)
	w1.sbblEDX(0x12345678)
	if err := w1.jmpRel32(site1Off + amd64SiteLen); err != nil {
		t.Fatalf("w1.jmpRel32 failed: %v", err)
	}
	if w1.offset() != stub1Off+amd64LFenceRDTSCStubLen {
		t.Fatalf("w1.offset() = %#x, want %#x", w1.offset(), stub1Off+amd64LFenceRDTSCStubLen)
	}
	if err := patchAMD64JmpRel32(buf, site1Off, stub1Off); err != nil {
		t.Fatalf("patchAMD64JmpRel32 failed: %v", err)
	}

	if got, want := disasmAMD64(t, buf, site1Off, site1Off+amd64SiteLen), []string{"jmp 0xfd0"}; !slices.Equal(got, want) {
		t.Errorf("site 1 disassembly: got %q, want %q", got, want)
	}
	wantStub1 := []string{
		"lfence",
		"rdtsc",
		"sub $0x9abcdef0,%eax",
		"sbb $0x12345678,%edx",
		"jmp 0x8b",
	}
	if got := disasmAMD64(t, buf, stub1Off, w1.offset()); !slices.Equal(got, wantStub1) {
		t.Errorf("stub 1 disassembly: got %q, want %q", got, wantStub1)
	}

	// Verify overflow detection for displacements outside int32.
	if err := patchAMD64JmpRel32(buf, 0, math.MaxInt32+amd64SiteLen+1); err == nil {
		t.Errorf("expected error for out-of-range jmp displacement, got nil")
	}
}
