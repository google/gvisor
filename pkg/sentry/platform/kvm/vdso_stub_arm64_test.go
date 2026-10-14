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
	"slices"
	"testing"
)

// disasmARM64 disassembles buf[startOff:endOff] as A64 instructions at image
// offset startOff.
func disasmARM64(t *testing.T, buf []byte, startOff, endOff int) []string {
	t.Helper()
	return disasmBytes(t, "aarch64", buf, startOff, endOff)
}

// TestMatchARM64CounterRead verifies against objdump disassembly that
// arm64StubWriter emits the expected site instructions and
// matchARM64CounterRead recognizes only valid non-XZR counter reads.
func TestMatchARM64CounterRead(t *testing.T) {
	for _, tc := range []struct {
		name       string
		emit       func(w *arm64StubWriter)
		wantDisasm string
		wantRt     uint32
		wantOK     bool
	}{
		{"CNTVCT_X2", func(w *arm64StubWriter) { w.mrsCNTVCT(2) }, "mrs x2, cntvct_el0", 2, true},
		{"CNTVCTSS_X0", func(w *arm64StubWriter) { w.mrsCNTVCTSS(0) }, "mrs x0, cntvctss_el0", 0, true},
		{"CNTVCT_XZR", func(w *arm64StubWriter) { w.mrsCNTVCT(arm64RegXZR) }, "mrs xzr, cntvct_el0", 0, false},
		{"CNTVCTSS_XZR", func(w *arm64StubWriter) { w.mrsCNTVCTSS(arm64RegXZR) }, "mrs xzr, cntvctss_el0", 0, false},
		{"ISB", func(w *arm64StubWriter) { w.isb() }, "isb", 0, false},
		{"NOP", func(w *arm64StubWriter) { w.nop() }, "nop", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf [4]byte
			w := newARM64StubWriter(buf[:], 0)
			tc.emit(&w)
			if gotDisasm := disasmARM64(t, buf[:], 0, 4); !slices.Equal(gotDisasm, []string{tc.wantDisasm}) {
				t.Errorf("disasmARM64(%x) = %q, want [%q]", buf, gotDisasm, tc.wantDisasm)
			}
			insn := binary.LittleEndian.Uint32(buf[:])
			gotRt, gotOK := matchARM64CounterRead(insn)
			if gotOK != tc.wantOK || gotRt != tc.wantRt {
				t.Errorf("matchARM64CounterRead(%#x) = (%d, %v), want (%d, %v)", insn, gotRt, gotOK, tc.wantRt, tc.wantOK)
			}
		})
	}
}

// TestARM64StubWriter verifies against objdump disassembly that patchARM64B
// and arm64StubWriter emit valid branch sites and CNTVCT adjustment stubs.
func TestARM64StubWriter(t *testing.T) {
	buf := make([]byte, 4096)
	const (
		site0Off = 0x84
		litOff   = 0xfc0
		stub0Off = 0xfc8
	)

	w0 := newARM64StubWriter(buf, stub0Off)
	w0.mrsCNTVCT(2)
	w0.pushRegToSP(0)
	if err := w0.ldrLiteral64(0, litOff); err != nil {
		t.Fatalf("w0.ldrLiteral64 failed: %v", err)
	}
	w0.subReg64(2, 2, 0)
	w0.popRegFromSP(0)
	if err := w0.b(site0Off + arm64SiteLen); err != nil {
		t.Fatalf("w0.b failed: %v", err)
	}
	if w0.offset() != stub0Off+arm64StubLen {
		t.Fatalf("w0.offset() = %#x, want %#x", w0.offset(), stub0Off+arm64StubLen)
	}
	if err := patchARM64B(buf, site0Off, stub0Off); err != nil {
		t.Fatalf("patchARM64B failed: %v", err)
	}

	if got, want := disasmARM64(t, buf, site0Off, site0Off+arm64SiteLen), []string{"b 0xfc8"}; !slices.Equal(got, want) {
		t.Errorf("site 0 disassembly: got %q, want %q", got, want)
	}
	wantStub0 := []string{
		"mrs x2, cntvct_el0",
		"str x0, [sp, #-16]!",
		"ldr x0, 0xfc0",
		"sub x2, x2, x0",
		"ldr x0, [sp], #16",
		"b 0x88",
	}
	if got := disasmARM64(t, buf, stub0Off, w0.offset()); !slices.Equal(got, wantStub0) {
		t.Errorf("stub 0 disassembly: got %q, want %q", got, wantStub0)
	}

	// Emit a second stub for cntvctss_el0 into x0 (using x1 as scratch).
	const site1Off = 0x8c
	stub1Off := w0.offset()
	w1 := newARM64StubWriter(buf, stub1Off)
	w1.mrsCNTVCTSS(0)
	w1.pushRegToSP(1)
	if err := w1.ldrLiteral64(1, litOff); err != nil {
		t.Fatalf("w1.ldrLiteral64 failed: %v", err)
	}
	w1.subReg64(0, 0, 1)
	w1.popRegFromSP(1)
	if err := w1.b(site1Off + arm64SiteLen); err != nil {
		t.Fatalf("w1.b failed: %v", err)
	}
	if w1.offset() != stub1Off+arm64StubLen {
		t.Fatalf("w1.offset() = %#x, want %#x", w1.offset(), stub1Off+arm64StubLen)
	}
	if err := patchARM64B(buf, site1Off, stub1Off); err != nil {
		t.Fatalf("patchARM64B failed: %v", err)
	}

	if got, want := disasmARM64(t, buf, site1Off, site1Off+arm64SiteLen), []string{"b 0xfe0"}; !slices.Equal(got, want) {
		t.Errorf("site 1 disassembly: got %q, want %q", got, want)
	}
	wantStub1 := []string{
		"mrs x0, cntvctss_el0",
		"str x1, [sp, #-16]!",
		"ldr x1, 0xfc0",
		"sub x0, x0, x1",
		"ldr x1, [sp], #16",
		"b 0x90",
	}
	if got := disasmARM64(t, buf, stub1Off, w1.offset()); !slices.Equal(got, wantStub1) {
		t.Errorf("stub 1 disassembly: got %q, want %q", got, wantStub1)
	}

	// Verify alignment and range checks.
	if err := w0.ldrLiteral64(0, litOff+4); err == nil {
		t.Errorf("expected error for non-8-byte-aligned literal offset, got nil")
	}
	unalignedW := newARM64StubWriter(buf, stub0Off+2)
	if err := unalignedW.ldrLiteral64(0, litOff); err == nil {
		t.Errorf("expected error for misaligned writer offset, got nil")
	}
	if err := w0.ldrLiteral64(0, w0.offset()+(1<<20)); err == nil {
		t.Errorf("expected error for out-of-range literal offset, got nil")
	}
	if err := patchARM64B(buf, site0Off, site0Off+2); err == nil {
		t.Errorf("expected error for misaligned branch target, got nil")
	}
	if err := patchARM64B(buf, site0Off+2, stub0Off+2); err == nil {
		t.Errorf("expected error for misaligned branch site and target with aligned difference, got nil")
	}
	if err := patchARM64B(buf, 0, 1<<27); err == nil {
		t.Errorf("expected error for out-of-range branch target, got nil")
	}
}
