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
)

const (
	// arm64SiteLen is the length of a counter read site, a single MRS.
	arm64SiteLen = 4

	// arm64LiteralLen is the length of the tscOffset literal that precedes
	// the stubs.
	arm64LiteralLen = 8

	// arm64StubLen is the length of a per-site stub: six instructions.
	arm64StubLen = 24

	// arm64RegXZR is the encoding of the 64-bit zero register XZR.
	arm64RegXZR = 31

	// ARM64 instruction encodings and masks:
	//   mrs <Xt>, cntvct_el0:   0xd53be040 | Rt
	//   mrs <Xt>, cntvctss_el0: 0xd53be0c0 | Rt
	//   isb:                    0xd5033fdf
	//   nop:                    0xd503201f
	//   str <Xt>, [sp, #-16]!:  0xf81f0fe0 | Rt
	//   ldr <Xt>, [sp], #16:    0xf84107e0 | Rt
	//   ldr <Xt>, <label>:      0x58000000 | (imm19 << 5) | Rt
	//   sub <Xd>, <Xn>, <Xm>:   0xcb000000 | (Rm << 16) | (Rn << 5) | Rd
	//   b <label>:              0x14000000 | imm26
	arm64InsnMRSMask      = 0xffffffe0
	arm64InsnMRSCNTVCT    = 0xd53be040
	arm64InsnMRSCNTVCTSS  = 0xd53be0c0
	arm64InsnISB          = 0xd5033fdf
	arm64InsnNOP          = 0xd503201f
	arm64InsnSTRPreSP16   = 0xf81f0fe0
	arm64InsnLDRPostSP16  = 0xf84107e0
	arm64InsnLDRLiteral64 = 0x58000000
	arm64InsnSUBReg64     = 0xcb000000
	arm64InsnB            = 0x14000000
)

// matchARM64CounterRead checks whether insn is "mrs <Xt>, cntvct_el0" or
// "mrs <Xt>, cntvctss_el0" into a general-purpose register (excluding XZR,
// which discards the counter value).
func matchARM64CounterRead(insn uint32) (rt uint32, ok bool) {
	if insn&arm64InsnMRSMask != arm64InsnMRSCNTVCT && insn&arm64InsnMRSMask != arm64InsnMRSCNTVCTSS {
		return 0, false
	}
	rt = insn & 0x1f
	if rt == arm64RegXZR {
		return 0, false
	}
	return rt, true
}

// arm64StubWriter emits A64 instructions into an image buffer at a tracked
// offset so that PC-relative displacements are computed from the instruction's
// own address.
type arm64StubWriter struct {
	buf []byte
	off int
}

// newARM64StubWriter returns a stub writer positioned at off in buf.
func newARM64StubWriter(buf []byte, off int) arm64StubWriter {
	return arm64StubWriter{buf: buf, off: off}
}

// offset returns the writer's current byte offset in the image buffer.
func (w *arm64StubWriter) offset() int {
	return w.off
}

// rawInsn emits a 32-bit instruction word verbatim.
func (w *arm64StubWriter) rawInsn(insn uint32) {
	binary.LittleEndian.PutUint32(w.buf[w.off:w.off+4], insn)
	w.off += 4
}

// mrsCNTVCT emits "mrs <Xt>, cntvct_el0".
func (w *arm64StubWriter) mrsCNTVCT(rt uint32) {
	w.rawInsn(arm64InsnMRSCNTVCT | (rt & 0x1f))
}

// mrsCNTVCTSS emits "mrs <Xt>, cntvctss_el0".
func (w *arm64StubWriter) mrsCNTVCTSS(rt uint32) {
	w.rawInsn(arm64InsnMRSCNTVCTSS | (rt & 0x1f))
}

// isb emits "isb".
func (w *arm64StubWriter) isb() {
	w.rawInsn(arm64InsnISB)
}

// nop emits "nop".
func (w *arm64StubWriter) nop() {
	w.rawInsn(arm64InsnNOP)
}

// pushRegToSP emits "str <Xt>, [sp, #-16]!" (pre-indexed 64-bit store).
func (w *arm64StubWriter) pushRegToSP(rt uint32) {
	w.rawInsn(arm64InsnSTRPreSP16 | (rt & 0x1f))
}

// popRegFromSP emits "ldr <Xt>, [sp], #16" (post-indexed 64-bit load).
func (w *arm64StubWriter) popRegFromSP(rt uint32) {
	w.rawInsn(arm64InsnLDRPostSP16 | (rt & 0x1f))
}

// ldrLiteral64 emits "ldr <Xt>, <literalOff>" (PC-relative 64-bit literal load).
func (w *arm64StubWriter) ldrLiteral64(rt uint32, literalOff int) error {
	if w.off&3 != 0 {
		return fmt.Errorf("ldr literal instruction offset %#x is not 4-byte aligned", w.off)
	}
	if literalOff&7 != 0 {
		return fmt.Errorf("ldr 64-bit literal offset %#x is not 8-byte aligned", literalOff)
	}
	relBytes := literalOff - w.off
	relWords := relBytes >> 2
	if relWords < -(1<<18) || relWords >= (1<<18) {
		return fmt.Errorf("ldr literal displacement %d words from %#x to %#x overflows 19-bit signed immediate", relWords, w.off, literalOff)
	}
	imm19 := uint32(int32(relWords)) & 0x7ffff
	w.rawInsn(arm64InsnLDRLiteral64 | (imm19 << 5) | (rt & 0x1f))
	return nil
}

// subReg64 emits "sub <Xd>, <Xn>, <Xm>" (64-bit shifted register, no flags).
func (w *arm64StubWriter) subReg64(rd, rn, rm uint32) {
	w.rawInsn(arm64InsnSUBReg64 | ((rm & 0x1f) << 16) | ((rn & 0x1f) << 5) | (rd & 0x1f))
}

// b emits an unconditional branch "b <targetOff>".
func (w *arm64StubWriter) b(targetOff int) error {
	if err := patchARM64B(w.buf, w.off, targetOff); err != nil {
		return err
	}
	w.off += 4
	return nil
}

// patchARM64B writes an unconditional branch "b <targetOff>" at
// buf[siteOff:siteOff+4].
func patchARM64B(buf []byte, siteOff, targetOff int) error {
	if siteOff&3 != 0 || targetOff&3 != 0 {
		return fmt.Errorf("branch offsets from %#x to %#x are not 4-byte aligned", siteOff, targetOff)
	}
	relBytes := targetOff - siteOff
	relWords := relBytes >> 2
	if relWords < -(1<<25) || relWords >= (1<<25) {
		return fmt.Errorf("branch displacement %d words from %#x to %#x overflows 26-bit signed immediate", relWords, siteOff, targetOff)
	}
	imm26 := uint32(int32(relWords)) & 0x03ffffff
	binary.LittleEndian.PutUint32(buf[siteOff:siteOff+4], arm64InsnB|imm26)
	return nil
}
