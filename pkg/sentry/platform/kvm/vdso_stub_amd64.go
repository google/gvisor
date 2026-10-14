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
	"encoding/binary"
	"fmt"
	"math"
)

const (
	// amd64SiteLen is the length of a counter read site. The kernel emits
	// rdtsc_ordered() as an ALTERNATIVE_2 whose longest replacement,
	// "lfence; rdtsc", is 5 bytes, so every site is padded to 5 bytes.
	amd64SiteLen = 5

	// amd64StubSuffixLen is the length of the stub body that follows the
	// counter read: subl (5), sbbl (6) and jmp (5).
	amd64StubSuffixLen = 16

	// amd64RDTSCPStubLen and amd64LFenceRDTSCStubLen are the stub lengths for
	// the two counter read forms.
	amd64RDTSCPStubLen      = 3 + amd64StubSuffixLen
	amd64LFenceRDTSCStubLen = 5 + amd64StubSuffixLen
)

// isAMD64NOP2 returns true if b0 b1 is a 2-byte NOP of the kind the kernel
// uses to pad alternatives: x86_nops[2] (66 90) or two 1-byte NOPs, which
// older kernels left behind when a replacement was applied.
func isAMD64NOP2(b0, b1 byte) bool {
	return (b0 == 0x66 && b1 == 0x90) || (b0 == 0x90 && b1 == 0x90)
}

// isAMD64NOP3 returns true if b0 b1 b2 is a 3-byte NOP of the kind the kernel
// uses to pad alternatives: x86_nops[3] (0f 1f 00), the K8 form (66 66 90),
// or combinations of 1- and 2-byte NOPs.
func isAMD64NOP3(b0, b1, b2 byte) bool {
	return (b0 == 0x0f && b1 == 0x1f && b2 == 0x00) ||
		(b0 == 0x66 && b1 == 0x66 && b2 == 0x90) ||
		(b0 == 0x66 && b1 == 0x90 && b2 == 0x90) ||
		(b0 == 0x90 && b1 == 0x66 && b2 == 0x90) ||
		(b0 == 0x90 && b1 == 0x90 && b2 == 0x90)
}

// matchAMD64RDTSCOrderedSite checks whether the 5-byte slice b is one of the
// three forms that the kernel's rdtsc_ordered() ALTERNATIVE_2 resolves to at
// boot:
//
//   - rdtscp (0f 01 f9) followed by a 2-byte NOP
//   - lfence; rdtsc (0f ae e8 0f 31)
//   - rdtsc (0f 31) followed by a 3-byte NOP
//
// If b matches, isRDTSCP reports whether the site uses rdtscp.
func matchAMD64RDTSCOrderedSite(b []byte) (isRDTSCP, ok bool) {
	if len(b) < amd64SiteLen {
		return false, false
	}
	switch {
	case b[0] == 0x0f && b[1] == 0x01 && b[2] == 0xf9 && isAMD64NOP2(b[3], b[4]):
		return true, true
	case b[0] == 0x0f && b[1] == 0xae && b[2] == 0xe8 && b[3] == 0x0f && b[4] == 0x31:
		return false, true
	case b[0] == 0x0f && b[1] == 0x31 && isAMD64NOP3(b[2], b[3], b[4]):
		return false, true
	default:
		return false, false
	}
}

// amd64StubWriter emits x86-64 instructions into an image buffer at a tracked
// offset so that PC-relative displacements are computed from the instruction's
// own address.
type amd64StubWriter struct {
	buf []byte
	off int
}

// newAMD64StubWriter returns a stub writer positioned at off in buf.
func newAMD64StubWriter(buf []byte, off int) amd64StubWriter {
	return amd64StubWriter{buf: buf, off: off}
}

// offset returns the writer's current byte offset in the image buffer.
func (w *amd64StubWriter) offset() int {
	return w.off
}

// rdtscp emits "rdtscp" (0f 01 f9).
func (w *amd64StubWriter) rdtscp() {
	copy(w.buf[w.off:w.off+3], []byte{0x0f, 0x01, 0xf9})
	w.off += 3
}

// lfence emits "lfence" (0f ae e8).
func (w *amd64StubWriter) lfence() {
	copy(w.buf[w.off:w.off+3], []byte{0x0f, 0xae, 0xe8})
	w.off += 3
}

// rdtsc emits "rdtsc" (0f 31).
func (w *amd64StubWriter) rdtsc() {
	copy(w.buf[w.off:w.off+2], []byte{0x0f, 0x31})
	w.off += 2
}

// nop1 emits a 1-byte "nop" (90).
func (w *amd64StubWriter) nop1() {
	w.buf[w.off] = 0x90
	w.off++
}

// nop2 emits a 2-byte NOP "xchg %ax, %ax" (66 90).
func (w *amd64StubWriter) nop2() {
	copy(w.buf[w.off:w.off+2], []byte{0x66, 0x90})
	w.off += 2
}

// nop3 emits a 3-byte NOP "nopl (%rax)" (0f 1f 00).
func (w *amd64StubWriter) nop3() {
	copy(w.buf[w.off:w.off+3], []byte{0x0f, 0x1f, 0x00})
	w.off += 3
}

// ret emits "ret" (c3).
func (w *amd64StubWriter) ret() {
	w.buf[w.off] = 0xc3
	w.off++
}

// sublEAX emits "subl $imm, %eax" (2d <imm32 LE>).
func (w *amd64StubWriter) sublEAX(imm uint32) {
	w.buf[w.off] = 0x2d
	binary.LittleEndian.PutUint32(w.buf[w.off+1:w.off+5], imm)
	w.off += 5
}

// sbblEDX emits "sbbl $imm, %edx" (81 da <imm32 LE>).
func (w *amd64StubWriter) sbblEDX(imm uint32) {
	w.buf[w.off] = 0x81
	w.buf[w.off+1] = 0xda
	binary.LittleEndian.PutUint32(w.buf[w.off+2:w.off+6], imm)
	w.off += 6
}

// jmpRel32 emits a 5-byte relative "jmp <targetOff>" (e9 <rel32 LE>).
func (w *amd64StubWriter) jmpRel32(targetOff int) error {
	if err := patchAMD64JmpRel32(w.buf, w.off, targetOff); err != nil {
		return err
	}
	w.off += 5
	return nil
}

// patchAMD64JmpRel32 writes a 5-byte relative "jmp <targetOff>" (e9 <rel32 LE>)
// at buf[siteOff:siteOff+5].
func patchAMD64JmpRel32(buf []byte, siteOff, targetOff int) error {
	rel := targetOff - (siteOff + amd64SiteLen)
	if rel < math.MinInt32 || rel > math.MaxInt32 {
		return fmt.Errorf("jmp displacement %d from %#x to %#x overflows int32", rel, siteOff, targetOff)
	}
	buf[siteOff] = 0xe9
	binary.LittleEndian.PutUint32(buf[siteOff+1:siteOff+amd64SiteLen], uint32(int32(rel)))
	return nil
}
