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

	"gvisor.dev/gvisor/pkg/log"
)

// amd64VDSOSite is a counter read site in the [vdso] .text section.
type amd64VDSOSite struct {
	// offset is the offset of the site in the image.
	offset int

	// isRDTSCP is true if the site reads the counter with rdtscp, and false
	// if it reads it with rdtsc.
	isRDTSCP bool
}

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

// patchVDSOTSCOffset patches every counter read in the .text section of the
// [vdso] image in vdsoBytes to subtract tscOffset from the hardware counter.
func patchVDSOTSCOffset(vdsoBytes []byte, tscOffset uint64) error {
	_, err := patchVDSOTSCOffsetAMD64(vdsoBytes, tscOffset)
	return err
}

// patchVDSOTSCOffsetAMD64 implements patchVDSOTSCOffset for amd64 and returns
// a description of the modifications.
//
// Counter reads in the vDSO are emitted by rdtsc_ordered(), which is an
// ALTERNATIVE_2 that the kernel resolves at boot to one of three 5-byte
// forms: "rdtscp" padded with a 2-byte NOP, "lfence; rdtsc", or "rdtsc"
// padded with a 3-byte NOP. Each site is redirected to a stub that performs
// the original read, subtracts tscOffset from edx:eax, and jumps back.
//
// Because x86 instructions have variable length, a byte pattern alone could
// match the tail of an unrelated instruction. A site is therefore accepted
// only if it is also the original instruction of an entry in .altinstructions,
// which is what every rdtsc_ordered() expansion is.
func patchVDSOTSCOffsetAMD64(vdsoBytes []byte, tscOffset uint64) (vdsoPatch, error) {
	img, err := parseVDSO(vdsoBytes)
	if err != nil {
		return vdsoPatch{}, err
	}
	anchors, err := img.altInstrTargets()
	if err != nil {
		return vdsoPatch{}, err
	}

	var sites []amd64VDSOSite
	totalStubsLen := 0
	for i := img.textStart; i <= img.textEnd-amd64SiteLen; i++ {
		if !anchors[i] {
			continue
		}
		b := vdsoBytes[i : i+amd64SiteLen]
		switch {
		case b[0] == 0x0f && b[1] == 0x01 && b[2] == 0xf9 && isAMD64NOP2(b[3], b[4]):
			sites = append(sites, amd64VDSOSite{offset: i, isRDTSCP: true})
			totalStubsLen += amd64RDTSCPStubLen
		case b[0] == 0x0f && b[1] == 0xae && b[2] == 0xe8 && b[3] == 0x0f && b[4] == 0x31:
			sites = append(sites, amd64VDSOSite{offset: i, isRDTSCP: false})
			totalStubsLen += amd64LFenceRDTSCStubLen
		case b[0] == 0x0f && b[1] == 0x31 && isAMD64NOP3(b[2], b[3], b[4]):
			sites = append(sites, amd64VDSOSite{offset: i, isRDTSCP: false})
			totalStubsLen += amd64LFenceRDTSCStubLen
		default:
			continue
		}
		// Sites cannot overlap: skip the rest of this one.
		i += amd64SiteLen - 1
	}
	if len(sites) == 0 {
		return vdsoPatch{}, fmt.Errorf("no rdtsc/rdtscp instructions found in [vdso] .text")
	}

	stubOffset, err := img.findStubOffset(totalStubsLen)
	if err != nil {
		return vdsoPatch{}, err
	}

	lo := uint32(tscOffset)
	hi := uint32(tscOffset >> 32)
	curStubOff := stubOffset

	// Each per-site stub executes:
	//   rdtscp (0f 01 f9) OR lfence; rdtsc (0f ae e8 0f 31)
	//   2d <lo: 4 bytes LE>              subl $lo, %eax
	//   81 da <hi: 4 bytes LE>           sbbl $hi, %edx
	//   e9 <rel32: 4 bytes LE>           jmp <s.offset + 5>
	//
	// rdtsc and rdtscp zero the upper halves of rax and rdx, so the 32-bit
	// subtract-with-borrow pair is an exact 64-bit subtraction. The
	// subtraction clobbers the flags, which is safe: the site is an inline
	// asm statement, and both GCC and Clang treat every x86 inline asm
	// statement as clobbering the flags, so nothing is kept in them across
	// the site. No other register or memory is touched.
	patch := vdsoPatch{siteLen: amd64SiteLen, stubOffset: stubOffset, stubLen: totalStubsLen}
	for _, s := range sites {
		siteStubOff := curStubOff
		if s.isRDTSCP {
			copy(vdsoBytes[curStubOff:], []byte{0x0f, 0x01, 0xf9})
			curStubOff += 3
		} else {
			copy(vdsoBytes[curStubOff:], []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31})
			curStubOff += 5
		}

		// subl $lo, %eax
		vdsoBytes[curStubOff] = 0x2d
		binary.LittleEndian.PutUint32(vdsoBytes[curStubOff+1:curStubOff+5], lo)
		// sbbl $hi, %edx
		vdsoBytes[curStubOff+5] = 0x81
		vdsoBytes[curStubOff+6] = 0xda
		binary.LittleEndian.PutUint32(vdsoBytes[curStubOff+7:curStubOff+11], hi)
		// jmp <s.offset + 5>
		vdsoBytes[curStubOff+11] = 0xe9
		jmpBackRel32 := int32((s.offset + amd64SiteLen) - (curStubOff + amd64StubSuffixLen))
		binary.LittleEndian.PutUint32(vdsoBytes[curStubOff+12:curStubOff+16], uint32(jmpBackRel32))
		curStubOff += amd64StubSuffixLen

		// Patch the original 5-byte site with: jmp <siteStubOff>
		jmpStubRel32 := int32(siteStubOff - (s.offset + amd64SiteLen))
		vdsoBytes[s.offset] = 0xe9 // JMP rel32
		binary.LittleEndian.PutUint32(vdsoBytes[s.offset+1:s.offset+amd64SiteLen], uint32(jmpStubRel32))
		patch.sites = append(patch.sites, s.offset)
	}

	log.Debugf("Patched %d rdtsc/rdtscp sites in shadow VDSO (tscOffset=%#x)", len(sites), tscOffset)
	return patch, nil
}
