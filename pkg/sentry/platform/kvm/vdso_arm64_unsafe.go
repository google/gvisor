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
	"unsafe"

	"gvisor.dev/gvisor/pkg/log"
)

// arm64VDSOSite is a counter read site in the [vdso] .text section.
type arm64VDSOSite struct {
	// offset is the offset of the site in the image.
	offset int

	// insn is the original MRS instruction.
	insn uint32

	// rt is the destination register of insn.
	rt uint32
}

const (
	// arm64SiteLen is the length of a counter read site, a single MRS.
	arm64SiteLen = 4

	// arm64LiteralLen is the length of the tscOffset literal that precedes
	// the stubs.
	arm64LiteralLen = 8

	// arm64StubLen is the length of a per-site stub: six instructions.
	arm64StubLen = 24
)

// flushICache cleans the data cache and invalidates the instruction cache
// to the point of unification for [addr, addr+length), so that code written
// through a data mapping is visible to instruction fetch.
func flushICache(addr, length uintptr)

// patchVDSOTSCOffset patches every counter read in the .text section of the
// [vdso] image in vdsoBytes to subtract tscOffset from the hardware counter.
func patchVDSOTSCOffset(vdsoBytes []byte, tscOffset uint64) error {
	if _, err := patchVDSOTSCOffsetARM64(vdsoBytes, tscOffset); err != nil {
		return err
	}
	flushICache(uintptr(unsafe.Pointer(&vdsoBytes[0])), uintptr(len(vdsoBytes)))
	return nil
}

// patchVDSOTSCOffsetARM64 implements patchVDSOTSCOffset for arm64 and returns
// a description of the modifications.
//
// Counter reads in the vDSO are "mrs <Xt>, cntvct_el0" or, on hosts with
// FEAT_ECV, "mrs <Xt>, cntvctss_el0". Instructions are fixed-size and
// aligned, so the exact encodings are matched directly. Each site is
// redirected to a stub that performs the original read, subtracts tscOffset
// from Xt, and branches back.
func patchVDSOTSCOffsetARM64(vdsoBytes []byte, tscOffset uint64) (vdsoPatch, error) {
	img, err := parseVDSO(vdsoBytes)
	if err != nil {
		return vdsoPatch{}, err
	}

	var sites []arm64VDSOSite
	for i := img.textStart; i <= img.textEnd-arm64SiteLen; i += arm64SiteLen {
		insn := binary.LittleEndian.Uint32(vdsoBytes[i : i+arm64SiteLen])
		// Check for:
		//   mrs <Xt>, cntvct_el0   (0xd53be040 | rt)
		//   mrs <Xt>, cntvctss_el0 (0xd53be0c0 | rt)
		if insn&0xffffffe0 == 0xd53be040 || insn&0xffffffe0 == 0xd53be0c0 {
			rt := insn & 0x1f
			if rt == 31 {
				// Reading into XZR discards the counter value.
				continue
			}
			sites = append(sites, arm64VDSOSite{
				offset: i,
				insn:   insn,
				rt:     rt,
			})
		}
	}
	if len(sites) == 0 {
		return vdsoPatch{}, fmt.Errorf("no cntvct_el0/cntvctss_el0 instructions found in [vdso] .text")
	}

	// Layout of stub space:
	//   [stubOffset : stubOffset+8]: 64-bit tscOffset literal
	//   Each site stub takes 24 bytes (6 instructions):
	//     1. origInsn (mrs <Xt>, cntvct_el0 / cntvctss_el0)
	//     2. str <Xscratch>, [sp, #-16]!
	//     3. ldr <Xscratch>, <pc_rel_stubOffset>
	//     4. sub <Xt>, <Xt>, <Xscratch>
	//     5. ldr <Xscratch>, [sp], #16
	//     6. b <s.offset + 4>
	//
	// SUB does not set the flags, and AAPCS64 has no red zone, so the
	// pre-indexed store below SP is safe and nothing but Xt is modified.
	totalStubsLen := arm64LiteralLen + len(sites)*arm64StubLen
	stubOffset, err := img.findStubOffset(totalStubsLen)
	if err != nil {
		return vdsoPatch{}, err
	}

	binary.LittleEndian.PutUint64(vdsoBytes[stubOffset:stubOffset+arm64LiteralLen], tscOffset)

	patch := vdsoPatch{siteLen: arm64SiteLen, stubOffset: stubOffset, stubLen: totalStubsLen}
	for idx, s := range sites {
		siteStubOff := stubOffset + arm64LiteralLen + idx*arm64StubLen
		scratch := uint32(0)
		if s.rt == 0 {
			scratch = 1
		}

		// 1. Original MRS instruction.
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff:siteStubOff+4], s.insn)

		// 2. str <Xscratch>, [sp, #-16]!
		// Pre-indexed STR: 0xf81f0fe0 | scratch
		strInsn := uint32(0xf81f0fe0) | scratch
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff+4:siteStubOff+8], strInsn)

		// 3. ldr <Xscratch>, <stubOffset>
		// PC is siteStubOff + 8. Load literal imm19 is (stubOffset - PC) >> 2.
		pc := siteStubOff + 8
		relWords := int32((stubOffset - pc) >> 2)
		ldrInsn := uint32(0x58000000) | ((uint32(relWords) & 0x7ffff) << 5) | scratch
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff+8:siteStubOff+12], ldrInsn)

		// 4. sub <Xt>, <Xt>, <Xscratch>
		// 64-bit SUB (no flags): 0xcb000000 | (scratch << 16) | (s.rt << 5) | s.rt
		subInsn := uint32(0xcb000000) | (scratch << 16) | (s.rt << 5) | s.rt
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff+12:siteStubOff+16], subInsn)

		// 5. ldr <Xscratch>, [sp], #16
		// Post-indexed LDR: 0xf84107e0 | scratch
		ldrPostInsn := uint32(0xf84107e0) | scratch
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff+16:siteStubOff+20], ldrPostInsn)

		// 6. b <s.offset + 4>
		// PC is siteStubOff + 20. Target is s.offset + 4.
		bBackRel := int32((s.offset+arm64SiteLen)-(siteStubOff+20)) >> 2
		bBackInsn := uint32(0x14000000) | (uint32(bBackRel) & 0x03ffffff)
		binary.LittleEndian.PutUint32(vdsoBytes[siteStubOff+20:siteStubOff+24], bBackInsn)

		// Patch original site with: b <siteStubOff>
		bStubRel := int32(siteStubOff-s.offset) >> 2
		bStubInsn := uint32(0x14000000) | (uint32(bStubRel) & 0x03ffffff)
		binary.LittleEndian.PutUint32(vdsoBytes[s.offset:s.offset+arm64SiteLen], bStubInsn)
		patch.sites = append(patch.sites, s.offset)
	}

	log.Debugf("Patched %d cntvct sites in ARM64 shadow VDSO (tscOffset=%#x)", len(sites), tscOffset)
	return patch, nil
}
