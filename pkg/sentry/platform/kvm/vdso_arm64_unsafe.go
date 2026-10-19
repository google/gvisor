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
		if rt, ok := matchARM64CounterRead(insn); ok {
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
	//     3. ldr <Xscratch>, <stubOffset>
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

		w := newARM64StubWriter(vdsoBytes, siteStubOff)
		w.rawInsn(s.insn)
		w.pushRegToSP(scratch)
		if err := w.ldrLiteral64(scratch, stubOffset); err != nil {
			return vdsoPatch{}, err
		}
		w.subReg64(s.rt, s.rt, scratch)
		w.popRegFromSP(scratch)
		if err := w.b(s.offset + arm64SiteLen); err != nil {
			return vdsoPatch{}, err
		}

		if err := patchARM64B(vdsoBytes, s.offset, siteStubOff); err != nil {
			return vdsoPatch{}, err
		}
		patch.sites = append(patch.sites, s.offset)
	}

	log.Debugf("Patched %d cntvct sites in ARM64 shadow VDSO (tscOffset=%#x)", len(sites), tscOffset)
	return patch, nil
}
