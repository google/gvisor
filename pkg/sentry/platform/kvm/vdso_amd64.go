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
		isRDTSCP, ok := matchAMD64RDTSCOrderedSite(vdsoBytes[i : i+amd64SiteLen])
		if !ok {
			continue
		}
		sites = append(sites, amd64VDSOSite{offset: i, isRDTSCP: isRDTSCP})
		if isRDTSCP {
			totalStubsLen += amd64RDTSCPStubLen
		} else {
			totalStubsLen += amd64LFenceRDTSCStubLen
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
	//   rdtscp OR lfence; rdtsc
	//   subl $lo, %eax
	//   sbbl $hi, %edx
	//   jmp <s.offset + 5>
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
		w := newAMD64StubWriter(vdsoBytes, siteStubOff)
		if s.isRDTSCP {
			w.rdtscp()
		} else {
			w.lfence()
			w.rdtsc()
		}
		w.sublEAX(lo)
		w.sbblEDX(hi)
		if err := w.jmpRel32(s.offset + amd64SiteLen); err != nil {
			return vdsoPatch{}, err
		}
		curStubOff = w.offset()

		if err := patchAMD64JmpRel32(vdsoBytes, s.offset, siteStubOff); err != nil {
			return vdsoPatch{}, err
		}
		patch.sites = append(patch.sites, s.offset)
	}

	log.Debugf("Patched %d rdtsc/rdtscp sites in shadow VDSO (tscOffset=%#x)", len(sites), tscOffset)
	return patch, nil
}
