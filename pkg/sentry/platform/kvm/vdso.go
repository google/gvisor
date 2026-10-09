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

package kvm

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// vdsoImage is a parsed copy of the host [vdso] ELF image.
type vdsoImage struct {
	f *elf.File

	// data is the raw image. Its length is that of the [vdso] mapping, which
	// is the image size rounded up to a page.
	data []byte

	// textStart and textEnd delimit the .text section in data.
	textStart, textEnd int
}

// vdsoPatch describes the modifications a patcher made to a shadow [vdso]
// image. It is used by tests to verify that nothing else was touched.
type vdsoPatch struct {
	// sites are the offsets of the patched counter read sites, each of
	// which is siteLen bytes long.
	sites   []int
	siteLen int

	// stubOffset and stubLen delimit the adjustment stubs.
	stubOffset, stubLen int
}

// vdsoDeadSections are the sections whose contents are dead in the runtime
// [vdso] image, and which the adjustment stubs may therefore overwrite. The
// kernel applies alternatives to its own copy of the image once at boot and
// never consults these sections again, and the shadow is a private copy that
// nothing but the guest reads.
var vdsoDeadSections = map[string]bool{
	".altinstructions":      true,
	".altinstr_replacement": true,
}

// parseVDSO parses vdsoBytes and validates the assumptions the patchers rely
// on: the image is a little-endian ELF64 object whose file offsets equal its
// virtual offsets, so that offsets into vdsoBytes can be used directly to
// compute PC-relative displacements, and .text lies within an executable
// PT_LOAD segment.
func parseVDSO(vdsoBytes []byte) (*vdsoImage, error) {
	f, err := elf.NewFile(bytes.NewReader(vdsoBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse [vdso] ELF: %v", err)
	}
	if f.Class != elf.ELFCLASS64 || f.ByteOrder != binary.LittleEndian {
		return nil, fmt.Errorf("[vdso] ELF is not little-endian ELF64 (class %v, byte order %v)", f.Class, f.ByteOrder)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Off != p.Vaddr {
			return nil, fmt.Errorf("[vdso] PT_LOAD segment file offset %#x != virtual address %#x", p.Off, p.Vaddr)
		}
	}
	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("[vdso] ELF missing .text section")
	}
	if textSec.Offset != textSec.Addr {
		return nil, fmt.Errorf("[vdso] .text file offset %#x != virtual address %#x", textSec.Offset, textSec.Addr)
	}
	if textSec.Offset+textSec.Size > uint64(len(vdsoBytes)) {
		return nil, fmt.Errorf("[vdso] .text section out of bounds")
	}
	img := &vdsoImage{
		f:         f,
		data:      vdsoBytes,
		textStart: int(textSec.Offset),
		textEnd:   int(textSec.Offset + textSec.Size),
	}
	if !img.inExecutableSegment(img.textStart, img.textEnd-img.textStart) {
		return nil, fmt.Errorf("[vdso] .text section is not in an executable PT_LOAD segment")
	}
	return img, nil
}

// altInstrTargets returns the set of .text offsets that are the original
// instruction of an alternatives entry.
//
// Every entry in .altinstructions begins with a 32-bit offset to the
// instruction it patches, relative to the address of the offset itself
// (`.long 661b - .` on x86, `.word 661b - .` on arm64). Scanning every byte
// offset of the section, rather than stepping by the size of an entry, keeps
// this independent of the entry layout of the host kernel version. Spurious
// targets produced by the remaining fields are harmless, since a counter read
// site must also match the expected instruction bytes.
func (img *vdsoImage) altInstrTargets() (map[int]bool, error) {
	sec := img.f.Section(".altinstructions")
	if sec == nil {
		return nil, fmt.Errorf("[vdso] ELF missing .altinstructions section")
	}
	start, end := int(sec.Offset), int(sec.Offset+sec.Size)
	if end > len(img.data) {
		return nil, fmt.Errorf("[vdso] .altinstructions section out of bounds")
	}
	targets := make(map[int]bool)
	for i := start; i+4 <= end; i++ {
		target := i + int(int32(binary.LittleEndian.Uint32(img.data[i:i+4])))
		if target >= img.textStart && target < img.textEnd {
			targets[target] = true
		}
	}
	return targets, nil
}

// inExecutableSegment returns true if [off, off+size) lies within the pages
// covered by an executable PT_LOAD segment. The [vdso] mapping covers whole
// pages, so the padding between the end of the segment and the end of its
// last page is mapped and executable as well.
func (img *vdsoImage) inExecutableSegment(off, size int) bool {
	if off < 0 || size < 0 || off+size > len(img.data) {
		return false
	}
	const pageMask = hostarch.PageSize - 1
	for _, p := range img.f.Progs {
		if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
			continue
		}
		segStart := int(p.Off) &^ pageMask
		segEnd := (int(p.Off+p.Memsz) + pageMask) &^ pageMask
		if segEnd > len(img.data) {
			segEnd = len(img.data)
		}
		if off >= segStart && off+size <= segEnd {
			return true
		}
	}
	return false
}

// sectionHeaderEnd returns the end offset of the section header table.
func (img *vdsoImage) sectionHeaderEnd() int {
	// parseVDSO guarantees a little-endian ELF64 header.
	shoff := binary.LittleEndian.Uint64(img.data[40:48])
	shentsize := binary.LittleEndian.Uint16(img.data[58:60])
	shnum := binary.LittleEndian.Uint16(img.data[60:62])
	return int(shoff) + int(shentsize)*int(shnum)
}

// findStubOffset returns an 8-byte aligned offset at which totalStubsLen bytes
// of adjustment stubs can be placed without disturbing anything the guest may
// execute or read. The candidates are, in order of preference:
//
//  1. The dead sections listed in vdsoDeadSections, merged where they are
//     adjacent. Their size does not depend on how the image happened to be
//     padded, so they are the most reliable choice.
//  2. The zero-filled tail of the mapping, past every section and past the
//     section header table. Its size depends on the image size modulo the
//     page size, so it may not be available on every host kernel build.
//
// Either must lie within an executable PT_LOAD segment.
func (img *vdsoImage) findStubOffset(totalStubsLen int) (int, error) {
	type span struct{ start, end int }
	var dead []span
	liveEnd := img.sectionHeaderEnd()
	for _, s := range img.f.Sections {
		if s.Type == elf.SHT_NULL || s.Type == elf.SHT_NOBITS || s.Size == 0 {
			continue
		}
		start, end := int(s.Offset), int(s.Offset+s.Size)
		if end > len(img.data) {
			return -1, fmt.Errorf("[vdso] section %q out of bounds", s.Name)
		}
		if vdsoDeadSections[s.Name] {
			dead = append(dead, span{start, end})
		} else if end > liveEnd {
			liveEnd = end
		}
	}

	// Merge dead sections separated only by zero-filled alignment padding.
	sort.Slice(dead, func(i, j int) bool { return dead[i].start < dead[j].start })
	var merged []span
	for _, d := range dead {
		if n := len(merged); n > 0 && d.start >= merged[n-1].end && isAllZero(img.data[merged[n-1].end:d.start]) {
			if d.end > merged[n-1].end {
				merged[n-1].end = d.end
			}
			continue
		}
		merged = append(merged, d)
	}
	for _, d := range merged {
		off := (d.start + 7) &^ 7
		if off+totalStubsLen <= d.end && img.inExecutableSegment(off, totalStubsLen) {
			return off, nil
		}
	}

	cand := (len(img.data) - totalStubsLen) &^ 7
	if cand >= liveEnd && img.inExecutableSegment(cand, totalStubsLen) && isAllZero(img.data[cand:cand+totalStubsLen]) {
		return cand, nil
	}

	return -1, fmt.Errorf("no space found in [vdso] for %d-byte adjustment stubs", totalStubsLen)
}

// isAllZero returns true if every byte of b is zero.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
