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
	"encoding/binary"
	"testing"
)

// Layout of the synthetic [vdso] image built by makeTestVDSOELF.
const (
	testVDSOSize = 4096

	// testVDSOTextOff and testVDSOTextLen delimit .text.
	testVDSOTextOff = 128
	testVDSOTextLen = 64

	// testVDSOAltOff is the offset of .altinstructions; its size is a
	// parameter of makeTestVDSOELF.
	testVDSOAltOff = 192

	// testVDSOAltEntryLen is the size of a synthetic .altinstructions
	// entry: a self-relative 32-bit offset to the original instruction
	// followed by padding, like the kernel's struct alt_instr.
	testVDSOAltEntryLen = 8

	testVDSOShstrOff = 448
	testVDSOShdrOff  = 512
	testVDSOShdrNum  = 4
	testVDSOLoadLen  = 512

	// testVDSOShdrEnd is the end of the section header table, past which
	// the zero tail of the image begins.
	testVDSOShdrEnd = testVDSOShdrOff + testVDSOShdrNum*64
)

// makeTestVDSOELF builds a minimal little-endian ELF64 image resembling a
// [vdso]: a single PT_LOAD segment with the given flags holding .text and an
// .altinstructions section of altSize bytes, followed by .shstrtab and the
// section header table, and a zero tail up to the page boundary.
//
// altTargets are .text offsets to record as the original instruction of
// consecutive .altinstructions entries; altSize must have room for them.
func makeTestVDSOELF(machine uint16, progFlags uint32, altSize int, altTargets []int) []byte {
	if altSize < len(altTargets)*testVDSOAltEntryLen || testVDSOAltOff+altSize > testVDSOShstrOff {
		panic("invalid .altinstructions size")
	}
	buf := make([]byte, testVDSOSize)
	// ELF header:
	copy(buf[0:16], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint16(buf[16:18], 3)               // ET_DYN
	binary.LittleEndian.PutUint16(buf[18:20], machine)         // e_machine
	binary.LittleEndian.PutUint32(buf[20:24], 1)               // EV_CURRENT
	binary.LittleEndian.PutUint64(buf[32:40], 64)              // e_phoff
	binary.LittleEndian.PutUint64(buf[40:48], testVDSOShdrOff) // e_shoff
	binary.LittleEndian.PutUint16(buf[52:54], 64)              // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:56], 56)              // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:58], 1)               // e_phnum
	binary.LittleEndian.PutUint16(buf[58:60], 64)              // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:62], testVDSOShdrNum) // e_shnum
	binary.LittleEndian.PutUint16(buf[62:64], 1)               // e_shstrndx

	// Program header (PT_LOAD):
	binary.LittleEndian.PutUint32(buf[64:68], 1)                 // PT_LOAD
	binary.LittleEndian.PutUint32(buf[68:72], progFlags)         // p_flags
	binary.LittleEndian.PutUint64(buf[72:80], 0)                 // p_offset
	binary.LittleEndian.PutUint64(buf[80:88], 0)                 // p_vaddr
	binary.LittleEndian.PutUint64(buf[88:96], 0)                 // p_paddr
	binary.LittleEndian.PutUint64(buf[96:104], testVDSOLoadLen)  // p_filesz
	binary.LittleEndian.PutUint64(buf[104:112], testVDSOLoadLen) // p_memsz
	binary.LittleEndian.PutUint64(buf[112:120], testVDSOSize)    // p_align

	// .altinstructions entries:
	for i, target := range altTargets {
		off := testVDSOAltOff + i*testVDSOAltEntryLen
		binary.LittleEndian.PutUint32(buf[off:off+4], uint32(int32(target-off)))
	}

	// .shstrtab:
	shstrtab := []byte("\x00.shstrtab\x00.text\x00.altinstructions\x00")
	copy(buf[testVDSOShstrOff:], shstrtab)

	// Section headers (section 0 is SHT_NULL):
	shdr := func(idx int, name, typ uint32, flags, addr, off, size uint64) {
		base := testVDSOShdrOff + idx*64
		binary.LittleEndian.PutUint32(buf[base:base+4], name)
		binary.LittleEndian.PutUint32(buf[base+4:base+8], typ)
		binary.LittleEndian.PutUint64(buf[base+8:base+16], flags)
		binary.LittleEndian.PutUint64(buf[base+16:base+24], addr)
		binary.LittleEndian.PutUint64(buf[base+24:base+32], off)
		binary.LittleEndian.PutUint64(buf[base+32:base+40], size)
	}
	shdr(1, 1, 3 /* SHT_STRTAB */, 0, 0, testVDSOShstrOff, uint64(len(shstrtab)))
	shdr(2, 11, 1 /* SHT_PROGBITS */, 6 /* SHF_ALLOC | SHF_EXECINSTR */, testVDSOTextOff, testVDSOTextOff, testVDSOTextLen)
	shdr(3, 17, 1 /* SHT_PROGBITS */, 2 /* SHF_ALLOC */, testVDSOAltOff, testVDSOAltOff, uint64(altSize))

	return buf
}

// testVDSOTailStubOffset returns where findStubOffset places totalStubsLen
// bytes of stubs in the zero tail of a makeTestVDSOELF image.
func testVDSOTailStubOffset(totalStubsLen int) int {
	return (testVDSOSize - totalStubsLen) &^ 7
}

// checkVDSOPatchFootprint verifies that patching before into after changed
// nothing outside the patched sites and the stub range, and that the stubs
// were placed at wantStubOffset.
func checkVDSOPatchFootprint(t *testing.T, before, after []byte, patch vdsoPatch, wantStubOffset int) {
	t.Helper()
	if patch.stubOffset != wantStubOffset {
		t.Errorf("stubs placed at %d, want %d", patch.stubOffset, wantStubOffset)
	}
	if len(before) != len(after) {
		t.Fatalf("image length changed from %d to %d", len(before), len(after))
	}
	inFootprint := func(i int) bool {
		if i >= patch.stubOffset && i < patch.stubOffset+patch.stubLen {
			return true
		}
		for _, s := range patch.sites {
			if i >= s && i < s+patch.siteLen {
				return true
			}
		}
		return false
	}
	for i := range before {
		if before[i] != after[i] && !inFootprint(i) {
			t.Errorf("byte %d changed outside the patch footprint: %#02x -> %#02x", i, before[i], after[i])
		}
	}
}
