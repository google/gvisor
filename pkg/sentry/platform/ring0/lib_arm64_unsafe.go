// Copyright 2019 The gVisor Authors.
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

// +build arm64

package ring0

import (
	"reflect"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	nopInstruction = 0xd503201f
	instSize       = unsafe.Sizeof(uint32(0))
	vectorsRawLen  = 0x800
)

func unsafeSlice(addr uintptr, length int) (slice []uint32) {
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	hdr.Data = addr
	hdr.Len = length / int(instSize)
	hdr.Cap = length / int(instSize)
	return slice
}

// Work around: move ring0.Vectors() into a specific address with 11-bits alignment.
//
// According to the design documentation of Arm64,
// the start address of exception vector table should be 11-bits aligned.
// Please see the code in linux kernel as reference: arch/arm64/kernel/entry.S
// But, we can't align a function's start address to a specific address by using golang.
// We have raised this question in golang community:
// https://groups.google.com/forum/m/#!topic/golang-dev/RPj90l5x86I
// This function will be removed when golang supports this feature.
//
// There are 2 jobs were implemented in this function:
// 1, move the start address of exception vector table into the specific address.
// 2, modify the offset of each instruction.
func rewriteVectors() {
	vectorsBegin := reflect.ValueOf(Vectors).Pointer()

	// The exception-vector-table is required to be 11-bits aligned.
	// And the size is 0x800.
	// Please see the documentation as reference:
	// https://developer.arm.com/docs/100933/0100/aarch64-exception-vector-table
	//
	// But, golang does not allow to set a function's address to a specific value.
	// So, for gvisor, I defined the size of exception-vector-table as 4K,
	// filled the 2nd 2K part with NOP-s.
	// So that, I can safely move the 1st 2K part into the address with 11-bits alignment.
	//
	// So, the prerequisite for this function to work correctly is:
	// vectorsSafeLen >= 0x1000
	// vectorsRawLen  = 0x800
	vectorsSafeLen := int(safecopy.FindEndAddress(vectorsBegin) - vectorsBegin)
	if vectorsSafeLen < 2*vectorsRawLen {
		panic("Can't update vectors")
	}

	vectorsSafeTable := unsafeSlice(vectorsBegin, vectorsSafeLen) // Now a []uint32
	vectorsRawLen32 := vectorsRawLen / int(instSize)

	offset := vectorsBegin & (1<<11 - 1)
	if offset != 0 {
		offset = 1<<11 - offset
	}

	pageBegin := (vectorsBegin + offset) & ^uintptr(usermem.PageSize-1)

	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, uintptr(pageBegin), uintptr(usermem.PageSize), uintptr(syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC))
	if errno != 0 {
		panic(errno.Error())
	}

	offset = offset / instSize // By index, not bytes.
	// Move exception-vector-table into the specific address, should uses memmove here.
	for i := 1; i <= vectorsRawLen32; i++ {
		vectorsSafeTable[int(offset)+vectorsRawLen32-i] = vectorsSafeTable[vectorsRawLen32-i]
	}

	// Adjust branch since instruction was moved forward.
	for i := 0; i < vectorsRawLen32; i++ {
		if vectorsSafeTable[int(offset)+i] != nopInstruction {
			vectorsSafeTable[int(offset)+i] -= uint32(offset)
		}
	}

	_, _, errno = syscall.Syscall(syscall.SYS_MPROTECT, uintptr(pageBegin), uintptr(usermem.PageSize), uintptr(syscall.PROT_READ|syscall.PROT_EXEC))
	if errno != 0 {
		panic(errno.Error())
	}
}
