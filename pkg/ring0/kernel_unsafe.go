// Copyright 2018 The gVisor Authors.
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

package ring0

import (
	"unsafe"
)

// eface mirrors runtime.eface.
type eface struct {
	typ  uintptr
	data unsafe.Pointer
}

// kernelAddr returns the kernel virtual address for the given object.
//
//go:nosplit
func kernelAddr(obj any) uintptr {
	e := (*eface)(unsafe.Pointer(&obj))
	return KernelStartAddress | uintptr(e.data)
}

// paranoidStackTop returns the kernel address to use as the interrupt stack
// pointer for the given stack and stores gsBase in the 8 bytes right above it.
// See paranoidException in entry_amd64.s.
func paranoidStackTop(stack []byte, gsBase uintptr) uint64 {
	// The CPU aligns the stack pointer to 16 bytes when it switches to an
	// interrupt stack, so align it here to make the location of the slot
	// deterministic.
	base := uintptr(unsafe.Pointer(&stack[0]))
	top := (base + uintptr(len(stack)) - 8) &^ 15
	slot := (*uintptr)(unsafe.Pointer(&stack[top-base]))
	*slot = gsBase
	return uint64(kernelAddr(slot))
}

// kernelFunc returns the address of the given function.
//
//go:nosplit
func kernelFunc(fn uintptr) uintptr {
	return KernelStartAddress | fn
}
