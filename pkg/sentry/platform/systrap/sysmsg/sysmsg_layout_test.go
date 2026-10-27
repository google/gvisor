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

package sysmsg

import (
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// TestPerThreadMemLayout checks the properties of the per-thread memory layout
// for the host page size that the stub relies on (see sysmsg.h).
func TestPerThreadMemLayout(t *testing.T) {
	pageSize := uintptr(hostarch.PageSize)
	memSize := uintptr(PerThreadMemSize)
	privateStackOffset := uintptr(PerThreadPrivateStackOffset)
	privateStackSize := uintptr(PerThreadPrivateStackSize)
	sharedStackOffset := uintptr(PerThreadSharedStackOffset)
	sharedStackSize := uintptr(PerThreadSharedStackSize)
	msgOffsetFromSharedStack := uintptr(MsgOffsetFromSharedStack)

	for _, v := range []struct {
		name  string
		value uintptr
	}{
		{"PerThreadMemSize", memSize},
		{"GuardSize", uintptr(GuardSize)},
		{"PerThreadPrivateStackOffset", privateStackOffset},
		{"PerThreadPrivateStackSize", privateStackSize},
		{"PerThreadSharedStackOffset", sharedStackOffset},
		{"PerThreadSharedStackSize", sharedStackSize},
		{"SpinningQueueMemSize", uintptr(SpinningQueueMemSize)},
	} {
		if v.value == 0 || v.value%pageSize != 0 {
			t.Errorf("%s = %#x, want a non-zero multiple of the page size (%#x)", v.name, v.value, pageSize)
		}
	}
	// There must be a guard page between the private and the shared stacks.
	if privateStackOffset+privateStackSize+pageSize > sharedStackOffset {
		t.Errorf("no guard page between the private stack [%#x, %#x) and the shared stack at %#x", privateStackOffset, privateStackOffset+privateStackSize, sharedStackOffset)
	}
	if got := sharedStackOffset + sharedStackSize; got != memSize {
		t.Errorf("shared stack ends at %#x, want PerThreadMemSize = %#x", got, memSize)
	}
	// The stub expects Msg in the last page of the per-thread memory region
	// (see sysmsg.h:MSG_OFFSET_FROM_START).
	if got, want := sharedStackOffset+msgOffsetFromSharedStack, memSize-pageSize; got != want {
		t.Errorf("Msg offset from the start of the per-thread memory region = %#x, want %#x", got, want)
	}
	// Msg must fit in the smallest supported page (see sysmsg.h:sysmsg_sp).
	if msgSize := unsafe.Sizeof(Msg{}); msgSize >= uintptr(hostarch.MinPageSize) {
		t.Errorf("Msg (%d bytes) doesn't fit in the smallest supported page (%d bytes)", msgSize, hostarch.MinPageSize)
	}
}
