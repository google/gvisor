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

package pagetables

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// newAlignedPTEs returns a set of aligned PTEs.
func newAlignedPTEs(n uintptr) []PTEs {
	ptes := make([]PTEs, n)
	offset := physicalFor(&ptes[0]) & (hostarch.PageSize - 1)
	if offset == 0 {
		return ptes
	}
	// Need to force an aligned allocation.
	entrySize := unsafe.Sizeof(PTEs{})
	unaligned := make([]byte, n*entrySize+hostarch.PageSize-1)
	offset = uintptr(unsafe.Pointer(&unaligned[0])) & (hostarch.PageSize - 1)
	if offset != 0 {
		offset = hostarch.PageSize - offset
	}
	return unsafe.Slice((*PTEs)(unsafe.Pointer(&unaligned[offset])), n)
}

// physicalFor returns the "physical" address for PTEs.
//
//go:nosplit
func physicalFor(ptes *PTEs) uintptr {
	return uintptr(unsafe.Pointer(ptes))
}

// fromPhysical returns the PTEs from the "physical" address.
//
//go:nosplit
func fromPhysical(physical uintptr) *PTEs {
	return (*PTEs)(unsafe.Pointer(physical))
}
