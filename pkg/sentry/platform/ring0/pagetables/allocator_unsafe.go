// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// newAlignedPTEs returns a set of aligned PTEs.
func newAlignedPTEs() *PTEs {
	ptes := new(PTEs)
	offset := physicalFor(ptes) & (usermem.PageSize - 1)
	if offset == 0 {
		// Already aligned.
		return ptes
	}

	// Need to force an aligned allocation.
	unaligned := make([]byte, (2*usermem.PageSize)-1)
	offset = uintptr(unsafe.Pointer(&unaligned[0])) & (usermem.PageSize - 1)
	if offset != 0 {
		offset = usermem.PageSize - offset
	}
	return (*PTEs)(unsafe.Pointer(&unaligned[offset]))
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
