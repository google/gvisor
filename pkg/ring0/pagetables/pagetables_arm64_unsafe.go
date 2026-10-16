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

package pagetables

import (
	"unsafe"
)

// as64K returns the 64K granule page table page that starts at p.
//
// Precondition: p must have been allocated while granule64K was true.
//
//go:nosplit
func (p *PTEs) as64K() *ptes64K {
	return (*ptes64K)(unsafe.Pointer(p))
}

// ptes returns p as *PTEs.
//
//go:nosplit
func (p *ptes64K) ptes() *PTEs {
	return (*PTEs)(unsafe.Pointer(p))
}

// newPTEs allocates a page table page for the current translation granule.
// The returned page table page may not be aligned.
func newPTEs() *PTEs {
	if granule64K {
		return new(ptes64K).ptes()
	}
	return new(PTEs)
}
