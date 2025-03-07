// Copyright 2025 The gVisor Authors.
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

package hostarch

import "fmt"

// MemoryType specifies CPU memory access behavior.
type MemoryType uint8

const (
	// MemoryTypeWriteBack is equivalent to Linux's default pgprot, or the
	// following architectural memory types:
	//
	// - x86: Write-back (WB)
	//
	// - ARM64: Normal write-back cacheable
	//
	// This memory type is appropriate for typical application memory and must
	// be the zero value for MemoryType.
	MemoryTypeWriteBack MemoryType = iota

	// MemoryTypeWriteCombine is equivalent to Linux's pgprot_writecombine(),
	// or the following architectural memory types:
	//
	// - x86: Write-combining (WC)
	//
	// - ARM64: Normal non-cacheable
	MemoryTypeWriteCombine

	// MemoryTypeUncached is equivalent to Linux's pgprot_noncached(), or the
	// following architectural memory types:
	//
	// - x86: Strong Uncacheable (UC) or Uncacheable (UC-); these differ in
	// that UC- may be "downgraded" to WC by a setting of WC or (Intel only) WP
	// in MTRR or EPT/NPT, but gVisor does not use MTRRs and KVM never sets WC
	// or WP in EPT/NPT.
	//
	// - ARM64: Device-nGnRnE
	MemoryTypeUncached

	// NumMemoryTypes is the number of memory types.
	NumMemoryTypes
)

// String implements fmt.Stringer.String.
func (mt MemoryType) String() string {
	switch mt {
	case MemoryTypeWriteBack:
		return "WriteBack"
	case MemoryTypeWriteCombine:
		return "WriteCombine"
	case MemoryTypeUncached:
		return "Uncached"
	default:
		return fmt.Sprintf("%d", mt)
	}
}

// ShortString returns a two-character string compactly representing the
// MemoryType.
func (mt MemoryType) ShortString() string {
	switch mt {
	case MemoryTypeWriteBack:
		return "WB"
	case MemoryTypeWriteCombine:
		return "WC"
	case MemoryTypeUncached:
		return "UC"
	default:
		return fmt.Sprintf("%02d", mt)
	}
}
