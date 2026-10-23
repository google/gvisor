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

//go:build arm64

package hostarch

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"golang.org/x/sys/unix"
)

// arm64 supports 4K, 16K and 64K translation granules, and Linux can be
// configured to use any of them as its base page size. gVisor supports 4K and
// 64K page size hosts with a single binary: rather than being fixed at build
// time, the page size is a property of the host that is determined once,
// during package initialization, from the page size reported by the kernel
// (AT_PAGESZ).
//
// Consequently, PageShift, PageSize, PageMask, HugePageShift, HugePageSize and
// HugePageMask are variables on arm64 (and constants on other architectures).
// They are never modified after initialization and must be treated as
// constants. Code that needs a compile-time constant (e.g. to size an array)
// must use MinPageSize or MaxPageSize instead.
const (
	// MinPageShift is the binary log of the smallest supported page size.
	MinPageShift = 12

	// MinPageSize is the smallest supported page size.
	MinPageSize = 1 << MinPageShift

	// MaxPageShift is the binary log of the largest supported page size.
	MaxPageShift = 16

	// MaxPageSize is the largest supported page size.
	MaxPageSize = 1 << MaxPageShift

	// JumboPageSize is the 1GB jumbo page size.
	JumboPageSize = 1 << JumboPageShift

	// CacheLineSize is the size of the cache line.
	CacheLineSize = 1 << CacheLineShift

	// JumboPageShift is the binary log of jumbo page whose size is 1GB.
	JumboPageShift = 30

	// CacheLineShift is the binary log of the cache line size.
	CacheLineShift = 6
)

var (
	// PageShift is the binary log of the system page size.
	PageShift = hostPageShift()

	// PageSize is the system page size.
	PageSize = uintptr(1) << PageShift

	// PageMask is PageSize - 1.
	PageMask = PageSize - 1

	// HugePageShift is the binary log of the system huge page size: the size
	// mapped by a single entry in the last-level page table directory (PMD),
	// i.e. PageShift + (PageShift - 3). This is 21 (2MB huge pages) for 4K
	// pages and 29 (512MB huge pages) for 64K pages.
	HugePageShift = hugePageShift(PageShift)

	// HugePageSize is the system huge page size.
	HugePageSize = uintptr(1) << HugePageShift

	// HugePageMask is HugePageSize - 1.
	HugePageMask = HugePageSize - 1
)

// hugePageShift returns the binary log of the huge page size for the given
// page size.
func hugePageShift(pageShift uint) uint {
	return 2*pageShift - 3
}

// setPageShift sets PageShift and all values derived from it.
func setPageShift(shift uint) {
	PageShift = shift
	PageSize = uintptr(1) << PageShift
	PageMask = PageSize - 1
	HugePageShift = hugePageShift(PageShift)
	HugePageSize = uintptr(1) << HugePageShift
	HugePageMask = HugePageSize - 1
}

// SetPageShiftForTesting sets PageShift (and the values derived from it) to
// shift, and returns a function that restores their previous values. shift
// must be the binary log of a supported page size.
//
// This allows testing code paths that are specific to page sizes other than
// the host's, but only in code that doesn't interact with the host using the
// page size (e.g. when mapping memory with a page size smaller than the
// host's), and that doesn't depend on state derived from the page size during
// initialization. It must only be used by tests.
func SetPageShiftForTesting(shift uint) (restore func()) {
	if !IsSupportedPageSize(1 << shift) {
		panic(fmt.Sprintf("unsupported page shift %d", shift))
	}
	oldShift := PageShift
	setPageShift(shift)
	return func() {
		setPageShift(oldShift)
	}
}

// hostPageShift returns the binary log of the host page size.
//
// It must not panic: hostarch is imported by tools that may run on hosts
// whose page size gVisor doesn't support. Such hosts are rejected when a
// sandbox is started, see IsSupportedPageSize.
func hostPageShift() uint {
	size := unix.Getpagesize()
	if size < MinPageSize || size > MaxPageSize || size&(size-1) != 0 {
		println("WARNING: unexpected host page size", size, "- assuming", MinPageSize)
		return MinPageShift
	}
	return uint(bits.TrailingZeros(uint(size)))
}

// IsSupportedPageSize returns true if gVisor supports running on hosts with
// the given page size.
func IsSupportedPageSize(size int) bool {
	return size == 1<<12 || size == 1<<16
}

var (
	// ByteOrder is the native byte order (little endian).
	ByteOrder = binary.LittleEndian
)

// Arm64: Exception Syndrome Register EL1.
const (
	_ESR_ELx_EC_SHIFT = 26
	_ESR_ELx_EC_MASK  = 0x3F << _ESR_ELx_EC_SHIFT

	_ESR_ELx_EC_IABT_LOW = 0x20
	_ESR_ELx_EC_DABT_LOW = 0x24

	_ESR_ELx_WNR = 1 << 6
	_ESR_ELx_CM  = 1 << 8
)

// ESRAccessType returns the memory access type for the given ESR (Exception
// Syndrome Register) code. If code does not represent an invalid memory
// access from a lower exception level, ESRAccessType returns NoAccess.
//
//go:nosplit
func ESRAccessType(code uint64) AccessType {
	switch (code & _ESR_ELx_EC_MASK) >> _ESR_ELx_EC_SHIFT {
	case _ESR_ELx_EC_IABT_LOW:
		return Execute
	case _ESR_ELx_EC_DABT_LOW:
		// For faults on cache maintenance and address translation
		// instructions, _ESR_ELx_WNR is always set.
		if code&(_ESR_ELx_WNR|_ESR_ELx_CM) == _ESR_ELx_WNR {
			return Write
		}
		return Read
	default:
		return NoAccess
	}
}

// UntaggedUserAddr clears the tag from the address pointer. Top-Byte-Ignore (TBI0)
// is enabled in Linux, so bits[63:56] of user space addresses are ignored.
func UntaggedUserAddr(addr Addr) Addr {
	return Addr(int64(addr<<8) >> 8)
}
