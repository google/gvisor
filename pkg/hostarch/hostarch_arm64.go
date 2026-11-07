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

// On arm64, the host page size (4K or 64K) is read at init, so PageShift,
// PageSize, PageMask and the HugePage values are variables. Treat them as
// constants; use MinPageSize or MaxPageSize for compile-time constants.
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

	// HugePageShift is the binary log of the system huge page size (the size
	// of a PMD entry): 21 for 4K pages, 29 for 64K pages.
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

// SetPageShiftForTesting sets PageShift and the values derived from it, and
// returns a function that restores them. Only for tests of code that doesn't
// use the page size with the host. It isn't synchronized: don't use it with
// t.Parallel() or while other goroutines may read page size values.
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

// hostPageShift returns the binary log of the host page size. It doesn't panic
// on unsupported sizes, since tools import hostarch.
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
