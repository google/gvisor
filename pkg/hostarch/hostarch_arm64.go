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
// +build arm64

package hostarch

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const (
	// PageSize is the system page size.
	// arm64 support 4K/16K/64K page size,
	// which can be get by unix.Getpagesize().
	// Currently, only 4K page size is supported.
	PageSize = 1 << PageShift

	// HugePageSize is the system huge page size.
	HugePageSize = 1 << HugePageShift

	// CacheLineSize is the size of the cache line.
	CacheLineSize = 1 << CacheLineShift

	// PageShift is the binary log of the system page size.
	PageShift = 12

	// HugePageShift is the binary log of the system huge page size.
	// Should be calculated by "PageShift + (PageShift - 3)"
	// when multiple page size support is ready.
	HugePageShift = 21

	// CacheLineShift is the binary log of the cache line size.
	CacheLineShift = 6
)

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

func init() {
	// Make sure the page size is 4K on arm64 platform.
	if size := unix.Getpagesize(); size != PageSize {
		panic("Only 4K page size is supported on arm64!")
	}
}
