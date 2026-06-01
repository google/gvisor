// Copyright 2024 The gVisor Authors.
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

//go:build loong64

package hostarch

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const (
	// PageShift is the binary log of the system page size. LoongArch on
	// Linux mainline uses 16K pages by default (CONFIG_PAGE_SIZE_16KB)
	// with 4-level page tables.
	PageShift = 14

	// PageSize is the system page size (16 KiB).
	PageSize = 1 << PageShift

	// HugePageShift gives 32 MiB huge pages on a 16K-page system, matching
	// the kernel's default LoongArch huge page size.
	HugePageShift = 25

	// HugePageSize is the system huge page size.
	HugePageSize = 1 << HugePageShift

	// CacheLineSize is the size of the cache line on Loongson-3A5000/3A6000.
	CacheLineSize = 1 << CacheLineShift

	// CacheLineShift is the binary log of the cache line size (64 bytes).
	CacheLineShift = 6
)

// ByteOrder is the native byte order (little endian).
var ByteOrder = binary.LittleEndian

func init() {
	if size := unix.Getpagesize(); size != PageSize {
		println("WARNING: host page size mismatch - expected 16K LoongArch page")
	}
}

// UntaggedUserAddr returns the address unchanged. Unlike arm64, LoongArch
// does not have a Top-Byte-Ignore tagged-address ABI; all 48 user bits are
// significant.
func UntaggedUserAddr(addr Addr) Addr {
	return addr
}
