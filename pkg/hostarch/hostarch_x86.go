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

//go:build amd64 || 386
// +build amd64 386

package hostarch

import "encoding/binary"

const (
	// PageSize is the system page size.
	PageSize = 1 << PageShift

	// PageMask is PageSize - 1.
	PageMask = PageSize - 1

	// MinPageShift is the binary log of the smallest supported page size.
	MinPageShift = PageShift

	// MinPageSize is the smallest supported page size.
	MinPageSize = 1 << MinPageShift

	// MaxPageShift is the binary log of the largest supported page size.
	MaxPageShift = PageShift

	// MaxPageSize is the largest supported page size.
	MaxPageSize = 1 << MaxPageShift

	// HugePageSize is the system huge page size.
	HugePageSize = 1 << HugePageShift

	// HugePageMask is HugePageSize - 1.
	HugePageMask = HugePageSize - 1

	// JumboPageSize is the 1GB jumbo page size.
	JumboPageSize = 1 << JumboPageShift

	// CacheLineSize is the size of the cache line.
	CacheLineSize = 1 << CacheLineShift

	// PageShift is the binary log of the system page size.
	PageShift = 12

	// HugePageShift is the binary log of the system huge page size.
	HugePageShift = 21

	// JumboPageShift is the binary log of jumbo page whose size is 1GB.
	JumboPageShift = 30

	// CacheLineShift is the binary log of the cache line size.
	CacheLineShift = 6
)

var (
	// ByteOrder is the native byte order (little endian).
	ByteOrder = binary.LittleEndian
)

// IsSupportedPageSize returns true if gVisor supports running on hosts with
// the given page size.
func IsSupportedPageSize(size int) bool {
	return size == PageSize
}

// UntaggedUserAddr is no-op on x86.
func UntaggedUserAddr(addr Addr) Addr {
	return addr
}
