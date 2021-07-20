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

	// PageShift is the binary log of the system page size.
	PageShift = 12

	// HugePageShift is the binary log of the system huge page size.
	// Should be calculated by "PageShift + (PageShift - 3)"
	// when multiple page size support is ready.
	HugePageShift = 21
)

var (
	// ByteOrder is the native byte order (little endian).
	ByteOrder = binary.LittleEndian
)

func init() {
	// Make sure the page size is 4K on arm64 platform.
	if size := unix.Getpagesize(); size != PageSize {
		panic("Only 4K page size is supported on arm64!")
	}
}
