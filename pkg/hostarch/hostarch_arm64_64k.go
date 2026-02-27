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

//go:build arm64 && pagesize_64k

package hostarch

import "golang.org/x/sys/unix"

const (
	// PageShift is the binary log of the system page size.
	// 64K pages: 2^16 = 65536
	PageShift = 16

	// HugePageShift is the binary log of the system huge page size.
	// For 64K pages: PageShift + (PageShift - 3) = 16 + 13 = 29
	// This gives 512MB huge pages.
	HugePageShift = 29
)

func init() {
	// Make sure the page size is 64K on arm64 platform.
	if size := unix.Getpagesize(); size != PageSize {
		panic("Only 64K page size is supported on arm64 with pagesize_64k build tag!")
	}
}
