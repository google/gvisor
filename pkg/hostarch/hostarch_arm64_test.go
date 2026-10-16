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

package hostarch

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHostPageSize(t *testing.T) {
	if got, want := PageSize, uintptr(unix.Getpagesize()); got != want {
		t.Errorf("PageSize = %d, want host page size %d", got, want)
	}
	if !IsSupportedPageSize(int(PageSize)) {
		t.Errorf("PageSize %d is not a supported page size", PageSize)
	}
}

func TestPageSizes(t *testing.T) {
	for _, test := range []struct {
		pageShift     uint
		pageSize      uintptr
		hugePageShift uint
		hugePageSize  uintptr
	}{
		{
			pageShift:     12,
			pageSize:      4 << 10,
			hugePageShift: 21,
			hugePageSize:  2 << 20,
		},
		{
			pageShift:     16,
			pageSize:      64 << 10,
			hugePageShift: 29,
			hugePageSize:  512 << 20,
		},
	} {
		t.Run(fmt.Sprintf("%dK", test.pageSize>>10), func(t *testing.T) {
			restore := SetPageShiftForTesting(test.pageShift)
			defer restore()

			if PageShift != test.pageShift || PageSize != test.pageSize || PageMask != test.pageSize-1 {
				t.Errorf("got PageShift=%d PageSize=%#x PageMask=%#x, want %d %#x %#x", PageShift, PageSize, PageMask, test.pageShift, test.pageSize, test.pageSize-1)
			}
			if HugePageShift != test.hugePageShift || HugePageSize != test.hugePageSize || HugePageMask != test.hugePageSize-1 {
				t.Errorf("got HugePageShift=%d HugePageSize=%#x HugePageMask=%#x, want %d %#x %#x", HugePageShift, HugePageSize, HugePageMask, test.hugePageShift, test.hugePageSize, test.hugePageSize-1)
			}
			if MinPageSize > PageSize || PageSize > MaxPageSize {
				t.Errorf("PageSize %#x not in [MinPageSize=%#x, MaxPageSize=%#x]", PageSize, MinPageSize, MaxPageSize)
			}

			// Rounding helpers must follow the page size.
			x := uint64(test.pageSize + 1)
			if got, want := PageRoundDown(x), uint64(test.pageSize); got != want {
				t.Errorf("PageRoundDown(%#x) = %#x, want %#x", x, got, want)
			}
			if got, ok := PageRoundUp(x); !ok || got != uint64(2*test.pageSize) {
				t.Errorf("PageRoundUp(%#x) = (%#x, %t), want (%#x, true)", x, got, ok, 2*test.pageSize)
			}
			if got, want := PageOffset(x), uint64(1); got != want {
				t.Errorf("PageOffset(%#x) = %#x, want %#x", x, got, want)
			}
			if IsPageAligned(x) || !IsPageAligned(uint64(test.pageSize)) {
				t.Errorf("IsPageAligned is inconsistent with PageSize %#x", test.pageSize)
			}
			if got, ok := ToPagesRoundUp(x); !ok || got != 2 {
				t.Errorf("ToPagesRoundUp(%#x) = (%d, %t), want (2, true)", x, got, ok)
			}
			if got, ok := ToPagesRoundUp(uint32(test.pageSize)); !ok || got != 1 {
				t.Errorf("ToPagesRoundUp(%#x) = (%d, %t), want (1, true)", test.pageSize, got, ok)
			}
			y := Addr(test.hugePageSize + test.pageSize)
			if got, want := y.HugeRoundDown(), Addr(test.hugePageSize); got != want {
				t.Errorf("Addr(%#x).HugeRoundDown() = %#x, want %#x", y, got, want)
			}
			if got, ok := y.HugeRoundUp(); !ok || got != Addr(2*test.hugePageSize) {
				t.Errorf("Addr(%#x).HugeRoundUp() = (%#x, %t), want (%#x, true)", y, got, ok, 2*test.hugePageSize)
			}
		})
	}
	// The previous page size must have been restored.
	TestHostPageSize(t)
}
