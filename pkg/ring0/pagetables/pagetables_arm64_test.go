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

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// setGranuleForTesting switches the translation granule used by page tables
// for the duration of the test.
func setGranuleForTesting(t testing.TB, g granule) {
	t.Helper()
	oldGranule, oldPTESize := activeGranule, pteSize
	activeGranule, pteSize = g, g.pageSize()
	t.Cleanup(func() {
		activeGranule, pteSize = oldGranule, oldPTESize
	})
}

// use4KPagesForTest selects the 4K translation granule for the duration of
// the test.
func use4KPagesForTest(t *testing.T) {
	setGranuleForTesting(t, granule4K)
}

// use64KPagesForTest selects the 64K translation granule for the duration of
// the test.
func use64KPagesForTest(t *testing.T) {
	setGranuleForTesting(t, granule64K)
}

func TestDefaultGranule(t *testing.T) {
	if got, want := pteSize, uintptr(hostarch.PageSize); got != want {
		t.Errorf("pteSize = %#x, want hostarch.PageSize = %#x", got, want)
	}
	if got, want := activeGranule, hostGranule(); got != want {
		t.Errorf("activeGranule = %v, want %v (hostarch.PageSize = %#x)", got, want, hostarch.PageSize)
	}
}

func Test2MAnd4K(t *testing.T) {
	use4KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a small page and a huge page.
	pt.Map(0x400000, pteSize4K, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize4K*42)
	pt.Map(0x0000ff0000000000, pmdSize4K, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize4K*47)

	pt.Map(0xffff000000400000, pteSize4K, MapOpts{AccessType: hostarch.ReadWrite, User: false}, pteSize4K*42)
	pt.Map(0xffffff0000000000, pmdSize4K, MapOpts{AccessType: hostarch.Read, User: false}, pmdSize4K*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize4K, pteSize4K * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pmdSize4K, pmdSize4K * 47, MapOpts{AccessType: hostarch.Read, User: true}},
		{0xffff000000400000, pteSize4K, pteSize4K * 42, MapOpts{AccessType: hostarch.ReadWrite, User: false}},
		{0xffffff0000000000, pmdSize4K, pmdSize4K * 47, MapOpts{AccessType: hostarch.Read, User: false}},
	})
}

func Test1GAnd4K(t *testing.T) {
	use4KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a small page and a super page.
	pt.Map(0x400000, pteSize4K, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize4K*42)
	pt.Map(0x0000ff0000000000, pudSize4K, MapOpts{AccessType: hostarch.Read, User: true}, pudSize4K*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize4K, pteSize4K * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pudSize4K, pudSize4K * 47, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

func TestSplit1GPage(t *testing.T) {
	use4KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a super page and knock out the middle.
	pt.Map(0x0000ff0000000000, pudSize4K, MapOpts{AccessType: hostarch.Read, User: true}, pudSize4K*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize4K), pudSize4K-(2*pteSize4K))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize4K, pudSize4K * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pudSize4K - pteSize4K, pteSize4K, pudSize4K*42 + pudSize4K - pteSize4K, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

func TestSplit2MPage(t *testing.T) {
	use4KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a huge page and knock out the middle.
	pt.Map(0x0000ff0000000000, pmdSize4K, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize4K*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize4K), pmdSize4K-(2*pteSize4K))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize4K, pmdSize4K * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pmdSize4K - pteSize4K, pteSize4K, pmdSize4K*42 + pmdSize4K - pteSize4K, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

func TestNumMemoryTypes(t *testing.T) {
	// MAIR accommodates up to 8 entries.
	if hostarch.NumMemoryTypes > 8 {
		t.Errorf("PTE.Set() and PTE.Opts() must be altered to map %d MemoryTypes to a smaller set of MAIR entries", hostarch.NumMemoryTypes)
	}
}

func TestPXN(t *testing.T) {
	testCases := []struct {
		name      string
		opts      MapOpts
		expectPXN bool
	}{
		{
			name:      "User Non-Executable",
			opts:      MapOpts{AccessType: hostarch.ReadWrite, User: true},
			expectPXN: true,
		},
		{
			name:      "User Executable",
			opts:      MapOpts{AccessType: hostarch.ReadExecute, User: true},
			expectPXN: true,
		},
		{
			name:      "Kernel Non-Executable",
			opts:      MapOpts{AccessType: hostarch.ReadWrite, User: false},
			expectPXN: true,
		},
		{
			name:      "Kernel Executable",
			opts:      MapOpts{AccessType: hostarch.ReadExecute, User: false},
			expectPXN: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var p PTE
			p.Set(0x1000, tc.opts)
			hasPXN := (uintptr(p) & pxn) != 0
			if hasPXN != tc.expectPXN {
				t.Errorf("PTE.Set(%v) PXN bit got %v, wanted %v", tc.opts, hasPXN, tc.expectPXN)
			}
		})
	}
}
