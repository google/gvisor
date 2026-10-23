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
// +build arm64

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// Test512MAnd64K tests mapping of 512MB sect pages and 64K pages.
func Test512MAnd64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a small page (64K) and a huge page (512MB).
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize64K*42)
	pt.Map(0x0000ff0000000000, pmdSize64K, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize64K*47)

	pt.Map(0xffff000000400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite, User: false}, pteSize64K*42)
	pt.Map(0xffffff0000000000, pmdSize64K, MapOpts{AccessType: hostarch.Read, User: false}, pmdSize64K*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pmdSize64K, pmdSize64K * 47, MapOpts{AccessType: hostarch.Read, User: true}},
		{0xffff000000400000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.ReadWrite, User: false}},
		{0xffffff0000000000, pmdSize64K, pmdSize64K * 47, MapOpts{AccessType: hostarch.Read, User: false}},
	})
}

// TestSplit512MPage tests splitting a 512MB sect page.
func TestSplit512MPage(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map a sect page (512MB) and knock out the middle.
	pt.Map(0x0000ff0000000000, pmdSize64K, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize64K*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize64K), pmdSize64K-(2*pteSize64K))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize64K, pmdSize64K * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pmdSize64K - pteSize64K, pteSize64K, pmdSize64K*42 + pmdSize64K - pteSize64K, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

// The tests below are the 64K granule equivalents of the generic tests in
// pagetables_test.go.

func TestUnmap64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map and unmap one entry.
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite}, pteSize64K*42)
	pt.Unmap(0x400000, pteSize64K)

	checkMappings(t, pt, nil)
}

func TestReadOnly64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map one entry.
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.Read}, pteSize64K*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestSerialEntries64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map two sequential entries.
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite}, pteSize64K*42)
	pt.Map(0x410000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite}, pteSize64K*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{0x410000, pteSize64K, pteSize64K * 47, MapOpts{AccessType: hostarch.ReadWrite}},
	})
}

func TestSpanningEntries64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Span a pgd with two pages.
	pt.Map(0x00007bffffff0000, 2*pteSize64K, MapOpts{AccessType: hostarch.Read}, pteSize64K*42)

	checkMappings(t, pt, []mapping{
		{0x00007bffffff0000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.Read}},
		{0x00007c0000000000, pteSize64K, pteSize64K * 43, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestSparseEntries64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())

	// Map two entries in different pgds.
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite}, pteSize64K*42)
	pt.Map(0x00007c0000000000, pteSize64K, MapOpts{AccessType: hostarch.Read}, pteSize64K*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize64K, pteSize64K * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{0x00007c0000000000, pteSize64K, pteSize64K * 47, MapOpts{AccessType: hostarch.Read}},
	})
}

// TestLookup64K verifies that Lookup rounds addresses down to 64K pages.
func TestLookup64K(t *testing.T) {
	use64KPagesForTest(t)

	pt := New(NewRuntimeAllocator())
	pt.Map(0x400000, pteSize64K, MapOpts{AccessType: hostarch.ReadWrite}, pteSize64K*42)

	// Lookup must round down to the 64K page.
	virtual, physical, size, opts := pt.Lookup(0x400000+0x1234, false /* findFirst */)
	if virtual != 0x400000 || physical != pteSize64K*42 || size != pteSize64K || opts.AccessType != hostarch.ReadWrite {
		t.Errorf("Lookup(0x401234) = (%#x, %#x, %#x, %+v), want (0x400000, %#x, %#x, ReadWrite)", virtual, physical, size, opts, pteSize64K*42, pteSize64K)
	}
}

// TestAllocatorAlignment64K verifies that page table pages are allocated
// with the size and alignment of the 64K granule.
func TestAllocatorAlignment64K(t *testing.T) {
	use64KPagesForTest(t)

	a := NewRuntimeAllocator()
	for i := 0; i < 16; i++ {
		ptes := a.NewPTEs()
		if addr := a.PhysicalFor(ptes); addr%pteSize64K != 0 {
			t.Fatalf("NewPTEs() = %#x, not aligned to %#x", addr, pteSize64K)
		}
		// All entries must be addressable.
		ptes.as64K()[entriesPerPage64K-1].Clear()
	}
}
