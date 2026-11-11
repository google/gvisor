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

//go:build amd64
// +build amd64

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
)

var (
	lowerTopAligned uintptr = 0x00007f0000000000
	pt              *PageTables
)

func getLargeAddressesEnabled() bool {
	featureSet := cpuid.HostFeatureSet()
	return featureSet.HasFeature(cpuid.X86FeatureLA57)
}

func getLowerTopAligned() uintptr {
	if getLargeAddressesEnabled() {
		return 0x00FF000000000000
	}
	return lowerTopAligned
}

func InitTest() {
	cpuid.Initialize()
	pt = New(NewRuntimeAllocator())
	pt.InitArch(NewRuntimeAllocator())
}

func TestLargeAddresses(t *testing.T) {
	InitTest()
	if !getLargeAddressesEnabled() {
		t.Skip("Large addresses are not supported on this platform")
	}
	pt.Map(hostarch.Addr(1<<50), pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Map(hostarch.Addr(1<<54), pmdSize, MapOpts{AccessType: hostarch.Read}, pmdSize*42)

	checkMappings(t, pt, []mapping{
		{uintptr(1 << 50), pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{uintptr(1 << 54), pmdSize, pmdSize * 42, MapOpts{AccessType: hostarch.Read}},
	})
}

func Test2MAnd4K(t *testing.T) {
	InitTest()
	// Map a small page and a huge page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Map(hostarch.Addr(getLowerTopAligned()), pmdSize, MapOpts{AccessType: hostarch.Read}, pmdSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{getLowerTopAligned(), pmdSize, pmdSize * 47, MapOpts{AccessType: hostarch.Read}},
	})
}

func Test1GAnd4K(t *testing.T) {
	InitTest()

	// Map a small page and a super page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Map(hostarch.Addr(getLowerTopAligned()), pudSize, MapOpts{AccessType: hostarch.Read}, pudSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{getLowerTopAligned(), pudSize, pudSize * 47, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestSplit1GPage(t *testing.T) {
	InitTest()

	// Map a super page and knock out the middle.
	pt.Map(hostarch.Addr(getLowerTopAligned()), pudSize, MapOpts{AccessType: hostarch.Read}, pudSize*42)
	pt.Unmap(hostarch.Addr(getLowerTopAligned()+pteSize), pudSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{getLowerTopAligned(), pteSize, pudSize * 42, MapOpts{AccessType: hostarch.Read}},
		{getLowerTopAligned() + pudSize - pteSize, pteSize, pudSize*42 + pudSize - pteSize, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestSplit2MPage(t *testing.T) {
	InitTest()

	// Map a huge page and knock out the middle.
	pt.Map(hostarch.Addr(getLowerTopAligned()), pmdSize, MapOpts{AccessType: hostarch.Read}, pmdSize*42)
	pt.Unmap(hostarch.Addr(getLowerTopAligned()+pteSize), pmdSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{getLowerTopAligned(), pteSize, pmdSize * 42, MapOpts{AccessType: hostarch.Read}},
		{getLowerTopAligned() + pmdSize - pteSize, pteSize, pmdSize*42 + pmdSize - pteSize, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestNumMemoryTypes(t *testing.T) {
	InitTest()
	// The PAT accommodates up to 8 entries. However, PTE.Set() currently
	// assumes that NumMemoryTypes <= 4, since the location of the most
	// significant bit of the PAT index in page table entries varies depending
	// on page size (and is never bit 5 == writeThroughShift + 2).
	if hostarch.NumMemoryTypes > 4 {
		t.Errorf("PTE.Set() and PTE.Opts() must be altered to handle %d MemoryTypes", hostarch.NumMemoryTypes)
	}
}

// TestMapLarge checks that MapLarge produces the same translations as Map.
func TestMapLarge(t *testing.T) {
	cpuid.Initialize()
	type rng struct {
		addr, length, physical uintptr
		opts                   MapOpts
	}
	rw := MapOpts{AccessType: hostarch.ReadWrite}
	ro := MapOpts{AccessType: hostarch.Read, Global: true}
	for _, tc := range [][]rng{
		// Like the KVM physical map: unaligned head, huge interior.
		{{0x1000, 0x79fbf8a2b000 - 0x1000, 0x200001000, rw}, {0x79fbf8a2d000, 0x7ffffffff000 - 0x79fbf8a2d000, 0x79fdf8a2d000, rw}},
		// Exactly aligned, crossing a 512GiB boundary.
		{{0x7f00000000, 0x200 * pudSize, 0x40000000, ro}},
		// Smaller than 1GiB: falls back to Map.
		{{0x400000, 0x200000, 0x1000000, rw}},
		// Physical not congruent modulo 1GiB: falls back to Map.
		{{0x40000000, 2 * pudSize, 0x200000, rw}},
		// Overlapping an existing mapping.
		{{0x80000000, pudSize + pteSize, 0x80000000, rw}, {0x40000000, 4 * pudSize, 0x40000000, ro}},
	} {
		want := New(NewRuntimeAllocator())
		want.InitArch(NewRuntimeAllocator())
		got := New(NewRuntimeAllocator())
		got.InitArch(NewRuntimeAllocator())
		for _, r := range tc {
			wp := want.Map(hostarch.Addr(r.addr), r.length, r.opts, r.physical)
			gp := got.MapLarge(hostarch.Addr(r.addr), r.length, r.opts, r.physical)
			if wp != gp {
				t.Errorf("Map(%#x, %#x) returned %v, MapLarge returned %v", r.addr, r.length, wp, gp)
			}
		}
		for _, r := range tc {
			for _, off := range []uintptr{0, pteSize, pmdSize, pudSize - pteSize, pudSize, 3*pudSize + 5*pteSize, r.length / 2, r.length - pteSize} {
				if off >= r.length {
					continue
				}
				a := hostarch.Addr(r.addr + off)
				wv, wphys, wsize, wopts := want.Lookup(a, false)
				gv, gphys, gsize, gopts := got.Lookup(a, false)
				if wv != gv || wphys != gphys || wsize != gsize || wopts != gopts {
					t.Errorf("Lookup(%#x): Map gave (%#x, %#x, %#x, %+v), MapLarge gave (%#x, %#x, %#x, %+v)", a, wv, wphys, wsize, wopts, gv, gphys, gsize, gopts)
				}
			}
		}
	}
}
