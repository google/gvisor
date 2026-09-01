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

//go:build arm64 && pagesize_64k
// +build arm64,pagesize_64k

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// Test512MAnd64K tests mapping of 512MB sect pages and 64K pages.
func Test512MAnd64K(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a small page (64K) and a huge page (512MB).
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize*42)
	pt.Map(0x0000ff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize*47)

	pt.Map(0xffff000000400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite, User: false}, pteSize*42)
	pt.Map(0xffffff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: false}, pmdSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pmdSize, pmdSize * 47, MapOpts{AccessType: hostarch.Read, User: true}},
		{0xffff000000400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite, User: false}},
		{0xffffff0000000000, pmdSize, pmdSize * 47, MapOpts{AccessType: hostarch.Read, User: false}},
	})
}

// TestSplit512MPage tests splitting a 512MB sect page.
func TestSplit512MPage(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a sect page (512MB) and knock out the middle.
	pt.Map(0x0000ff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize), pmdSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize, pmdSize * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pmdSize - pteSize, pteSize, pmdSize*42 + pmdSize - pteSize, MapOpts{AccessType: hostarch.Read, User: true}},
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
