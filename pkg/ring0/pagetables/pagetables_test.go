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

//go:build !pagesize_64k

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestUnmap(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map and unmap one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Unmap(0x400000, pteSize)

	checkMappings(t, pt, nil)
}

func TestReadOnly(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.Read}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestReadWrite(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
	})
}

func TestSerialEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map two sequential entries.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Map(0x401000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{0x401000, pteSize, pteSize * 47, MapOpts{AccessType: hostarch.ReadWrite}},
	})
}

func TestSpanningEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Span a pgd with two pages.
	pt.Map(0x00007efffffff000, 2*pteSize, MapOpts{AccessType: hostarch.Read}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x00007efffffff000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.Read}},
		{0x00007f0000000000, pteSize, pteSize * 43, MapOpts{AccessType: hostarch.Read}},
	})
}

func TestSparseEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map two entries in different pgds.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite}, pteSize*42)
	pt.Map(0x00007f0000000000, pteSize, MapOpts{AccessType: hostarch.Read}, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite}},
		{0x00007f0000000000, pteSize, pteSize * 47, MapOpts{AccessType: hostarch.Read}},
	})
}
