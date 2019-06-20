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

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

type mapping struct {
	start  uintptr
	length uintptr
	addr   uintptr
	opts   MapOpts
}

type checkVisitor struct {
	expected []mapping // Input.
	current  int       // Temporary.
	found    []mapping // Output.
	failed   string    // Output.
}

func (v *checkVisitor) visit(start uintptr, pte *PTE, align uintptr) {
	v.found = append(v.found, mapping{
		start:  start,
		length: align + 1,
		addr:   pte.Address(),
		opts:   pte.Opts(),
	})
	if v.failed != "" {
		// Don't keep looking for errors.
		return
	}

	if v.current >= len(v.expected) {
		v.failed = "more mappings than expected"
	} else if v.expected[v.current].start != start {
		v.failed = "start didn't match expected"
	} else if v.expected[v.current].length != (align + 1) {
		v.failed = "end didn't match expected"
	} else if v.expected[v.current].addr != pte.Address() {
		v.failed = "address didn't match expected"
	} else if v.expected[v.current].opts != pte.Opts() {
		v.failed = "opts didn't match"
	}
	v.current++
}

func (*checkVisitor) requiresAlloc() bool { return false }

func (*checkVisitor) requiresSplit() bool { return false }

func checkMappings(t *testing.T, pt *PageTables, m []mapping) {
	// Iterate over all the mappings.
	w := checkWalker{
		pageTables: pt,
		visitor: checkVisitor{
			expected: m,
		},
	}
	w.iterateRange(0, ^uintptr(0))

	// Were we expected additional mappings?
	if w.visitor.failed == "" && w.visitor.current != len(w.visitor.expected) {
		w.visitor.failed = "insufficient mappings found"
	}

	// Emit a meaningful error message on failure.
	if w.visitor.failed != "" {
		t.Errorf("%s; got %#v, wanted %#v", w.visitor.failed, w.visitor.found, w.visitor.expected)
	}
}

func TestUnmap(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map and unmap one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)
	pt.Unmap(0x400000, pteSize)

	checkMappings(t, pt, nil)
}

func TestReadOnly(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.Read}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.Read}},
	})
}

func TestReadWrite(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map one entry.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.ReadWrite}},
	})
}

func TestSerialEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map two sequential entries.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)
	pt.Map(0x401000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.ReadWrite}},
		{0x401000, pteSize, pteSize * 47, MapOpts{AccessType: usermem.ReadWrite}},
	})
}

func TestSpanningEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Span a pgd with two pages.
	pt.Map(0x00007efffffff000, 2*pteSize, MapOpts{AccessType: usermem.Read}, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x00007efffffff000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.Read}},
		{0x00007f0000000000, pteSize, pteSize * 43, MapOpts{AccessType: usermem.Read}},
	})
}

func TestSparseEntries(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map two entries in different pgds.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)
	pt.Map(0x00007f0000000000, pteSize, MapOpts{AccessType: usermem.Read}, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.ReadWrite}},
		{0x00007f0000000000, pteSize, pteSize * 47, MapOpts{AccessType: usermem.Read}},
	})
}
