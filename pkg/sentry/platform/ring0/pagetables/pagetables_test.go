// Copyright 2018 Google Inc.
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
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type reflectTranslater struct{}

func (r reflectTranslater) TranslateToPhysical(ptes *PTEs) uintptr {
	return reflect.ValueOf(ptes).Pointer()
}

type mapping struct {
	start     uintptr
	length    uintptr
	addr      uintptr
	writeable bool
}

func checkMappings(t *testing.T, pt *PageTables, m []mapping) {
	var (
		current int
		found   []mapping
		failed  string
	)

	// Iterate over all the mappings.
	pt.iterateRange(0, ^uintptr(0), false, func(s, e uintptr, pte *PTE, align uintptr) {
		found = append(found, mapping{
			start:     s,
			length:    e - s,
			addr:      pte.Address(),
			writeable: pte.Writeable(),
		})
		if failed != "" {
			// Don't keep looking for errors.
			return
		}

		if current >= len(m) {
			failed = "more mappings than expected"
		} else if m[current].start != s {
			failed = "start didn't match expected"
		} else if m[current].length != (e - s) {
			failed = "end didn't match expected"
		} else if m[current].addr != pte.Address() {
			failed = "address didn't match expected"
		} else if m[current].writeable != pte.Writeable() {
			failed = "writeable didn't match"
		}
		current++
	})

	// Were we expected additional mappings?
	if failed == "" && current != len(m) {
		failed = "insufficient mappings found"
	}

	// Emit a meaningful error message on failure.
	if failed != "" {
		t.Errorf("%s; got %#v, wanted %#v", failed, found, m)
	}
}

func TestAllocFree(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})
	pt.Release()
}

func TestUnmap(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map and unmap one entry.
	pt.Map(0x400000, pteSize, true, usermem.ReadWrite, pteSize*42)
	pt.Unmap(0x400000, pteSize)

	checkMappings(t, pt, nil)
	pt.Release()
}

func TestReadOnly(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map one entry.
	pt.Map(0x400000, pteSize, true, usermem.Read, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, false},
	})
	pt.Release()
}

func TestReadWrite(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map one entry.
	pt.Map(0x400000, pteSize, true, usermem.ReadWrite, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, true},
	})
	pt.Release()
}

func TestSerialEntries(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map two sequential entries.
	pt.Map(0x400000, pteSize, true, usermem.ReadWrite, pteSize*42)
	pt.Map(0x401000, pteSize, true, usermem.ReadWrite, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, true},
		{0x401000, pteSize, pteSize * 47, true},
	})
	pt.Release()
}

func TestSpanningEntries(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Span a pgd with two pages.
	pt.Map(0x00007efffffff000, 2*pteSize, true, usermem.Read, pteSize*42)

	checkMappings(t, pt, []mapping{
		{0x00007efffffff000, pteSize, pteSize * 42, false},
		{0x00007f0000000000, pteSize, pteSize * 43, false},
	})
	pt.Release()
}

func TestSparseEntries(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map two entries in different pgds.
	pt.Map(0x400000, pteSize, true, usermem.ReadWrite, pteSize*42)
	pt.Map(0x00007f0000000000, pteSize, true, usermem.Read, pteSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, true},
		{0x00007f0000000000, pteSize, pteSize * 47, false},
	})
	pt.Release()
}
