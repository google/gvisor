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

func (v *checkVisitor) visit(start uintptr, pte *PTE, align uintptr) bool {
	v.found = append(v.found, mapping{
		start:  start,
		length: align + 1,
		addr:   pte.Address(),
		opts:   pte.Opts(),
	})
	if v.failed != "" {
		// Don't keep looking for errors.
		return false
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
	return true
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
