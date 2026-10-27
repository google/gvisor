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

package tests

import (
	"bytes"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func TestLoadHooks(t *testing.T) {
	runTestCases(t, false, "load-hooks", []any{
		// Root object being a struct.
		afterLoadStruct{v: 1},
		valueLoadStruct{v: 1},
		genericContainer{v: &afterLoadStruct{v: 1}},
		genericContainer{v: &valueLoadStruct{v: 1}},
		sliceContainer{v: []any{&afterLoadStruct{v: 1}}},
		sliceContainer{v: []any{&valueLoadStruct{v: 1}}},
		// Root object being a pointer.
		&afterLoadStruct{v: 1},
		&valueLoadStruct{v: 1},
		&genericContainer{v: &afterLoadStruct{v: 1}},
		&genericContainer{v: &valueLoadStruct{v: 1}},
		&sliceContainer{v: []any{&afterLoadStruct{v: 1}}},
		&sliceContainer{v: []any{&valueLoadStruct{v: 1}}},
		&mapContainer{v: map[int]any{0: &afterLoadStruct{v: 1}}},
		&mapContainer{v: map[int]any{0: &valueLoadStruct{v: 1}}},
	})
}

func TestCycles(t *testing.T) {
	// cs is a single object cycle.
	cs := cycleStruct{nil}
	cs.c = &cs

	// cs1 and cs2 are in a two object cycle.
	cs1 := cycleStruct{nil}
	cs2 := cycleStruct{nil}
	cs1.c = &cs2
	cs2.c = &cs1

	runTestCases(t, false, "cycles", []any{
		cs,
		cs1,
	})
}

func TestDeadlock(t *testing.T) {
	// bs is a single object cycle. This does not cause deadlock because an
	// object cannot wait for itself.
	bs := badCycleStruct{nil}
	bs.b = &bs

	runTestCases(t, false, "self", []any{
		&bs,
	})

	// bs1 and bs2 are in a deadlocking cycle.
	bs1 := badCycleStruct{nil}
	bs2 := badCycleStruct{nil}
	bs1.b = &bs2
	bs2.b = &bs1

	t.Run("cycle_with_user_callback", func(t *testing.T) {
		checkDependencyCycle(t, &bs1)
	})

	t.Run("dependent_outside_cycle", func(t *testing.T) {
		// The first incomplete object is blocked by a cycle but is not
		// itself in that cycle.
		dependent := badCycleStruct{b: &bs1}
		checkDependencyCycle(t, &dependent)
	})

	t.Run("branch_to_another_cycle", func(t *testing.T) {
		var a, b, c, d branchingCycle
		// Discover B before D: B is the first object waiting on A, but
		// traversing B's dependents reaches the B/C cycle without A.
		// Searching only for a return to A would recurse indefinitely.
		a.reachable = &b
		a.waitFor = &d
		b.waitFor = &a
		b.alsoWaitFor = &c
		c.waitFor = &b
		d.waitFor = &a
		checkDependencyCycle(t, &a)
	})
}

func checkDependencyCycle[T any](t *testing.T, root *T) {
	t.Helper()
	var saved bytes.Buffer
	// Keep the nodes below the special root object, which Load permits
	// other objects to reference without waiting.
	if _, err := state.Save(t.Context(), &saved, &root); err != nil {
		t.Fatal(err)
	}
	var restored *T
	if _, err := state.Load(t.Context(), &saved, &restored); err == nil || !strings.Contains(err.Error(), "dependency cycle:") {
		t.Fatalf("Load = %v, want a dependency cycle diagnostic", err)
	}
}
