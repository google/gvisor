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
	"testing"
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

	// bs2 and bs2 are in a deadlocking cycle.
	bs1 := badCycleStruct{nil}
	bs2 := badCycleStruct{nil}
	bs1.b = &bs2
	bs2.b = &bs1

	runTestCases(t, true, "deadlock", []any{
		&bs1,
	})
}
