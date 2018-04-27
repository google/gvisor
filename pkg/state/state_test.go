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

package state

import (
	"bytes"
	"io/ioutil"
	"math"
	"reflect"
	"testing"
)

// TestCase is used to define a single success/failure testcase of
// serialization of a set of objects.
type TestCase struct {
	// Name is the name of the test case.
	Name string

	// Objects is the list of values to serialize.
	Objects []interface{}

	// Fail is whether the test case is supposed to fail or not.
	Fail bool
}

// runTest runs all testcases.
func runTest(t *testing.T, tests []TestCase) {
	for _, test := range tests {
		t.Logf("TEST %s:", test.Name)
		for i, root := range test.Objects {
			t.Logf("  case#%d: %#v", i, root)

			// Save the passed object.
			saveBuffer := &bytes.Buffer{}
			saveObjectPtr := reflect.New(reflect.TypeOf(root))
			saveObjectPtr.Elem().Set(reflect.ValueOf(root))
			if err := Save(saveBuffer, saveObjectPtr.Interface(), nil); err != nil && !test.Fail {
				t.Errorf("    FAIL: Save failed unexpectedly: %v", err)
				continue
			} else if err != nil {
				t.Logf("    PASS: Save failed as expected: %v", err)
				continue
			}

			// Load a new copy of the object.
			loadObjectPtr := reflect.New(reflect.TypeOf(root))
			if err := Load(bytes.NewReader(saveBuffer.Bytes()), loadObjectPtr.Interface(), nil); err != nil && !test.Fail {
				t.Errorf("    FAIL: Load failed unexpectedly: %v", err)
				continue
			} else if err != nil {
				t.Logf("    PASS: Load failed as expected: %v", err)
				continue
			}

			// Compare the values.
			loadedValue := loadObjectPtr.Elem().Interface()
			if eq := reflect.DeepEqual(root, loadedValue); !eq && !test.Fail {
				t.Errorf("    FAIL: Objects differs; got %#v", loadedValue)
				continue
			} else if !eq {
				t.Logf("    PASS: Object different as expected.")
				continue
			}

			// Everything went okay. Is that good?
			if test.Fail {
				t.Errorf("    FAIL: Unexpected success.")
			} else {
				t.Logf("    PASS: Success.")
			}
		}
	}
}

// dumbStruct is a struct which does not implement the loader/saver interface.
// We expect that serialization of this struct will fail.
type dumbStruct struct {
	A int
	B int
}

// smartStruct is a struct which does implement the loader/saver interface.
// We expect that serialization of this struct will succeed.
type smartStruct struct {
	A int
	B int
}

func (s *smartStruct) save(m Map) {
	m.Save("A", &s.A)
	m.Save("B", &s.B)
}

func (s *smartStruct) load(m Map) {
	m.Load("A", &s.A)
	m.Load("B", &s.B)
}

// valueLoadStruct uses a value load.
type valueLoadStruct struct {
	v int
}

func (v *valueLoadStruct) save(m Map) {
	m.SaveValue("v", v.v)
}

func (v *valueLoadStruct) load(m Map) {
	m.LoadValue("v", new(int), func(value interface{}) {
		v.v = value.(int)
	})
}

// afterLoadStruct has an AfterLoad function.
type afterLoadStruct struct {
	v int
}

func (a *afterLoadStruct) save(m Map) {
}

func (a *afterLoadStruct) load(m Map) {
	m.AfterLoad(func() {
		a.v++
	})
}

// genericContainer is a generic dispatcher.
type genericContainer struct {
	v interface{}
}

func (g *genericContainer) save(m Map) {
	m.Save("v", &g.v)
}

func (g *genericContainer) load(m Map) {
	m.Load("v", &g.v)
}

// sliceContainer is a generic slice.
type sliceContainer struct {
	v []interface{}
}

func (s *sliceContainer) save(m Map) {
	m.Save("v", &s.v)
}

func (s *sliceContainer) load(m Map) {
	m.Load("v", &s.v)
}

// mapContainer is a generic map.
type mapContainer struct {
	v map[int]interface{}
}

func (mc *mapContainer) save(m Map) {
	m.Save("v", &mc.v)
}

func (mc *mapContainer) load(m Map) {
	// Some of the test cases below assume legacy behavior wherein maps
	// will automatically inherit dependencies.
	m.LoadWait("v", &mc.v)
}

// dumbMap is a map which does not implement the loader/saver interface.
// Serialization of this map will default to the standard encode/decode logic.
type dumbMap map[string]int

// pointerStruct contains various pointers, shared and non-shared, and pointers
// to pointers. We expect that serialization will respect the structure.
type pointerStruct struct {
	A *int
	B *int
	C *int
	D *int

	AA **int
	BB **int
}

func (p *pointerStruct) save(m Map) {
	m.Save("A", &p.A)
	m.Save("B", &p.B)
	m.Save("C", &p.C)
	m.Save("D", &p.D)
	m.Save("AA", &p.AA)
	m.Save("BB", &p.BB)
}

func (p *pointerStruct) load(m Map) {
	m.Load("A", &p.A)
	m.Load("B", &p.B)
	m.Load("C", &p.C)
	m.Load("D", &p.D)
	m.Load("AA", &p.AA)
	m.Load("BB", &p.BB)
}

// testInterface is a trivial interface example.
type testInterface interface {
	Foo()
}

// testImpl is a trivial implementation of testInterface.
type testImpl struct {
}

// Foo satisfies testInterface.
func (t *testImpl) Foo() {
}

// testImpl is trivially serializable.
func (t *testImpl) save(m Map) {
}

// testImpl is trivially serializable.
func (t *testImpl) load(m Map) {
}

// testI demonstrates interface dispatching.
type testI struct {
	I testInterface
}

func (t *testI) save(m Map) {
	m.Save("I", &t.I)
}

func (t *testI) load(m Map) {
	m.Load("I", &t.I)
}

// cycleStruct is used to implement basic cycles.
type cycleStruct struct {
	c *cycleStruct
}

func (c *cycleStruct) save(m Map) {
	m.Save("c", &c.c)
}

func (c *cycleStruct) load(m Map) {
	m.Load("c", &c.c)
}

// badCycleStruct actually has deadlocking dependencies.
//
// This should pass if b.b = {nil|b} and fail otherwise.
type badCycleStruct struct {
	b *badCycleStruct
}

func (b *badCycleStruct) save(m Map) {
	m.Save("b", &b.b)
}

func (b *badCycleStruct) load(m Map) {
	m.LoadWait("b", &b.b)
	m.AfterLoad(func() {
		// This is not executable, since AfterLoad requires that the
		// object and all dependencies are complete. This should cause
		// a deadlock error during load.
	})
}

// emptyStructPointer points to an empty struct.
type emptyStructPointer struct {
	nothing *struct{}
}

func (e *emptyStructPointer) save(m Map) {
	m.Save("nothing", &e.nothing)
}

func (e *emptyStructPointer) load(m Map) {
	m.Load("nothing", &e.nothing)
}

// truncateInteger truncates an integer.
type truncateInteger struct {
	v  int64
	v2 int32
}

func (t *truncateInteger) save(m Map) {
	t.v2 = int32(t.v)
	m.Save("v", &t.v)
}

func (t *truncateInteger) load(m Map) {
	m.Load("v", &t.v2)
	t.v = int64(t.v2)
}

// truncateUnsignedInteger truncates an unsigned integer.
type truncateUnsignedInteger struct {
	v  uint64
	v2 uint32
}

func (t *truncateUnsignedInteger) save(m Map) {
	t.v2 = uint32(t.v)
	m.Save("v", &t.v)
}

func (t *truncateUnsignedInteger) load(m Map) {
	m.Load("v", &t.v2)
	t.v = uint64(t.v2)
}

// truncateFloat truncates a floating point number.
type truncateFloat struct {
	v  float64
	v2 float32
}

func (t *truncateFloat) save(m Map) {
	t.v2 = float32(t.v)
	m.Save("v", &t.v)
}

func (t *truncateFloat) load(m Map) {
	m.Load("v", &t.v2)
	t.v = float64(t.v2)
}

func TestTypes(t *testing.T) {
	// x and y are basic integers, while xp points to x.
	x := 1
	y := 2
	xp := &x

	// cs is a single object cycle.
	cs := cycleStruct{nil}
	cs.c = &cs

	// cs1 and cs2 are in a two object cycle.
	cs1 := cycleStruct{nil}
	cs2 := cycleStruct{nil}
	cs1.c = &cs2
	cs2.c = &cs1

	// bs is a single object cycle.
	bs := badCycleStruct{nil}
	bs.b = &bs

	// bs2 and bs2 are in a deadlocking cycle.
	bs1 := badCycleStruct{nil}
	bs2 := badCycleStruct{nil}
	bs1.b = &bs2
	bs2.b = &bs1

	// regular nils.
	var (
		nilmap   dumbMap
		nilslice []byte
	)

	// embed points to embedded fields.
	embed1 := pointerStruct{}
	embed1.AA = &embed1.A
	embed2 := pointerStruct{}
	embed2.BB = &embed2.B

	// es1 contains two structs pointing to the same empty struct.
	es := emptyStructPointer{new(struct{})}
	es1 := []emptyStructPointer{es, es}

	tests := []TestCase{
		{
			Name: "bool",
			Objects: []interface{}{
				true,
				false,
			},
		},
		{
			Name: "integers",
			Objects: []interface{}{
				int(0),
				int(1),
				int(-1),
				int8(0),
				int8(1),
				int8(-1),
				int16(0),
				int16(1),
				int16(-1),
				int32(0),
				int32(1),
				int32(-1),
				int64(0),
				int64(1),
				int64(-1),
			},
		},
		{
			Name: "unsigned integers",
			Objects: []interface{}{
				uint(0),
				uint(1),
				uint8(0),
				uint8(1),
				uint16(0),
				uint16(1),
				uint32(1),
				uint64(0),
				uint64(1),
			},
		},
		{
			Name: "strings",
			Objects: []interface{}{
				"",
				"foo",
				"bar",
			},
		},
		{
			Name: "slices",
			Objects: []interface{}{
				[]int{-1, 0, 1},
				[]*int{&x, &x, &x},
				[]int{1, 2, 3}[0:1],
				[]int{1, 2, 3}[1:2],
				make([]byte, 32),
				make([]byte, 32)[:16],
				make([]byte, 32)[:16:20],
				nilslice,
			},
		},
		{
			Name: "arrays",
			Objects: []interface{}{
				&[1048576]bool{false, true, false, true},
				&[1048576]uint8{0, 1, 2, 3},
				&[1048576]byte{0, 1, 2, 3},
				&[1048576]uint16{0, 1, 2, 3},
				&[1048576]uint{0, 1, 2, 3},
				&[1048576]uint32{0, 1, 2, 3},
				&[1048576]uint64{0, 1, 2, 3},
				&[1048576]uintptr{0, 1, 2, 3},
				&[1048576]int8{0, -1, -2, -3},
				&[1048576]int16{0, -1, -2, -3},
				&[1048576]int32{0, -1, -2, -3},
				&[1048576]int64{0, -1, -2, -3},
				&[1048576]float32{0, 1.1, 2.2, 3.3},
				&[1048576]float64{0, 1.1, 2.2, 3.3},
			},
		},
		{
			Name: "pointers",
			Objects: []interface{}{
				&pointerStruct{A: &x, B: &x, C: &y, D: &y, AA: &xp, BB: &xp},
				&pointerStruct{},
			},
		},
		{
			Name: "empty struct",
			Objects: []interface{}{
				struct{}{},
			},
		},
		{
			Name: "unenlightened structs",
			Objects: []interface{}{
				&dumbStruct{A: 1, B: 2},
			},
			Fail: true,
		},
		{
			Name: "enlightened structs",
			Objects: []interface{}{
				&smartStruct{A: 1, B: 2},
			},
		},
		{
			Name: "load-hooks",
			Objects: []interface{}{
				&afterLoadStruct{v: 1},
				&valueLoadStruct{v: 1},
				&genericContainer{v: &afterLoadStruct{v: 1}},
				&genericContainer{v: &valueLoadStruct{v: 1}},
				&sliceContainer{v: []interface{}{&afterLoadStruct{v: 1}}},
				&sliceContainer{v: []interface{}{&valueLoadStruct{v: 1}}},
				&mapContainer{v: map[int]interface{}{0: &afterLoadStruct{v: 1}}},
				&mapContainer{v: map[int]interface{}{0: &valueLoadStruct{v: 1}}},
			},
		},
		{
			Name: "maps",
			Objects: []interface{}{
				dumbMap{"a": -1, "b": 0, "c": 1},
				map[smartStruct]int{{}: 0, {A: 1}: 1},
				nilmap,
				&mapContainer{v: map[int]interface{}{0: &smartStruct{A: 1}}},
			},
		},
		{
			Name: "interfaces",
			Objects: []interface{}{
				&testI{&testImpl{}},
				&testI{nil},
				&testI{(*testImpl)(nil)},
			},
		},
		{
			Name: "unregistered-interfaces",
			Objects: []interface{}{
				&genericContainer{v: afterLoadStruct{v: 1}},
				&genericContainer{v: valueLoadStruct{v: 1}},
				&sliceContainer{v: []interface{}{afterLoadStruct{v: 1}}},
				&sliceContainer{v: []interface{}{valueLoadStruct{v: 1}}},
				&mapContainer{v: map[int]interface{}{0: afterLoadStruct{v: 1}}},
				&mapContainer{v: map[int]interface{}{0: valueLoadStruct{v: 1}}},
			},
			Fail: true,
		},
		{
			Name: "cycles",
			Objects: []interface{}{
				&cs,
				&cs1,
				&cycleStruct{&cs1},
				&cycleStruct{&cs},
				&badCycleStruct{nil},
				&bs,
			},
		},
		{
			Name: "deadlock",
			Objects: []interface{}{
				&bs1,
			},
			Fail: true,
		},
		{
			Name: "embed",
			Objects: []interface{}{
				&embed1,
				&embed2,
			},
			Fail: true,
		},
		{
			Name: "empty structs",
			Objects: []interface{}{
				new(struct{}),
				es,
				es1,
			},
		},
		{
			Name: "truncated okay",
			Objects: []interface{}{
				&truncateInteger{v: 1},
				&truncateUnsignedInteger{v: 1},
				&truncateFloat{v: 1.0},
			},
		},
		{
			Name: "truncated bad",
			Objects: []interface{}{
				&truncateInteger{v: math.MaxInt32 + 1},
				&truncateUnsignedInteger{v: math.MaxUint32 + 1},
				&truncateFloat{v: math.MaxFloat32 * 2},
			},
			Fail: true,
		},
	}

	runTest(t, tests)
}

// benchStruct is used for benchmarking.
type benchStruct struct {
	b *benchStruct

	// Dummy data is included to ensure that these objects are large.
	// This is to detect possible regression when registering objects.
	_ [4096]byte
}

func (b *benchStruct) save(m Map) {
	m.Save("b", &b.b)
}

func (b *benchStruct) load(m Map) {
	m.LoadWait("b", &b.b)
	m.AfterLoad(b.afterLoad)
}

func (b *benchStruct) afterLoad() {
	// Do nothing, just force scheduling.
}

// buildObject builds a benchmark object.
func buildObject(n int) (b *benchStruct) {
	for i := 0; i < n; i++ {
		b = &benchStruct{b: b}
	}
	return
}

func BenchmarkEncoding(b *testing.B) {
	b.StopTimer()
	bs := buildObject(b.N)
	var stats Stats
	b.StartTimer()
	if err := Save(ioutil.Discard, bs, &stats); err != nil {
		b.Errorf("save failed: %v", err)
	}
	b.StopTimer()
	if b.N > 1000 {
		b.Logf("breakdown (n=%d): %s", b.N, &stats)
	}
}

func BenchmarkDecoding(b *testing.B) {
	b.StopTimer()
	bs := buildObject(b.N)
	var newBS benchStruct
	buf := &bytes.Buffer{}
	if err := Save(buf, bs, nil); err != nil {
		b.Errorf("save failed: %v", err)
	}
	var stats Stats
	b.StartTimer()
	if err := Load(buf, &newBS, &stats); err != nil {
		b.Errorf("load failed: %v", err)
	}
	b.StopTimer()
	if b.N > 1000 {
		b.Logf("breakdown (n=%d): %s", b.N, &stats)
	}
}

func init() {
	Register("stateTest.smartStruct", (*smartStruct)(nil), Fns{
		Save: (*smartStruct).save,
		Load: (*smartStruct).load,
	})
	Register("stateTest.afterLoadStruct", (*afterLoadStruct)(nil), Fns{
		Save: (*afterLoadStruct).save,
		Load: (*afterLoadStruct).load,
	})
	Register("stateTest.valueLoadStruct", (*valueLoadStruct)(nil), Fns{
		Save: (*valueLoadStruct).save,
		Load: (*valueLoadStruct).load,
	})
	Register("stateTest.genericContainer", (*genericContainer)(nil), Fns{
		Save: (*genericContainer).save,
		Load: (*genericContainer).load,
	})
	Register("stateTest.sliceContainer", (*sliceContainer)(nil), Fns{
		Save: (*sliceContainer).save,
		Load: (*sliceContainer).load,
	})
	Register("stateTest.mapContainer", (*mapContainer)(nil), Fns{
		Save: (*mapContainer).save,
		Load: (*mapContainer).load,
	})
	Register("stateTest.pointerStruct", (*pointerStruct)(nil), Fns{
		Save: (*pointerStruct).save,
		Load: (*pointerStruct).load,
	})
	Register("stateTest.testImpl", (*testImpl)(nil), Fns{
		Save: (*testImpl).save,
		Load: (*testImpl).load,
	})
	Register("stateTest.testI", (*testI)(nil), Fns{
		Save: (*testI).save,
		Load: (*testI).load,
	})
	Register("stateTest.cycleStruct", (*cycleStruct)(nil), Fns{
		Save: (*cycleStruct).save,
		Load: (*cycleStruct).load,
	})
	Register("stateTest.badCycleStruct", (*badCycleStruct)(nil), Fns{
		Save: (*badCycleStruct).save,
		Load: (*badCycleStruct).load,
	})
	Register("stateTest.emptyStructPointer", (*emptyStructPointer)(nil), Fns{
		Save: (*emptyStructPointer).save,
		Load: (*emptyStructPointer).load,
	})
	Register("stateTest.truncateInteger", (*truncateInteger)(nil), Fns{
		Save: (*truncateInteger).save,
		Load: (*truncateInteger).load,
	})
	Register("stateTest.truncateUnsignedInteger", (*truncateUnsignedInteger)(nil), Fns{
		Save: (*truncateUnsignedInteger).save,
		Load: (*truncateUnsignedInteger).load,
	})
	Register("stateTest.truncateFloat", (*truncateFloat)(nil), Fns{
		Save: (*truncateFloat).save,
		Load: (*truncateFloat).load,
	})
	Register("stateTest.benchStruct", (*benchStruct)(nil), Fns{
		Save: (*benchStruct).save,
		Load: (*benchStruct).load,
	})
}
