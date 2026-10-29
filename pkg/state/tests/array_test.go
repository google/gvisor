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
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

var allArrayPrimitives = []any{
	[0]*int{},
	[0]uint64{},
	[2]int64{-1 << 63, 1<<63 - 1},
	[2]uint64{0, ^uint64(0)},
	[2]arraySigned{-7, 11},
	[2]arrayUnsigned{0, ^arrayUnsigned(0)},
	[2]arrayString{"", "owned"},
	[2]float32{0, -1.5},
	[2]float64{math.Copysign(0, -1), math.Inf(1)},
	[2]complex64{0, 1.25 - 3i},
	[2]complex128{complex(math.Copysign(0, -1), 0), 2 - 5i},
	[1]bool{},
	[1]bool{true},
	[2]bool{false, true},
	[1]int{},
	[1]int{1},
	[2]int{0, 1},
	[1]int8{},
	[1]int8{1},
	[2]int8{0, 1},
	[1]int16{},
	[1]int16{1},
	[2]int16{0, 1},
	[1]int32{},
	[1]int32{1},
	[2]int32{0, 1},
	[1]int64{},
	[1]int64{1},
	[2]int64{0, 1},
	[1]uint{},
	[1]uint{1},
	[2]uint{0, 1},
	[1]uintptr{},
	[1]uintptr{1},
	[2]uintptr{0, 1},
	[1]uint8{},
	[1]uint8{1},
	[2]uint8{0, 1},
	[1]uint16{},
	[1]uint16{1},
	[2]uint16{0, 1},
	[1]uint32{},
	[1]uint32{1},
	[2]uint32{0, 1},
	[1]uint64{},
	[1]uint64{1},
	[2]uint64{0, 1},
	[1]string{},
	[1]string{""},
	[1]string{nonEmptyString},
	[2]string{"", nonEmptyString},
}

func TestArrayPrimitives(t *testing.T) {
	runWithBothEngines(t, func(t *testing.T) {
		runTestCases(t, false, "plain", flatten(allArrayPrimitives))
		runTestCases(t, false, "pointers", pointersTo(flatten(allArrayPrimitives)))
		runTestCases(t, false, "interfaces", interfacesTo(flatten(allArrayPrimitives)))
		runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(flatten(allArrayPrimitives))))
	})
}

func TestSlices(t *testing.T) {
	var allSlices = flatten(
		filter(allArrayPrimitives, func(o any) (any, bool) {
			v := reflect.New(reflect.TypeOf(o)).Elem()
			v.Set(reflect.ValueOf(o))
			return v.Slice(0, v.Len()).Interface(), true
		}),
		filter(allArrayPrimitives, func(o any) (any, bool) {
			v := reflect.New(reflect.TypeOf(o)).Elem()
			v.Set(reflect.ValueOf(o))
			if v.Len() == 0 {
				// Return the pure "nil" value for the slice.
				return reflect.New(v.Slice(0, 0).Type()).Elem().Interface(), true
			}
			return v.Slice(1, v.Len()).Interface(), true
		}),
		filter(allArrayPrimitives, func(o any) (any, bool) {
			v := reflect.New(reflect.TypeOf(o)).Elem()
			v.Set(reflect.ValueOf(o))
			if v.Len() == 0 {
				// Return the zero-valued slice.
				return reflect.MakeSlice(v.Slice(0, 0).Type(), 0, 0).Interface(), true
			}
			return v.Slice(0, v.Len()-1).Interface(), true
		}),
	)
	runWithBothEngines(t, func(t *testing.T) {
		runTestCases(t, false, "plain", allSlices)
		runTestCases(t, false, "pointers", pointersTo(allSlices))
		runTestCases(t, false, "interfaces", interfacesTo(allSlices))
		runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(allSlices)))
	})
}

func TestArrayContainers(t *testing.T) {
	var (
		emptyArray [1]any
		fullArray  [1]any
	)
	fullArray[0] = &emptyArray
	runTestCases(t, false, "", []any{
		arrayContainer{v: emptyArray},
		arrayContainer{v: fullArray},
		arrayPtrContainer{v: nil},
		arrayPtrContainer{v: &emptyArray},
		arrayPtrContainer{v: &fullArray},
	})
}

func TestSliceContainers(t *testing.T) {
	var (
		nilSlice            []any
		emptySlice          = make([]any, 0)
		fullSlice           = []any{nil}
		unusedCapacitySlice = []any{savableEmptyStruct{}, unregisteredEmptyStruct{}}[:1]
	)
	runTestCases(t, false, "", []any{
		sliceContainer{v: nilSlice},
		sliceContainer{v: emptySlice},
		sliceContainer{v: fullSlice},
		sliceContainer{v: unusedCapacitySlice},
		slicePtrContainer{v: nil},
		slicePtrContainer{v: &nilSlice},
		slicePtrContainer{v: &emptySlice},
		slicePtrContainer{v: &fullSlice},
		slicePtrContainer{v: &unusedCapacitySlice},
	})
}

// useWireEngine selects the codec whose array storage these tests exercise.
func useWireEngine(t *testing.T) {
	previous := state.GraphEngineEnabled()
	state.EnableGraphEngine(false)
	t.Cleanup(func() { state.EnableGraphEngine(previous) })
}

func TestArraySnapshotTiming(t *testing.T) {
	useWireEngine(t)
	first := &arraySnapshotSource{values: [2]uint64{7, 11}}
	original := system{v1: first, v2: &arraySnapshotMutator{target: first}}
	var encoded bytes.Buffer
	if _, err := state.Save(t.Context(), &encoded, &original); err != nil {
		t.Fatal(err)
	}
	if got, want := first.values[0], uint64(99); got != want {
		t.Fatalf("later hook mutation = %d, want %d", got, want)
	}
	var loaded system
	if _, err := state.Load(t.Context(), &encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	child := loaded.v1.(*arraySnapshotSource)
	if got, want := child.values, ([2]uint64{7, 11}); got != want {
		t.Errorf("captured array = %v, want %v", got, want)
	}
	if got, want := loaded.v2.(*arraySnapshotMutator).target, child; got != want {
		t.Errorf("shared target = %p, want %p", got, want)
	}
}

func TestArrayLateParent(t *testing.T) {
	useWireEngine(t)
	backing := [2][2]uint64{{7, 11}, {13, 17}}
	// Encode the interior array first. Later slice discovery clears the unused
	// capacity and reparents that object under the complete backing array.
	// The containing array must be captured anew after the clearing.
	original := system{v1: &backing[1], v2: &arrayTailDiscovery{values: backing[:1]}}
	var encoded bytes.Buffer
	if _, err := state.Save(t.Context(), &encoded, &original); err != nil {
		t.Fatal(err)
	}
	if got, want := backing[1], ([2]uint64{}); got != want {
		t.Fatalf("cleared backing tail = %v, want %v", got, want)
	}
	var loaded system
	if _, err := state.Load(t.Context(), &encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	child := loaded.v1.(*[2]uint64)
	parent := loaded.v2.(*arrayTailDiscovery).values
	if got, want := cap(parent), 2; got != want {
		t.Fatalf("backing capacity = %d, want %d", got, want)
	}
	if got, want := child, &parent[:2][1]; got != want {
		t.Errorf("interior array = %p, want %p", got, want)
	}
	if got, want := *child, ([2]uint64{}); got != want {
		t.Errorf("recaptured tail = %v, want %v", got, want)
	}
}

func TestPrimitiveArrayFloatEncoding(t *testing.T) {
	useWireEngine(t)
	positiveSignal := math.Float32frombits(0x7f800001)
	negativeSignal := math.Float32frombits(0xff800001)
	quiet := math.Float32frombits(0x7fc00042)
	for _, test := range []struct {
		name  string
		value any
	}{
		{"float32", &[4]float32{positiveSignal, negativeSignal, quiet, 1.25}},
		{"complex64", &[2]complex64{complex(positiveSignal, negativeSignal), complex(quiet, 1.25)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A scalar root uses the reflected scalar encoder. Compare that
			// public boundary with each element captured by the bulk path.
			capture := func(value any) wire.Object {
				t.Helper()
				var buf bytes.Buffer
				if _, err := state.Save(t.Context(), &buf, value); err != nil {
					t.Fatal(err)
				}
				reader := wire.Reader{Reader: &buf}
				if count, object, err := state.ReadHeader(&reader); err != nil || !object || count != 1 {
					t.Fatalf("ReadHeader = %d, %t, %v; want one object", count, object, err)
				}
				if id := wire.Load(&reader); id != wire.Uint(1) {
					t.Fatalf("root ID = %v, want 1", id)
				}
				return wire.Load(&reader)
			}
			array := capture(test.value).(wire.Array)
			source := reflect.ValueOf(test.value).Elem()
			for i := range source.Len() {
				var captured, scalar bytes.Buffer
				wire.Save(&wire.Writer{Writer: &captured}, array.Element(i))
				wire.Save(&wire.Writer{Writer: &scalar}, capture(source.Index(i).Addr().Interface()))
				if got, want := captured.Bytes(), scalar.Bytes(); !bytes.Equal(got, want) {
					t.Errorf("element %d encoding = %x, want scalar encoding %x", i, got, want)
				}
			}
		})
	}
}

func TestArrayRetainedLoadReceivers(t *testing.T) {
	useWireEngine(t)
	for _, first := range []string{"slice", "dynamic", "interior", "pointer_dynamic", "pointer_interior"} {
		for _, deferred := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deferred=%t", first, deferred), func(t *testing.T) {
				backing := [3]countedArrayWord{{value: 7}, {value: 11}, {value: 13}}
				pointers := [3]*countedArrayWord{&backing[0], &backing[1], nil}
				original := countedArrayContainer{
					values: backing[:2], pointers: pointers[:2],
					zeros: make([]registeredMapStruct, 2),
				}
				switch first {
				case "dynamic":
					original.first = original.values
				case "interior":
					original.first = &backing[1]
				case "pointer_dynamic":
					original.first = original.pointers
				case "pointer_interior":
					original.first = &pointers[1]
				}
				var receivers arrayReceiverCensus
				ctx := context.WithValue(t.Context(), arrayReceiverKey{}, &receivers)
				var encoded bytes.Buffer
				if _, err := state.Save(ctx, &encoded, &original); err != nil {
					t.Fatal(err)
				}
				if deferred {
					reverseObjectBodies(t, &encoded)
				}
				var restored countedArrayContainer
				if _, err := state.Load(ctx, &encoded, &restored); err != nil {
					t.Fatal(err)
				}
				if got, want := restored, original; !reflect.DeepEqual(got, want) {
					t.Fatalf("restored arrays = %+v, want %+v", got, want)
				}
				if got, want := cap(restored.values), 3; got != want {
					t.Fatalf("value capacity = %d, want %d", got, want)
				}
				if got, want := cap(restored.pointers), 3; got != want {
					t.Fatalf("pointer capacity = %d, want %d", got, want)
				}
				values := restored.values[:3]
				if got, want := len(receivers.loaded), 3; got != want {
					t.Fatalf("Load receivers = %d, want %d", got, want)
				}
				seen := make(map[*countedArrayWord]struct{})
				for _, receiver := range receivers.loaded {
					if _, ok := seen[receiver]; ok {
						t.Fatalf("reused Load receiver %p", receiver)
					}
					seen[receiver] = struct{}{}
				}
				for i := range values {
					if _, ok := seen[&values[i]]; !ok {
						t.Errorf("Load did not use backing element %d at %p", i, &values[i])
					}
				}
				for i, pointer := range restored.pointers {
					if got, want := pointer, &values[i]; got != want {
						t.Errorf("pointer %d = %p, want %p", i, got, want)
					}
				}
				if got, want := values[2].value, uint64(0); got != want {
					t.Errorf("cleared tail = %d, want %d", got, want)
				}
				if got, want := restored.pointers[:3][2], (*countedArrayWord)(nil); got != want {
					t.Errorf("pointer tail = %p, want %p", got, want)
				}
				for _, receiver := range receivers.loaded {
					if receiver == &values[1] {
						receiver.value = 29
					}
				}
				if got, want := restored.pointers[1].value, uint64(29); got != want {
					t.Errorf("receiver mutation = %d, want %d", got, want)
				}
				switch first {
				case "dynamic":
					if got, want := &restored.first.([]countedArrayWord)[1], &values[1]; got != want {
						t.Errorf("dynamic array alias = %p, want %p", got, want)
					}
				case "interior":
					if got, want := restored.first.(*countedArrayWord), &values[1]; got != want {
						t.Errorf("interior alias = %p, want %p", got, want)
					}
				case "pointer_dynamic":
					if got, want := &restored.first.([]*countedArrayWord)[1], &restored.pointers[1]; got != want {
						t.Errorf("dynamic pointer array alias = %p, want %p", got, want)
					}
				case "pointer_interior":
					if got, want := restored.first.(**countedArrayWord), &restored.pointers[1]; got != want {
						t.Errorf("pointer interior alias = %p, want %p", got, want)
					}
				}
			})
		}
	}
}

// TestArrayLiveSliceHeader covers root and field destinations for the same
// Array-to-slice operation. A first hook changes the actual header, so a
// captured []T view would restore the wrong second receiver.
func TestArrayLiveSliceHeader(t *testing.T) {
	useWireEngine(t)
	for _, field := range []bool{false, true} {
		for _, shrink := range []bool{false, true} {
			t.Run(fmt.Sprintf("field=%t/shrink=%t", field, shrink), func(t *testing.T) {
				values := [2]arraySliceLoadWord{{value: 7}, {value: 11}}
				var encoded bytes.Buffer
				var saved any = &values
				if field {
					saved = &arraySliceLoad{values: values[:]}
				}
				if _, err := state.Save(t.Context(), &encoded, saved); err != nil {
					t.Fatal(err)
				}
				backing := [2]arraySliceLoadWord{}
				replacement := [2]arraySliceLoadWord{{value: 101}, {value: 103}}
				loaded := arraySliceLoad{values: backing[:]}
				load := arraySliceLoadState{target: &loaded.values, replacement: replacement[:]}
				if shrink {
					load.replacement = load.replacement[:1]
				}
				ctx := context.WithValue(t.Context(), arraySliceLoadKey{}, &load)
				var target any = &loaded.values
				if field {
					target = &loaded
				}
				_, err := state.Load(ctx, &encoded, target)
				if shrink {
					if err == nil || !strings.Contains(err.Error(), "slice index out of range") {
						t.Fatalf("Load error = %v, want slice index out of range", err)
					}
					if got, want := len(load.receivers), 1; got != want {
						t.Fatalf("Load receivers = %d, want %d", got, want)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if got, want := len(load.receivers), 2; got != want {
						t.Fatalf("Load receivers = %d, want %d", got, want)
					}
					if got, want := load.receivers[1], &replacement[1]; got != want {
						t.Errorf("second receiver = %p, want %p", got, want)
					}
					if got, want := replacement[1].value, uint64(11); got != want {
						t.Errorf("replacement value = %d, want %d", got, want)
					}
				}
				if got, want := load.receivers[0], &backing[0]; got != want {
					t.Errorf("first receiver = %p, want %p", got, want)
				}
				if got, want := loaded.values, load.replacement; !reflect.DeepEqual(got, want) {
					t.Errorf("header after hook = %v, want %v", got, want)
				}
				if got, want := backing[0].value, uint64(7); got != want {
					t.Errorf("first store = %d, want %d", got, want)
				}
				if got, want := backing[1].value, uint64(0); got != want {
					t.Errorf("old second slot = %d, want %d", got, want)
				}
			})
		}
	}
}

// reverseObjectBodies puts every non-root object before root without changing
// the schema order, object IDs, or each value's encoding.
func reverseObjectBodies(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	data := bytes.Clone(buf.Bytes())
	input := bytes.NewReader(data)
	reader := wire.Reader{Reader: input}
	count, object, err := state.ReadHeader(&reader)
	if err != nil || !object {
		t.Fatalf("ReadHeader = %d, %t, %v", count, object, err)
	}
	var schemas, objects [][]byte
	for uint64(len(objects)) < count {
		start := len(data) - input.Len()
		value := wire.Load(&reader)
		if _, ok := value.(*wire.Type); ok {
			schemas = append(schemas, data[start:len(data)-input.Len()])
			continue
		}
		if _, ok := value.(wire.Uint); !ok {
			t.Fatalf("object ID type = %T, want wire.Uint", value)
		}
		wire.Load(&reader)
		objects = append(objects, data[start:len(data)-input.Len()])
	}
	buf.Reset()
	writer := wire.Writer{Writer: buf}
	if err := state.WriteHeader(&writer, count, true); err != nil {
		t.Fatal(err)
	}
	for _, schema := range schemas {
		buf.Write(schema)
	}
	for i := len(objects) - 1; i >= 0; i-- {
		buf.Write(objects[i])
	}
}
