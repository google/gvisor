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
	"math"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

var allMapPrimitives = []any{
	bool(true),
	int(1),
	int8(1),
	int16(1),
	int32(1),
	int64(1),
	uint(1),
	uintptr(1),
	uint8(1),
	uint16(1),
	uint32(1),
	uint64(1),
	string(""),
	registeredMapStruct{},
}

var allMapKeys = flatten(allMapPrimitives, pointersTo(allMapPrimitives))

var allMapValues = flatten(allMapPrimitives, pointersTo(allMapPrimitives), interfacesTo(allMapPrimitives))

var emptyMaps = combine(allMapKeys, allMapValues, func(v1, v2 any) any {
	m := reflect.MakeMap(reflect.MapOf(reflect.TypeOf(v1), reflect.TypeOf(v2)))
	return m.Interface()
})

var fullMaps = combine(allMapKeys, allMapValues, func(v1, v2 any) any {
	m := reflect.MakeMap(reflect.MapOf(reflect.TypeOf(v1), reflect.TypeOf(v2)))
	m.SetMapIndex(reflect.Zero(reflect.TypeOf(v1)), reflect.Zero(reflect.TypeOf(v2)))
	return m.Interface()
})

func TestMapAliasing(t *testing.T) {
	v := make(map[int]int)
	ptrToV := &v
	aliases := []map[int]int{v, v}
	runTestCases(t, false, "", []any{ptrToV, aliases})
}

func TestMapNaNKeys(t *testing.T) {
	// Identical NaNs compare unequal, so both entries must survive even
	// though neither can be retrieved using a map lookup.
	const nanBits = uint64(0x7ff8000000000001)
	nan := math.Float64frombits(nanBits)
	original := map[float64]int{1: 3}
	original[nan] = 1
	original[nan] = 2
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	var restored map[float64]int
	if _, err := state.Load(t.Context(), &buf, &restored); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	want := map[int]uint64{1: nanBits, 2: nanBits, 3: math.Float64bits(1)}
	if len(restored) != len(want) {
		t.Fatalf("Restored %d entries, want %d", len(restored), len(want))
	}
	for key, value := range restored {
		if bits, ok := want[value]; !ok || math.Float64bits(key) != bits {
			t.Fatalf("Unexpected restored entry: key bits=%#x, value=%d", math.Float64bits(key), value)
		}
		delete(want, value)
	}
}

func TestMapsEmpty(t *testing.T) {
	runTestCases(t, false, "plain", emptyMaps)
	runTestCases(t, false, "pointers", pointersTo(emptyMaps))
	runTestCases(t, false, "interfaces", interfacesTo(emptyMaps))
	runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(emptyMaps)))
}

func TestMapsFull(t *testing.T) {
	runTestCases(t, false, "plain", fullMaps)
	runTestCases(t, false, "pointers", pointersTo(fullMaps))
	runTestCases(t, false, "interfaces", interfacesTo(fullMaps))
	runTestCases(t, false, "interfacesToPointer", interfacesTo(pointersTo(fullMaps)))
}

func TestMapContainers(t *testing.T) {
	var (
		nilMap   map[int]any
		emptyMap = make(map[int]any)
		fullMap  = map[int]any{0: nil}
	)
	runTestCases(t, false, "", []any{
		mapContainer{v: nilMap},
		mapContainer{v: emptyMap},
		mapContainer{v: fullMap},
		mapPtrContainer{v: nil},
		mapPtrContainer{v: &nilMap},
		mapPtrContainer{v: &emptyMap},
		mapPtrContainer{v: &fullMap},
	})
}

// loadMapEntries fixes the wire order so a non-nil entry is always decoded
// before a nil entry. Save's map iteration order cannot guarantee that order.
func loadMapEntries(t *testing.T, dst any, entries *wire.Map, objects ...wire.Object) {
	t.Helper()
	var buf bytes.Buffer
	w := wire.Writer{Writer: &buf}
	if err := state.WriteHeader(&w, uint64(1+len(objects)), true); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	// Interface entries below use type ID 1 for int, including *int.
	wire.Save(&w, &wire.Type{Name: "int"})
	wire.Save(&w, wire.Uint(1))
	wire.Save(&w, entries)
	for i, object := range objects {
		wire.Save(&w, wire.Uint(i+2))
		wire.Save(&w, object)
	}
	if _, err := state.Load(t.Context(), &buf, dst); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestMapNilValues(t *testing.T) {
	seven := 7
	for _, test := range []struct {
		name    string
		values  []wire.Object
		backing wire.Object
		want    any
	}{
		{
			name:    "pointer",
			values:  []wire.Object{&wire.Ref{Root: 2}, &wire.Ref{}},
			backing: wire.Int(7),
			want:    map[int]*int{1: &seven, 2: nil},
		},
		{
			name:    "map",
			values:  []wire.Object{&wire.Ref{Root: 2}, &wire.Ref{}},
			backing: &wire.Map{Keys: []wire.Object{wire.Int(7)}, Values: []wire.Object{wire.Int(9)}},
			want:    map[int]map[int]int{1: {7: 9}, 2: nil},
		},
		{
			name: "slice",
			values: []wire.Object{
				&wire.Slice{Length: 1, Capacity: 1, Ref: wire.Ref{Root: 2}},
				&wire.Slice{},
			},
			backing: &wire.Array{Contents: []wire.Object{wire.Int(7)}},
			want:    map[int][]int{1: {7}, 2: nil},
		},
		{
			name: "interface",
			values: []wire.Object{
				&wire.Interface{Type: &wire.TypeSpecPointer{Type: wire.TypeID(1)}, Value: &wire.Ref{Root: 2}},
				&wire.Interface{Type: &wire.TypeSpecPointer{Type: wire.TypeID(1)}, Value: &wire.Ref{}},
				&wire.Interface{Type: wire.TypeSpecNil{}, Value: wire.Nil{}},
			},
			backing: wire.Int(7),
			want:    map[int]any{1: &seven, 2: (*int)(nil), 3: nil},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := &wire.Map{Values: test.values}
			for i := range test.values {
				entries.Keys = append(entries.Keys, wire.Int(i+1))
			}
			loaded := reflect.New(reflect.TypeOf(test.want))
			loadMapEntries(t, loaded.Interface(), entries, test.backing)
			if got, want := loaded.Elem().Interface(), test.want; !reflect.DeepEqual(got, want) {
				t.Errorf("loaded map = %#v, want %#v", got, want)
			}
		})
	}
}

func TestMapNilKeys(t *testing.T) {
	t.Run("pointer", func(t *testing.T) {
		var loaded map[*int]int
		loadMapEntries(t, &loaded, &wire.Map{
			Keys:   []wire.Object{&wire.Ref{Root: 2}, &wire.Ref{}},
			Values: []wire.Object{wire.Int(1), wire.Int(2)},
		}, wire.Int(7))
		if got, want := len(loaded), 2; got != want {
			t.Fatalf("map length = %d, want %d", got, want)
		}
		if got, want := loaded[nil], 2; got != want {
			t.Errorf("nil key value = %d, want %d", got, want)
		}
		for key, value := range loaded {
			if key != nil {
				if got, want := *key, 7; got != want {
					t.Errorf("pointed-to key = %d, want %d", got, want)
				}
				if got, want := value, 1; got != want {
					t.Errorf("non-nil key value = %d, want %d", got, want)
				}
			}
		}
	})
	t.Run("interface", func(t *testing.T) {
		var loaded map[any]int
		loadMapEntries(t, &loaded, &wire.Map{
			Keys: []wire.Object{
				&wire.Interface{Type: wire.TypeID(1), Value: wire.Int(7)},
				&wire.Interface{Type: &wire.TypeSpecPointer{Type: wire.TypeID(1)}, Value: &wire.Ref{}},
				&wire.Interface{Type: wire.TypeSpecNil{}, Value: wire.Nil{}},
			},
			Values: []wire.Object{wire.Int(1), wire.Int(2), wire.Int(3)},
		})
		if got, want := loaded, (map[any]int{7: 1, (*int)(nil): 2, nil: 3}); !reflect.DeepEqual(got, want) {
			t.Errorf("loaded map = %#v, want %#v", got, want)
		}
	})
}

func TestMapLoadHookReceivers(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"struct keys", map[mapLoadHook]int{{1}: 1, {2}: 2}},
		{"struct values", map[int]mapLoadHook{1: {1}, 2: {2}}},
		{"array keys", map[[1]mapLoadHook]int{{{1}}: 1, {{2}}: 2}},
		{"array values", map[int][1]mapLoadHook{1: {{1}}, 2: {{2}}}},
		{"interface keys", map[any]int{mapLoadHook{1}: 1, mapLoadHook{2}: 2}},
		{"interface values", map[int]any{1: mapLoadHook{1}, 2: mapLoadHook{2}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Both hooks run after the map entries have been decoded. If
			// aggregate storage is reused, both callbacks see the last entry.
			receivers := make(map[*mapLoadHook]struct{})
			values := make(map[int]int)
			ctx := context.WithValue(t.Context(), mapLoadHookContextKey{}, func(v *mapLoadHook) {
				receivers[v] = struct{}{}
				values[v.value]++
			})
			original := reflect.New(reflect.TypeOf(test.value))
			original.Elem().Set(reflect.ValueOf(test.value))
			var buf bytes.Buffer
			if _, err := state.Save(ctx, &buf, original.Interface()); err != nil {
				t.Fatalf("Save: %v", err)
			}
			loaded := reflect.New(original.Elem().Type())
			if _, err := state.Load(ctx, &buf, loaded.Interface()); err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got, want := loaded.Elem().Interface(), test.value; !reflect.DeepEqual(got, want) {
				t.Errorf("loaded map = %#v, want %#v", got, want)
			}
			if got, want := len(receivers), 2; got != want {
				t.Errorf("distinct hook receivers = %d, want %d", got, want)
			}
			if got, want := values, (map[int]int{1: 1, 2: 1}); !reflect.DeepEqual(got, want) {
				t.Errorf("hook values = %v, want %v", got, want)
			}
		})
	}
}
