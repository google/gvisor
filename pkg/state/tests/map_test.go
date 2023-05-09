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
	"reflect"
	"testing"
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
