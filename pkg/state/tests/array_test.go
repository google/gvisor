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

var allArrayPrimitives = []any{
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
	runTestCases(t, false, "plain", flatten(allArrayPrimitives))
	runTestCases(t, false, "pointers", pointersTo(flatten(allArrayPrimitives)))
	runTestCases(t, false, "interfaces", interfacesTo(flatten(allArrayPrimitives)))
	runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(flatten(allArrayPrimitives))))
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
	runTestCases(t, false, "plain", allSlices)
	runTestCases(t, false, "pointers", pointersTo(allSlices))
	runTestCases(t, false, "interfaces", interfacesTo(allSlices))
	runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(allSlices)))
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
		nilSlice   []any
		emptySlice = make([]any, 0)
		fullSlice  = []any{nil}
	)
	runTestCases(t, false, "", []any{
		sliceContainer{v: nilSlice},
		sliceContainer{v: emptySlice},
		sliceContainer{v: fullSlice},
		slicePtrContainer{v: nil},
		slicePtrContainer{v: &nilSlice},
		slicePtrContainer{v: &emptySlice},
		slicePtrContainer{v: &fullSlice},
	})
}
