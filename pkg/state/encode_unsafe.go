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

package state

import (
	"reflect"
	"unsafe"
)

// arrayFromSlice constructs a new pointer to the slice data.
//
// It would be similar to the following:
//
//	x := make([]Foo, l, c)
//	a := ([l]Foo*)(unsafe.Pointer(x[0]))
//
func arrayFromSlice(obj reflect.Value) reflect.Value {
	return reflect.NewAt(
		reflect.ArrayOf(obj.Cap(), obj.Type().Elem()),
		unsafe.Pointer(obj.Pointer()))
}

// pbSlice returns a protobuf-supported slice of the array and erase the
// original element type (which could be a defined type or non-supported type).
func pbSlice(obj reflect.Value) reflect.Value {
	var typ reflect.Type
	switch obj.Type().Elem().Kind() {
	case reflect.Uint8:
		typ = reflect.TypeOf(byte(0))
	case reflect.Uint16:
		typ = reflect.TypeOf(uint16(0))
	case reflect.Uint32:
		typ = reflect.TypeOf(uint32(0))
	case reflect.Uint64:
		typ = reflect.TypeOf(uint64(0))
	case reflect.Uintptr:
		typ = reflect.TypeOf(uint64(0))
	case reflect.Int8:
		typ = reflect.TypeOf(byte(0))
	case reflect.Int16:
		typ = reflect.TypeOf(int16(0))
	case reflect.Int32:
		typ = reflect.TypeOf(int32(0))
	case reflect.Int64:
		typ = reflect.TypeOf(int64(0))
	case reflect.Bool:
		typ = reflect.TypeOf(bool(false))
	case reflect.Float32:
		typ = reflect.TypeOf(float32(0))
	case reflect.Float64:
		typ = reflect.TypeOf(float64(0))
	default:
		panic("slice element is not of basic value type")
	}
	return reflect.NewAt(
		reflect.ArrayOf(obj.Len(), typ),
		unsafe.Pointer(obj.Slice(0, obj.Len()).Pointer()),
	).Elem().Slice(0, obj.Len())
}

func castSlice(obj reflect.Value, elemTyp reflect.Type) reflect.Value {
	if obj.Type().Elem().Size() != elemTyp.Size() {
		panic("cannot cast slice into other element type of different size")
	}
	return reflect.NewAt(
		reflect.ArrayOf(obj.Len(), elemTyp),
		unsafe.Pointer(obj.Slice(0, obj.Len()).Pointer()),
	).Elem()
}
