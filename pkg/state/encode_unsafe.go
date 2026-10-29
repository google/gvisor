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

	"gvisor.dev/gvisor/pkg/state/wire"
)

// arrayFromSlice constructs a new pointer to the slice data.
//
// It would be similar to the following:
//
//	x := make([]Foo, l, c)
//	a := ([l]Foo*)(unsafe.Pointer(x[0]))
func arrayFromSlice(obj reflect.Value) reflect.Value {
	arr := reflect.NewAt(
		reflect.ArrayOf(obj.Cap(), obj.Type().Elem()),
		unsafe.Pointer(obj.Pointer()))
	if obj.Len() < obj.Cap() {
		arr.Elem().Slice(obj.Len(), obj.Cap()).Clear()
	}
	return arr
}

// captureArray returns a typed copy of a primitive array, or false
// for other element kinds. Unaddressable arrays (from interfaces or map values)
// are copied once to obtain an address.
func (es *encodeState) captureArray(obj reflect.Value) (wire.Object, bool) {
	if !obj.CanAddr() {
		switch obj.Type().Elem().Kind() {
		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
			// Interface and map values can supply an unaddressable array.
			// Obtain a typed address once instead of boxing its elements.
			local := reflect.New(obj.Type()).Elem()
			local.Set(obj)
			obj = local
		default:
			return nil, false
		}
	}
	var captured wire.Object
	length := obj.Len()
	switch obj.Type().Elem().Kind() {
	case reflect.Bool:
		captured = wire.CaptureBoolArray(unsafe.Slice((*bool)(obj.Addr().UnsafePointer()), length))
	case reflect.Int:
		captured = wire.CaptureIntArray(unsafe.Slice((*int)(obj.Addr().UnsafePointer()), length))
	case reflect.Int8:
		captured = wire.CaptureIntArray(unsafe.Slice((*int8)(obj.Addr().UnsafePointer()), length))
	case reflect.Int16:
		captured = wire.CaptureIntArray(unsafe.Slice((*int16)(obj.Addr().UnsafePointer()), length))
	case reflect.Int32:
		captured = wire.CaptureIntArray(unsafe.Slice((*int32)(obj.Addr().UnsafePointer()), length))
	case reflect.Int64:
		captured = wire.CaptureIntArray(unsafe.Slice((*int64)(obj.Addr().UnsafePointer()), length))
	case reflect.Uint:
		captured = wire.CaptureUintArray(unsafe.Slice((*uint)(obj.Addr().UnsafePointer()), length))
	case reflect.Uint8:
		captured = wire.CaptureUintArray(unsafe.Slice((*uint8)(obj.Addr().UnsafePointer()), length))
	case reflect.Uint16:
		captured = wire.CaptureUintArray(unsafe.Slice((*uint16)(obj.Addr().UnsafePointer()), length))
	case reflect.Uint32:
		captured = wire.CaptureUintArray(unsafe.Slice((*uint32)(obj.Addr().UnsafePointer()), length))
	case reflect.Uint64:
		captured = wire.CaptureUintArray(unsafe.Slice((*uint64)(obj.Addr().UnsafePointer()), length))
	case reflect.Uintptr:
		captured = wire.CaptureUintArray(unsafe.Slice((*uintptr)(obj.Addr().UnsafePointer()), length))
	case reflect.Float32:
		captured = wire.CaptureFloat32Array(unsafe.Slice((*float32)(obj.Addr().UnsafePointer()), length))
	case reflect.Float64:
		captured = wire.CaptureFloat64Array(unsafe.Slice((*float64)(obj.Addr().UnsafePointer()), length))
	case reflect.Complex64:
		captured = wire.CaptureComplex64Array(unsafe.Slice((*complex64)(obj.Addr().UnsafePointer()), length))
	case reflect.Complex128:
		captured = wire.CaptureComplex128Array(unsafe.Slice((*complex128)(obj.Addr().UnsafePointer()), length))
	case reflect.String:
		captured = wire.CaptureStringArray(unsafe.Slice((*string)(obj.Addr().UnsafePointer()), length))
	default:
		return nil, false
	}
	return captured, true
}
