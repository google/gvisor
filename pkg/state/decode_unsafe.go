// Copyright 2020 The gVisor Authors.
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
	"fmt"
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// reflectValueRWAddr is equivalent to obj.Addr(), except that the returned
// reflect.Value is usable in assignments even if obj was obtained by the use
// of unexported struct fields.
//
// Preconditions: obj.CanAddr().
func reflectValueRWAddr(obj reflect.Value) reflect.Value {
	return reflect.NewAt(obj.Type(), unsafe.Pointer(obj.UnsafeAddr()))
}

// reflectValueRWSlice3 is equivalent to arr.Slice3(i, j, k), except that the
// returned reflect.Value is usable in assignments even if obj was obtained by
// the use of unexported struct fields.
//
// Preconditions:
//   - arr.Kind() == reflect.Array and arr.CanAddr().
//   - i, j, k >= 0.
//   - i <= j <= k <= arr.Len().
func reflectValueRWSlice3(arr reflect.Value, i, j, k int) reflect.Value {
	if arr.Kind() != reflect.Array {
		panic(fmt.Sprintf("arr has kind %v, wanted %v", arr.Kind(), reflect.Array))
	}
	return reflectValueRWAddr(arr).Elem().Slice3(i, j, k)
}

// decodeArray owns length checks and the homogeneous wire-kind dispatch.
// Composite elements can invoke hooks, so their destination is indexed anew
// for each element. Primitive elements have no graph dependencies or hooks.
func (ds *decodeState) decodeArray(ods *objectDecodeState, target reflect.Value, encoded wire.Array) {
	length := target.Len()
	if encoded.Len() != length {
		Failf("mismatching array length expect=%d, actual=%d", length, encoded.Len())
	}
	if length == 0 {
		// Index(0) below requires a non-empty target.
		return
	}
	switch values := encoded.(type) {
	case *wire.ObjectArray:
		for i, value := range values.Contents {
			ds.decodeObject(ods, target.Index(i), value)
			ds.waitObject(ods, value, nil)
		}
		return
	}

	// The actual reflected flags must allow writes, even for an unexported
	// field. A slice value itself need not be addressable; its elements must
	// be. Defined scalar types have the same memory layout as their Kind.
	element := target.Index(0)
	if !element.CanSet() {
		Failf("array element of type %s is not settable", element.Type())
	}
	pointer := element.Addr().UnsafePointer()
	kind := element.Kind()
	switch values := encoded.(type) {
	case *wire.BoolArray:
		if kind == reflect.Bool {
			copy(unsafe.Slice((*bool)(pointer), length), values.Contents)
			return
		}
	case *wire.IntArray[wire.Int]:
		switch kind {
		case reflect.Int:
			restoreIntArray(unsafe.Slice((*int)(pointer), length), values.Contents)
		case reflect.Int8:
			restoreIntArray(unsafe.Slice((*int8)(pointer), length), values.Contents)
		case reflect.Int16:
			restoreIntArray(unsafe.Slice((*int16)(pointer), length), values.Contents)
		case reflect.Int32:
			restoreIntArray(unsafe.Slice((*int32)(pointer), length), values.Contents)
		case reflect.Int64:
			restoreIntArray(unsafe.Slice((*int64)(pointer), length), values.Contents)
		default:
			Failf("signed array cannot restore %s", element.Type())
		}
		return
	case *wire.UintArray[wire.Uint]:
		switch kind {
		case reflect.Uint:
			restoreUintArray(unsafe.Slice((*uint)(pointer), length), values.Contents)
		case reflect.Uint8:
			restoreUintArray(unsafe.Slice((*uint8)(pointer), length), values.Contents)
		case reflect.Uint16:
			restoreUintArray(unsafe.Slice((*uint16)(pointer), length), values.Contents)
		case reflect.Uint32:
			restoreUintArray(unsafe.Slice((*uint32)(pointer), length), values.Contents)
		case reflect.Uint64:
			restoreUintArray(unsafe.Slice((*uint64)(pointer), length), values.Contents)
		case reflect.Uintptr:
			restoreUintArray(unsafe.Slice((*uintptr)(pointer), length), values.Contents)
		default:
			Failf("unsigned array cannot restore %s", element.Type())
		}
		return
	case *wire.Float32Array[wire.Float32]:
		switch kind {
		case reflect.Float32:
			restoreFloatArray(unsafe.Slice((*float32)(pointer), length), values.Contents, false)
		case reflect.Float64:
			restoreFloatArray(unsafe.Slice((*float64)(pointer), length), values.Contents, false)
		default:
			Failf("floating point array cannot restore %s", element.Type())
		}
		return
	case *wire.Float64Array:
		switch kind {
		case reflect.Float32:
			restoreFloatArray(unsafe.Slice((*float32)(pointer), length), values.Contents, true)
		case reflect.Float64:
			restoreFloatArray(unsafe.Slice((*float64)(pointer), length), values.Contents, true)
		default:
			Failf("floating point array cannot restore %s", element.Type())
		}
		return
	case *wire.Complex64Array:
		switch kind {
		case reflect.Complex64:
			restoreComplexArray(unsafe.Slice((*complex64)(pointer), length), values.Contents, false)
		case reflect.Complex128:
			restoreComplexArray(unsafe.Slice((*complex128)(pointer), length), values.Contents, false)
		default:
			Failf("complex array cannot restore %s", element.Type())
		}
		return
	case *wire.Complex128Array:
		switch kind {
		case reflect.Complex64:
			restoreComplexArray(unsafe.Slice((*complex64)(pointer), length), values.Contents, true)
		case reflect.Complex128:
			restoreComplexArray(unsafe.Slice((*complex128)(pointer), length), values.Contents, true)
		default:
			Failf("complex array cannot restore %s", element.Type())
		}
		return
	case *wire.StringArray:
		if kind == reflect.String {
			copy(unsafe.Slice((*string)(pointer), length), values.Contents)
			return
		}
	}
	Failf("array %T cannot restore %s", encoded, target.Type())
}

// Store before checking, matching decodeObject's scalar path on malformed input.
func restoreIntArray[T ~int | ~int8 | ~int16 | ~int32 | ~int64](target []T, values []wire.Int) {
	for i, value := range values {
		target[i] = T(value)
		checkInt(int64(value), int64(target[i]))
	}
}

func restoreUintArray[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr](target []T, values []wire.Uint) {
	for i, value := range values {
		target[i] = T(value)
		checkUint(uint64(value), uint64(target[i]))
	}
}

func restoreFloatArray[T, S ~float32 | ~float64](target []T, values []S, check bool) {
	for i, value := range values {
		// Promote Float32 payloads through float64 to match SetFloat's
		// signaling-NaN conversion.
		promoted := float64(value)
		target[i] = T(promoted)
		if check {
			checkFloat(promoted, float64(target[i]))
		}
	}
}

func restoreComplexArray[T ~complex64 | ~complex128, S ~complex128](target []T, values []S, check bool) {
	for i, value := range values {
		target[i] = T(value)
		if check {
			checkComplex(complex128(value), complex128(target[i]))
		}
	}
}
