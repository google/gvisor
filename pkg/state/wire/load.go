// Copyright 2026 The gVisor Authors.
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

package wire

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// Load loads a new object. The returned object does not alias the reader's
// buffers.
//
// N.B. This function will panic on error.
//
// +checkescape:hard
func Load(r *Reader) Object {
	return loadPayload(r, loadUint(r))
}

// loadPayload is the sole data-value grammar. Homogeneous arrays and maps
// omit repeated tags after their first element; their payloads use this same
// parser. Typed allocations check full-width counts before narrowing to int.
func loadPayload(r *Reader, tag Uint) Object {
	switch tag {
	case typeBool:
		return loadBool(r) // Escapes: scalar Object payload.
	case typeInt:
		return loadInt(r) // Escapes: scalar Object payload.
	case typeUint:
		return loadUint(r) // Escapes: scalar Object payload.
	case typeFloat32:
		return loadFloat32(r) // Escapes: scalar Object payload.
	case typeFloat64:
		return loadFloat64(r) // Escapes: scalar Object payload.
	case typeComplex64:
		value := loadComplex64(r) // Escapes: owned complex payload.
		return &value
	case typeComplex128:
		value := loadComplex128(r) // Escapes: owned complex payload.
		return &value
	case typeNil:
		return Nil{} // Escapes: zero-sized Object payload.
	case typeNoObjects:
		return noObjects{} // Escapes: zero-sized Object payload.
	case typeRef:
		value := loadReference(r) // Escapes: owned reference payload.
		return &value
	case typeString:
		value := loadString(r) // Escapes: owned string header.
		return &value
	case typeSlice:
		length, capacity := loadUint(r), loadUint(r)
		return &Slice{Length: length, Capacity: capacity, Ref: loadReference(r)} // Escapes: owned slice payload.
	case typeArray:
		count := loadUint(r)
		// Reject a nonrepresentable length before trying to read the tag.
		// Each typed make below also checks its element-size multiplication.
		if count > Uint(^uint(0)>>1) {
			panic(fmt.Errorf("array length %d overflows int", count)) // Escapes: error formatting.
		}
		if count == 0 {
			return &ObjectArray{} // Escapes: owned empty array header.
		}
		return loadArray(r, count, loadUint(r))
	case typeMultipleObjects:
		values := make(multipleObjects, loadUint(r)) // Escapes: owned field header and elements.
		for i := range values {
			values[i] = Load(r)
		}
		return &values
	case typeMap:
		count := loadUint(r)
		value := &Map{} // Escapes: owned map header.
		if count != 0 {
			value.Keys = make([]Object, count)   // Escapes: owned keys; make checks the full-width size.
			value.Values = make([]Object, count) // Escapes: owned values.
			keyTag := loadUint(r)
			value.Keys[0] = loadPayload(r, keyTag)
			valueTag := loadUint(r)
			value.Values[0] = loadPayload(r, valueTag)
			for i := 1; i < len(value.Keys); i++ {
				value.Keys[i] = loadPayload(r, keyTag)
				value.Values[i] = loadPayload(r, valueTag)
			}
		}
		return value
	case typeStruct:
		id := TypeID(loadUint(r))
		return &Struct{TypeID: id, fields: Load(r)} // Escapes: owned struct payload.
	case typeInterface:
		typ := loadType(r)
		return &Interface{Type: typ, Value: Load(r)} // Escapes: owned interface payload.
	case typeType:
		typ := &Type{Name: string(loadString(r))} // Escapes: owned schema payload.
		typ.Fields = make([]string, loadUint(r))  // Escapes: owned schema field headers.
		for i := range typ.Fields {
			typ.Fields[i] = string(loadString(r))
		}
		return typ
	default:
		panic(fmt.Errorf("unknown header: %d", tag)) // Escapes: error formatting.
	}
}

func loadFloat32(r *Reader) Float32 {
	return Float32(math.Float32frombits(uint32(loadUint(r))))
}

func loadFloat64(r *Reader) Float64 {
	return Float64(math.Float64frombits(uint64(loadUint(r))))
}

func loadComplex64(r *Reader) Complex64 {
	re, im := math.Float32frombits(uint32(loadUint(r))), math.Float32frombits(uint32(loadUint(r)))
	return Complex64(complex(float64(re), float64(im)))
}

func loadComplex128(r *Reader) Complex128 {
	re, im := math.Float64frombits(uint64(loadUint(r))), math.Float64frombits(uint64(loadUint(r)))
	return Complex128(complex(re, im))
}

// loadArray selects storage once from the wire's homogeneous element tag.
// Payload readers are shared with loadPayload; no scalar Object is allocated
// or boxed while filling these arrays. Integer payloads retain their full wire
// width until restoration checks the destination's width.
func loadArray(r *Reader, count Uint, tag Uint) Array {
	switch tag {
	case typeBool:
		return &BoolArray{Contents: loadArrayValues(r, count, loadBoolValue)} // Escapes: owned homogeneous array header.
	case typeInt:
		return &IntArray[Int]{Contents: loadArrayValues(r, count, loadInt)} // Escapes: owned homogeneous array header.
	case typeUint:
		return &UintArray[Uint]{Contents: loadArrayValues(r, count, loadUint)} // Escapes: owned homogeneous array header.
	case typeFloat32:
		return &Float32Array[Float32]{Contents: loadArrayValues(r, count, loadFloat32)} // Escapes: owned homogeneous array header.
	case typeFloat64:
		return &Float64Array{Contents: loadArrayValues(r, count, loadFloat64Value)} // Escapes: owned homogeneous array header.
	case typeComplex64:
		return &Complex64Array{Contents: loadArrayValues(r, count, loadComplex64)} // Escapes: owned homogeneous array header.
	case typeComplex128:
		return &Complex128Array{Contents: loadArrayValues(r, count, loadComplex128)} // Escapes: owned homogeneous array header.
	case typeString:
		return &StringArray{Contents: loadArrayValues(r, count, loadStringValue)} // Escapes: owned homogeneous array header.
	default:
		values := loadArrayValues(r, count, func(r *Reader) Object { return loadPayload(r, tag) }) // Escapes: owned composite elements.
		return &ObjectArray{Contents: values}                                                      // Escapes: owned homogeneous array header.
	}
}

func loadBoolValue(r *Reader) bool { return bool(loadBool(r)) }

func loadFloat64Value(r *Reader) float64 { return float64(loadFloat64(r)) }

func loadStringValue(r *Reader) string { return string(loadString(r)) }

func loadArrayValues[T any](r *Reader, count Uint, load func(*Reader) T) []T {
	values := make([]T, count) // Escapes: owned typed elements; make checks the full-width size.
	for i := range values {
		values[i] = load(r)
	}
	return values
}

func loadReference(r *Reader) Ref {
	ref := Ref{Root: loadUint(r)}
	count := loadUint(r)
	if count == 0 {
		return ref
	}
	ref.Dots = make([]Dot, count) // Escapes: owned reference path; make checks the full-width count.
	for i := range ref.Dots {
		dot := loadInt(r)
		if dot >= 0 {
			ref.Dots[i] = Index(dot) // Escapes: existing Index narrowing and interface boxing.
		} else {
			data := make([]byte, -dot) // Escapes: independently owned field name.
			readFull(r, data)
			name := FieldName(gohacks.StringFromImmutableBytes(data)) // Escapes: owned field-name interface.
			ref.Dots[i] = &name
		}
	}
	ref.Type = loadType(r)
	return ref
}

// loadType is the sole TypeSpec grammar. Its tag namespace is independent of
// data-value tags; full-width IDs and array counts remain intact.
func loadType(r *Reader) TypeSpec {
	header := loadUint(r)
	switch header {
	case typeSpecTypeID:
		return TypeID(loadUint(r)) // Escapes: owned type ID interface.
	case typeSpecPointer:
		return &TypeSpecPointer{Type: loadType(r)} // Escapes: owned type metadata.
	case typeSpecSlice:
		return &TypeSpecSlice{Type: loadType(r)} // Escapes: owned type metadata.
	case typeSpecArray:
		count := loadUint(r)
		return &TypeSpecArray{Count: count, Type: loadType(r)} // Escapes: owned type metadata.
	case typeSpecMap:
		key, value := loadType(r), loadType(r)
		return &TypeSpecMap{Key: key, Value: value} // Escapes: owned type metadata.
	case typeSpecNil:
		return TypeSpecNil{}
	default:
		panic(fmt.Errorf("unknown header: %d", header)) // Escapes: error formatting.
	}
}
