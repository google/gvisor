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

import "slices"

// Array is a homogeneous array value. Element boxes a single element for
// inspection. Load produces IntArray[Int], UintArray[Uint] and
// Float32Array[Float32]; capture may use the native element width.
type Array interface {
	Object
	Len() int
	Element(int) Object
	array()
}

type arrayKind struct{}

func (arrayKind) array() {}

func snapshotValues[T any](values []T) []T {
	if len(values) == 0 {
		// An empty snapshot must not retain the source's backing object.
		return nil
	}
	return slices.Clone(values)
}

func saveArrayHeader(w *Writer, length int, kind Uint) bool {
	Uint(length).save(w)
	if length == 0 {
		return false
	}
	kind.save(w)
	return true
}

// CaptureBoolArray returns a BoolArray holding a copy of values.
func CaptureBoolArray(values []bool) Object {
	return &BoolArray{Contents: snapshotValues(values)}
}

// BoolArray owns homogeneous boolean values.
type BoolArray struct {
	arrayKind
	Contents []bool
}

func (a *BoolArray) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeBool) {
		return
	}
	for _, value := range a.Contents {
		Bool(value).save(w)
	}
}

// CaptureIntArray returns a IntArray holding a copy of values.
func CaptureIntArray[T ~int | ~int8 | ~int16 | ~int32 | ~int64](values []T) Object {
	return &IntArray[T]{Contents: snapshotValues(values)}
}

// IntArray owns homogeneous signed integer values.
type IntArray[T ~int | ~int8 | ~int16 | ~int32 | ~int64] struct {
	arrayKind
	Contents []T
}

func (a *IntArray[T]) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeInt) {
		return
	}
	for _, value := range a.Contents {
		Int(value).save(w)
	}
}

// CaptureUintArray returns a UintArray holding a copy of values.
func CaptureUintArray[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr](values []T) Object {
	return &UintArray[T]{Contents: snapshotValues(values)}
}

// UintArray owns homogeneous unsigned integer values.
type UintArray[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr] struct {
	arrayKind
	Contents []T
}

func (a *UintArray[T]) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeUint) {
		return
	}
	for _, value := range a.Contents {
		Uint(value).save(w)
	}
}

// CaptureFloat32Array returns a Float32Array holding a copy of values.
func CaptureFloat32Array(values []float32) Object {
	// Scalar encoding promotes float32 through reflect.Value.Float before
	// narrowing to wire.Float32. Preserve that conversion at capture time:
	// a signaling NaN can become quiet during the promotion.
	captured := make([]float64, len(values))
	for i, value := range values {
		captured[i] = float64(value)
	}
	return &Float32Array[float64]{Contents: captured}
}

// Float32Array owns homogeneous 32-bit floating point values.
type Float32Array[T ~float32 | ~float64] struct {
	arrayKind
	Contents []T
}

func (a *Float32Array[T]) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeFloat32) {
		return
	}
	for _, value := range a.Contents {
		Float32(value).save(w)
	}
}

// CaptureFloat64Array returns a Float64Array holding a copy of values.
func CaptureFloat64Array(values []float64) Object {
	return &Float64Array{Contents: snapshotValues(values)}
}

// Float64Array owns homogeneous 64-bit floating point values.
type Float64Array struct {
	arrayKind
	Contents []float64
}

func (a *Float64Array) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeFloat64) {
		return
	}
	for _, value := range a.Contents {
		Float64(value).save(w)
	}
}

// CaptureComplex64Array returns a Complex64Array holding a copy of values.
func CaptureComplex64Array(values []complex64) Object {
	captured := make([]Complex64, len(values))
	for i, value := range values {
		captured[i] = Complex64(complex128(value))
	}
	return &Complex64Array{Contents: captured}
}

// Complex64Array owns homogeneous 64-bit complex values.
type Complex64Array struct {
	arrayKind
	Contents []Complex64
}

func (a *Complex64Array) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeComplex64) {
		return
	}
	for _, value := range a.Contents {
		v := Complex64(value)
		v.save(w)
	}
}

// CaptureComplex128Array returns a Complex128Array holding a copy of values.
func CaptureComplex128Array(values []complex128) Object {
	captured := make([]Complex128, len(values))
	for i, value := range values {
		captured[i] = Complex128(value)
	}
	return &Complex128Array{Contents: captured}
}

// Complex128Array owns homogeneous 128-bit complex values.
type Complex128Array struct {
	arrayKind
	Contents []Complex128
}

func (a *Complex128Array) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeComplex128) {
		return
	}
	for _, value := range a.Contents {
		v := Complex128(value)
		v.save(w)
	}
}

// CaptureStringArray returns a StringArray holding a copy of values.
func CaptureStringArray(values []string) Object {
	return &StringArray{Contents: snapshotValues(values)}
}

// StringArray owns homogeneous string values.
type StringArray struct {
	arrayKind
	Contents []string
}

func (a *StringArray) save(w *Writer) {
	if !saveArrayHeader(w, len(a.Contents), typeString) {
		return
	}
	for _, value := range a.Contents {
		v := String(value)
		v.save(w)
	}
}

func (a *BoolArray) Len() int                   { return len(a.Contents) }
func (a *BoolArray) Element(i int) Object       { return Bool(a.Contents[i]) }
func (a *IntArray[T]) Len() int                 { return len(a.Contents) }
func (a *IntArray[T]) Element(i int) Object     { return Int(a.Contents[i]) }
func (a *UintArray[T]) Len() int                { return len(a.Contents) }
func (a *UintArray[T]) Element(i int) Object    { return Uint(a.Contents[i]) }
func (a *Float32Array[T]) Len() int             { return len(a.Contents) }
func (a *Float32Array[T]) Element(i int) Object { return Float32(a.Contents[i]) }
func (a *Float64Array) Len() int                { return len(a.Contents) }
func (a *Float64Array) Element(i int) Object    { return Float64(a.Contents[i]) }
func (a *Complex64Array) Len() int              { return len(a.Contents) }
func (a *Complex64Array) Element(i int) Object {
	value := a.Contents[i]
	return &value
}
func (a *Complex128Array) Len() int { return len(a.Contents) }
func (a *Complex128Array) Element(i int) Object {
	value := a.Contents[i]
	return &value
}
func (a *StringArray) Len() int { return len(a.Contents) }
func (a *StringArray) Element(i int) Object {
	value := String(a.Contents[i])
	return &value
}
