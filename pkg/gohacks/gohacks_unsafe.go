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

// Package gohacks contains utilities for subverting the Go compiler.
package gohacks

import (
	"fmt"
	"reflect"
	"unsafe"
)

// Noescape hides a pointer from escape analysis. Noescape is the identity
// function but escape analysis doesn't think the output depends on the input.
// Noescape is inlined and currently compiles down to zero instructions.
// USE CAREFULLY!
//
// (Noescape is copy/pasted from Go's runtime/stubs.go:noescape().)
//
//go:nosplit
func Noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

// ImmutableBytesFromString is equivalent to []byte(s), except that it uses the
// same memory backing s instead of making a heap-allocated copy. This is only
// valid if the returned slice is never mutated.
func ImmutableBytesFromString(s string) []byte {
	shdr := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var bs []byte
	bshdr := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	bshdr.Data = shdr.Data
	bshdr.Len = shdr.Len
	bshdr.Cap = shdr.Len
	return bs
}

// StringFromImmutableBytes is equivalent to string(bs), except that it uses
// the same memory backing bs instead of making a heap-allocated copy. This is
// only valid if bs is never mutated after StringFromImmutableBytes returns.
func StringFromImmutableBytes(bs []byte) string {
	// This is cheaper than messing with reflect.StringHeader and
	// reflect.SliceHeader, which as of this writing produces many dead stores
	// of zeroes. Compare strings.Builder.String().
	return *(*string)(unsafe.Pointer(&bs))
}

func primitiveKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool, reflect.Int, reflect.Uint, reflect.Int8, reflect.Uint8, reflect.Int16, reflect.Uint16, reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64:
		return true
	default:
		return false
	}
}

// TransmutePrimitiveSlice unsafely moves the contents of a src slice to a dst
// slice of a different type without copying memory.
//
// Caller should pass in a reflect.Value of a pointer to a slice for both src
// and dst. Both slices should have primitive types as elements. The dst slice
// should be empty.
//
// Example:
//
// type Int32 int32
// xs := []int32{1, 2, 3}
// var ys []Int32
//
// TransmutePrimitiveSlice(reflect.ValueOf(&xs), reflect.ValueOf(&ys))
// // ys now contains the data from xs, xs is now uninitialized.
//
// Postcondition: src is uninitialized.
func TransmutePrimitiveSlice(src reflect.Value, dst reflect.Value) {
	if k := src.Kind(); k != reflect.Ptr {
		panic(fmt.Sprintf("src (type = %v) not a pointer", k))
	}
	if k := dst.Kind(); k != reflect.Ptr {
		panic(fmt.Sprintf("dst (type = %v) not a pointer", k))
	}

	srcT := src.Elem().Type()
	dstT := dst.Elem().Type()

	if srcT.Kind() != reflect.Slice {
		panic(fmt.Sprintf("*src (type = %v) not a slice", srcT))
	}

	if dstT.Kind() != reflect.Slice {
		panic(fmt.Sprintf("*dst (type = %v) not a slice", dstT))
	}

	srcElemT := srcT.Elem()
	dstElemT := dstT.Elem()
	srcElemSize := int(srcElemT.Size())
	dstElemSize := int(dstElemT.Size())

	if k := srcElemT.Kind(); !primitiveKind(k) {
		panic(fmt.Sprintf("src elem type = %v is not a primitive", k))
	}
	if k := dstElemT.Kind(); !primitiveKind(k) {
		panic(fmt.Sprintf("src elem type = %v is not a primitive", k))
	}

	srcHdr := (*reflect.SliceHeader)(unsafe.Pointer(src.Pointer()))
	dstHdr := (*reflect.SliceHeader)(unsafe.Pointer(dst.Pointer()))

	srcLenBytes := srcHdr.Len * srcElemSize
	srcCapBytes := srcHdr.Cap * srcElemSize

	// Make sure src fits in full multiples of dst's elem size.
	if srcLenBytes%dstElemSize != 0 {
		panic(fmt.Sprintf("src len (in bytes) %d doesn't fit in whole multiples of dst elem type %v with size %d", srcLenBytes, dstElemT, dstElemSize))
	}
	if srcCapBytes%dstElemSize != 0 {
		panic(fmt.Sprintf("src capacity (in bytes) %d doesn't fit in whole multiples of dst elem type %v with size %d", srcCapBytes, dstElemT, dstElemSize))
	}

	dstHdr.Len = srcLenBytes / dstElemSize
	dstHdr.Cap = srcCapBytes / dstElemSize
	dstHdr.Data = srcHdr.Data

	// Release src's ownership of its underlying data, so dst's lifetime becomes decoupled from src.
	srcHdr.Len = 0
	srcHdr.Cap = 0
	srcHdr.Data = uintptr(0)
}
