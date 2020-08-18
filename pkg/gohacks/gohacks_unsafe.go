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
