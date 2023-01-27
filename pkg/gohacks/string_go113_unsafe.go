// Copyright 2023 The gVisor Authors.
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

//go:build go1.13 && !go1.20
// +build go1.13,!go1.20

// TODO(go.dev/issue/8422): Remove this file once Go 1.19 is no longer
// supported.

package gohacks

import (
	"unsafe"
)

// stringHeader is equivalent to reflect.StringHeader, but represents the
// pointer to the underlying array as unsafe.Pointer rather than uintptr,
// allowing StringHeaders to be directly converted to strings.
type stringHeader struct {
	Data unsafe.Pointer
	Len  int
}

// ImmutableBytesFromString is equivalent to []byte(s), except that it uses the
// same memory backing s instead of making a heap-allocated copy. This is only
// valid if the returned slice is never mutated.
func ImmutableBytesFromString(s string) []byte {
	shdr := (*stringHeader)(unsafe.Pointer(&s))
	return Slice((*byte)(shdr.Data), shdr.Len)
}

// StringFromImmutableBytes is equivalent to string(bs), except that it uses
// the same memory backing bs instead of making a heap-allocated copy. This is
// only valid if bs is never mutated after StringFromImmutableBytes returns.
func StringFromImmutableBytes(bs []byte) string {
	// This is cheaper than messing with StringHeader and SliceHeader, which as
	// of this writing produces many dead stores of zeroes. Compare
	// strings.Builder.String().
	return *(*string)(unsafe.Pointer(&bs))
}
