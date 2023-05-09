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

// TODO(go.dev/issue/8422): Remove this once Go 1.19 is no longer supported,
// and update callers to use unsafe.Slice directly.

package gohacks

import (
	"unsafe"
)

// sliceHeader is equivalent to reflect.SliceHeader, but represents the pointer
// to the underlying array as unsafe.Pointer rather than uintptr, allowing
// sliceHeaders to be directly converted to slice objects.
type sliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// Slice returns a slice whose underlying array starts at ptr an which length
// and capacity are len.
func Slice[T any](ptr *T, length int) []T {
	var s []T
	hdr := (*sliceHeader)(unsafe.Pointer(&s))
	hdr.Data = unsafe.Pointer(ptr)
	hdr.Len = length
	hdr.Cap = length
	return s
}
