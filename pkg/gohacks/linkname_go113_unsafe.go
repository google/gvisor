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

//go:build go1.13

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

// Package gohacks contains utilities for subverting the Go compiler.
package gohacks

import (
	"unsafe"
)

// Note that go:linkname silently doesn't work if the local name is exported,
// necessitating an indirection for exported functions.

// Memmove is runtime.memmove, exported for SeqAtomicLoad/SeqAtomicTryLoad<T>.
//
//go:nosplit
func Memmove(to, from unsafe.Pointer, n uintptr) {
	memmove(to, from, n)
}

//go:linkname memmove runtime.memmove
//go:noescape
func memmove(to, from unsafe.Pointer, n uintptr)

// Nanotime is runtime.nanotime.
//
//go:nosplit
func Nanotime() int64 {
	return nanotime()
}

//go:linkname nanotime runtime.nanotime
//go:noescape
func nanotime() int64
