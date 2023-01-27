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

package gohacks

import (
	"unsafe"
)

// Noescape hides a pointer from escape analysis. Noescape is the identity
// function but escape analysis doesn't think the output depends on the input.
// Noescape is inlined and currently compiles down to zero instructions.
// USE CAREFULLY!
//
// Noescape is copy/pasted from Go's runtime/stubs.go:noescape(), and is valid
// as of Go 1.20. It is possible that this approach stops working in future
// versions of the toolchain, at which point `p` may still escape.
//
//go:nosplit
func Noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}
