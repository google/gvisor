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

package atomicbitops

import "unsafe"

// float64Bits is math.Float64bits with a nosplit guarantee even when not inlined.
// Pointer checks are unnecessary for reinterpreting scalars of the same size and
// alignment, and their runtime calls could split the stack.
//
// +checkescape:all
//
//go:nosplit
//go:nocheckptr
func float64Bits(f float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&f))
}

// float64FromBits is the inverse of float64Bits, with the same stack and pointer
// checking requirements.
//
// +checkescape:all
//
//go:nosplit
//go:nocheckptr
func float64FromBits(b uint64) float64 {
	return *(*float64)(unsafe.Pointer(&b))
}
