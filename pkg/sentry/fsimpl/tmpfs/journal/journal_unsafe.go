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

package journal

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// atomicLoad64 atomically loads the little-endian uint64 in b.
//
// Preconditions: b is 8 bytes long and 8-byte aligned.
func atomicLoad64(b []byte) uint64 {
	return (*atomicbitops.Uint64)(unsafe.Pointer(&b[0])).Load()
}

// atomicStore64 atomically stores v to b.
//
// Preconditions: b is 8 bytes long and 8-byte aligned.
func atomicStore64(b []byte, v uint64) {
	(*atomicbitops.Uint64)(unsafe.Pointer(&b[0])).Store(v)
}

// atomicStore32 atomically stores v to b.
//
// Preconditions: b is 4 bytes long and 4-byte aligned.
func atomicStore32(b []byte, v uint32) {
	(*atomicbitops.Uint32)(unsafe.Pointer(&b[0])).Store(v)
}
