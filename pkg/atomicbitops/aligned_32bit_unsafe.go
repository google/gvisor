// Copyright 2021 The gVisor Authors.
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

// +build arm 386

package atomicbitops

import (
	"sync/atomic"
	"unsafe"
)

// AlignedAtomicInt64 is an atomic int64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems.
//
// Per https://golang.org/pkg/sync/atomic/#pkg-note-BUG:
//
// "On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange
// for 64-bit alignment of 64-bit words accessed atomically. The first word in
// a variable or in an allocated struct, array, or slice can be relied upon to
// be 64-bit aligned."
type AlignedAtomicInt64 struct {
	value [15]byte
}

func (aa *AlignedAtomicInt64) ptr() *int64 {
	return (*int64)(unsafe.Pointer((uintptr(unsafe.Pointer(&aa.value)) + 7) &^ 7))
}

// Load is analagous to atomic.LoadInt64.
func (aa *AlignedAtomicInt64) Load() int64 {
	return atomic.LoadInt64(aa.ptr())
}

// Store is analagous to atomic.StoreInt64.
func (aa *AlignedAtomicInt64) Store(v int64) {
	atomic.StoreInt64(aa.ptr(), v)
}

// Add is analagous to atomic.AddInt64.
func (aa *AlignedAtomicInt64) Add(v int64) int64 {
	return atomic.AddInt64(aa.ptr(), v)
}

// AlignedAtomicUint64 is an atomic uint64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems.
//
// Per https://golang.org/pkg/sync/atomic/#pkg-note-BUG:
//
// "On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange
// for 64-bit alignment of 64-bit words accessed atomically. The first word in
// a variable or in an allocated struct, array, or slice can be relied upon to
// be 64-bit aligned."
type AlignedAtomicUint64 struct {
	value [15]byte
}

func (aa *AlignedAtomicUint64) ptr() *uint64 {
	return (*uint64)(unsafe.Pointer((uintptr(unsafe.Pointer(&aa.value)) + 7) &^ 7))
}

// Load is analagous to atomic.LoadUint64.
func (aa *AlignedAtomicUint64) Load() uint64 {
	return atomic.LoadUint64(aa.ptr())
}

// Store is analagous to atomic.StoreUint64.
func (aa *AlignedAtomicUint64) Store(v uint64) {
	atomic.StoreUint64(aa.ptr(), v)
}

// Add is analagous to atomic.AddUint64.
func (aa *AlignedAtomicUint64) Add(v uint64) uint64 {
	return atomic.AddUint64(aa.ptr(), v)
}
