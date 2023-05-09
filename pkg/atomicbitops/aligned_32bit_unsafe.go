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

//go:build arm || mips || mipsle || 386
// +build arm mips mipsle 386

package atomicbitops

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sync"
)

// Int64 is an atomic int64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems.
//
// Don't add fields to this struct. It is important that it remain the same
// size as its builtin analogue.
//
// Per https://golang.org/pkg/sync/atomic/#pkg-note-BUG:
//
// "On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange
// for 64-bit alignment of 64-bit words accessed atomically. The first word in
// a variable or in an allocated struct, array, or slice can be relied upon to
// be 64-bit aligned."
//
// +stateify savable
type Int64 struct {
	_       sync.NoCopy
	value   int64
	value32 int32
}

//go:nosplit
func (i *Int64) ptr() *int64 {
	// On 32-bit systems, i.value is guaranteed to be 32-bit aligned. It means
	// that in the 12-byte i.value, there are guaranteed to be 8 contiguous bytes
	// with 64-bit alignment.
	return (*int64)(unsafe.Pointer((uintptr(unsafe.Pointer(&i.value)) + 4) &^ 7))
}

// FromInt64 returns an Int64 initialized to value v.
//
//go:nosplit
func FromInt64(v int64) Int64 {
	var i Int64
	*i.ptr() = v
	return i
}

// Load is analogous to atomic.LoadInt64.
//
//go:nosplit
func (i *Int64) Load() int64 {
	return atomic.LoadInt64(i.ptr())
}

// RacyLoad is analogous to reading an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (i *Int64) RacyLoad() int64 {
	return *i.ptr()
}

// Store is analogous to atomic.StoreInt64.
//
//go:nosplit
func (i *Int64) Store(v int64) {
	atomic.StoreInt64(i.ptr(), v)
}

// RacyStore is analogous to setting an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (i *Int64) RacyStore(v int64) {
	*i.ptr() = v
}

// Add is analogous to atomic.AddInt64.
//
//go:nosplit
func (i *Int64) Add(v int64) int64 {
	return atomic.AddInt64(i.ptr(), v)
}

// RacyAdd is analogous to adding to an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (i *Int64) RacyAdd(v int64) int64 {
	*i.ptr() += v
	return *i.ptr()
}

// Swap is analogous to atomic.SwapInt64.
//
//go:nosplit
func (i *Int64) Swap(v int64) int64 {
	return atomic.SwapInt64(i.ptr(), v)
}

// CompareAndSwap is analogous to atomic.CompareAndSwapInt64.
//
//go:nosplit
func (i *Int64) CompareAndSwap(oldVal, newVal int64) bool {
	return atomic.CompareAndSwapInt64(&i.value, oldVal, newVal)
}

// Uint64 is an atomic uint64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems.
//
// Don't add fields to this struct. It is important that it remain the same
// size as its builtin analogue.
//
// Per https://golang.org/pkg/sync/atomic/#pkg-note-BUG:
//
// "On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange
// for 64-bit alignment of 64-bit words accessed atomically. The first word in
// a variable or in an allocated struct, array, or slice can be relied upon to
// be 64-bit aligned."
//
// +stateify savable
type Uint64 struct {
	_       sync.NoCopy
	value   uint64
	value32 uint32
}

//go:nosplit
func (u *Uint64) ptr() *uint64 {
	// On 32-bit systems, i.value is guaranteed to be 32-bit aligned. It means
	// that in the 12-byte i.value, there are guaranteed to be 8 contiguous bytes
	// with 64-bit alignment.
	return (*uint64)(unsafe.Pointer((uintptr(unsafe.Pointer(&u.value)) + 4) &^ 7))
}

// FromUint64 returns an Uint64 initialized to value v.
//
//go:nosplit
func FromUint64(v uint64) Uint64 {
	var u Uint64
	*u.ptr() = v
	return u
}

// Load is analogous to atomic.LoadUint64.
//
//go:nosplit
func (u *Uint64) Load() uint64 {
	return atomic.LoadUint64(u.ptr())
}

// RacyLoad is analogous to reading an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (u *Uint64) RacyLoad() uint64 {
	return *u.ptr()
}

// Store is analogous to atomic.StoreUint64.
//
//go:nosplit
func (u *Uint64) Store(v uint64) {
	atomic.StoreUint64(u.ptr(), v)
}

// RacyStore is analogous to setting an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (u *Uint64) RacyStore(v uint64) {
	*u.ptr() = v
}

// Add is analogous to atomic.AddUint64.
//
//go:nosplit
func (u *Uint64) Add(v uint64) uint64 {
	return atomic.AddUint64(u.ptr(), v)
}

// RacyAdd is analogous to adding to an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (u *Uint64) RacyAdd(v uint64) uint64 {
	*u.ptr() += v
	return *u.ptr()
}

// Swap is analogous to atomic.SwapUint64.
//
//go:nosplit
func (u *Uint64) Swap(v uint64) uint64 {
	return atomic.SwapUint64(u.ptr(), v)
}

// CompareAndSwap is analogous to atomic.CompareAndSwapUint64.
//
//go:nosplit
func (u *Uint64) CompareAndSwap(oldVal, newVal uint64) bool {
	return atomic.CompareAndSwapUint64(u.ptr(), oldVal, newVal)
}
