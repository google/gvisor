// Copyright 2022 The gVisor Authors.
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

// Bool is an atomic Boolean.
//
// It is implemented by a Uint32, with value 0 indicating false, and 1
// indicating true.
//
// +stateify savable
type Bool struct {
	Uint32
}

// b32 returns a uint32 0 or 1 representing b.
func b32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// FromBool returns a Bool initialized to value val.
//
//go:nosplit
func FromBool(val bool) Bool {
	return Bool{
		Uint32: FromUint32(b32(val)),
	}
}

// Load is analogous to atomic.LoadBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Load() bool {
	return b.Uint32.Load() != 0
}

// RacyLoad is analogous to reading an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (b *Bool) RacyLoad() bool {
	return b.Uint32.RacyLoad() != 0
}

// Store is analogous to atomic.StoreBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Store(val bool) {
	b.Uint32.Store(b32(val))
}

// RacyStore is analogous to setting an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (b *Bool) RacyStore(val bool) {
	b.Uint32.RacyStore(b32(val))
}

// Swap is analogous to atomic.SwapBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Swap(val bool) bool {
	return b.Uint32.Swap(b32(val)) != 0
}

// CompareAndSwap is analogous to atomic.CompareAndSwapBool, if such a thing
// existed.
//
//go:nosplit
func (b *Bool) CompareAndSwap(oldVal, newVal bool) bool {
	return b.Uint32.CompareAndSwap(b32(oldVal), b32(newVal))
}
