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

// Package crosspkg is a second package for testing.
package crosspkg

import (
	"sync"

	atomicfields "gvisor.dev/gvisor/tools/checklocks/test/atomic"
)

var (
	// +checklocks:FooMu
	Foo   int
	FooMu sync.Mutex
)

// StandaloneFoo is a guarded global declared outside a var block.
//
// +checklocks:FooMu
var StandaloneFoo int

// GenericGuard is a generic type with a guarded field. This is used to verify
// that facts exported by this package are correctly imported when another
// package instantiates GenericGuard[T].
type GenericGuard[T any] struct {
	Mu sync.Mutex
	// +checklocks:Mu
	Value T
}

// ReadAnyGuard allows readers to hold either mutex; writers need both.
type ReadAnyGuard[T any] struct {
	Mu      sync.Mutex
	OtherMu sync.RWMutex

	// +checklocks:Mu
	// +checklocks:OtherMu
	Value T // +checklocksreadany
}

// Do not import sync/atomic or gvisor.dev/gvisor/pkg/atomicbitops here: their
// methods must be resolved from type information for a transitive dependency,
// not a direct SSA import.
func readIndirectAtomics(v *atomicfields.Values) {
	_ = atomicfields.Load(&v.Raw) // +checklocksfail=non-atomic function
	_ = v.Standard.Load()
	_ = v.Bitops.Load()
	v.Standard.Store(nil)
	v.Bitops.Store(1)
	_ = v.Bitops.RacyLoad() // +checklocksfail=non-atomic operation
	// A method expression forces an SSA wrapper instead of selecting the
	// embedded field directly, as an ordinary promoted call would.
	_ = (*atomicfields.WrappedAtomic).Load(&v.Promoted) // +checklocksfail=shared function or wrapper

	v.Mu.Lock()
	_ = v.Mixed.RacyLoad()
	v.Mu.Unlock()
}

// Keep the lock/unlock functions out of line so importers do not need these
// private globals for inlined calls. Their guards still cross the package
// boundary.
var globalMu sync.Mutex

// The fixture always acquires globalMu before globalStruct.mu, so inference
// also reports the nested lock as guarded.
var globalStruct struct { // +checklocksfail=may require checklocks annotation for globalMu
	mu sync.Mutex // +checklocksfail=may require checklocks annotation for globalMu
}

// LockPrivate acquires both private locks.
//
// +checklocksacquire:globalMu
// +checklocksacquire:globalStruct.mu
//
//go:noinline
func LockPrivate() {
	globalMu.Lock()
	globalStruct.mu.Lock()
}

// UnlockPrivate releases both private locks.
//
// +checklocksrelease:globalMu
// +checklocksrelease:globalStruct.mu
//
//go:noinline
func UnlockPrivate() {
	globalStruct.mu.Unlock()
	globalMu.Unlock()
}

// RequirePrivate requires both private locks.
//
// +checklocks:globalMu
// +checklocks:globalStruct.mu
func RequirePrivate() {}

// ExcludePrivate excludes both private locks.
//
// +checklocksexclude:globalMu
// +checklocksexclude:globalStruct.mu
func ExcludePrivate() {}

// IndirectValues exposes methods without importing their defining package.
type IndirectValues = atomicfields.Values

var privateFieldMu sync.Mutex

var privateFieldStruct struct {
	mu sync.Mutex
}

var (
	// +checklocks:privateFieldMu
	PrivateValue int
)

// PrivateState exposes a field protected by a private global's mutex field.
type PrivateState struct {
	// +checklocks:privateFieldStruct.mu
	Value int
}

// LockPrivateField acquires the private global mutex.
// Keep acquisition and release out of line so export data does not include
// the private globals merely because an importer might inline these bodies.
//
// +checklocksacquire:privateFieldMu
//
//go:noinline
func LockPrivateField() { privateFieldMu.Lock() }

// UnlockPrivateField releases the private global mutex.
// +checklocksrelease:privateFieldMu
//
//go:noinline
func UnlockPrivateField() { privateFieldMu.Unlock() }

// RequirePrivateField requires the private global mutex to be held.
// +checklocks:privateFieldMu
func RequirePrivateField() {}

// ExcludePrivateField requires the private global mutex not to be held.
// +checklocksexclude:privateFieldMu
func ExcludePrivateField() {}

// LockPrivateStruct acquires the mutex in the private global struct.
// +checklocksacquire:privateFieldStruct.mu
//
//go:noinline
func LockPrivateStruct() { privateFieldStruct.mu.Lock() }

// UnlockPrivateStruct releases the mutex in the private global struct.
// +checklocksrelease:privateFieldStruct.mu
//
//go:noinline
func UnlockPrivateStruct() { privateFieldStruct.mu.Unlock() }

// RequirePrivateStruct requires the private struct's mutex to be held.
// +checklocks:privateFieldStruct.mu
func RequirePrivateStruct() {}

// ExcludePrivateStruct requires the private struct's mutex not to be held.
// +checklocksexclude:privateFieldStruct.mu
func ExcludePrivateStruct() {}
