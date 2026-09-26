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

import "sync"

var (
	// +checklocks:FooMu
	Foo   int
	FooMu sync.Mutex
)

// GenericGuard is a generic type with a guarded field. This is used to verify
// that facts exported by this package are correctly imported when another
// package instantiates GenericGuard[T].
type GenericGuard[T any] struct {
	Mu sync.Mutex
	// +checklocks:Mu
	Value T
}

var globalMu sync.Mutex

var globalStruct struct {
	mu sync.Mutex
}

var (
	// +checklocks:globalMu
	PrivateValue int
)

// PrivateState exposes a field protected by a private global's mutex field.
type PrivateState struct {
	// +checklocks:globalStruct.mu
	Value int
}

// LockPrivate acquires the private global mutex.
// Keep acquisition and release out of line so export data does not include
// the private globals merely because an importer might inline these bodies.
//
// +checklocksacquire:globalMu
//
//go:noinline
func LockPrivate() { globalMu.Lock() }

// UnlockPrivate releases the private global mutex.
// +checklocksrelease:globalMu
//
//go:noinline
func UnlockPrivate() { globalMu.Unlock() }

// RequirePrivate requires the private global mutex to be held.
// +checklocks:globalMu
func RequirePrivate() {}

// ExcludePrivate requires the private global mutex not to be held.
// +checklocksexclude:globalMu
func ExcludePrivate() {}

// LockPrivateStruct acquires the mutex in the private global struct.
// +checklocksacquire:globalStruct.mu
//
//go:noinline
func LockPrivateStruct() { globalStruct.mu.Lock() }

// UnlockPrivateStruct releases the mutex in the private global struct.
// +checklocksrelease:globalStruct.mu
//
//go:noinline
func UnlockPrivateStruct() { globalStruct.mu.Unlock() }

// RequirePrivateStruct requires the private struct's mutex to be held.
// +checklocks:globalStruct.mu
func RequirePrivateStruct() {}

// ExcludePrivateStruct requires the private struct's mutex not to be held.
// +checklocksexclude:globalStruct.mu
func ExcludePrivateStruct() {}
