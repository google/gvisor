// Copyright 2020 The gVisor Authors.
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

package test

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
)

var (
	globalMu   sync.Mutex
	globalRWMu sync.RWMutex

	// +checkatomic
	atomicGlobal = atomicbitops.FromInt32(1)

	// +checkatomic
	// +checklocks:globalRWMu
	mixedAtomicGlobal atomicbitops.Int32

	unannotatedAtomicGlobal atomicbitops.Int32
	unannotatedRawGlobal    int32

	// +checklocks:globalRWMu
	guardedRawGlobal int32
)

// +checklocks:globalMu
var standaloneGlobal int

// +checkatomic
var standaloneAtomicGlobal int32

var (
	// +checklocks:globalMu
	firstGlobal, _, secondGlobal int
)

// A var block's header does not annotate its entries, even with one spec.
//
// +checklocks:globalMu
var (
	blockHeaderGlobal int
)

var globalStruct struct {
	mu sync.Mutex
	// +checklocks:mu
	guardedField int
}

var otherStruct struct {
	// +checklocks:globalMu
	guardedField1 int
	// +checklocks:globalRWMu
	guardedField2 int
	// +checklocks:globalStruct.mu
	guardedField3 int
}

func testGlobalValid() {
	blockHeaderGlobal = 1

	globalMu.Lock()
	standaloneGlobal = 1
	firstGlobal = 1
	secondGlobal = 1
	otherStruct.guardedField1 = 1
	globalMu.Unlock()

	globalRWMu.Lock()
	otherStruct.guardedField2 = 1
	globalRWMu.Unlock()

	globalRWMu.RLock()
	_ = otherStruct.guardedField2
	globalRWMu.RUnlock()

	globalStruct.mu.Lock()
	globalStruct.guardedField = 1
	otherStruct.guardedField3 = 1
	globalStruct.mu.Unlock()
}

// +checklocks:globalStruct.mu
func testGlobalValidPreconditions0() {
	globalStruct.guardedField = 1
}

// +checklocks:globalMu
func testGlobalValidPreconditions1() {
	otherStruct.guardedField1 = 1
}

// +checklocks:globalRWMu
func testGlobalValidPreconditions2() {
	otherStruct.guardedField2 = 1
}

// +checklocks:globalStruct.mu
func testGlobalValidPreconditions3() {
	otherStruct.guardedField3 = 1
}

// +checklocksexclude:globalMu
func testGlobalExcludePreconditions() {
}

func testGlobalExcludeValid() {
	testGlobalExcludePreconditions()
}

func testGlobalExcludeInvalid() {
	globalMu.Lock()
	testGlobalExcludePreconditions() // +checklocksfail
	globalMu.Unlock()
}

func testGlobalInvalid() {
	standaloneGlobal = 1          // +checklocksfail
	firstGlobal = 1               // +checklocksfail
	secondGlobal = 1              // +checklocksfail
	standaloneAtomicGlobal = 1    // +checklocksfail=non-atomic write
	globalStruct.guardedField = 1 // +checklocksfail
	otherStruct.guardedField1 = 1 // +checklocksfail
	otherStruct.guardedField2 = 1 // +checklocksfail
	otherStruct.guardedField3 = 1 // +checklocksfail
	var sink atomic.Pointer[int32]
	sink.Store(&standaloneAtomicGlobal) // +checklocksfail=illegal use
}

func testCrosspkgGlobalValid() {
	crosspkg.FooMu.Lock()
	crosspkg.Foo = 1
	crosspkg.StandaloneFoo = 1
	crosspkg.FooMu.Unlock()
}

func testCrosspkgGlobalInvalid() {
	crosspkg.Foo = 1           // +checklocksfail
	crosspkg.StandaloneFoo = 1 // +checklocksfail
}

func testAtomicGlobal() {
	defer atomicGlobal.Store(1)
	_ = atomicGlobal.Load()
	atomicGlobal.Store(1)
	_ = atomicGlobal.RacyLoad() // +checklocksfail=non-atomic operation
	atomicGlobal.RacyStore(1)   // +checklocksfail=non-atomic operation

	atomicGlobal = atomicbitops.FromInt32(0) // +checklocksfail=non-atomic write
}

func testMixedAtomicGlobal() {
	_ = mixedAtomicGlobal.Load()
	mixedAtomicGlobal.Store(1)       // +checklocksfail=atomic write function
	_ = mixedAtomicGlobal.RacyLoad() // +checklocksfail=non-atomic operation

	globalRWMu.Lock()
	mixedAtomicGlobal.Store(1)
	_ = mixedAtomicGlobal.RacyLoad()
	mixedAtomicGlobal.RacyStore(1) // +checklocksfail=non-atomic operation
	globalRWMu.Unlock()

	globalRWMu.RLock()
	_ = mixedAtomicGlobal.RacyLoad()
	mixedAtomicGlobal.Store(1) // +checklocksfail=atomic write function
	globalRWMu.RUnlock()
}

func testUnannotatedGlobalAtomics(out **int32) {
	_ = unannotatedAtomicGlobal.RacyLoad()
	unannotatedAtomicGlobal.RacyStore(1)
	_ = atomic.LoadInt32(&unannotatedRawGlobal)

	globalRWMu.RLock()
	_ = atomic.LoadInt32(&guardedRawGlobal)
	*out = &guardedRawGlobal
	globalRWMu.RUnlock()
}

// +checklocksignore
func testAtomicGlobalIgnore() {
	atomicGlobal.RacyStore(1)
	atomicGlobal = atomicbitops.FromInt32(0)
}

func testCrosspkgPrivateGuards() {
	crosspkg.RequirePrivate() // +checklocksfail=must hold globalMu|must hold globalStruct.mu
	crosspkg.ExcludePrivate()
	crosspkg.LockPrivate()
	crosspkg.RequirePrivate()
	crosspkg.ExcludePrivate() // +checklocksfail=must not hold globalMu|must not hold globalStruct.mu
	crosspkg.UnlockPrivate()
	crosspkg.RequirePrivate() // +checklocksfail=must hold globalMu|must hold globalStruct.mu
	crosspkg.ExcludePrivate()

	// Same-named globals in this package are different locks.
	globalMu.Lock()
	globalStruct.mu.Lock()
	crosspkg.RequirePrivate() // +checklocksfail=must hold globalMu|must hold globalStruct.mu
	crosspkg.ExcludePrivate()
	globalStruct.mu.Unlock()
	globalMu.Unlock()
}

var FooMu sync.Mutex

func testCrosspkgGlobalNameCollision() {
	FooMu.Lock()
	crosspkg.Foo = 1 // +checklocksfail=invalid field access, FooMu
	FooMu.Unlock()
}

type invalidGlobalMutex = sync.Mutex

// +checklocks:invalidGlobalMutex
func testGlobalTypeGuard() {} // +checklocksfail=does not have a match
