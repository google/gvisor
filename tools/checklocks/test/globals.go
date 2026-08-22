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

	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
)

var (
	globalMu   sync.Mutex
	globalRWMu sync.RWMutex
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
