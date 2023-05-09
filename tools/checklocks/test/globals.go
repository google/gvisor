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
	globalMu.Lock()
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

func testGlobalInvalid() {
	globalStruct.guardedField = 1 // +checklocksfail
	otherStruct.guardedField1 = 1 // +checklocksfail
	otherStruct.guardedField2 = 1 // +checklocksfail
	otherStruct.guardedField3 = 1 // +checklocksfail
}

func testCrosspkgGlobalValid() {
	crosspkg.FooMu.Lock()
	crosspkg.Foo = 1
	crosspkg.FooMu.Unlock()
}

func testCrosspkgGlobalInvalid() {
	crosspkg.Foo = 1 // +checklocksfail
}
