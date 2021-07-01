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
)

type testMethods struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int
}

func (t *testMethods) methodValid() {
	t.mu.Lock()
	t.guardedField = 1
	t.mu.Unlock()
}

func (t *testMethods) methodInvalid() {
	t.guardedField = 2 // +checklocksfail
}

// +checklocks:t.mu
func (t *testMethods) MethodLocked(a, b, c int) {
	t.guardedField = 3
}

// +checklocksignore
func (t *testMethods) methodIgnore() {
	t.guardedField = 2
}

func testMethodCallsValid(tc *testMethods) {
	tc.methodValid()
}

func testMethodCallsValidPreconditions(tc *testMethods) {
	tc.mu.Lock()
	tc.MethodLocked(1, 2, 3)
	tc.mu.Unlock()
}

func testMethodCallsInvalid(tc *testMethods) {
	tc.MethodLocked(4, 5, 6) // +checklocksfail
}

func testMultipleParameters(tc1, tc2, tc3 *testMethods) {
	tc1.mu.Lock()
	tc1.guardedField = 1
	tc2.guardedField = 2 // +checklocksfail
	tc3.guardedField = 3 // +checklocksfail
	tc1.mu.Unlock()
}

type testMethodsWithParameters struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int
}

type ptrToTestMethodsWithParameters *testMethodsWithParameters

// +checklocks:t.mu
// +checklocks:a.mu
func (t *testMethodsWithParameters) methodLockedWithParameters(a *testMethodsWithParameters, b *testMethodsWithParameters) {
	t.guardedField = a.guardedField
	b.guardedField = a.guardedField // +checklocksfail
}

// +checklocks:t.mu
// +checklocks:a.mu
// +checklocks:b.mu
func (t *testMethodsWithParameters) methodLockedWithPtrType(a *testMethodsWithParameters, b ptrToTestMethodsWithParameters) {
	t.guardedField = a.guardedField
	b.guardedField = a.guardedField
}

// +checklocks:a.mu
func standaloneFunctionWithGuard(a *testMethodsWithParameters) {
	a.guardedField = 1
	a.mu.Unlock()
	a.guardedField = 1 // +checklocksfail
}

type testMethodsWithEmbedded struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int
	p            *testMethodsWithParameters
}

// +checklocks:t.mu
func (t *testMethodsWithEmbedded) DoLocked(a, b *testMethodsWithParameters) {
	t.guardedField = 1
	a.mu.Lock()
	b.mu.Lock()
	t.p.methodLockedWithParameters(a, b) // +checklocksfail
	a.mu.Unlock()
	b.mu.Unlock()
}
