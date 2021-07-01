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

func testLockedAccessValid(tc *oneGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testLockedAccessIgnore(tc *oneGuardStruct) {
	tc.mu.Lock()
	tc.unguardedField = 1
	tc.mu.Unlock()
}

func testUnlockedAccessInvalidWrite(tc *oneGuardStruct) {
	tc.guardedField = 2 // +checklocksfail
}

func testUnlockedAccessInvalidRead(tc *oneGuardStruct) {
	x := tc.guardedField // +checklocksfail
	_ = x
}

func testUnlockedAccessValid(tc *oneGuardStruct) {
	tc.unguardedField = 2
}

func testCallValidAccess(tc *oneGuardStruct) {
	callValidAccess(tc)
}

func callValidAccess(tc *oneGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testCallValueMixup(tc *oneGuardStruct) {
	callValueMixup(tc, tc)
}

func callValueMixup(tc1, tc2 *oneGuardStruct) {
	tc1.mu.Lock()
	tc2.guardedField = 2 // +checklocksfail
	tc1.mu.Unlock()
}

func testCallPreconditionsInvalid(tc *oneGuardStruct) {
	callPreconditions(tc) // +checklocksfail
}

func testCallPreconditionsValid(tc *oneGuardStruct) {
	tc.mu.Lock()
	callPreconditions(tc)
	tc.mu.Unlock()
}

// +checklocks:tc.mu
func callPreconditions(tc *oneGuardStruct) {
	tc.guardedField = 1
}

type nestedFieldsStruct struct {
	mu sync.Mutex

	// +checklocks:mu
	nestedStruct struct {
		nested1 int
		nested2 int
	}
}

func testNestedGuardValid(tc *nestedFieldsStruct) {
	tc.mu.Lock()
	tc.nestedStruct.nested1 = 1
	tc.nestedStruct.nested2 = 2
	tc.mu.Unlock()
}

func testNestedGuardInvalid(tc *nestedFieldsStruct) {
	tc.nestedStruct.nested1 = 1 // +checklocksfail
}

type rwGuardStruct struct {
	rwMu sync.RWMutex

	// +checklocks:rwMu
	guardedField int
}

func testRWValidRead(tc *rwGuardStruct) {
	tc.rwMu.Lock()
	tc.guardedField = 1
	tc.rwMu.Unlock()
}

func testRWValidWrite(tc *rwGuardStruct) {
	tc.rwMu.RLock()
	tc.guardedField = 2
	tc.rwMu.RUnlock()
}

func testRWInvalidWrite(tc *rwGuardStruct) {
	tc.guardedField = 3 // +checklocksfail
}

func testRWInvalidRead(tc *rwGuardStruct) {
	x := tc.guardedField + 3 // +checklocksfail
	_ = x
}

func testTwoLocksDoubleGuardStructValid(tc *twoLocksDoubleGuardStruct) {
	tc.mu.Lock()
	tc.secondMu.Lock()
	tc.doubleGuardedField = 1
	tc.secondMu.Unlock()
}

func testTwoLocksDoubleGuardStructOnlyOne(tc *twoLocksDoubleGuardStruct) {
	tc.mu.Lock()
	tc.doubleGuardedField = 2 // +checklocksfail
	tc.mu.Unlock()
}

func testTwoLocksDoubleGuardStructInvalid(tc *twoLocksDoubleGuardStruct) {
	tc.doubleGuardedField = 3 // +checklocksfail:2
}
