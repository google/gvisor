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

type inferredStruct struct {
	mu             sync.Mutex
	guardedField   int // +checklocksfail
	unguardedField int

	// +checklocks:mu
	declaredField int
}

func testInferredPositive(tc *inferredStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testInferredNegative(tc *inferredStruct) {
	tc.unguardedField = 1
}

// +checklocks:tc.mu
// +checklocks:other.mu
func testInferredDeclaredName(tc, other *inferredStruct) {
	tc.declaredField = 1
}

// inferredNestedGuardStruct uses the same mu declaration for distinct owners.
type inferredNestedGuardStruct struct {
	mu    sync.RWMutex
	inner *inferredNestedGuardStruct

	// +checklocks:inner.mu
	guardedField int

	// +checklocks:inner.mu
	additionallyGuardedField int // +checklocksfail=may require checklocks annotation for mu, used with lock held 100% of the time

	// +checklocks:inner.mu
	writeField int
}

// +checklocks:tc.inner.mu
func testInferredNestedDeclaredGuard(tc *inferredNestedGuardStruct) {
	tc.guardedField = 1
}

// +checklocks:tc.inner.mu
// +checklocks:tc.mu
func testInferredDistinctOwner(tc *inferredNestedGuardStruct) {
	tc.additionallyGuardedField = 1
}

// +checklocks:tc.mu
func testInferredWrongOwner(tc *inferredNestedGuardStruct) {
	tc.additionallyGuardedField = 1 // +checklocksfail=invalid field access
}

// +checklocksread:tc.inner.mu
func testInferredWrongMode(tc *inferredNestedGuardStruct) {
	tc.writeField = 1 // +checklocksfail=invalid field access
}
