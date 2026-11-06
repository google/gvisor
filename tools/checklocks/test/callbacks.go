// Copyright 2026 The gVisor Authors.
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
	"slices"

	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
)

// +checklocks:tc.mu
func (tc *oneGuardStruct) matches(i int) bool {
	return tc.guardedField == i
}

func forwardAny[T any](values []T, pred func(T) bool) bool {
	return crosspkg.Any(pred, values)
}

func testBoundPredicate(tc *oneGuardStruct, values []int) {
	tc.mu.Lock()
	slices.ContainsFunc(values, tc.matches)
	forwardAny(values, tc.matches)
	tc.mu.Unlock()
	slices.ContainsFunc(values, tc.matches) // +checklocksfail=must hold tc.mu
}

func testCallbackModes(tc *oneReadGuardStruct, values []int) {
	tc.mu.RLock()
	slices.IndexFunc(values, func(i int) bool {
		tc.guardedField = i // +checklocksfail=invalid field access
		return true
	})
	tc.mu.RUnlock()
}

func testChangesCallbackLock(tc *oneGuardStruct, xs []int) {
	tc.mu.Lock()
	slices.ContainsFunc(xs, func(i int) bool { // +checklocksfail=callback must preserve held locks
		tc.mu.Unlock()
		return i > 0
	})
	tc.mu.Unlock()
}

func testCallbackPointer(tc, other *oneGuardStruct, xs []int) {
	p := tc
	tc.mu.Lock()
	slices.ContainsFunc(xs, func(i int) bool {
		read := p.guardedField // +checklocksfail=invalid field access
		p = other
		return read == i
	})
	p.guardedField = 1 // +checklocksfail=invalid field access
	tc.mu.Unlock()
}

func invokeBoth(first, second func()) {
	first()
	second()
}

func testOtherCallback(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	invokeBoth(func() {}, func() {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	})
}

func testCallbackBranch(extra *oneGuardStruct, values []int) {
	slices.ContainsFunc(values, func(i int) bool { // +checklocksfail=incompatible return states
		if i == 0 {
			extra.mu.Lock()
			return true
		}
		return false
	})
}

func callAndReturnOther(invoke, keep func()) func() {
	invoke()
	return keep
}

func testSameClosureEscapes(tc *oneGuardStruct) func() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	fn := func() { tc.guardedField = 1 } // +checklocksfail=invalid field access
	return callAndReturnOther(fn, fn)
}

// +checklocks:globalMu
func guardedPredicate(i int) bool { return standaloneGlobal == i }

// +checklocksrelease:globalMu
func releasePredicate(i int) bool {
	globalMu.Unlock()
	return i > 0
}

// +checklocks:x.mu
func guardedElement(x *oneGuardStruct) bool { return x.guardedField != 0 }

func testNamedPredicate(values []int, elements []*oneGuardStruct, other *oneGuardStruct) {
	globalMu.Lock()
	slices.ContainsFunc(values, guardedPredicate)
	slices.ContainsFunc(values, releasePredicate) // +checklocksfail=callback must preserve held locks
	globalMu.Unlock()
	slices.ContainsFunc(values, guardedPredicate) // +checklocksfail=must hold globalMu

	other.mu.Lock()
	slices.ContainsFunc(elements, guardedElement) // +checklocksfail=field x.mu cannot be resolved
	other.mu.Unlock()
}

// +checklocksrelease:globalMu
func unlockBeforeYield(yield func(int) bool) {
	globalMu.Unlock()
	if yield(2) {
		yield(1)
	}
}

// +checklocksrelease:globalMu
func testSortedFunc(order int) []int {
	// SortedFunc collects the entire sequence before it calls the comparator.
	// Checklocks cannot infer the iterator's unlock through SortedFunc.
	return slices.SortedFunc(unlockBeforeYield, func(a, b int) int { // +checklocksfail=return with unexpected locks held
		if otherStruct.guardedField1 == order { // +checklocksfail=invalid field access
			return b - a
		}
		return a - b
	})
}
