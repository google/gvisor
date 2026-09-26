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

func testDeferValidUnlock(tc *oneGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	defer tc.mu.Unlock()
}

func testDeferValidAccess(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer func() {
		tc.guardedField = 1
		tc.mu.Unlock()
	}()
}

func testDeferInvalidAccess(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer func() {
		// N.B. Executed after tc.mu.Unlock().
		tc.guardedField = 1 // +checklocksfail
	}()
	tc.mu.Unlock()
}

func testDeferClosureFrame(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	func() {
		defer func() {
			tc.guardedField = 1
		}()
	}()
	// The inner function's defers must not run the caller's pending Unlock.
	tc.guardedField = 2
}

func testDeferClosureArgument(tc, other *oneGuardStruct) {
	p := tc
	tc.mu.Lock()
	defer func(arg *oneGuardStruct) {
		arg.mu.Unlock()
	}(p)
	func() {
		p = other
	}()
}

func testDeferClosureIndex(tc []*oneGuardStruct) {
	i := 0
	tc[i].mu.Lock()
	defer func(arg *oneGuardStruct) {
		arg.mu.Unlock()
	}(tc[i])
	func() {
		tc[i].guardedField = 1
		i = 1
	}()
}
