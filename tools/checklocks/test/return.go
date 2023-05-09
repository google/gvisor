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

// +checklocks:tc.mu
func testReturnInvalidGuard() (tc *oneGuardStruct) { // +checklocksfail
	return new(oneGuardStruct)
}

// +checklocksrelease:tc.mu
func testReturnInvalidRelease() (tc *oneGuardStruct) { // +checklocksfail
	return new(oneGuardStruct)
}

// +checklocksacquire:tc.mu
func testReturnInvalidAcquire() (tc *oneGuardStruct) {
	return new(oneGuardStruct) // +checklocksfail
}

// +checklocksacquire:tc.mu
func testReturnValidAcquire() (tc *oneGuardStruct) {
	tc = new(oneGuardStruct)
	tc.mu.Lock()
	return tc
}

func testReturnAcquireCall() {
	tc := testReturnValidAcquire()
	tc.guardedField = 1
	tc.mu.Unlock()
}

// +checklocksacquire:tc.val.mu
// +checklocksacquire:tc.ptr.mu
func testReturnValidNestedAcquire() (tc *nestedGuardStruct) {
	tc = new(nestedGuardStruct)
	tc.ptr = new(oneGuardStruct)
	tc.val.mu.Lock()
	tc.ptr.mu.Lock()
	return tc
}

func testReturnNestedAcquireCall() {
	tc := testReturnValidNestedAcquire()
	tc.val.guardedField = 1
	tc.ptr.guardedField = 1
	tc.val.mu.Unlock()
	tc.ptr.mu.Unlock()
}
