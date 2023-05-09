// Copyright 2021 The gVisor Authors.
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
// +checklocksalias:tc2.mu=tc.mu
func testAliasValid(tc *oneGuardStruct, tc2 *oneGuardStruct) {
	tc2.guardedField = 1
}

// +checklocks:tc.mu
func testAliasInvalid(tc *oneGuardStruct, tc2 *oneGuardStruct) {
	tc2.guardedField = 1 // +checklocksfail
}
