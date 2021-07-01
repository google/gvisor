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

func testParameterPassingbyAddrValid(tc *oneGuardStruct) {
	tc.mu.Lock()
	nestedWithGuardByAddr(&tc.guardedField, &tc.unguardedField)
	tc.mu.Unlock()
}

func testParameterPassingByAddrInalid(tc *oneGuardStruct) {
	nestedWithGuardByAddr(&tc.guardedField, &tc.unguardedField) // +checklocksfail
}

func testParameterPassingByValueValid(tc *oneGuardStruct) {
	tc.mu.Lock()
	nestedWithGuardByValue(tc.guardedField, tc.unguardedField)
	tc.mu.Unlock()
}

func testParameterPassingByValueInalid(tc *oneGuardStruct) {
	nestedWithGuardByValue(tc.guardedField, tc.unguardedField) // +checklocksfail
}

func nestedWithGuardByAddr(guardedField, unguardedField *int) {
	*guardedField = 4
	*unguardedField = 5
}

func nestedWithGuardByValue(guardedField, unguardedField int) {
	// read the fields to keep SA4009 static analyzer happy.
	_ = guardedField
	_ = unguardedField
	guardedField = 4
	unguardedField = 5
}
