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

import (
	"sync"
)

// oneReadGuardStruct has one read-guarded field.
type oneReadGuardStruct struct {
	mu sync.RWMutex
	// +checklocks:mu
	guardedField int
}

func testRWAccessValidRead(tc *oneReadGuardStruct) {
	tc.mu.Lock()
	_ = tc.guardedField
	tc.mu.Unlock()
	tc.mu.RLock()
	_ = tc.guardedField
	tc.mu.RUnlock()
}

func testRWAccessValidWrite(tc *oneReadGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testRWAccessInvalidWrite(tc *oneReadGuardStruct) {
	tc.guardedField = 2 // +checklocksfail
	tc.mu.RLock()
	tc.guardedField = 2 // +checklocksfail
	tc.mu.RUnlock()
}

func testRWAccessInvalidRead(tc *oneReadGuardStruct) {
	_ = tc.guardedField // +checklocksfail
}
