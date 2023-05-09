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
	"math/rand"
)

func testInconsistentReturn(tc *oneGuardStruct) { // +checklocksfail
	if x := rand.Intn(10); x%2 == 1 {
		tc.mu.Lock()
	}
}

func testConsistentBranching(tc *oneGuardStruct) {
	x := rand.Intn(10)
	if x%2 == 1 {
		tc.mu.Lock()
	} else {
		tc.mu.Lock()
	}
	tc.guardedField = 1
	if x%2 == 1 {
		tc.mu.Unlock()
	} else {
		tc.mu.Unlock()
	}
}

func testInconsistentBranching(tc *oneGuardStruct) { // +checklocksfail:2
	// We traverse the control flow graph in all consistent ways. We cannot
	// determine however, that the first if block and second if block will
	// evaluate to the same condition. Therefore, there are two consistent
	// paths through this code, and two inconsistent paths. Either way, the
	// guardedField should be also marked as an invalid access.
	x := rand.Intn(10)
	if x%2 == 1 {
		tc.mu.Lock()
	}
	tc.guardedField = 1 // +checklocksfail
	if x%2 == 1 {
		tc.mu.Unlock() // +checklocksforce
	}
}

func testUnboundedLocks(tc []*oneGuardStruct) {
	for _, l := range tc {
		l.mu.Lock()
	}
	// This test should have the above *not fail*, though the exact
	// lock state cannot be tracked through the below. Therefore, we
	// expect the next loop to actually fail, and we force the unlock
	// loop to succeed in exactly the same way.
	for _, l := range tc {
		l.guardedField = 1 // +checklocksfail
	}
	for _, l := range tc {
		l.mu.Unlock() // +checklocksforce
	}
}
