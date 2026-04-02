// Copyright 2024 The gVisor Authors.
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

// testRangeFuncValid tests that range-over-func iterators properly inherit
// lock state from the enclosing function. The lock is held when the iterator
// body executes, so accessing guarded fields should be valid.
func testRangeFuncValid(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for item := range generate {
		tc.guardedField = item // Should pass: lock is held.
	}
}

// testRangeFuncInvalid tests that range-over-func iterators still detect
// violations when the lock is not held.
func testRangeFuncInvalid(tc *oneGuardStruct) {
	for item := range generate {
		tc.guardedField = item // +checklocksfail
	}
}

// testRangeFuncDeferUnlock tests range-over-func with defer unlock pattern.
func testRangeFuncDeferUnlock(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for item := range generate {
		tc.guardedField = item // Should pass: lock is held.
		tc.unguardedField = item
	}
}

// testRangeFuncLockInsideValid tests that acquiring and releasing a lock
// inside the iterator body works correctly.
func testRangeFuncLockInsideValid(tc *oneGuardStruct) {
	for item := range generate {
		tc.mu.Lock()
		tc.guardedField = item // Should pass: lock acquired in body.
		tc.mu.Unlock()
	}
}

// testRangeFuncSeq2Valid tests range-over-func with two-value iterators.
func testRangeFuncSeq2Valid(tc *oneGuardStruct) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for i, v := range generate2 {
		tc.guardedField = i + v // Should pass: lock is held.
	}
}

// generate is a simple iterator function for testing.
func generate(yield func(int) bool) {
	for i := 0; i < 10; i++ {
		if !yield(i) {
			return
		}
	}
}

// generate2 is a two-value iterator function for testing.
func generate2(yield func(int, int) bool) {
	for i := 0; i < 10; i++ {
		if !yield(i, i*2) {
			return
		}
	}
}
