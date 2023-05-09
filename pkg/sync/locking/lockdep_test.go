// Copyright 2022 The gVisor Authors.
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

//go:build lockdep
// +build lockdep

package locking_test

import (
	"testing"
)

func TestReverse(t *testing.T) {
	m := testMutex{}
	m2 := test2RWMutex{}
	m.Lock()
	m2.Lock()
	m2.Unlock()
	m.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()

	m2.Lock()
	m.Lock()
	m.Unlock()
	m2.Unlock()
	t.Error("The reverse lock order hasn't been detected")
}

func TestIndirect(t *testing.T) {
	m1 := testMutex{}
	m2 := test2RWMutex{}
	m3 := test3Mutex{}

	m1.Lock()
	m2.Lock()
	m2.Unlock()
	m1.Unlock()
	m2.Lock()
	m3.Lock()
	m3.Unlock()
	m2.Unlock()
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()

	m3.Lock()
	m1.Lock()
	m1.Unlock()
	m3.Unlock()
	t.Error("The reverse lock order hasn't been detected")
}

func TestSame(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()

	m := testMutex{}
	m.Lock()
	m.Lock()
	m.Unlock()
	m.Unlock()
	t.Error("The same lock has been locked twice, and was not detected.")
}

func TestReverseNested(t *testing.T) {
	m1 := testMutex{}
	m2 := testMutex{}
	m1.Lock()
	m2.NestedLock(testLockM2)
	m1.Unlock()
	m2.NestedUnlock(testLockM2)

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()

	m2.NestedLock(testLockM2)
	m1.Lock()
	m1.NestedUnlock(testLockM2)
	m2.Unlock()

	t.Error("The reverse lock order hasn't been detected")
}

func TestReverseNestedDeeper(t *testing.T) {
	m1 := testMutex{}
	m2 := testMutex{}
	m3 := testMutex{}
	m1.Lock()
	m2.NestedLock(testLockM2)
	m3.NestedLock(testLockM3)
	m1.Unlock()
	m3.NestedUnlock(testLockM3)
	m2.NestedUnlock(testLockM2)

	m1.Lock()
	m2.NestedLock(testLockM2)
	m3.NestedLock(testLockM3)
	m1.Unlock()
	m2.NestedUnlock(testLockM2)
	m3.NestedUnlock(testLockM3)

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()

	m2.NestedLock(testLockM2)
	m3.NestedLock(testLockM3)
	m1.Lock()
	m1.Unlock()
	m3.NestedUnlock(testLockM3)
	m2.NestedUnlock(testLockM2)

	t.Error("The reverse lock order hasn't been detected")
}

func TestUnknownLock(t *testing.T) {
	m1 := testMutex{}
	m2 := testMutex{}

	m1.Lock()
	m2.NestedLock(testLockM2)
	m2.NestedUnlock(testLockM2)
	m1.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic: %s", r)
		}
	}()
	m1.Lock()
	m2.NestedUnlock(testLockM2)
	t.Error("An unknown lock has not been detected.")
}
