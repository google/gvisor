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
	"sync/atomic"
)

type atomicStruct struct {
	accessedNormally int32

	// +checkatomic
	accessedAtomically int32

	// +checklocksignore
	ignored int32
}

func testNormalAccess(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- tc.accessedNormally
	p <- &tc.accessedNormally
}

func testAtomicAccess(tc *atomicStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedAtomically)
}

func testAtomicAccessInvalid(tc *atomicStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedNormally) // +checklocksfail
}

func testNormalAccessInvalid(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- tc.accessedAtomically  // +checklocksfail
	p <- &tc.accessedAtomically // +checklocksfail
}

func testIgnored(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- atomic.LoadInt32(&tc.ignored)
	v <- tc.ignored
	p <- &tc.ignored
}

type atomicMixedStruct struct {
	mu sync.Mutex

	// +checkatomic
	// +checklocks:mu
	accessedMixed int32
}

func testAtomicMixedValidRead(tc *atomicMixedStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedMixed)
}

func testAtomicMixedInvalidRead(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	v <- tc.accessedMixed  // +checklocksfail
	p <- &tc.accessedMixed // +checklocksfail
}

func testAtomicMixedValidLockedWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.mu.Lock()
	atomic.StoreInt32(&tc.accessedMixed, 1)
	tc.mu.Unlock()
}

func testAtomicMixedInvalidLockedWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.mu.Lock()
	tc.accessedMixed = 1 // +checklocksfail:2
	tc.mu.Unlock()
}

func testAtomicMixedInvalidAtomicWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	atomic.StoreInt32(&tc.accessedMixed, 1) // +checklocksfail
}

func testAtomicMixedInvalidWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.accessedMixed = 1 // +checklocksfail:2
}
