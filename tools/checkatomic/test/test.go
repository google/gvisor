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

// Package test is a test package.
package test

import (
	"sync/atomic"
)

// atomicStruct is an atomic structure.
type atomicStruct struct {
	accessedNormally int32

	// +checkatomic
	accessedAtomically int32

	// +checkatomic:fail
	accessedOnceButShouldNot int32

	// +checkatomic:fail
	// +checkatomic:fail
	accessedTwiceButShouldNot int32

	// +checkatomic
	// +checkatomic:fail
	accessedByValueButShouldNot int32

	// +checkatomic
	// +checkatomic:fail
	accessedByPtrButShouldNot int32

	// +checkatomic:ignore
	ignored int32

	// +checkatomic:fail
	// +checkatomic:ignore
	// +checkatomic
	conflictOne int32

	// +checkatomic:fail
	// +checkatomic
	// +checkatomic:ignore
	conflictTwo int32
}

// Do is compiled.
func (a *atomicStruct) Do(v chan int32, p chan *int32) {
	// Test normal accesses.
	v <- a.accessedNormally
	p <- &a.accessedNormally

	// Test atomic accesses.
	v <- atomic.LoadInt32(&a.accessedAtomically)

	// Test invalid accesses of non-atomic values.
	v <- atomic.LoadInt32(&a.accessedOnceButShouldNot)
	v <- atomic.LoadInt32(&a.accessedTwiceButShouldNot)
	v <- atomic.LoadInt32(&a.accessedTwiceButShouldNot)

	// Test non-atomic accesses of an atomic value.
	v <- a.accessedByValueButShouldNot
	p <- &a.accessedByPtrButShouldNot

	// Test ignored can do both.
	v <- atomic.LoadInt32(&a.ignored)
	v <- a.ignored
	p <- &a.ignored
}
