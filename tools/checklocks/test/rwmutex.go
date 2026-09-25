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

	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
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

// +checklocksexcludewrite:tc.mu
func testRWExcludeWrite(tc *oneReadGuardStruct) {
}

func testRWExcludeWriteSatisfied(tc *oneReadGuardStruct) {
	tc.mu.RLock()
	testRWExcludeWrite(tc)
	tc.mu.RUnlock()
}

func testRWExcludeWriteViolated(tc *oneReadGuardStruct) {
	tc.mu.Lock()
	testRWExcludeWrite(tc) // +checklocksfail
	tc.mu.Unlock()
}

func testReadAnyGuards(tc *crosspkg.ReadAnyGuard[int]) {
	_ = tc.Value // +checklocksfail=at least one
	tc.Mu.Lock()
	_ = tc.Value
	tc.Value = 1 // +checklocksfail=OtherMu
	tc.Mu.Unlock()

	tc.OtherMu.RLock()
	_ = tc.Value
	tc.Value = 2 // +checklocksfail=access, Mu|access, OtherMu
	tc.OtherMu.RUnlock()

	tc.Mu.Lock()
	tc.OtherMu.RLock()
	tc.Value = 3 // +checklocksfail=OtherMu
	tc.OtherMu.RUnlock()
	tc.OtherMu.Lock()
	tc.Value = 4
	tc.OtherMu.Unlock()
	tc.Mu.Unlock()
}

type invalidReadAnyGuards struct {
	mu sync.Mutex

	// +checklocksreadany
	unguarded int // +checklocksfail=requires at least one

	// +checklocks:mu
	// +checklocksreadany
	// +checklocksreadany
	duplicate int // +checklocksfail=specified more than once

	// +checklocks:mu
	// +checklocksreadany:mu
	argument int // +checklocksfail=does not take arguments

	// +checklocks:mu
	// +checklocksreadany
	// +checklocksignore
	ignored int // +checklocksfail=cannot be combined
}

// +checklocksreadany
func invalidReadAnyFunction() {} // +checklocksfail=only valid on fields

var (
	// +checklocksreadany
	invalidReadAnyGlobal int // +checklocksfail=only valid on fields
)

func testReadAnyIndirectWrites(tc *crosspkg.ReadAnyGuard[struct{ member int }]) {
	tc.Mu.Lock()
	tc.Value.member = 1             // +checklocksfail=OtherMu
	mutateReadAny(&tc.Value.member) // +checklocksfail=OtherMu
	tc.OtherMu.RLock()
	tc.Value.member = 2 // +checklocksfail=OtherMu
	tc.OtherMu.RUnlock()
	tc.Mu.Unlock()
}

func mutateReadAny(p *int) {
	*p = 1
}

// +checklocksreadany
type invalidReadAnyType int // +checklocksfail=only valid on fields

// A modifier may precede a guard in the field's trailing comment.
type readAnyTrailingGuard struct {
	mu sync.Mutex

	// +checklocksreadany
	value int // +checklocks:mu
}

// +checklocksreadany
var invalidStandaloneReadAny int // +checklocksfail=only valid on fields

func testReadAnyRetainedAddress(tc *crosspkg.ReadAnyGuard[int]) {
	tc.Mu.Lock()
	p := &tc.Value // +checklocksfail=OtherMu
	tc.Mu.Unlock()
	_ = *p

	// An immediate first load must not authorize a later unlocked load.
	tc.Mu.Lock()
	p = &tc.Value // +checklocksfail=OtherMu
	_ = *p
	tc.Mu.Unlock()
	_ = *p
}

// +checklocksread:tc.OtherMu
func testReadAnyPrecondition(tc *crosspkg.ReadAnyGuard[int]) int {
	return tc.Value
}

type groupedReadAnyGuards struct {
	mu, otherMu sync.Mutex

	// +checklocks:mu
	// +checklocks:otherMu
	// +checklocksreadany
	first, second int

	// +checklocks:mu
	last int
}

func testGroupedReadAnyGuards(tc *groupedReadAnyGuards) {
	tc.first = 1  // +checklocksfail=access, mu|access, otherMu
	tc.second = 2 // +checklocksfail=access, mu|access, otherMu
	tc.last = 3   // +checklocksfail=access, mu
	tc.mu.Lock()
	_ = tc.first
	_ = tc.second
	tc.last = 3
	tc.otherMu.Lock()
	tc.first = 1
	tc.second = 2
	tc.otherMu.Unlock()
	tc.mu.Unlock()
}
