// Copyright 2026 The gVisor Authors.
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

var declarationMu sync.Mutex
var declarationOtherMu sync.Mutex

// +checklocks:declarationMu
var standaloneFirst, _, standaloneLast int

// A descriptive doc comment must not hide a trailing annotation.
var trailingFirst, trailingLast int // +checklocks:declarationMu

var (
	// +checklocks:declarationMu
	groupedFirst, _, groupedLast int
	groupedTrailing              int // +checklocks:declarationMu
)

// +checklocks:declarationMu
var (
	groupDocFirst int
	groupDocLast  int
	groupDocBoth  int // +checklocks:declarationOtherMu
)

// +checkatomic
var standaloneAtomic int32

var trailingAtomic int32 // +checkatomic

func testAtomicDeclarationComments() {
	standaloneAtomic = 1 // +checklocksfail=non-atomic write
	trailingAtomic = 1   // +checklocksfail=non-atomic write
	atomic.StoreInt32(&standaloneAtomic, 1)
	atomic.StoreInt32(&trailingAtomic, 1)
}

func testGlobalDeclarationComments() {
	standaloneFirst = 1 // +checklocksfail=invalid field access
	standaloneLast = 1  // +checklocksfail=invalid field access
	trailingFirst = 1   // +checklocksfail=invalid field access
	trailingLast = 1    // +checklocksfail=invalid field access
	groupedFirst = 1    // +checklocksfail=invalid field access
	groupedLast = 1     // +checklocksfail=invalid field access
	groupedTrailing = 1 // +checklocksfail=invalid field access
	groupDocFirst = 1   // +checklocksfail=invalid field access
	groupDocLast = 1    // +checklocksfail=invalid field access

	declarationMu.Lock()
	standaloneFirst = 1
	standaloneLast = 1
	trailingFirst = 1
	trailingLast = 1
	groupedFirst = 1
	groupedLast = 1
	groupedTrailing = 1
	groupDocFirst = 1
	groupDocLast = 1
	groupDocBoth = 1 // +checklocksfail=invalid field access
	declarationOtherMu.Lock()
	groupDocBoth = 1
	declarationOtherMu.Unlock()
	declarationMu.Unlock()

	declarationOtherMu.Lock()
	groupDocBoth = 1 // +checklocksfail=invalid field access
	declarationOtherMu.Unlock()
}

type declarationFields struct {
	padding, _ int
	mu         sync.Mutex
	// +checklocks:mu
	first, second int
	last          int // +checklocks:mu
}

func testGroupedStructFields(v *declarationFields) {
	v.first = 1  // +checklocksfail=invalid field access
	v.second = 1 // +checklocksfail=invalid field access
	v.last = 1   // +checklocksfail=invalid field access
	v.mu.Lock()
	v.first = 1
	v.second = 1
	v.last = 1
	v.mu.Unlock()
}

type declarationEmbedded struct {
	paddingFirst, paddingLast int
	sync.Mutex
	// +checklocks:Mutex
	value int
}

func testEmbeddedFieldAfterGroup(v *declarationEmbedded) {
	v.value = 1 // +checklocksfail=invalid field access
	v.Mutex.Lock()
	v.value = 1
	v.Mutex.Unlock()
}

var inferredAnonymous = struct {
	mu sync.Mutex
	// +checklocks:mu
	value int
}{}

func testInferredAnonymousGlobal() {
	inferredAnonymous.value = 1 // +checklocksfail=invalid field access
	inferredAnonymous.mu.Lock()
	inferredAnonymous.value = 1
	inferredAnonymous.mu.Unlock()
}

type pointerAnonymous struct {
	nested *struct {
		mu sync.Mutex
		// +checklocks:mu
		value int
	}
}

func testPointerAnonymousField(v *pointerAnonymous) {
	v.nested.value = 1 // +checklocksfail=invalid field access
	v.nested.mu.Lock()
	v.nested.value = 1
	v.nested.mu.Unlock()
}

func testAnonymousSignature(v *struct {
	mu sync.Mutex
	// +checklocks:mu
	value int
}) {
	v.value = 1 // +checklocksfail=invalid field access
	v.mu.Lock()
	v.value = 1
	v.mu.Unlock()
}

func testLocalStructDeclaration() {
	type local struct {
		mu sync.Mutex
		// +checklocks:mu
		value int
	}
	var v local
	func(p *local) {
		p.value = 1 // +checklocksfail=invalid field access
		p.mu.Lock()
		p.value = 1
		p.mu.Unlock()
	}(&v)
}
