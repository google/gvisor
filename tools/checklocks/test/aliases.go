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

import "sync"

// +checklocksalias:inner.mu=mu
type aliasOuter struct {
	mu    sync.Mutex
	inner aliasInner

	// +checklocks:inner.mu
	guardedField int
}

func testTypeAliasValid(a *aliasOuter) {
	a.mu.Lock()
	a.guardedField = 1
	a.mu.Unlock()
}

func testTypeAliasInvalid(a *aliasOuter) {
	a.guardedField = 1 // +checklocksfail
}

type aliasInner struct {
	mu *sync.Mutex
}

// +checklocksalias:inner.mu=mu
type aliasInnerNested struct {
	mu    sync.Mutex
	inner aliasInner
}

// +checklocksalias:inner.mu=mu
// +checklocksalias:inner.mu=mu
type aliasDuplicateExact struct { // +checklocksfail=is redundant
	mu    sync.Mutex
	inner aliasInner
}

// +checklocksalias:inner.mu=mu
// +checklocksalias:mu=inner.mu
type aliasDuplicateSwapped struct { // +checklocksfail=is redundant
	mu    sync.Mutex
	inner aliasInner
}

// +checklocksalias:inner.mu=mu
type aliasNonStructField struct { // +checklocksfail=expected to be struct
	mu    sync.Mutex
	inner int
}

// +checklocksalias:mu=mu
type aliasSameLock struct { // +checklocksfail=refers to the same lock
	mu sync.Mutex
}

// +checklocksalias:mu=inner.mu
type aliasRequiresPointer struct { // +checklocksfail=requires a pointer or interface lock
	mu    sync.Mutex
	inner struct{ mu sync.Mutex }
}

// +checklocksalias:mu
type aliasInvalidFormat struct { // +checklocksfail=invalid annotation
	mu sync.Mutex
}

// +checklocksalias:mu=other.mu
type aliasNonStructType int // +checklocksfail=only valid on struct types

// +checklocksalias:inner.inner.mu=inner.mu
type aliasRedundantNested struct { // +checklocksfail=is redundant
	inner aliasInnerNested
}

type aliasEndpoint struct {
	mu sync.Mutex
}

type aliasSender struct {
	ep *aliasEndpoint
}

// +checklocksalias:snd.ep.mu=ep.mu
type aliasReceiver struct {
	ep  *aliasEndpoint
	snd aliasSender
}

// +checklocksalias:rc.snd.ep.mu=rc.ep.mu
type aliasRedundantDeep struct { // +checklocksfail=is redundant
	rc aliasReceiver
}

// +checklocksalias:inner.mu=mu
type aliasBranchOuter struct {
	mu sync.RWMutex

	// +checklocks:mu
	inner *aliasBranchInner
}

// +checklocksalias:mu=outer.mu
type aliasBranchInner struct {
	mu    *sync.RWMutex
	outer *aliasBranchOuter
}

// Visiting the inner type discovers the reverse alias, which can change the
// held mutex's representative without changing its identity.
func visitAliasBranchInner(inner *aliasBranchInner) {}

// +checklocks:a.mu
// +checklocks:b.mu
func testAliasBranchSameLock(a, b *aliasBranchOuter, visit bool) {
	if !visit {
		return
	}
	visitAliasBranchInner(a.inner)
}

// The negative cases return values so exit diagnostics have explicit source
// positions without requiring implicit-return reporting.
//
// +checklocks:a.mu
func testAliasBranchWrongMode(a *aliasBranchOuter, visit bool) bool { // +checklocksfail=incompatible return states
	if !visit {
		return false
	}
	visitAliasBranchInner(a.inner)
	a.mu.Unlock()
	a.mu.RLock()
	return true // +checklocksfail=not held exclusively
}

// +checklocks:a.mu
// +checklocks:b.mu
func testAliasBranchWrongOwner(a, b, c *aliasBranchOuter, visit bool) bool { // +checklocksfail=incompatible return states
	if !visit {
		return false
	}
	visitAliasBranchInner(a.inner)
	b.mu.Unlock()
	c.mu.Lock()
	return true // +checklocksfail=not held exclusively
}

// +checklocks:a.mu
func testAliasBranchExtraLock(a, b *aliasBranchOuter, visit bool) bool { // +checklocksfail=incompatible return states
	if !visit {
		return false
	}
	visitAliasBranchInner(a.inner)
	b.mu.Lock()
	return true // +checklocksfail=return with unexpected locks held
}
