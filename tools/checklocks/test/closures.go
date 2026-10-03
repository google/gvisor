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

func testClosureInvalid(tc *oneGuardStruct) {
	// This is expected to fail.
	callClosure(func() {
		tc.guardedField = 1 // +checklocksfail
	})
}

func testClosureUnsupported(tc *oneGuardStruct) {
	// Locked outside the closure, so may or may not be valid. This cannot
	// be handled and we should explicitly fail. This can't be handled
	// because of the call through callClosure, below, which means the
	// closure will actually be passed as a value somewhere.
	tc.mu.Lock()
	callClosure(func() {
		tc.guardedField = 1 // +checklocksfail
	})
	tc.mu.Unlock()
}

func testClosureValid(tc *oneGuardStruct) {
	// All locking happens within the closure. This should not present a
	// problem for analysis.
	callClosure(func() {
		tc.mu.Lock()
		tc.guardedField = 1
		tc.mu.Unlock()
	})
}

func testClosureInline(tc *oneGuardStruct) {
	tc.mu.Lock()
	func() {
		tc.guardedField = 1
		func() {
			tc.guardedField = 2
		}()
	}()
	tc.mu.Unlock()
}

// +checklocksignore
func testClosureIgnore(tc *oneGuardStruct) {
	// Inherit the checklocksignore.
	x := func() {
		tc.guardedField = 1
		atomicGlobal.RacyStore(1)
	}
	x()

	// Passing a closure as an argument is not an inline invocation.
	callClosure(func() {
		callPreconditions(tc)
		tc.guardedField = 1
	})
	defer callClosure(func() {
		callPreconditions(tc)
		tc.guardedField = 1
	})
}

func testAnonymousInvalid(tc *oneGuardStruct) {
	// Invalid, as per testClosureInvalid above.
	callAnonymous(func(tc *oneGuardStruct) {
		tc.guardedField = 1 // +checklocksfail
	}, tc)
}

func testAnonymousUnsupported(tc *oneGuardStruct) {
	// Not supportable, as per testClosureUnsupported above.
	tc.mu.Lock()
	callAnonymous(func(tc *oneGuardStruct) {
		tc.guardedField = 1 // +checklocksfail
	}, tc)
	tc.mu.Unlock()
}

func testAnonymousValid(tc *oneGuardStruct) {
	// Valid, as per testClosureValid above.
	callAnonymous(func(tc *oneGuardStruct) {
		tc.mu.Lock()
		tc.guardedField = 1
		tc.mu.Unlock()
	}, tc)
}

func testAnonymousInline(tc *oneGuardStruct) {
	tc.mu.Lock()
	func(tc *oneGuardStruct) {
		tc.guardedField = 1
	}(tc)
	tc.mu.Unlock()
}

// +checklocksignore
func testAnonymousIgnore(tc *oneGuardStruct) {
	// Inherit the checklocksignore.
	x := func(tc *oneGuardStruct) {
		tc.guardedField = 1
	}
	x(tc)
}

func testClosureLockChanges(tc *oneGuardStruct) {
	func() {
		tc.mu.Lock()
	}()
	tc.guardedField = 1
	func() {
		tc.mu.Unlock()
	}()
	tc.guardedField = 2 // +checklocksfail=invalid field access
}

func testClosureLeakedLock(tc *oneGuardStruct) { // +checklocksfail=unexpected locks held
	func() {
		tc.mu.Lock()
	}()
}

func testClosureParameters(tc, other *oneGuardStruct) {
	tc.mu.Lock()
	func(p *oneGuardStruct) {
		tc.guardedField = 1
		p.mu.Lock()
	}(other)
	other.guardedField = 2
	other.mu.Unlock()
	tc.mu.Unlock()
}

func testClosureReadLock(tc *oneReadGuardStruct) {
	tc.mu.RLock()
	func() {
		_ = tc.guardedField
		tc.guardedField = 1 // +checklocksfail=invalid field access
		tc.mu.RUnlock()
	}()
}

func testClosureIdempotentUnlock(tc *oneReadGuardStruct, early bool) {
	tc.mu.RLock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			tc.mu.RUnlock()
			unlocked = true
		}
	}
	defer unlock()
	if early {
		unlock()
	}
}

func testClosureBooleanWrite(tc *oneGuardStruct, condition bool) {
	access := false
	func() {
		if condition {
			access = true
		}
	}()
	if access {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	}
}

func testClosureBooleanEscape(tc *oneGuardStruct) {
	access := false
	func() {
		setBoolean(&access)
	}()
	if access {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	}
}

func testClosureBooleanCaptureEscape(tc *oneGuardStruct) {
	access := false
	callClosure(func() {
		access = true
	})
	if access {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	}
}

func testClosureBooleanConcurrent(tc *oneGuardStruct) {
	access := false
	go func() {
		access = true
	}()
	if access {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	}
}

func testClosureBooleanAddressAlias(tc *oneGuardStruct) {
	access := false
	alias := &access
	setBoolean(alias)
	if access {
		tc.guardedField = 1 // +checklocksfail=invalid field access
	}
}

//go:noinline
func setBoolean(value *bool) {
	*value = true
}

func testClosureAssignCapture(tc, other *oneGuardStruct) {
	p := tc
	func() {
		p = other
	}()
	other.mu.Lock()
	p.guardedField = 1
	other.mu.Unlock()
	tc.mu.Lock()
	p.guardedField = 2 // +checklocksfail=invalid field access
	tc.mu.Unlock()
}

func testClosureAssignParameter(tc, other *oneGuardStruct) {
	p := tc
	func(dst **oneGuardStruct) {
		*dst = other
	}(&p)
	other.mu.Lock()
	p.guardedField = 1
	other.mu.Unlock()
}

func testClosureAssignThroughCapture(tc, other *oneGuardStruct) {
	p := tc
	dst := &p
	func() {
		*dst = other
	}()
	other.mu.Lock()
	p.guardedField = 1
	other.mu.Unlock()
}

func testClosureEvaluatedPointer(tc, other *oneGuardStruct) {
	p := tc
	saved := p
	func() {
		p = other
	}()
	tc.mu.Lock()
	saved.guardedField = 1
	tc.mu.Unlock()
}

func testClosureRepeatedStore(tc, other *oneGuardStruct) {
	p := tc
	var saved, ignored *oneGuardStruct
	f := func(dst **oneGuardStruct) {
		*dst = p
	}
	f(&saved)
	p = other
	f(&ignored)
	tc.mu.Lock()
	saved.guardedField = 1
	tc.mu.Unlock()
}

func testClosureIncompatibleLocks(tc, other *oneGuardStruct, cond bool) {
	func() { // +checklocksfail=incompatible return states
		if cond {
			tc.mu.Lock()
		} else {
			other.mu.Lock()
		}
	}()
}

func testClosureIncompatibleModes(tc *oneReadGuardStruct, cond bool) {
	func() { // +checklocksfail=incompatible return states
		if cond {
			tc.mu.Lock()
		} else {
			tc.mu.RLock()
		}
	}()
}

func testClosureBranchAliases(tc, other *oneGuardStruct, cond bool) {
	p := tc
	func() {
		if cond {
			p = tc
			return
		}
		p = other
	}()
	tc.mu.Lock()
	p.guardedField = 1 // +checklocksfail=invalid field access
	tc.mu.Unlock()
}

func testClosureLoopAlias(tc, other *oneGuardStruct, count int) {
	p := tc
	func() {
		for i := 0; i < count; i++ {
			p = other
		}
	}()
	tc.mu.Lock()
	p.guardedField = 1 // +checklocksfail=invalid field access
	tc.mu.Unlock()
}

func testClosureConditionalPointerStore(dst **oneGuardStruct, other *oneGuardStruct, cond bool) {
	saved := *dst
	saved.mu.Lock()
	func() {
		if cond {
			*dst = other
		}
	}()
	(*dst).guardedField = 1 // +checklocksfail=invalid field access
	saved.guardedField = 2
	saved.mu.Unlock()
}

func testClosureRepeatedConditionalStore(dst **oneGuardStruct, first, second *oneGuardStruct, firstCond, secondCond bool) {
	var current *oneGuardStruct
	update := func(value *oneGuardStruct, cond bool) {
		if cond {
			*dst = value
		}
		current = *dst
	}
	update(first, firstCond)
	saved := current
	saved.mu.Lock()
	update(second, secondCond)
	current.guardedField = 1 // +checklocksfail=invalid field access
	saved.guardedField = 2
	saved.mu.Unlock()
}

type closurePointerGuard struct {
	child *oneGuardStruct
	// +checklocks:child.mu
	guarded int
}

func testClosureStoredGuard(tc *oneGuardStruct) {
	tc.mu.Lock()
	local := closurePointerGuard{child: tc}
	callPreconditions(local.child)
	pointer := &closurePointerGuard{child: tc}
	callPreconditions(pointer.child)
	tc.mu.Unlock()
}

func testClosureCopiedGuard(first, second *oneGuardStruct) {
	source := closurePointerGuard{child: first}
	copy := source
	source.child = second
	first.mu.Lock()
	callPreconditions(copy.child)
	callPreconditions(source.child) // +checklocksfail
	first.mu.Unlock()
}

func testClosureOverwriteGuard(first *oneGuardStruct, replacement closurePointerGuard) {
	local := closurePointerGuard{child: first}
	first.mu.Lock()
	callPreconditions(local.child)
	local = replacement
	callPreconditions(local.child) // +checklocksfail
	first.mu.Unlock()
}

func testClosureNestedCopy(first, second *oneGuardStruct) {
	type nested struct {
		inner closurePointerGuard
	}
	source := nested{inner: closurePointerGuard{child: first}}
	copy := source
	source.inner = closurePointerGuard{child: second}
	first.mu.Lock()
	callPreconditions(copy.inner.child)
	callPreconditions(source.inner.child) // +checklocksfail
	first.mu.Unlock()
}

func testClosureCopiedMutex(original *oneGuardStruct) {
	original.mu.Lock()
	// Copying a mutex must not transfer the original lock's identity.
	copy := *original //nolint:copylocks
	callPreconditions(original)
	callPreconditions(&copy) // +checklocksfail
	original.mu.Unlock()
}

func testClosureConditionalStructStore(first, second *oneGuardStruct, cond bool) {
	local := closurePointerGuard{child: first}
	saved := local
	if cond {
		local = closurePointerGuard{child: second}
	}
	first.mu.Lock()
	callPreconditions(saved.child)
	callPreconditions(local.child) // +checklocksfail=must hold tc.mu|must hold tc.mu
	first.mu.Unlock()
}

func testClosureOverwriteArray(first *oneGuardStruct, replacement [1]*oneGuardStruct) {
	local := &[1]*oneGuardStruct{first}
	first.mu.Lock()
	callPreconditions(local[0])
	*local = replacement
	callPreconditions(local[0]) // +checklocksfail
	first.mu.Unlock()
}

func testClosureConditionalGuard(tc *closurePointerGuard, first, second *oneGuardStruct, firstCond, secondCond bool) {
	func() {
		if firstCond {
			tc.child = first
		}
	}()
	tc.child.mu.Lock()
	tc.guarded = 1
	tc.child.mu.Unlock()
	saved := tc.child
	saved.mu.Lock()
	func() {
		if secondCond {
			tc.child = second
		}
	}()
	tc.guarded = 2 // +checklocksfail=invalid field access
	saved.guardedField = 3
	saved.mu.Unlock()
}

func testClosureLoopPointerStore(dst **oneGuardStruct, other *oneGuardStruct, count int, cond bool) {
	saved := *dst
	saved.mu.Lock()
	func() {
		for i := 0; i < count; i++ {
			if cond {
				*dst = other
			}
			(*dst).unguardedField = i
		}
	}()
	(*dst).guardedField = 1 // +checklocksfail=invalid field access
	saved.guardedField = 2
	saved.mu.Unlock()
}

func testClosureBranchLocks(tc *oneGuardStruct, cond bool) {
	func() {
		if cond {
			tc.mu.Lock()
			return
		}
		tc.mu.Lock()
	}()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testAnonymousAsync(tc *oneGuardStruct) {
	f := func(p *oneGuardStruct) {
		p.guardedField = 1 // +checklocksfail=invalid field access
	}
	tc.mu.Lock()
	f(tc)
	go f(tc)
	tc.mu.Unlock()
}

func testAnonymousEscaped(tc *oneGuardStruct) {
	f := func(p *oneGuardStruct) {
		p.guardedField = 1 // +checklocksfail=invalid field access
	}
	tc.mu.Lock()
	f(tc)
	callAnonymous(f, tc)
	tc.mu.Unlock()
}

//go:noinline
func callClosure(fn func()) {
	fn()
}

//go:noinline
func callAnonymous(fn func(*oneGuardStruct), tc *oneGuardStruct) {
	fn(tc)
}
