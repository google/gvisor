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

	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
)

var genericGlobalMu sync.Mutex

type genericValueStruct[T any] struct {
	mu sync.Mutex
	// +checklocks:mu
	value T
}

func (g *genericValueStruct[T]) set(v T) {
	g.mu.Lock()
	g.value = v
	g.mu.Unlock()
}

func (g *genericValueStruct[T]) setUnlocked(v T) {
	g.value = v // +checklocksfail
}

// +checklocks:g.mu
func (g *genericValueStruct[T]) setLocked(v T) {
	g.value = v
}

// genericMapStruct is a minimal reproduction of generic guarded fields.
// See https://github.com/google/gvisor/issues/10372 and #11671.
type genericMapStruct[K comparable] struct {
	mu sync.Mutex
	// +checklocks:mu
	m map[K]struct{}
}

func (g *genericMapStruct[K]) add(k K) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.m[k] = struct{}{}
}

// genericUnlockedWrite should fail: writing without holding the guard.
func genericUnlockedWrite[K comparable](g *genericMapStruct[K], k K) {
	g.m[k] = struct{}{} // +checklocksfail
}

// +checklocks:genericGlobalMu
func genericNeedsGlobalLock[T any](v T) {
	_ = v
}

func genericCallsWithoutLock[T any](v T) {
	genericNeedsGlobalLock(v) // +checklocksfail
}

func genericCallsWithLock[T any](v T) {
	genericGlobalMu.Lock()
	genericNeedsGlobalLock(v)
	genericGlobalMu.Unlock()
}

// crossPkgGenericValid ensures that lock guard facts on generic types imported
// from another package are still found when analyzing a generic use site.
func crossPkgGenericValid[T any](g *crosspkg.GenericGuard[T], v T) {
	g.Mu.Lock()
	g.Value = v
	g.Mu.Unlock()
}

// crossPkgGenericInvalidWrite should fail: writing without holding the guard.
func crossPkgGenericInvalidWrite[T any](g *crosspkg.GenericGuard[T], v T) {
	g.Value = v // +checklocksfail
}
