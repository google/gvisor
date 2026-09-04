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

// Package atomic exposes atomic fields to a consumer that does not directly
// import their types' packages. Its name deliberately matches sync/atomic to
// test that checklocks identifies atomic operations by package path, not name.
package atomic

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

type Values struct {
	// +checkatomic
	Raw uint64
	// +checkatomic
	Standard atomic.Pointer[int]
	// +checkatomic
	Bitops atomicbitops.Uint64
	// +checkatomic
	Promoted WrappedAtomic

	Mu      sync.Mutex
	OtherMu sync.Mutex
	// +checklocks:Mu
	// +checklocks:OtherMu
	// +checklocksreadany
	// +checkatomic
	Mixed atomicbitops.Uint64
}

type WrappedAtomic struct {
	atomicbitops.Uint64
}

// Load deliberately performs a non-atomic read despite its package and name.
func Load[T any](p *T) T {
	return *p
}

var globalMu sync.Mutex

// RequirePrivate requires a lock in this indirectly imported package.
//
// +checklocks:globalMu
func (*Values) RequirePrivate() {}

// ExcludePrivate excludes a lock in this indirectly imported package.
//
// +checklocksexclude:globalMu
func (*Values) ExcludePrivate() {}
