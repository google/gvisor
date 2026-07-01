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

// Package spinlock provides spinlock implementation.
package spinlock

import (
	"runtime"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// A Spinlock is a spin exclusion lock, just like kernel spinlock.
// value:
//
//	0, unlocked
//	1, locked
type Spinlock struct {
	state atomicbitops.Uint32
}

// Lock locks the spinlock.
//
//go:nosplit
func (s *Spinlock) Lock() {
	for !s.state.CompareAndSwap(0, 1) {
	}
}

// LockYield locks the spinlock. If the lock is not available, it can yield the CPU.
//
//go:nosplit
func (s *Spinlock) LockYield() {
	count := 1000
	for !s.state.CompareAndSwap(0, 1) {
		if count--; count == 0 {
			runtime.Gosched()
			count = 1000
		}
	}
}

// Unlock unlocks the spinlock.
//
//go:nosplit
func (s *Spinlock) Unlock() {
	s.state.Store(0)
}
