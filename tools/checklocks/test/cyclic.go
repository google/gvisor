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
)

// cyclicPointer is a self-referential type via pointer.
type cyclicPointer struct {
	mu   sync.Mutex
	next *cyclicPointer
	// +checklocks:mu
	data int
}

func testCyclicPointerValid(c *cyclicPointer) {
	c.mu.Lock()
	c.data = 1
	c.mu.Unlock()
}

func testCyclicPointerInvalid(c *cyclicPointer) {
	c.data = 1 // +checklocksfail
}

// cyclicIndirect is a cyclic type via pointer to another type.
type cyclicIndirect struct {
	mu   sync.Mutex
	impl *cyclicImpl
	// +checklocks:mu
	data int
}

// cyclicImpl is part of a cyclic type chain.
type cyclicImpl struct {
	parent *cyclicIndirect
}

func testCyclicIndirectValid(c *cyclicIndirect) {
	c.mu.Lock()
	c.data = 1
	c.mu.Unlock()
}

func testCyclicIndirectInvalid(c *cyclicIndirect) {
	c.data = 1 // +checklocksfail
}
