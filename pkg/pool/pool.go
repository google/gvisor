// Copyright 2018 The gVisor Authors.
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

// Package pool provides a trivial integer pool.
package pool

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// Pool is a simple allocator.
type Pool struct {
	mu sync.Mutex

	// cache is the set of returned values.
	cache []uint64

	// Start is the starting value (if needed).
	Start uint64

	// max is the current maximum issued.
	max uint64

	// Limit is the upper limit.
	Limit uint64
}

// Get gets a value from the pool.
func (p *Pool) Get() (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Anything cached?
	if len(p.cache) > 0 {
		v := p.cache[len(p.cache)-1]
		p.cache = p.cache[:len(p.cache)-1]
		return v, true
	}

	// Over the limit?
	if p.Start == p.Limit {
		return 0, false
	}

	// Generate a new value.
	v := p.Start
	p.Start++
	return v, true
}

// Put returns a value to the pool.
func (p *Pool) Put(v uint64) {
	p.mu.Lock()
	p.cache = append(p.cache, v)
	p.mu.Unlock()
}
