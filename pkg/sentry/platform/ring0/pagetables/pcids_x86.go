// Copyright 2018 Google Inc.
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

// +build i386 amd64

package pagetables

import (
	"sync"
)

// maxPCID is the maximum allowed PCID.
const maxPCID = 4095

// PCIDs is a simple PCID database.
type PCIDs struct {
	mu sync.Mutex

	// last is the last fresh PCID given out (not including the available
	// pool). If last >= maxPCID, then the only PCIDs available in the
	// available pool below.
	last uint16

	// available are PCIDs that have been freed.
	available map[uint16]struct{}
}

// NewPCIDs returns a new PCID set.
func NewPCIDs() *PCIDs {
	return &PCIDs{
		available: make(map[uint16]struct{}),
	}
}

// allocate returns an unused PCID, or zero if all are taken.
func (p *PCIDs) allocate() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.available) > 0 {
		for id := range p.available {
			delete(p.available, id)
			return id
		}
	}
	if id := p.last + 1; id <= maxPCID {
		p.last = id
		return id
	}
	// Nothing available.
	return 0
}

// free returns a PCID to the pool.
//
// It is safe to call free with a zero pcid. That is, you may always call free
// with anything returned by allocate.
func (p *PCIDs) free(id uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != 0 {
		p.available[id] = struct{}{}
	}
}
