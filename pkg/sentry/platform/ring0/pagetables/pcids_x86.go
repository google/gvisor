// Copyright 2018 Google LLC
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

// limitPCID is the number of valid PCIDs.
const limitPCID = 4096

// PCIDs is a simple PCID database.
//
// This is not protected by locks and is thus suitable for use only with a
// single CPU at a time.
type PCIDs struct {
	// mu protects below.
	mu sync.Mutex

	// cache are the assigned page tables.
	cache map[*PageTables]uint16

	// avail are available PCIDs.
	avail []uint16
}

// NewPCIDs returns a new PCID database.
//
// start is the first index to assign. Typically this will be one, as the zero
// pcid will always be flushed on transition (see pagetables_x86.go). This may
// be more than one if specific PCIDs are reserved.
//
// Nil is returned iff the start and size are out of range.
func NewPCIDs(start, size uint16) *PCIDs {
	if start+uint16(size) >= limitPCID {
		return nil // See comment.
	}
	p := &PCIDs{
		cache: make(map[*PageTables]uint16),
	}
	for pcid := start; pcid < start+size; pcid++ {
		p.avail = append(p.avail, pcid)
	}
	return p
}

// Assign assigns a PCID to the given PageTables.
//
// This may overwrite any previous assignment provided. If this in the case,
// true is returned to indicate that the PCID should be flushed.
func (p *PCIDs) Assign(pt *PageTables) (uint16, bool) {
	p.mu.Lock()
	if pcid, ok := p.cache[pt]; ok {
		p.mu.Unlock()
		return pcid, false // No flush.
	}

	// Is there something available?
	if len(p.avail) > 0 {
		pcid := p.avail[len(p.avail)-1]
		p.avail = p.avail[:len(p.avail)-1]
		p.cache[pt] = pcid

		// We need to flush because while this is in the available
		// pool, it may have been used previously.
		p.mu.Unlock()
		return pcid, true
	}

	// Evict an existing table.
	for old, pcid := range p.cache {
		delete(p.cache, old)
		p.cache[pt] = pcid

		// A flush is definitely required in this case, these page
		// tables may still be active. (They will just be assigned some
		// other PCID if and when they hit the given CPU again.)
		p.mu.Unlock()
		return pcid, true
	}

	// No PCID.
	p.mu.Unlock()
	return 0, false
}

// Drop drops references to a set of page tables.
func (p *PCIDs) Drop(pt *PageTables) {
	p.mu.Lock()
	if pcid, ok := p.cache[pt]; ok {
		delete(p.cache, pt)
		p.avail = append(p.avail, pcid)
	}
	p.mu.Unlock()
}
