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

package fragmentation

import (
	"container/heap"
	"fmt"
	"math"
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

type hole struct {
	first   uint16
	last    uint16
	deleted bool
}

type reassembler struct {
	reassemblerEntry
	id           uint32
	size         int
	mu           sync.Mutex
	holes        []hole
	deleted      int
	heap         fragHeap
	done         bool
	creationTime time.Time
}

func newReassembler(id uint32) *reassembler {
	r := &reassembler{
		id:           id,
		holes:        make([]hole, 0, 16),
		deleted:      0,
		heap:         make(fragHeap, 0, 8),
		creationTime: time.Now(),
	}
	r.holes = append(r.holes, hole{
		first:   0,
		last:    math.MaxUint16,
		deleted: false})
	return r
}

// updateHoles updates the list of holes for an incoming fragment and
// returns true iff the fragment filled at least part of an existing hole.
func (r *reassembler) updateHoles(first, last uint16, more bool) bool {
	used := false
	for i := range r.holes {
		if r.holes[i].deleted || first > r.holes[i].last || last < r.holes[i].first {
			continue
		}
		used = true
		r.deleted++
		r.holes[i].deleted = true
		if first > r.holes[i].first {
			r.holes = append(r.holes, hole{r.holes[i].first, first - 1, false})
		}
		if last < r.holes[i].last && more {
			r.holes = append(r.holes, hole{last + 1, r.holes[i].last, false})
		}
	}
	return used
}

func (r *reassembler) process(first, last uint16, more bool, vv buffer.VectorisedView) (buffer.VectorisedView, bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	consumed := 0
	if r.done {
		// A concurrent goroutine might have already reassembled
		// the packet and emptied the heap while this goroutine
		// was waiting on the mutex. We don't have to do anything in this case.
		return buffer.VectorisedView{}, false, consumed
	}
	if r.updateHoles(first, last, more) {
		// We store the incoming packet only if it filled some holes.
		heap.Push(&r.heap, fragment{offset: first, vv: vv.Clone(nil)})
		consumed = vv.Size()
		r.size += consumed
	}
	// Check if all the holes have been deleted and we are ready to reassamble.
	if r.deleted < len(r.holes) {
		return buffer.VectorisedView{}, false, consumed
	}
	res, err := r.heap.reassemble()
	if err != nil {
		panic(fmt.Sprintf("reassemble failed with: %v. There is probably a bug in the code handling the holes.", err))
	}
	return res, true, consumed
}

func (r *reassembler) tooOld(timeout time.Duration) bool {
	return time.Now().Sub(r.creationTime) > timeout
}

func (r *reassembler) checkDoneOrMark() bool {
	r.mu.Lock()
	prev := r.done
	r.done = true
	r.mu.Unlock()
	return prev
}
