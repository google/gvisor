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

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791 and RFC 815.
package fragmentation

import (
	"log"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// DefaultReassembleTimeout is based on the linux stack: net.ipv4.ipfrag_time.
const DefaultReassembleTimeout = 30 * time.Second

// HighFragThreshold is the threshold at which we start trimming old
// fragmented packets. Linux uses a default value of 4 MB. See
// net.ipv4.ipfrag_high_thresh for more information.
const HighFragThreshold = 4 << 20 // 4MB

// LowFragThreshold is the threshold we reach to when we start dropping
// older fragmented packets. It's important that we keep enough room for newer
// packets to be re-assembled. Hence, this needs to be lower than
// HighFragThreshold enough. Linux uses a default value of 3 MB. See
// net.ipv4.ipfrag_low_thresh for more information.
const LowFragThreshold = 3 << 20 // 3MB

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu           sync.Mutex
	highLimit    int
	lowLimit     int
	reassemblers map[uint32]*reassembler
	rList        reassemblerList
	size         int
	timeout      time.Duration
}

// NewFragmentation creates a new Fragmentation.
//
// highMemoryLimit specifies the limit on the memory consumed
// by the fragments stored by Fragmentation (overhead of internal data-structures
// is not accounted). Fragments are dropped when the limit is reached.
//
// lowMemoryLimit specifies the limit on which we will reach by dropping
// fragments after reaching highMemoryLimit.
//
// reassemblingTimeout specifes the maximum time allowed to reassemble a packet.
// Fragments are lazily evicted only when a new a packet with an
// already existing fragmentation-id arrives after the timeout.
func NewFragmentation(highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	return &Fragmentation{
		reassemblers: make(map[uint32]*reassembler),
		highLimit:    highMemoryLimit,
		lowLimit:     lowMemoryLimit,
		timeout:      reassemblingTimeout,
	}
}

// Process processes an incoming fragment beloning to an ID
// and returns a complete packet when all the packets belonging to that ID have been received.
func (f *Fragmentation) Process(id uint32, first, last uint16, more bool, vv buffer.VectorisedView) (buffer.VectorisedView, bool) {
	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) {
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		f.release(r)
		ok = false
	}
	if !ok {
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()

	res, done, consumed := r.process(first, last, more, vv)

	f.mu.Lock()
	f.size += consumed
	if done {
		f.release(r)
	}
	// Evict reassemblers if we are consuming more memory than highLimit until
	// we reach lowLimit.
	if f.size > f.highLimit {
		tail := f.rList.Back()
		for f.size > f.lowLimit && tail != nil {
			f.release(tail)
			tail = tail.Prev()
		}
	}
	f.mu.Unlock()
	return res, done
}

func (f *Fragmentation) release(r *reassembler) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.size -= r.size
	if f.size < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.size)
		f.size = 0
	}
}
