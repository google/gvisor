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

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type hole struct {
	first  uint16
	last   uint16
	filled bool
}

type reassembler struct {
	reassemblerEntry
	id           FragmentID
	size         int
	proto        uint8
	mu           sync.Mutex
	holes        []hole
	filled       int
	heap         fragHeap
	done         bool
	creationTime int64
	pkt          *stack.PacketBuffer
}

func newReassembler(id FragmentID, clock tcpip.Clock) *reassembler {
	r := &reassembler{
		id:           id,
		holes:        make([]hole, 0, 16),
		heap:         make(fragHeap, 0, 8),
		creationTime: clock.NowMonotonic(),
	}
	r.holes = append(r.holes, hole{
		first:  0,
		last:   math.MaxUint16,
		filled: false,
	})
	return r
}

// updateHoles updates the list of holes for an incoming fragment. It returns
// true if the fragment fits, it is not a duplicate and it does not overlap with
// another fragment.
//
// For IPv6, overlaps with an existing fragment are explicitly forbidden by
// RFC 8200 section 4.5:
//   If any of the fragments being reassembled overlap with any other fragments
//   being reassembled for the same packet, reassembly of that packet must be
//   abandoned and all the fragments that have been received for that packet
//   must be discarded, and no ICMP error messages should be sent.
//
// It is not explicitly forbidden for IPv4, but to keep parity with Linux we
// disallow it as well:
// https://github.com/torvalds/linux/blob/38525c6/net/ipv4/inet_fragment.c#L349
func (r *reassembler) updateHoles(first, last uint16, more bool) (bool, error) {
	for i := range r.holes {
		currentHole := &r.holes[i]

		if currentHole.filled || last < currentHole.first || currentHole.last < first {
			continue
		}

		if first < currentHole.first || currentHole.last < last {
			// Incoming fragment only partially fits in the free hole.
			return false, ErrFragmentOverlap
		}

		r.filled++
		if first > currentHole.first {
			r.holes = append(r.holes, hole{
				first:  currentHole.first,
				last:   first - 1,
				filled: false,
			})
		}
		if last < currentHole.last && more {
			r.holes = append(r.holes, hole{
				first:  last + 1,
				last:   currentHole.last,
				filled: false,
			})
		}
		// Update the current hole to precisely match the incoming fragment.
		r.holes[i] = hole{
			first:  first,
			last:   last,
			filled: true,
		}
		return true, nil
	}

	// Incoming fragment is a duplicate/subset, or its offset comes after the end
	// of the reassembled payload.
	return false, nil
}

func (r *reassembler) process(first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (buffer.VectorisedView, uint8, bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		// A concurrent goroutine might have already reassembled
		// the packet and emptied the heap while this goroutine
		// was waiting on the mutex. We don't have to do anything in this case.
		return buffer.VectorisedView{}, 0, false, 0, nil
	}

	used, err := r.updateHoles(first, last, more)
	if err != nil {
		return buffer.VectorisedView{}, 0, false, 0, fmt.Errorf("fragment reassembly failed: %w", err)
	}

	var consumed int
	if used {
		// For IPv6, it is possible to have different Protocol values between
		// fragments of a packet (because, unlike IPv4, the Protocol is not used to
		// identify a fragment). In this case, only the Protocol of the first
		// fragment must be used as per RFC 8200 Section 4.5.
		//
		// TODO(gvisor.dev/issue/3648): During reassembly of an IPv6 packet, IP
		// options received in the first fragment should be used - and they should
		// override options from following fragments.
		if first == 0 {
			r.pkt = pkt
			r.proto = proto
		}
		vv := pkt.Data
		// We store the incoming packet only if it filled some holes.
		heap.Push(&r.heap, fragment{offset: first, vv: vv.Clone(nil)})
		consumed = vv.Size()
		r.size += consumed
	}

	// Check if all the holes have been filled and we are ready to reassemble.
	if r.filled < len(r.holes) {
		return buffer.VectorisedView{}, 0, false, consumed, nil
	}
	res, err := r.heap.reassemble()
	if err != nil {
		return buffer.VectorisedView{}, 0, false, 0, fmt.Errorf("fragment reassembly failed: %w", err)
	}
	return res, r.proto, true, consumed, nil
}

func (r *reassembler) checkDoneOrMark() bool {
	r.mu.Lock()
	prev := r.done
	r.done = true
	r.mu.Unlock()
	return prev
}
