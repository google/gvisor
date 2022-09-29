// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"math/bits"
	"runtime"
	"sync"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// TODO: Make generic.
// TODO: Reuse with segments.

const (
	// enableLogging indicates whether reference-related events should be logged
	// (with stack traces). This is false by default and should only be set to
	// true for debugging purposes, as it can generate an extremely large amount
	// of output and drastically degrade performance.
	enableLogging = false

	upgradingState = 1 << 62
	upgradedState  = 1 << 63
)

// Refs keeps a reference count. It calls a destructor upon reaching zero. It
// prevents double-decrementing by giving out unique references called Tickets
// that are only valid for a single call to DecRef().
//
// Refs is optimized for small-magnitude reference counting. This makes it well
// suited for PacketBuffers, which are typically incremented only a few times:
// e.g. at creation, when handed off to the TCP package, and when enqueued at a
// socket. As long as there 62 or fewer references taken over the lifetime of
// an object, Refs can increment and decrement the reference count with two
// atomic operations. If there are more than 62, it falls back on a slower,
// mutex-based implementation.
//
// Normal networking should never use the slow path. Hitting the slow path
// requires pathological use cases, e.g. opening a TCP socket and 62+ packet
// sockets.
//
// +stateify savable
type Refs struct {
	// Refs begins as a bitset. Each bit is a Ticket: the caller of
	// NewPacketBuffer gets Ticket 1, the first caller of IncRef gets 2, the next
	// gets 4, etc. It also keeps a leftmost "marker bit" to track the next
	// Ticket to distribute. So if the bitset looks like this:
	//
	//   0000....011010.
	//
	// The meaning is: references 1 and 4 have been passed to DecRef, references
	// 2 and 8 are live, and the marker bit indicates that 16 is the next Ticket
	// to distributes.
	//
	// The 2 most significant bits are reserved to indicate that too many
	// references have been given out, and the counter will "upgrade" to the
	// slower implementation. When a call to IncRef acquires the second most
	// significant bit (the "upgrading bit") it puts all live Ticket values into
	// the tickets slice, then sets the most significant bit (the "upgraded
	// bit"). Any operations on Refs that observe the upgrading bit loop until
	// the upgrade is complete. Any operations that observe the upgraded bit use
	// the slow path. Because the bitset is modified in a CompareAndSwap loop,
	// the reference count maintains a consistent state.
	bitset atomicbitops.Uint64

	// The slow stuff. Only used when we run out of bits in our bitset.
	mu         sync.Mutex
	tickets    []Ticket
	nextTicket uint64
}

// Ticket provides a way of DecRefing a reference exactly once.
type Ticket struct {
	val uint64
}

// InitRefs initializes rf with one reference and, if enabled, activates leak
// checking.
//
//go:nosplit
func (rf *Refs) InitRefs() Ticket {
	// The least significant 2 bits will be set in the bitset: the first ticket
	// (1) and the marker flag (2).
	ticket := Ticket{1}
	rf.bitset = atomicbitops.FromUint64(0b11)
	refsvfs2.Register(rf)
	return ticket
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
//
//go:nosplit
func (rf *Refs) ReadRefs() int64 {
	for {
		cur := rf.bitset.Load()
		if cur&upgradingState == upgradingState {
			// Yield while waiting for the upgrade, which should be brief.
			runtime.Gosched()
			continue
		}
		if cur&upgradedState == upgradedState {
			rf.mu.Lock()
			defer rf.mu.Unlock()
			return int64(len(rf.tickets))
		}
		return int64(bits.OnesCount64(rf.bitset.Load()) - 1)
	}
}

// IncRef increments the reference count.
//
//go:nosplit
func (rf *Refs) IncRef() Ticket {
	// Fast path.
	for {
		cur := rf.bitset.Load()
		if cur&upgradingState == upgradingState {
			// Yield while waiting for the upgrade, which should be brief.
			runtime.Gosched()
			continue
		}
		if cur&upgradedState == upgradedState {
			break
		}

		if bits.OnesCount64(cur) <= 1 {
			// The only bit set is the marker bit, so this has a refcount of zero.
			panic(fmt.Sprintf("Incrementing non-positive count %p on %s", rf, rf.RefType()))
		}

		// Reserve a ticket.
		bitsLeft := bits.LeadingZeros64(cur)
		markerVal := uint64(1) << (64 - bitsLeft)
		if !rf.bitset.CompareAndSwap(cur, cur|markerVal) {
			continue
		}
		ticketVal := markerVal >> 1

		// The common case.
		if markerVal != upgradingState {
			return Ticket{ticketVal}
		}

		// We've given out all 63 tickets. Provide a slow, mutex-based ticket and
		// convert existing tickets to mutex tickets.
		rf.mu.Lock()
		rf.tickets = make([]Ticket, 0, 128)
		for i := 0; i < 62; i++ {
			if ticket := (cur | upgradingState) & (uint64(1) << i); ticket != 0 {
				rf.tickets = append(rf.tickets, Ticket{ticket})
			}
		}
		rf.mu.Unlock()

		if !rf.bitset.CompareAndSwap(cur|upgradingState, upgradedState) {
			panic("other goroutines should not race to modify rf.bitset")
		}
		return Ticket{ticketVal}
	}

	// Slow path.
	rf.mu.Lock()

	// We can't give out tickets with a power of two value.
	for bits.OnesCount64(rf.nextTicket) == 1 {
		rf.nextTicket++
	}
	ticket := Ticket{rf.nextTicket}
	rf.nextTicket++
	rf.tickets = append(rf.tickets, ticket)

	if enableLogging {
		refsvfs2.LogIncRef(rf, int64(len(rf.tickets)))
	}

	if len(rf.tickets) <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", rf, rf.RefType()))
	}

	rf.mu.Unlock()
	return ticket
}

// DecRef decrements the reference count.
//
//go:nosplit
func (rf *Refs) DecRef(ticket Ticket, destroy func(*PacketBufferPtr), pk *PacketBufferPtr) {
	// log.Printf("kmk(%p): DecRef called from: %s", rf, string(debug.Stack()))
	for {
		cur := rf.bitset.Load()
		if cur&upgradingState == upgradingState {
			// Yield while waiting for the upgrade, which should be brief.
			runtime.Gosched()
			continue
		}
		if cur&upgradedState == upgradedState {
			break
		}

		// Is this a valid ticket?
		if cur&ticket.val != ticket.val {
			panic(fmt.Sprintf("Tried to DecRef (%p) with non-existent ticket %d, owned by %s", rf, ticket.val, rf.RefType()))
		}

		// Update the refcount.
		if newVal := cur &^ ticket.val; rf.bitset.CompareAndSwap(cur, newVal) {
			// If only the marker flag is left, we've hit zero references.
			if bits.OnesCount64(newVal) == 1 {
				refsvfs2.Unregister(rf)
				// Call the destructor.
				if destroy != nil {
					destroy(pk)
				}
			}
			return
		}
	}

	// Slow path.
	rf.mu.Lock()
	count := len(rf.tickets)
	if count == 0 {
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", rf, rf.RefType()))
	}

	for i, other := range rf.tickets {
		if ticket != other {
			continue
		}

		if enableLogging {
			refsvfs2.LogDecRef(rf, int64(len(rf.tickets)))
		}

		rf.tickets = append(rf.tickets[:i], rf.tickets[i+1:]...)
		rf.mu.Unlock()
		if count == 1 {
			refsvfs2.Unregister(rf)
			// Call the destructor.
			if destroy != nil {
				destroy(pk)
			}
		}

		return
	}

	panic(fmt.Sprintf("Tried to DecRef with non-existent ticket %d, owned by %s", ticket.val, rf.RefType()))
}

// RefType implements refsvfs2.CheckedObject.RefType.
//
//go:nosplit
func (rf *Refs) RefType() string {
	return "packetBuffer"
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
//
//go:nosplit
func (rf *Refs) LeakMessage() string {
	return fmt.Sprintf("[%s %p] reference count of %d instead of 0", rf.RefType(), rf, rf.ReadRefs())
}

// LogRefs implements refsvfs2.CheckedObject.LogRefs.
//
//go:nosplit
func (rf *Refs) LogRefs() bool {
	return enableLogging
}

func (rf *Refs) afterLoad() {
	if rf.ReadRefs() > 0 {
		refsvfs2.Register(rf)
	}
}
