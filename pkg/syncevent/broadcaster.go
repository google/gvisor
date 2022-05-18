// Copyright 2020 The gVisor Authors.
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

package syncevent

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// Broadcaster is an implementation of Source that supports any number of
// subscribed Receivers.
//
// The zero value of Broadcaster is valid and has no subscribed Receivers.
// Broadcaster is not copyable by value.
//
// All Broadcaster methods may be called concurrently from multiple goroutines.
type Broadcaster struct {
	// Broadcaster is implemented as a hash table where keys are assigned by
	// the Broadcaster and returned as SubscriptionIDs, making it safe to use
	// the identity function for hashing. The hash table resolves collisions
	// using linear probing and features Robin Hood insertion and backward
	// shift deletion in order to support a relatively high load factor
	// efficiently, which matters since the cost of Broadcast is linear in the
	// size of the table.

	// mu protects the following fields.
	mu sync.Mutex

	// Invariants: len(table) is 0 or a power of 2.
	table []broadcasterSlot

	// load is the number of entries in table with receiver != nil.
	load int

	lastID SubscriptionID
}

type broadcasterSlot struct {
	// Invariants: If receiver == nil, then filter == NoEvents and id == 0.
	// Otherwise, id != 0.
	receiver *Receiver
	filter   Set
	id       SubscriptionID
}

const (
	broadcasterMinNonZeroTableSize = 2 // must be a power of 2 > 1

	broadcasterMaxLoadNum = 13
	broadcasterMaxLoadDen = 16
)

// SubscribeEvents implements Source.SubscribeEvents.
func (b *Broadcaster) SubscribeEvents(r *Receiver, filter Set) SubscriptionID {
	b.mu.Lock()

	// Assign an ID for this subscription.
	b.lastID++
	id := b.lastID

	// Expand the table if over the maximum load factor:
	//
	//          load / len(b.table) > broadcasterMaxLoadNum / broadcasterMaxLoadDen
	// load * broadcasterMaxLoadDen > broadcasterMaxLoadNum * len(b.table)
	b.load++
	if (b.load * broadcasterMaxLoadDen) > (broadcasterMaxLoadNum * len(b.table)) {
		// Double the number of slots in the new table.
		newlen := broadcasterMinNonZeroTableSize
		if len(b.table) != 0 {
			newlen = 2 * len(b.table)
		}
		if newlen <= cap(b.table) {
			// Reuse excess capacity in the current table, moving entries not
			// already in their first-probed positions to better ones.
			newtable := b.table[:newlen]
			newmask := uint64(newlen - 1)
			for i := range b.table {
				if b.table[i].receiver != nil && uint64(b.table[i].id)&newmask != uint64(i) {
					entry := b.table[i]
					b.table[i] = broadcasterSlot{}
					broadcasterTableInsert(newtable, entry.id, entry.receiver, entry.filter)
				}
			}
			b.table = newtable
		} else {
			newtable := make([]broadcasterSlot, newlen)
			// Copy existing entries to the new table.
			for i := range b.table {
				if b.table[i].receiver != nil {
					broadcasterTableInsert(newtable, b.table[i].id, b.table[i].receiver, b.table[i].filter)
				}
			}
			// Switch to the new table.
			b.table = newtable
		}
	}

	broadcasterTableInsert(b.table, id, r, filter)
	b.mu.Unlock()
	return id
}

// Preconditions:
//   - table must not be full.
//   - len(table) is a power of 2.
func broadcasterTableInsert(table []broadcasterSlot, id SubscriptionID, r *Receiver, filter Set) {
	entry := broadcasterSlot{
		receiver: r,
		filter:   filter,
		id:       id,
	}
	mask := uint64(len(table) - 1)
	i := uint64(id) & mask
	disp := uint64(0)
	for {
		if table[i].receiver == nil {
			table[i] = entry
			return
		}
		// If we've been displaced farther from our first-probed slot than the
		// element stored in this one, swap elements and switch to inserting
		// the replaced one. (This is Robin Hood insertion.)
		slotDisp := (i - uint64(table[i].id)) & mask
		if disp > slotDisp {
			table[i], entry = entry, table[i]
			disp = slotDisp
		}
		i = (i + 1) & mask
		disp++
	}
}

// UnsubscribeEvents implements Source.UnsubscribeEvents.
func (b *Broadcaster) UnsubscribeEvents(id SubscriptionID) {
	b.mu.Lock()

	mask := uint64(len(b.table) - 1)
	i := uint64(id) & mask
	for {
		if b.table[i].id == id {
			// Found the element to remove. Move all subsequent elements
			// backward until we either find an empty slot, or an element that
			// is already in its first-probed slot. (This is backward shift
			// deletion.)
			for {
				next := (i + 1) & mask
				if b.table[next].receiver == nil {
					break
				}
				if uint64(b.table[next].id)&mask == next {
					break
				}
				b.table[i] = b.table[next]
				i = next
			}
			b.table[i] = broadcasterSlot{}
			break
		}
		i = (i + 1) & mask
	}

	// If a table 1/4 of the current size would still be at or under the
	// maximum load factor (i.e. the current table size is at least two
	// expansions bigger than necessary), halve the size of the table to reduce
	// the cost of Broadcast. Since we are concerned with iteration time and
	// not memory usage, reuse the existing slice to reduce future allocations
	// from table re-expansion.
	b.load--
	if len(b.table) > broadcasterMinNonZeroTableSize && (b.load*(4*broadcasterMaxLoadDen)) <= (broadcasterMaxLoadNum*len(b.table)) {
		newlen := len(b.table) / 2
		newtable := b.table[:newlen]
		for i := newlen; i < len(b.table); i++ {
			if b.table[i].receiver != nil {
				broadcasterTableInsert(newtable, b.table[i].id, b.table[i].receiver, b.table[i].filter)
				b.table[i] = broadcasterSlot{}
			}
		}
		b.table = newtable
	}

	b.mu.Unlock()
}

// Broadcast notifies all Receivers subscribed to the Broadcaster of the subset
// of events to which they subscribed. The order in which Receivers are
// notified is unspecified.
func (b *Broadcaster) Broadcast(events Set) {
	b.mu.Lock()
	for i := range b.table {
		if intersection := events & b.table[i].filter; intersection != 0 {
			// We don't need to check if broadcasterSlot.receiver is nil, since
			// if it is then broadcasterSlot.filter is 0.
			b.table[i].receiver.Notify(intersection)
		}
	}
	b.mu.Unlock()
}

// FilteredEvents returns the set of events for which Broadcast will notify at
// least one Receiver, i.e. the union of filters for all subscribed Receivers.
func (b *Broadcaster) FilteredEvents() Set {
	var es Set
	b.mu.Lock()
	for i := range b.table {
		es |= b.table[i].filter
	}
	b.mu.Unlock()
	return es
}
