// Copyright 2022 The gVisor Authors.
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

// Package qdisc provides shared building blocks used by queueing disciplines.
package qdisc

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// PacketBufferCircularList is a slice-backed circular list. All operations are
// O(1) unless otherwise noted. It only allocates once, during the call to
// Init().
//
// Users should call Init() before using PacketBufferCircularList.
//
// +stateify savable
type PacketBufferCircularList struct {
	pbs  []*stack.PacketBuffer
	head int
	size int
}

// Init initializes the list with the given size.
func (pl *PacketBufferCircularList) Init(size int) {
	pl.pbs = make([]*stack.PacketBuffer, size)
}

// Length returns the number of elements in the list.
//
//go:nosplit
func (pl *PacketBufferCircularList) Length() int {
	return pl.size
}

// HasSpace returns whether there is space left in the list.
//
//go:nosplit
func (pl *PacketBufferCircularList) HasSpace() bool {
	return pl.size < len(pl.pbs)
}

// IsEmpty returns whether the list is empty.
//
//go:nosplit
func (pl *PacketBufferCircularList) IsEmpty() bool {
	return pl.size == 0
}

// PushBack inserts the PacketBuffer at the end of the list.
//
// Users must check beforehand that there is space via a call to HasSpace().
// Failing to do so may clobber existing entries.
//
//go:nosplit
func (pl *PacketBufferCircularList) PushBack(pb *stack.PacketBuffer) {
	next := (pl.head + pl.size) % len(pl.pbs)
	pl.pbs[next] = pb
	pl.size++
}


// PeekFront returns the first element of the list without removing it, or nil
// if empty. The list retains its reference; the caller must not DecRef. To take
// ownership, call RemoveFront, which returns the same pointer. The returned
// pointer is only valid until the next mutation of the list.
//
//go:nosplit
func (pl *PacketBufferCircularList) PeekFront() *stack.PacketBuffer {
	if pl.IsEmpty() {
		return nil
	}
	return pl.pbs[pl.head]
}

// RemoveFront returns the first element of the list or nil.
//
//go:nosplit
func (pl *PacketBufferCircularList) RemoveFront() *stack.PacketBuffer {
	if pl.IsEmpty() {
		return nil
	}
	ret := pl.pbs[pl.head]
	pl.pbs[pl.head] = nil
	pl.head = (pl.head + 1) % len(pl.pbs)
	pl.size--
	return ret
}

// DecRef decreases the reference count on each stack.PacketBuffer stored in
// the list.
//
// NOTE: runs in O(n) time.
//
//go:nosplit
func (pl *PacketBufferCircularList) DecRef() {
	for i := 0; i < pl.size; i++ {
		pl.pbs[(pl.head+i)%len(pl.pbs)].DecRef()
	}
}
