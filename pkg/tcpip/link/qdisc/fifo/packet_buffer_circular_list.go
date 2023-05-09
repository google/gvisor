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

package fifo

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// packetBufferCircularList is a slice-backed circular list. All operations are
// O(1) unless otherwise noted. It only allocates once, during the call to
// init().
//
// Users should call init() before using packetBufferCircularList.
//
// +stateify savable
type packetBufferCircularList struct {
	pbs  []stack.PacketBufferPtr
	head int
	size int
}

// init initializes the list with the given size.
func (pl *packetBufferCircularList) init(size int) {
	pl.pbs = make([]stack.PacketBufferPtr, size)
}

// length returns the number of elements in the list.
//
//go:nosplit
func (pl *packetBufferCircularList) length() int {
	return pl.size
}

// hasSpace returns whether there is space left in the list.
//
//go:nosplit
func (pl *packetBufferCircularList) hasSpace() bool {
	return pl.size < len(pl.pbs)
}

// isEmpty returns whether the list is empty.
//
//go:nosplit
func (pl *packetBufferCircularList) isEmpty() bool {
	return pl.size == 0
}

// pushBack inserts the PacketBuffer at the end of the list.
//
// Users must check beforehand that there is space via a call to hasSpace().
// Failing to do so may clobber existing entries.
//
//go:nosplit
func (pl *packetBufferCircularList) pushBack(pb stack.PacketBufferPtr) {
	next := (pl.head + pl.size) % len(pl.pbs)
	pl.pbs[next] = pb
	pl.size++
}

// removeFront returns the first element of the list or nil.
//
//go:nosplit
func (pl *packetBufferCircularList) removeFront() stack.PacketBufferPtr {
	if pl.isEmpty() {
		return stack.PacketBufferPtr{}
	}
	ret := pl.pbs[pl.head]
	pl.pbs[pl.head] = stack.PacketBufferPtr{}
	pl.head = (pl.head + 1) % len(pl.pbs)
	pl.size--
	return ret
}

// decRef decreases the reference count on each stack.PacketBuffer stored in
// the list.
//
// NOTE: runs in O(n) time.
//
//go:nosplit
func (pl *packetBufferCircularList) decRef() {
	for i := 0; i < pl.size; i++ {
		pl.pbs[(pl.head+i)%len(pl.pbs)].DecRef()
	}
}
