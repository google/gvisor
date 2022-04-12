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

// PacketBufferCircularList is a slice-backed circular list. All operations are
// O(1) unless otherwise noted. It only allocates once, during the call to
// Init().
//
// Users should call Init() before using PacketBufferCircularList.
//
// +stateify savable
type PacketBufferCircularList struct {
	pbs  []PacketBufferPtr
	head int
	size int
}

// Init initializes the list with the given size.
//
//go:nosplit
func (pl *PacketBufferCircularList) Init(size int) {
	pl.pbs = make([]PacketBufferPtr, size)
}

// Front returns the first element of the list or nil.
//
//go:nosplit
func (pl *PacketBufferCircularList) Front() PacketBufferPtr {
	if pl.IsEmpty() {
		return PacketBufferPtr{}
	}
	return pl.pbs[pl.head]
}

// Len returns the number of elements in the list.
//
//go:nosplit
func (pl *PacketBufferCircularList) Len() int {
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
func (pl *PacketBufferCircularList) PushBack(pb PacketBufferPtr) {
	next := (pl.head + pl.size) % len(pl.pbs)
	pl.pbs[next] = pb
	pl.size++
}

// RemoveFront removes the first element of the list.
//
// Users must check beforehand that the list is not empty via IsEmpty().
//
//go:nosplit
func (pl *PacketBufferCircularList) RemoveFront() {
	pl.head = (pl.head + 1) % len(pl.pbs)
	pl.size--
}

// DecRef decreases the reference count on each PacketBuffer stored in the list.
//
// NOTE: runs in O(n) time.
//
//go:nosplit
func (pl *PacketBufferCircularList) DecRef() {
	for i := 0; i < pl.size; i++ {
		pl.pbs[(pl.head+i)%len(pl.pbs)].DecRef()
	}
}
