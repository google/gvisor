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

// PacketBufferList is a slice-backed list. All operations are O(1) unless
// otherwise noted. It is optimized to for zero allocations when used with a
// queueing discipline.
//
// Users should call Init() before using PacketBufferList.
//
// +stateify savable
type PacketBufferList struct {
	pbs []PacketBufferPtr
}

// AsSlice returns a slice containing the packets in the list.
//
//go:nosplit
func (pl *PacketBufferList) AsSlice() []PacketBufferPtr {
	return pl.pbs
}

// Reset decrements all elements and resets the list to the empty state.
//
//go:nosplit
func (pl *PacketBufferList) Reset() {
	for i, pb := range pl.pbs {
		pb.DecRef()
		pl.pbs[i] = PacketBufferPtr{}
	}
	pl.pbs = pl.pbs[:0]
}

// Len returns the number of elements in the list.
//
//go:nosplit
func (pl *PacketBufferList) Len() int {
	return len(pl.pbs)
}

// PushBack inserts the PacketBuffer at the back of the list.
//
//go:nosplit
func (pl *PacketBufferList) PushBack(pb PacketBufferPtr) {
	pl.pbs = append(pl.pbs, pb)
}

// DecRef decreases the reference count on each PacketBuffer
// stored in the list.
//
// NOTE: runs in O(n) time.
//
//go:nosplit
func (pl PacketBufferList) DecRef() {
	for _, pb := range pl.pbs {
		pb.DecRef()
	}
}
