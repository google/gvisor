// Copyright 2026 The gVisor Authors.
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

package state

import "math/bits"

// addrMap maps non-maximal uintptr keys, such as addresses, to int32 values.
// It uses open addressing with linear probing, which is faster than Go maps
// for these keys.
//
// Like Go maps, addrMap is not safe for concurrent use by multiple goroutines.
type addrMap struct {
	// slots holds keys plus one, so that zero marks empty slots.
	slots []addrSlot
	n     int
	// shift is 64 minus the log2 of len(slots).
	shift uint
}

type addrSlot struct {
	key uintptr
	val int32
}

// minAddrMapSize is the minimum number of slots.
const minAddrMapSize = 64

// init allocates m for about n entries.
func (m *addrMap) init(n int) {
	if n > 1<<29 {
		Failf("address map size %d too large", n)
	}
	size := minAddrMapSize
	for size < 2*n {
		size *= 2
	}
	m.slots = make([]addrSlot, size)
	m.n = 0
	m.shift = uint(64 - bits.TrailingZeros(uint(size)))
}

func (m *addrMap) index(k uintptr) int {
	// Fibonacci hashing spreads nearby keys.
	return int((uint64(k) * 0x9e3779b97f4a7c15) >> m.shift)
}

// get returns the value of k.
func (m *addrMap) get(k uintptr) (int32, bool) {
	if m.slots == nil || k == ^uintptr(0) {
		return 0, false
	}
	k++
	mask := len(m.slots) - 1
	for i := m.index(k); ; i = (i + 1) & mask {
		s := &m.slots[i]
		if s.key == k {
			return s.val, true
		}
		if s.key == 0 {
			return 0, false
		}
	}
}

// set sets the value of k.
func (m *addrMap) set(k uintptr, v int32) {
	if k == ^uintptr(0) {
		Failf("invalid address map key %#x", k)
	}
	if 2*(m.n+1) > len(m.slots) {
		m.grow()
	}
	k++
	mask := len(m.slots) - 1
	for i := m.index(k); ; i = (i + 1) & mask {
		s := &m.slots[i]
		if s.key == k {
			s.val = v
			return
		}
		if s.key == 0 {
			s.key, s.val = k, v
			m.n++
			return
		}
	}
}

func (m *addrMap) grow() {
	old := m.slots
	m.init(max(len(old), minAddrMapSize/2))
	for _, s := range old {
		if s.key != 0 {
			m.set(s.key-1, s.val)
		}
	}
}

// reset removes all entries.
func (m *addrMap) reset() {
	clear(m.slots)
	m.n = 0
}
