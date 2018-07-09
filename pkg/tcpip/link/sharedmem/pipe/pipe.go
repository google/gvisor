// Copyright 2018 Google Inc.
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

// Package pipe implements a shared memory ring buffer on which a single reader
// and a single writer can operate (read/write) concurrently. The ring buffer
// allows for data of different sizes to be written, and preserves the boundary
// of the written data.
//
// Example usage is as follows:
//
//	wb := t.Push(20)
//	// Write data to wb.
//	t.Flush()
//
//	rb := r.Pull()
//	// Do something with data in rb.
//	t.Flush()
package pipe

import (
	"math"
)

const (
	jump           uint64 = math.MaxUint32 + 1
	offsetMask     uint64 = math.MaxUint32
	revolutionMask uint64 = ^offsetMask

	sizeOfSlotHeader        = 8 // sizeof(uint64)
	slotFree         uint64 = 1 << 63
	slotSizeMask     uint64 = math.MaxUint32
)

// payloadToSlotSize calculates the total size of a slot based on its payload
// size. The  total size is the header size, plus the payload size, plus padding
// if necessary to make the total size a multiple of sizeOfSlotHeader.
func payloadToSlotSize(payloadSize uint64) uint64 {
	s := sizeOfSlotHeader + payloadSize
	return (s + sizeOfSlotHeader - 1) &^ (sizeOfSlotHeader - 1)
}

// slotToPayloadSize calculates the payload size of a slot based on the total
// size of the slot. This is only meant to be used when creating slots that
// don't carry information (e.g., free slots or wrap slots).
func slotToPayloadSize(offset uint64) uint64 {
	return offset - sizeOfSlotHeader
}

// pipe is a basic data structure used by both (transmit & receive) ends of a
// pipe. Indices into this pipe are split into two fields: offset, which counts
// the number of bytes from the beginning of the buffer, and revolution, which
// counts the number of times the index has wrapped around.
type pipe struct {
	buffer []byte
}

// init initializes the pipe buffer such that its size is a multiple of the size
// of the slot header.
func (p *pipe) init(b []byte) {
	p.buffer = b[:len(b)&^(sizeOfSlotHeader-1)]
}

// data returns a section of the buffer starting at the given index (which may
// include revolution information) and with the given size.
func (p *pipe) data(idx uint64, size uint64) []byte {
	return p.buffer[(idx&offsetMask)+sizeOfSlotHeader:][:size]
}
