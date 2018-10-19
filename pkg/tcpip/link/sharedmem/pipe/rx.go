// Copyright 2018 Google LLC
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

package pipe

// Rx is the receive side of the shared memory ring buffer.
type Rx struct {
	p pipe

	tail uint64
	head uint64
}

// Init initializes the receive end of the pipe. In the initial state, the next
// slot to be inspected is the very first one.
func (r *Rx) Init(b []byte) {
	r.p.init(b)
	r.tail = 0xfffffffe * jump
	r.head = r.tail
}

// Pull reads the next buffer from the pipe, returning nil if there isn't one
// currently available.
//
// The returned slice is available until Flush() is next called. After that, it
// must not be touched.
func (r *Rx) Pull() []byte {
	if r.head == r.tail+jump {
		// We've already pulled the whole pipe.
		return nil
	}

	header := r.p.readAtomic(r.head)
	if header&slotFree != 0 {
		// The next slot is free, we can't pull it yet.
		return nil
	}

	payloadSize := header & slotSizeMask
	newHead := r.head + payloadToSlotSize(payloadSize)
	headWrap := (r.head & revolutionMask) | uint64(len(r.p.buffer))

	// Check if this is a wrapping slot. If that's the case, it carries no
	// data, so we just skip it and try again from the first slot.
	if int64(newHead-headWrap) >= 0 {
		if int64(newHead-headWrap) > int64(jump) || newHead&offsetMask != 0 {
			return nil
		}

		if r.tail == r.head {
			// If this is the first pull since the last Flush()
			// call, we flush the state so that the sender can use
			// this space if it needs to.
			r.p.writeAtomic(r.head, slotFree|slotToPayloadSize(newHead-r.head))
			r.tail = newHead
		}

		r.head = newHead
		return r.Pull()
	}

	// Grab the buffer before updating r.head.
	b := r.p.data(r.head, payloadSize)
	r.head = newHead
	return b
}

// Flush tells the transmitter that all buffers pulled since the last Flush()
// have been used, so the transmitter is free to used their slots for further
// transmission.
func (r *Rx) Flush() {
	if r.head == r.tail {
		return
	}
	r.p.writeAtomic(r.tail, slotFree|slotToPayloadSize(r.head-r.tail))
	r.tail = r.head
}

// Bytes returns the byte slice on which the pipe operates.
func (r *Rx) Bytes() []byte {
	return r.p.buffer
}
