// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pipe

// Tx is the transmit side of the shared memory ring buffer.
type Tx struct {
	p              pipe
	maxPayloadSize uint64

	head uint64
	tail uint64
	next uint64

	tailHeader uint64
}

// Init initializes the transmit end of the pipe. In the initial state, the next
// slot to be written is the very first one, and the transmitter has the whole
// ring buffer available to it.
func (t *Tx) Init(b []byte) {
	t.p.init(b)
	// maxPayloadSize excludes the header of the payload, and the header
	// of the wrapping message.
	t.maxPayloadSize = uint64(len(t.p.buffer)) - 2*sizeOfSlotHeader
	t.tail = 0xfffffffe * jump
	t.next = t.tail
	t.head = t.tail + jump
	t.p.write(t.tail, slotFree)
}

// Capacity determines how many records of the given size can be written to the
// pipe before it fills up.
func (t *Tx) Capacity(recordSize uint64) uint64 {
	available := uint64(len(t.p.buffer)) - sizeOfSlotHeader
	entryLen := payloadToSlotSize(recordSize)
	return available / entryLen
}

// Push reserves "payloadSize" bytes for transmission in the pipe. The caller
// populates the returned slice with the data to be transferred and enventually
// calls Flush() to make the data visible to the reader, or Abort() to make the
// pipe forget all Push() calls since the last Flush().
//
// The returned slice is available until Flush() or Abort() is next called.
// After that, it must not be touched.
func (t *Tx) Push(payloadSize uint64) []byte {
	// Fail request if we know we will never have enough room.
	if payloadSize > t.maxPayloadSize {
		return nil
	}

	totalLen := payloadToSlotSize(payloadSize)
	newNext := t.next + totalLen
	nextWrap := (t.next & revolutionMask) | uint64(len(t.p.buffer))
	if int64(newNext-nextWrap) >= 0 {
		// The new buffer would overflow the pipe, so we push a wrapping
		// slot, then try to add the actual slot to the front of the
		// pipe.
		newNext = (newNext & revolutionMask) + jump
		wrappingPayloadSize := slotToPayloadSize(newNext - t.next)
		if !t.reclaim(newNext) {
			return nil
		}

		oldNext := t.next
		t.next = newNext
		if oldNext != t.tail {
			t.p.write(oldNext, wrappingPayloadSize)
		} else {
			t.tailHeader = wrappingPayloadSize
			t.Flush()
		}

		newNext += totalLen
	}

	// Check that we have enough room for the buffer.
	if !t.reclaim(newNext) {
		return nil
	}

	if t.next != t.tail {
		t.p.write(t.next, payloadSize)
	} else {
		t.tailHeader = payloadSize
	}

	// Grab the buffer before updating t.next.
	b := t.p.data(t.next, payloadSize)
	t.next = newNext

	return b
}

// reclaim attempts to advance the head until at least newNext. If the head is
// already at or beyond newNext, nothing happens and true is returned; otherwise
// it tries to reclaim slots that have already been consumed by the receive end
// of the pipe (they will be marked as free) and returns a boolean indicating
// whether it was successful in reclaiming enough slots.
func (t *Tx) reclaim(newNext uint64) bool {
	for int64(newNext-t.head) > 0 {
		// Can't reclaim if slot is not free.
		header := t.p.readAtomic(t.head)
		if header&slotFree == 0 {
			return false
		}

		payloadSize := header & slotSizeMask
		newHead := t.head + payloadToSlotSize(payloadSize)

		// Check newHead is within bounds and valid.
		if int64(newHead-t.tail) > int64(jump) || newHead&offsetMask >= uint64(len(t.p.buffer)) {
			return false
		}

		t.head = newHead
	}

	return true
}

// Abort causes all Push() calls since the last Flush() to be forgotten and
// therefore they will not be made visible to the receiver.
func (t *Tx) Abort() {
	t.next = t.tail
}

// Flush causes all buffers pushed since the last Flush() [or Abort(), whichever
// is the most recent] to be made visible to the receiver.
func (t *Tx) Flush() {
	if t.next == t.tail {
		// Nothing to do if there are no pushed buffers.
		return
	}

	if t.next != t.head {
		// The receiver will spin in t.next, so we must make sure that
		// the slotFree bit is set.
		t.p.write(t.next, slotFree)
	}

	t.p.writeAtomic(t.tail, t.tailHeader)
	t.tail = t.next
}

// Bytes returns the byte slice on which the pipe operates.
func (t *Tx) Bytes() []byte {
	return t.p.buffer
}
