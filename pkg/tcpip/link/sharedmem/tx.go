// Copyright 2018 The gVisor Authors.
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

package sharedmem

import (
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
)

const (
	nilID = math.MaxUint64
)

// tx holds all state associated with a tx queue.
type tx struct {
	data []byte
	q    queue.Tx
	ids  idManager
	bufs bufferManager
}

// init initializes all state needed by the tx queue based on the information
// provided.
//
// The caller always retains ownership of all file descriptors passed in. The
// queue implementation will duplicate any that it may need in the future.
func (t *tx) init(mtu uint32, c *QueueConfig) error {
	// Map in all buffers.
	txPipe, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}

	rxPipe, err := getBuffer(c.RxPipeFD)
	if err != nil {
		unix.Munmap(txPipe)
		return err
	}

	data, err := getBuffer(c.DataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		return err
	}

	// Initialize state based on buffers.
	t.q.Init(txPipe, rxPipe)
	t.ids.init()
	t.bufs.init(0, len(data), int(mtu))
	t.data = data

	return nil
}

// cleanup releases all resources allocated during init(). It must only be
// called if init() has previously succeeded.
func (t *tx) cleanup() {
	a, b := t.q.Bytes()
	unix.Munmap(a)
	unix.Munmap(b)
	unix.Munmap(t.data)
}

// transmit sends a packet made of bufs. Returns a boolean that specifies
// whether the packet was successfully transmitted.
func (t *tx) transmit(bufs ...buffer.View) bool {
	// Pull completions from the tx queue and add their buffers back to the
	// pool so that we can reuse them.
	for {
		id, ok := t.q.CompletedPacket()
		if !ok {
			break
		}

		if buf := t.ids.remove(id); buf != nil {
			t.bufs.free(buf)
		}
	}

	bSize := t.bufs.entrySize
	total := uint32(0)
	for _, data := range bufs {
		total += uint32(len(data))
	}
	bufCount := (total + bSize - 1) / bSize

	// Allocate enough buffers to hold all the data.
	var buf *queue.TxBuffer
	for i := bufCount; i != 0; i-- {
		b := t.bufs.alloc()
		if b == nil {
			// Failed to get all buffers. Return to the pool
			// whatever we had managed to get.
			if buf != nil {
				t.bufs.free(buf)
			}
			return false
		}
		b.Next = buf
		buf = b
	}

	// Copy data into allocated buffers.
	nBuf := buf
	var dBuf []byte
	for _, data := range bufs {
		for len(data) > 0 {
			if len(dBuf) == 0 {
				dBuf = t.data[nBuf.Offset:][:nBuf.Size]
				nBuf = nBuf.Next
			}
			n := copy(dBuf, data)
			data = data[n:]
			dBuf = dBuf[n:]
		}
	}

	// Get an id for this packet and send it out.
	id := t.ids.add(buf)
	if !t.q.Enqueue(id, total, bufCount, buf) {
		t.ids.remove(id)
		t.bufs.free(buf)
		return false
	}

	return true
}

// getBuffer returns a memory region mapped to the full contents of the given
// file descriptor.
func getBuffer(fd int) ([]byte, error) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return nil, err
	}

	// Check that size doesn't overflow an int.
	if s.Size > int64(^uint(0)>>1) {
		return nil, unix.EDOM
	}

	return unix.Mmap(fd, 0, int(s.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FILE)
}

// idDescriptor is used by idManager to either point to a tx buffer (in case
// the ID is assigned) or to the next free element (if the id is not assigned).
type idDescriptor struct {
	buf      *queue.TxBuffer
	nextFree uint64
}

// idManager is a manager of tx buffer identifiers. It assigns unique IDs to
// tx buffers that are added to it; the IDs can only be reused after they have
// been removed.
//
// The ID assignments are stored so that the tx buffers can be retrieved from
// the IDs previously assigned to them.
type idManager struct {
	// ids is a slice containing all tx buffers. The ID is the index into
	// this slice.
	ids []idDescriptor

	// freeList a list of free IDs.
	freeList uint64
}

// init initializes the id manager.
func (m *idManager) init() {
	m.freeList = nilID
}

// add assigns an ID to the given tx buffer.
func (m *idManager) add(b *queue.TxBuffer) uint64 {
	if i := m.freeList; i != nilID {
		// There is an id available in the free list, just use it.
		m.ids[i].buf = b
		m.freeList = m.ids[i].nextFree
		return i
	}

	// We need to expand the id descriptor.
	m.ids = append(m.ids, idDescriptor{buf: b})
	return uint64(len(m.ids) - 1)
}

// remove retrieves the tx buffer associated with the given ID, and removes the
// ID from the assigned table so that it can be reused in the future.
func (m *idManager) remove(i uint64) *queue.TxBuffer {
	if i >= uint64(len(m.ids)) {
		return nil
	}

	desc := &m.ids[i]
	b := desc.buf
	if b == nil {
		// The provided id is not currently assigned.
		return nil
	}

	desc.buf = nil
	desc.nextFree = m.freeList
	m.freeList = i

	return b
}

// bufferManager manages a buffer region broken up into smaller, equally sized
// buffers. Smaller buffers can be allocated and freed.
type bufferManager struct {
	freeList  *queue.TxBuffer
	curOffset uint64
	limit     uint64
	entrySize uint32
}

// init initializes the buffer manager.
func (b *bufferManager) init(initialOffset, size, entrySize int) {
	b.freeList = nil
	b.curOffset = uint64(initialOffset)
	b.limit = uint64(initialOffset + size/entrySize*entrySize)
	b.entrySize = uint32(entrySize)
}

// alloc allocates a buffer from the manager, if one is available.
func (b *bufferManager) alloc() *queue.TxBuffer {
	if b.freeList != nil {
		// There is a descriptor ready for reuse in the free list.
		d := b.freeList
		b.freeList = d.Next
		d.Next = nil
		return d
	}

	if b.curOffset < b.limit {
		// There is room available in the never-used range, so create
		// a new descriptor for it.
		d := &queue.TxBuffer{
			Offset: b.curOffset,
			Size:   b.entrySize,
		}
		b.curOffset += uint64(b.entrySize)
		return d
	}

	return nil
}

// free returns all buffers in the list to the buffer manager so that they can
// be reused.
func (b *bufferManager) free(d *queue.TxBuffer) {
	// Find the last buffer in the list.
	last := d
	for last.Next != nil {
		last = last.Next
	}

	// Push list onto free list.
	last.Next = b.freeList
	b.freeList = d
}
