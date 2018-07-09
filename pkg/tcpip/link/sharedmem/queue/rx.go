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

// Package queue provides the implementation of transmit and receive queues
// based on shared memory ring buffers.
package queue

import (
	"encoding/binary"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sharedmem/pipe"
)

const (
	// Offsets within a posted buffer.
	postedOffset           = 0
	postedSize             = 8
	postedRemainingInGroup = 12
	postedUserData         = 16
	postedID               = 24

	sizeOfPostedBuffer = 32

	// Offsets within a received packet header.
	consumedPacketSize     = 0
	consumedPacketReserved = 4

	sizeOfConsumedPacketHeader = 8

	// Offsets within a consumed buffer.
	consumedOffset   = 0
	consumedSize     = 8
	consumedUserData = 12
	consumedID       = 20

	sizeOfConsumedBuffer = 28

	// The following are the allowed states of the shared data area.
	eventFDUninitialized = 0
	eventFDDisabled      = 1
	eventFDEnabled       = 2
)

// RxBuffer is the descriptor of a receive buffer.
type RxBuffer struct {
	Offset   uint64
	Size     uint32
	ID       uint64
	UserData uint64
}

// Rx is a receive queue. It is implemented with one tx and one rx pipe: the tx
// pipe is used to "post" buffers, while the rx pipe is used to receive packets
// whose contents have been written to previously posted buffers.
//
// This struct is thread-compatible.
type Rx struct {
	tx                 pipe.Tx
	rx                 pipe.Rx
	sharedEventFDState *uint32
}

// Init initializes the receive queue with the given pipes, and shared state
// pointer -- the latter is used to enable/disable eventfd notifications.
func (r *Rx) Init(tx, rx []byte, sharedEventFDState *uint32) {
	r.sharedEventFDState = sharedEventFDState
	r.tx.Init(tx)
	r.rx.Init(rx)
}

// EnableNotification updates the shared state such that the peer will notify
// the eventfd when there are packets to be dequeued.
func (r *Rx) EnableNotification() {
	atomic.StoreUint32(r.sharedEventFDState, eventFDEnabled)
}

// DisableNotification updates the shared state such that the peer will not
// notify the eventfd.
func (r *Rx) DisableNotification() {
	atomic.StoreUint32(r.sharedEventFDState, eventFDDisabled)
}

// PostedBuffersLimit returns the maximum number of buffers that can be posted
// before the tx queue fills up.
func (r *Rx) PostedBuffersLimit() uint64 {
	return r.tx.Capacity(sizeOfPostedBuffer)
}

// PostBuffers makes the given buffers available for receiving data from the
// peer. Once they are posted, the peer is free to write to them and will
// eventually post them back for consumption.
func (r *Rx) PostBuffers(buffers []RxBuffer) bool {
	for i := range buffers {
		b := r.tx.Push(sizeOfPostedBuffer)
		if b == nil {
			r.tx.Abort()
			return false
		}

		pb := &buffers[i]
		binary.LittleEndian.PutUint64(b[postedOffset:], pb.Offset)
		binary.LittleEndian.PutUint32(b[postedSize:], pb.Size)
		binary.LittleEndian.PutUint32(b[postedRemainingInGroup:], 0)
		binary.LittleEndian.PutUint64(b[postedUserData:], pb.UserData)
		binary.LittleEndian.PutUint64(b[postedID:], pb.ID)
	}

	r.tx.Flush()

	return true
}

// Dequeue receives buffers that have been previously posted by PostBuffers()
// and that have been filled by the peer and posted back.
//
// This is similar to append() in that new buffers are appended to "bufs", with
// reallocation only if "bufs" doesn't have enough capacity.
func (r *Rx) Dequeue(bufs []RxBuffer) ([]RxBuffer, uint32) {
	for {
		outBufs := bufs

		// Pull the next descriptor from the rx pipe.
		b := r.rx.Pull()
		if b == nil {
			return bufs, 0
		}

		if len(b) < sizeOfConsumedPacketHeader {
			log.Warningf("Ignoring packet header: size (%v) is less than header size (%v)", len(b), sizeOfConsumedPacketHeader)
			r.rx.Flush()
			continue
		}

		totalDataSize := binary.LittleEndian.Uint32(b[consumedPacketSize:])

		// Calculate the number of buffer descriptors and copy them
		// over to the output.
		count := (len(b) - sizeOfConsumedPacketHeader) / sizeOfConsumedBuffer
		offset := sizeOfConsumedPacketHeader
		buffersSize := uint32(0)
		for i := count; i > 0; i-- {
			s := binary.LittleEndian.Uint32(b[offset+consumedSize:])
			buffersSize += s
			if buffersSize < s {
				// The buffer size overflows an unsigned 32-bit
				// integer, so break out and force it to be
				// ignored.
				totalDataSize = 1
				buffersSize = 0
				break
			}

			outBufs = append(outBufs, RxBuffer{
				Offset: binary.LittleEndian.Uint64(b[offset+consumedOffset:]),
				Size:   s,
				ID:     binary.LittleEndian.Uint64(b[offset+consumedID:]),
			})

			offset += sizeOfConsumedBuffer
		}

		r.rx.Flush()

		if buffersSize < totalDataSize {
			// The descriptor is corrupted, ignore it.
			log.Warningf("Ignoring packet: actual data size (%v) less than expected size (%v)", buffersSize, totalDataSize)
			continue
		}

		return outBufs, totalDataSize
	}
}

// Bytes returns the byte slices on which the queue operates.
func (r *Rx) Bytes() (tx, rx []byte) {
	return r.tx.Bytes(), r.rx.Bytes()
}

// DecodeRxBufferHeader decodes the header of a buffer posted on an rx queue.
func DecodeRxBufferHeader(b []byte) RxBuffer {
	return RxBuffer{
		Offset:   binary.LittleEndian.Uint64(b[postedOffset:]),
		Size:     binary.LittleEndian.Uint32(b[postedSize:]),
		ID:       binary.LittleEndian.Uint64(b[postedID:]),
		UserData: binary.LittleEndian.Uint64(b[postedUserData:]),
	}
}

// RxCompletionSize returns the number of bytes needed to encode an rx
// completion containing "count" buffers.
func RxCompletionSize(count int) uint64 {
	return sizeOfConsumedPacketHeader + uint64(count)*sizeOfConsumedBuffer
}

// EncodeRxCompletion encodes an rx completion header.
func EncodeRxCompletion(b []byte, size, reserved uint32) {
	binary.LittleEndian.PutUint32(b[consumedPacketSize:], size)
	binary.LittleEndian.PutUint32(b[consumedPacketReserved:], reserved)
}

// EncodeRxCompletionBuffer encodes the i-th rx completion buffer header.
func EncodeRxCompletionBuffer(b []byte, i int, rxb RxBuffer) {
	b = b[RxCompletionSize(i):]
	binary.LittleEndian.PutUint64(b[consumedOffset:], rxb.Offset)
	binary.LittleEndian.PutUint32(b[consumedSize:], rxb.Size)
	binary.LittleEndian.PutUint64(b[consumedUserData:], rxb.UserData)
	binary.LittleEndian.PutUint64(b[consumedID:], rxb.ID)
}
