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

package queue

import (
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sharedmem/pipe"
)

const (
	// Offsets within a packet header.
	packetID       = 0
	packetSize     = 8
	packetReserved = 12

	sizeOfPacketHeader = 16

	// Offsets with a buffer descriptor
	bufferOffset = 0
	bufferSize   = 8

	sizeOfBufferDescriptor = 12
)

// TxBuffer is the descriptor of a transmit buffer.
type TxBuffer struct {
	Next   *TxBuffer
	Offset uint64
	Size   uint32
}

// Tx is a transmit queue. It is implemented with one tx and one rx pipe: the
// tx pipe is used to request the transmission of packets, while the rx pipe
// is used to receive which transmissions have completed.
//
// This struct is thread-compatible.
type Tx struct {
	tx pipe.Tx
	rx pipe.Rx
}

// Init initializes the transmit queue with the given pipes.
func (t *Tx) Init(tx, rx []byte) {
	t.tx.Init(tx)
	t.rx.Init(rx)
}

// Enqueue queues the given linked list of buffers for transmission as one
// packet. While it is queued, the caller must not modify them.
func (t *Tx) Enqueue(id uint64, totalDataLen, bufferCount uint32, buffer *TxBuffer) bool {
	// Reserve room in the tx pipe.
	totalLen := sizeOfPacketHeader + uint64(bufferCount)*sizeOfBufferDescriptor

	b := t.tx.Push(totalLen)
	if b == nil {
		return false
	}

	// Initialize the packet and buffer descriptors.
	binary.LittleEndian.PutUint64(b[packetID:], id)
	binary.LittleEndian.PutUint32(b[packetSize:], totalDataLen)
	binary.LittleEndian.PutUint32(b[packetReserved:], 0)

	offset := sizeOfPacketHeader
	for i := bufferCount; i != 0; i-- {
		binary.LittleEndian.PutUint64(b[offset+bufferOffset:], buffer.Offset)
		binary.LittleEndian.PutUint32(b[offset+bufferSize:], buffer.Size)
		offset += sizeOfBufferDescriptor
		buffer = buffer.Next
	}

	t.tx.Flush()

	return true
}

// CompletedPacket returns the id of the last completed transmission. The
// returned id, if any, refers to a value passed on a previous call to
// Enqueue().
func (t *Tx) CompletedPacket() (id uint64, ok bool) {
	for {
		b := t.rx.Pull()
		if b == nil {
			return 0, false
		}

		if len(b) != 8 {
			t.rx.Flush()
			log.Warningf("Ignoring completed packet: size (%v) is less than expected (%v)", len(b), 8)
			continue
		}

		v := binary.LittleEndian.Uint64(b)

		t.rx.Flush()

		return v, true
	}
}

// Bytes returns the byte slices on which the queue operates.
func (t *Tx) Bytes() (tx, rx []byte) {
	return t.tx.Bytes(), t.rx.Bytes()
}

// TxPacketInfo holds information about a packet sent on a tx queue.
type TxPacketInfo struct {
	ID          uint64
	Size        uint32
	Reserved    uint32
	BufferCount int
}

// DecodeTxPacketHeader decodes the header of a packet sent over a tx queue.
func DecodeTxPacketHeader(b []byte) TxPacketInfo {
	return TxPacketInfo{
		ID:          binary.LittleEndian.Uint64(b[packetID:]),
		Size:        binary.LittleEndian.Uint32(b[packetSize:]),
		Reserved:    binary.LittleEndian.Uint32(b[packetReserved:]),
		BufferCount: (len(b) - sizeOfPacketHeader) / sizeOfBufferDescriptor,
	}
}

// DecodeTxBufferHeader decodes the header of the i-th buffer of a packet sent
// over a tx queue.
func DecodeTxBufferHeader(b []byte, i int) TxBuffer {
	b = b[sizeOfPacketHeader+i*sizeOfBufferDescriptor:]
	return TxBuffer{
		Offset: binary.LittleEndian.Uint64(b[bufferOffset:]),
		Size:   binary.LittleEndian.Uint32(b[bufferSize:]),
	}
}

// EncodeTxCompletion encodes a tx completion header.
func EncodeTxCompletion(b []byte, id uint64) {
	binary.LittleEndian.PutUint64(b, id)
}
