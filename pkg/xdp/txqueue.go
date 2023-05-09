// Copyright 2022 The gVisor Authors.
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

//go:build amd64 || arm64
// +build amd64 arm64

package xdp

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// The TXQueue is how a process tells the kernel which buffers are available to
// be sent via the NIC.
//
// TXQueue is not thread-safe and requires external synchronization
type TXQueue struct {
	// sockfd is the underlying AF_XDP socket.
	sockfd uint32

	// mem is the mmap'd area shared with the kernel. Many other fields of
	// this struct point into mem.
	mem []byte

	// ring is the actual ring buffer. It is a list of XDP descriptors
	// pointing to ready-to-transmit packets.
	//
	// len(ring) must be a power of 2.
	ring []unix.XDPDesc

	// mask is used whenever indexing into ring. It is always len(ring)-1.
	// It prevents index out of bounds errors while allowing the producer
	// and consumer pointers to repeatedly "overflow" and loop back around
	// the ring.
	mask uint32

	// producer points to the shared atomic value that indicates the last
	// produced descriptor. Only we update this value.
	producer *atomicbitops.Uint32

	// consumer points to the shared atomic value that indicates the last
	// consumed descriptor. Only the kernel updates this value.
	consumer *atomicbitops.Uint32

	// flags points to the shared atomic value that holds flags for the
	// queue.
	flags *atomicbitops.Uint32

	// Cached values are used to avoid relatively expensive atomic
	// operations. They are used, incremented, and decremented multiple
	// times with non-atomic operations, and then "batch-updated" by
	// reading or writing atomically to synchronize with the kernel.

	// cachedProducer is used to atomically write *producer.
	cachedProducer uint32
	// cachedConsumer is updated when we atomically read *consumer.
	// cachedConsumer is actually len(ring) larger than the real consumer
	// value. See free() for details.
	cachedConsumer uint32
}

// Reserve reserves descriptors in the queue. If toReserve descriptors cannot
// be reserved, none are reserved.
//
// +checklocks:umem.mu
func (tq *TXQueue) Reserve(umem *UMEM, toReserve uint32) (nReserved, index uint32) {
	if umem.nFreeFrames < toReserve || tq.free(toReserve) < toReserve {
		return 0, 0
	}
	idx := tq.cachedProducer
	tq.cachedProducer += toReserve
	return toReserve, idx
}

// free returns the number of free descriptors in the TX queue.
func (tq *TXQueue) free(toReserve uint32) uint32 {
	// Try to find free descriptors without incurring an atomic operation.
	//
	// cachedConsumer is always len(tq.ring) larger than the real consumer
	// value. This lets us, in the common case, compute the number of free
	// descriptors simply via tq.cachedConsumer - tq.cachedProducer without
	// also addign len(tq.ring).
	if available := tq.cachedConsumer - tq.cachedProducer; available >= toReserve {
		return available
	}

	// If we didn't already have enough descriptors available, check
	// whether the kernel has returned some to us.
	tq.cachedConsumer = tq.consumer.Load()
	tq.cachedConsumer += uint32(len(tq.ring))
	return tq.cachedConsumer - tq.cachedProducer
}

// Notify updates the producer such that it is visible to the kernel.
func (tq *TXQueue) Notify() {
	tq.producer.Store(tq.cachedProducer)
	tq.kick()
}

// Set sets the TX queue's descriptor at index to addr.
func (tq *TXQueue) Set(index uint32, desc unix.XDPDesc) {
	// Use mask to avoid overflowing and loop back around the ring.
	tq.ring[index&tq.mask] = desc
}
