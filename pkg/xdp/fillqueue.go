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
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// The FillQueue is how a process tells the kernel which buffers are available
// to be filled by incoming packets.
//
// FillQueue is not thread-safe and requires external synchronization
type FillQueue struct {
	// mem is the mmap'd area shared with the kernel. Many other fields of
	// this struct point into mem.
	mem []byte

	// ring is the actual ring buffer. It is a list of frame addresses
	// ready for incoming packets.
	//
	// len(ring) must be a power of 2.
	ring []uint64

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

// free returns the number of free descriptors in the fill queue.
func (fq *FillQueue) free(toReserve uint32) uint32 {
	// Try to find free descriptors without incurring an atomic operation.
	//
	// cachedConsumer is always len(fq.ring) larger than the real consumer
	// value. This lets us, in the common case, compute the number of free
	// descriptors simply via fq.cachedConsumer - fq.cachedProducer without
	// also adding len(fq.ring).
	if available := fq.cachedConsumer - fq.cachedProducer; available >= toReserve {
		return available
	}

	// If we didn't already have enough descriptors available, check
	// whether the kernel has returned some to us.
	fq.cachedConsumer = fq.consumer.Load()
	fq.cachedConsumer += uint32(len(fq.ring))
	return fq.cachedConsumer - fq.cachedProducer
}

// Notify updates the producer such that it is visible to the kernel.
func (fq *FillQueue) Notify() {
	fq.producer.Store(fq.cachedProducer)
}

// Set sets the fill queue's descriptor at index to addr.
func (fq *FillQueue) Set(index uint32, addr uint64) {
	// Use mask to avoid overflowing and loop back around the ring.
	fq.ring[index&fq.mask] = addr
}

// FillAll posts as many empty buffers as possible for the kernel to fill, then
// notifies the kernel.
//
// +checklocks:umem.mu
func (fq *FillQueue) FillAll(umem *UMEM) {
	// Figure out how many buffers and queue slots are available.
	available := fq.free(umem.nFreeFrames)
	if available == 0 {
		return
	}
	if available > umem.nFreeFrames {
		available = umem.nFreeFrames
	}

	// Fill the queue as much as possible and notify ther kernel.
	index := fq.cachedProducer
	fq.cachedProducer += available
	for i := uint32(0); i < available; i++ {
		fq.Set(index+i, umem.AllocFrame())
	}
	fq.Notify()
}
