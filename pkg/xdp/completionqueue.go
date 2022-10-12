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

// The CompletionQueue is how the kernel tells a process which buffers have
// been transmitted and can be reused.
//
// CompletionQueue is not thread-safe and requires external synchronization
type CompletionQueue struct {
	// mem is the mmap'd area shared with the kernel. Many other fields of
	// this struct point into mem.
	mem []byte

	// ring is the actual ring buffer. It is a list of frame addresses
	// ready to be reused.
	//
	// len(ring) must be a power of 2.
	ring []uint64

	// mask is used whenever indexing into ring. It is always len(ring)-1.
	// It prevents index out of bounds errors while allowing the producer
	// and consumer pointers to repeatedly "overflow" and loop back around
	// the ring.
	mask uint32

	// producer points to the shared atomic value that indicates the last
	// produced descriptor. Only the kernel updates this value.
	producer *atomicbitops.Uint32

	// consumer points to the shared atomic value that indicates the last
	// consumed descriptor. Only we update this value.
	consumer *atomicbitops.Uint32

	// flags points to the shared atomic value that holds flags for the
	// queue.
	flags *atomicbitops.Uint32

	// Cached values are used to avoid relatively expensive atomic
	// operations. They are used, incremented, and decremented multiple
	// times with non-atomic operations, and then "batch-updated" by
	// reading or writing atomically to synchronize with the kernel.

	// cachedProducer is updated when we atomically read *producer.
	cachedProducer uint32
	// cachedConsumer is used to atomically write *consumer.
	cachedConsumer uint32
}

// Peek returns the number of buffers available to reuse as well as the index
// at which they start. Peek will only return a buffer once, so callers must
// process any received buffers.
func (cq *CompletionQueue) Peek() (nAvailable, index uint32) {
	// Get the number of available buffers and update cachedConsumer to
	// reflect that we're going to consume them.
	entries := cq.free()
	index = cq.cachedConsumer
	cq.cachedConsumer += entries
	return entries, index
}

func (cq *CompletionQueue) free() uint32 {
	// Return any buffers we know about without incurring an atomic
	// operation if possible.
	entries := cq.cachedProducer - cq.cachedConsumer
	// If we're not aware of any completed packets, refresh the producer
	// pointer to see whether the kernel enqueued anything.
	if entries == 0 {
		cq.cachedProducer = cq.producer.Load()
		entries = cq.cachedProducer - cq.cachedConsumer
	}
	return entries
}

// Release notifies the kernel that we have consumed nDone packets.
func (cq *CompletionQueue) Release(nDone uint32) {
	// We don't have to use an atomic add because only we update this; the
	// kernel just reads it.
	cq.consumer.Store(cq.consumer.RacyLoad() + nDone)
}

// Get gets the descriptor at index.
func (cq *CompletionQueue) Get(index uint32) uint64 {
	// Use mask to avoid overflowing and loop back around the ring.
	return cq.ring[index&cq.mask]
}

// FreeAll dequeues as many buffers as possible from the queue and returns them
// to the UMEM.
//
// +checklocks:umem.mu
func (cq *CompletionQueue) FreeAll(umem *UMEM) {
	available, index := cq.Peek()
	if available < 1 {
		return
	}
	for i := uint32(0); i < available; i++ {
		umem.FreeFrame(cq.Get(index + i))
	}
	cq.Release(available)
}
