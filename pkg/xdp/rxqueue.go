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

// The RXQueue is how the kernel tells a process which buffers are full with
// incoming packets.
//
// RXQueue is not thread-safe and requires external synchronization
type RXQueue struct {
	// mem is the mmap'd area shared with the kernel. Many other fields of
	// this struct point into mem.
	mem []byte

	// ring is the actual ring buffer. It is a list of XDP descriptors
	// pointing to incoming packets.
	//
	// len(ring) must be a power of 2.
	ring []unix.XDPDesc

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

// Peek returns the number of packets available to read as well as the index at
// which they start. Peek will only return a packet once, so callers must
// process any received packets.
func (rq *RXQueue) Peek() (nReceived, index uint32) {
	// Get the number of available buffers and update cachedConsumer to
	// reflect that we're going to consume them.
	entries := rq.free()
	index = rq.cachedConsumer
	rq.cachedConsumer += entries
	return entries, index
}

func (rq *RXQueue) free() uint32 {
	// Return any buffers we know about without incurring an atomic
	// operation if possible.
	entries := rq.cachedProducer - rq.cachedConsumer
	// If we're not aware of any RX'd packets, refresh the producer pointer
	// to see whether the kernel enqueued anything.
	if entries == 0 {
		rq.cachedProducer = rq.producer.Load()
		entries = rq.cachedProducer - rq.cachedConsumer
	}
	return entries
}

// Release notifies the kernel that we have consumed nDone packets.
func (rq *RXQueue) Release(nDone uint32) {
	// We don't have to use an atomic add because only we update this; the
	// kernel just reads it.
	rq.consumer.Store(rq.consumer.RacyLoad() + nDone)
}

// Get gets the descriptor at index.
func (rq *RXQueue) Get(index uint32) unix.XDPDesc {
	// Use mask to avoid overflowing and loop back around the ring.
	return rq.ring[index&rq.mask]
}
