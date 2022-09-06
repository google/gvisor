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
	"fmt"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// The FillQueue is how a process tells the kernel which buffers are available
// to be filled by incoming packets.
type FillQueue struct {
	// mem is the mmap'd area shared with the kernel. Many other fields of
	// this struct point into mem.
	mem []byte

	// umem is the UMEM (i.e. shared buffer space) to which the queue's
	// descriptors point.
	umem *UMEM

	// ring is the actual ring buffer. It is a list of frame addresses
	// ready for incoming packets.
	ring []uint64

	// mask is used whenever indexing into ring. It prevents index out of
	// bounds errors while allowing the producer and consumer pointers to
	// repeatedly "overflow" and loop back around the ring.
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
	// operations.
	cachedProducer uint32
	// cachedConsumer is actually len(ring) larger than the real consumer
	// value. See Free() for details.
	cachedConsumer uint32
}

// Reserve reserves descriptors in the fill queue. If toReserve descriptors
// cannot be reserved, none are reserved.
func (fq *FillQueue) Reserve(toReserve uint32) (nReserved, index uint32) {
	if fq.free(toReserve) < toReserve {
		// Unable to free the desired number of descriptors.
		return 0, 0
	}
	idx := fq.cachedProducer
	fq.cachedProducer += toReserve
	return toReserve, idx
}

// free returns the number of free descriptors in the fill queue.
func (fq *FillQueue) free(toReserve uint32) uint32 {
	// cachedConsumer is always len(fq.ring) larger than the real consumer
	// value. This lets us, in the common case, compute the number of free
	// descriptors simply via fq.cachedConsumer - fq.cachedProducer.
	if available := fq.cachedConsumer - fq.cachedProducer; available >= toReserve {
		return available
	}

	// If we didn't already have enough descriptors available, check
	// whether the kernel has returned some to us.
	fq.cachedConsumer = fq.consumer.Load()
	fq.cachedConsumer += uint32(len(fq.ring))
	return fq.cachedConsumer - fq.cachedProducer
}

// Notify updates the prodcer such that it is visible to the kernel.
func (fq *FillQueue) Notify() {
	fq.producer.Store(fq.cachedProducer)
}

// Set sets the fill queue's descriptor at index to addr.
func (fq *FillQueue) Set(index uint32, addr uint64) {
	fq.ring[index&fq.mask] = addr
}

// FillAll fills the queue with as many buffers as possible from the UMEM, then
// notifies the kernel.
func (fq *FillQueue) FillAll() {
	available := fq.free(fq.umem.nFreeFrames)
	if available < 1 {
		return
	}
	if available > fq.umem.nFreeFrames {
		available = fq.umem.nFreeFrames
	}
	_, index := fq.Reserve(available)
	for i := uint32(0); i < available; i++ {
		addr, err := fq.umem.AllocFrame()
		if err != nil {
			panic(fmt.Sprintf("failed to alloc frame #%d: %v", index+i, err))
		}
		fq.Set(index+i, addr)
	}
	fq.Notify()
}
