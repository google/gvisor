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

// Package xdp provides tools for working with AF_XDP sockets.
//
// AF_XDP shares a memory area (UMEM) with the kernel to pass packets
// back and forth. Communication is done via a number of queues.
// Briefly, the queues work as follows:
//
//   - Receive: Userspace adds a descriptor to the fill queue. The
//     descriptor points to an area of the UMEM that the kernel should fill
//     with an incoming packet. The packet is filled by the kernel, which
//     places a descriptor to the same UMEM area in the RX queue, signifying
//     that userspace may read the packet.
//   - Trasmit: Userspace adds a descriptor to TX queue. The kernel
//     sends the packet (stored in UMEM) pointed to by the descriptor.
//     Upon completion, the kernel places a desciptor in the completion
//     queue to notify userspace that the packet is sent and the UMEM
//     area can be reused.
//
// So in short: RX packets move from the fill to RX queue, and TX
// packets move from the TX to completion queue.
//
// Note that the shared UMEM for RX and TX means that packet forwarding
// can be done without copying; only the queues need to be updated to point to
// the packet in UMEM.
package xdp

import (
	"fmt"
	"math/bits"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
)

// A ControlBlock contains all the control structures necessary to use an
// AF_XDP socket.
//
// The ControlBlock and the structures it contains are meant to be used with a
// single RX goroutine and a single TX goroutine.
type ControlBlock struct {
	UMEM       UMEM
	Fill       FillQueue
	RX         RXQueue
	TX         TXQueue
	Completion CompletionQueue
}

// ReadOnlySocketOpts configure a read-only AF_XDP socket.
type ReadOnlySocketOpts struct {
	NFrames      uint32
	FrameSize    uint32
	NDescriptors uint32
}

// DefaultReadOnlyOpts provides recommended default options for initializing a
// readonly AF_XDP socket. AF_XDP setup is extremely finnicky and can fail if
// incorrect values are used.
func DefaultReadOnlyOpts() ReadOnlySocketOpts {
	return ReadOnlySocketOpts{
		NFrames: 4096,
		// Frames must be 2048 or 4096 bytes, although not all drivers support
		// both.
		FrameSize:    4096,
		NDescriptors: 2048,
	}
}

// ReadOnlySocket returns an initialized read-only AF_XDP socket bound to a
// particular interface and queue.
func ReadOnlySocket(ifaceIdx, queueID uint32, opts ReadOnlySocketOpts) (*ControlBlock, error) {
	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP socket: %v", err)
	}
	return ReadOnlyFromSocket(sockfd, ifaceIdx, queueID, opts)
}

// ReadOnlyFromSocket takes an AF_XDP socket, initializes it, and binds it to a
// particular interface and queue.
func ReadOnlyFromSocket(sockfd int, ifaceIdx, queueID uint32, opts ReadOnlySocketOpts) (*ControlBlock, error) {
	if opts.FrameSize != 2048 && opts.FrameSize != 4096 {
		return nil, fmt.Errorf("invalid frame size %d: must be either 2048 or 4096", opts.FrameSize)
	}
	if bits.OnesCount32(opts.NDescriptors) != 1 {
		return nil, fmt.Errorf("invalid number of descriptors %d: must be a power of 2", opts.NDescriptors)
	}

	var cb ControlBlock

	// Create the UMEM area. Use mmap instead of make([[]byte) to ensure
	// that the UMEM is page-aligned. Aligning the UMEM keeps individual
	// packets from spilling over between pages.
	var zerofd uintptr
	umemMemory, err := memutil.MapSlice(
		0,
		uintptr(opts.NFrames*opts.FrameSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		zerofd-1,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap umem: %v", err)
	}
	cleanup := cleanup.Make(func() {
		memutil.UnmapSlice(umemMemory)
	})

	if sliceBackingPointer(umemMemory)%uintptr(unix.Getpagesize()) != 0 {
		return nil, fmt.Errorf("UMEM is not page aligned (address 0x%x)", sliceBackingPointer(umemMemory))
	}

	cb.UMEM = UMEM{
		mem:            umemMemory,
		sockfd:         uint32(sockfd),
		frameAddresses: make([]uint64, opts.NFrames),
		nFreeFrames:    opts.NFrames,
		frameMask:      ^(uint64(opts.FrameSize) - 1),
	}

	// Fill in each frame address.
	for i := range cb.UMEM.frameAddresses {
		cb.UMEM.frameAddresses[i] = uint64(i) * uint64(opts.FrameSize)
	}

	// Check whether we're likely to fail due to RLIMIT_MEMLOCK.
	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return nil, fmt.Errorf("failed to get rlimit for memlock: %v", err)
	}
	if rlimit.Cur < uint64(len(cb.UMEM.mem)) {
		log.Infof("UMEM size (%d) may exceed RLIMIT_MEMLOCK (%+v) and cause registration to fail", len(cb.UMEM.mem), rlimit)
	}

	reg := unix.XDPUmemReg{
		Addr: uint64(sliceBackingPointer(umemMemory)),
		Len:  uint64(len(umemMemory)),
		Size: opts.FrameSize,
		// Not useful in the RX path.
		Headroom: 0,
		// TODO(b/240191988): Investigate use of SHARED flag.
		Flags: 0,
	}
	if err := registerUMEM(sockfd, reg); err != nil {
		return nil, fmt.Errorf("failed to register UMEM: %v", err)
	}

	// Set the number of descriptors in the fill queue.
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register fill ring: %v", err)
	}
	// Set the number of descriptors in the completion queue.
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register completion ring: %v", err)
	}
	// Set the number of descriptors in the RX queue.
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register RX queue: %v", err)
	}
	// Set the number of descriptors in the TX queue.
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register TX queue: %v", err)
	}

	// Get offset information for the queues. Offsets indicate where, once
	// we mmap space for each queue, values in the queue are. They give
	// offsets for the shared pointers, a shared flags value, and the
	// beginning of the ring of descriptors.
	off, err := getOffsets(sockfd)
	if err != nil {
		return nil, fmt.Errorf("failed to get offsets: %v", err)
	}

	// Allocate space for the fill queue.
	fillQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Fr.Desc+uint64(opts.NDescriptors)*sizeOfFillQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_UMEM_PGOFF_FILL_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap fill queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(fillQueueMem)
	})
	// Setup the fillQueue with offsets into allocated memory.
	cb.Fill = FillQueue{
		mem:            fillQueueMem,
		mask:           opts.NDescriptors - 1,
		cachedConsumer: opts.NDescriptors,
	}
	cb.Fill.init(off, opts)

	// Allocate space for the completion queue.
	completionQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Cr.Desc+uint64(opts.NDescriptors)*sizeOfCompletionQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_UMEM_PGOFF_COMPLETION_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap completion queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(completionQueueMem)
	})
	// Setup the completionQueue with offsets into allocated memory.
	cb.Completion = CompletionQueue{
		mem:  completionQueueMem,
		mask: opts.NDescriptors - 1,
	}
	cb.Completion.init(off, opts)

	// Allocate space for the RX queue.
	rxQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Rx.Desc+uint64(opts.NDescriptors)*sizeOfRXQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_PGOFF_RX_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap RX queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(rxQueueMem)
	})
	// Setup the rxQueue with offsets into allocated memory.
	cb.RX = RXQueue{
		mem:  rxQueueMem,
		mask: opts.NDescriptors - 1,
	}
	cb.RX.init(off, opts)

	// Allocate space for the TX queue.
	txQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Tx.Desc+uint64(opts.NDescriptors)*sizeOfTXQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_PGOFF_TX_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap tx queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(txQueueMem)
	})
	// Setup the txQueue with offsets into allocated memory.
	cb.TX = TXQueue{
		sockfd:         uint32(sockfd),
		mem:            txQueueMem,
		mask:           opts.NDescriptors - 1,
		cachedConsumer: opts.NDescriptors,
	}
	cb.TX.init(off, opts)

	addr := unix.SockaddrXDP{
		// XDP_USE_NEED_WAKEUP lets the driver sleep if there is no
		// work to do. It will need to be woken by poll. It is expected
		// that this improves performance by preventing the driver from
		// burning cycles.
		//
		// By not setting either XDP_COPY or XDP_ZEROCOPY, we instruct
		// the kernel to use zerocopy if available and then fallback to
		// copy mode.
		Flags:   unix.XDP_USE_NEED_WAKEUP,
		Ifindex: ifaceIdx,
		// AF_XDP sockets are per device RX queue, although multiple
		// sockets on multiple queues (or devices) can share a single
		// UMEM.
		QueueID: queueID,
		// We're not using shared mode, so the value here is irrelevant.
		SharedUmemFD: 0,
	}
	if err := unix.Bind(sockfd, &addr); err != nil {
		return nil, fmt.Errorf("failed to bind with addr %+v: %v", addr, err)
	}

	cleanup.Release()
	return &cb, nil
}
