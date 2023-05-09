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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

// TODO(b/240191988): There's some kind of memory corruption bug that occurs
// occasionally. This occured even before TX was supported.

// TODO(b/240191988): We can hold locks for less time if we accept a more
// obtuse API. For example, CompletionQueue.FreeAll doesn't need to hold a
// mutex for its entire duration.

// UMEM is the shared memory area that the kernel and userspace put packets in.
type UMEM struct {
	// mem is the mmap'd area shared with the kernel.
	mem []byte

	// sockfd is the underlying AF_XDP socket.
	sockfd uint32

	// frameMask masks the lower bits of an adderess to get the frame's
	// address.
	frameMask uint64

	// mu protects frameAddresses and nFreeFrames.
	mu sync.Mutex

	// frameAddresses is a stack of available frame addresses.
	// +checklocks:mu
	frameAddresses []uint64

	// nFreeFrames is the number of frames available and is used to index
	// into frameAddresses.
	// +checklocks:mu
	nFreeFrames uint32
}

// SockFD returns the underlying AF_XDP socket FD.
func (um *UMEM) SockFD() uint32 {
	return um.sockfd
}

// Lock locks the UMEM.
//
// +checklocksacquire:um.mu
func (um *UMEM) Lock() {
	um.mu.Lock()
}

// Unlock unlocks the UMEM.
//
// +checklocksrelease:um.mu
func (um *UMEM) Unlock() {
	um.mu.Unlock()
}

// FreeFrame returns the frame containing addr to the set of free frames.
//
// The UMEM must be locked during the call to FreeFrame.
//
// +checklocks:um.mu
func (um *UMEM) FreeFrame(addr uint64) {
	um.frameAddresses[um.nFreeFrames] = addr
	um.nFreeFrames++
}

// AllocFrame returns the address of a frame that can be enqueued to the fill
// or TX queue. It will panic if there are no frames left, so callers must call
// it no more than the number of buffers reserved via TXQueue.Reserve().
//
// The UMEM must be locked during the call to AllocFrame.
//
// +checklocks:um.mu
func (um *UMEM) AllocFrame() uint64 {
	um.nFreeFrames--
	return um.frameAddresses[um.nFreeFrames] & um.frameMask
}

// Get gets the bytes of the packet pointed to by desc.
func (um *UMEM) Get(desc unix.XDPDesc) []byte {
	end := desc.Addr + uint64(desc.Len)
	if desc.Addr&um.frameMask != (end-1)&um.frameMask {
		panic(fmt.Sprintf("UMEM (%+v) access crosses frame boundaries: %+v", um, desc))
	}
	return um.mem[desc.Addr:end]
}
