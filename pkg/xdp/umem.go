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
)

// UMEM is the shared memory area that the kernel and userspace put packets in.
type UMEM struct {
	// mem is the mmap'd area shared with the kernel.
	mem []byte

	// sockfd is the underlying AF_XDP socket.
	sockfd uint32

	// frameAddresses is a stack of available frame addresses.
	frameAddresses []uint64

	// nFreeFrames is the number of frames available and is used to index
	// into frameAddresses.
	nFreeFrames uint32
}

// SockFD returns the underlying AF_XDP socket FD.
func (um *UMEM) SockFD() uint32 {
	return um.sockfd
}

// FreeFrame returns the frame containing addr to the set of free frames.
func (um *UMEM) FreeFrame(addr uint64) {
	um.frameAddresses[um.nFreeFrames] = addr
	um.nFreeFrames++
}

// AllocFrame returns the address of a frame that can be enqueued to the fill
// or TX queue.
func (um *UMEM) AllocFrame() (uint64, error) {
	um.nFreeFrames--
	return um.frameAddresses[um.nFreeFrames], nil
}

// Get gets the bytes of the packet pointed to by desc.
func (um *UMEM) Get(desc unix.XDPDesc) []byte {
	return um.mem[desc.Addr : desc.Addr+uint64(desc.Len)]
}
