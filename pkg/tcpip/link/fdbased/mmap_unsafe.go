// Copyright 2019 The gVisor Authors.
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

// +build linux,amd64 linux,arm64

package fdbased

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tPacketHdrlen is the TPACKET_HDRLEN variable defined in <linux/if_packet.h>.
var tPacketHdrlen = tPacketAlign(unsafe.Sizeof(tPacketHdr{}) + unsafe.Sizeof(unix.RawSockaddrLinklayer{}))

// tpStatus returns the frame status field.
// The status is concurrently updated by the kernel as a result we must
// use atomic operations to prevent races.
func (t tPacketHdr) tpStatus() uint32 {
	hdr := unsafe.Pointer(&t[0])
	statusPtr := unsafe.Pointer(uintptr(hdr) + uintptr(tpStatusOffset))
	return atomic.LoadUint32((*uint32)(statusPtr))
}

// setTPStatus set's the frame status to the provided status.
// The status is concurrently updated by the kernel as a result we must
// use atomic operations to prevent races.
func (t tPacketHdr) setTPStatus(status uint32) {
	hdr := unsafe.Pointer(&t[0])
	statusPtr := unsafe.Pointer(uintptr(hdr) + uintptr(tpStatusOffset))
	atomic.StoreUint32((*uint32)(statusPtr), status)
}

func newPacketMMapDispatcher(fd int, e *endpoint) (linkDispatcher, error) {
	d := &packetMMapDispatcher{
		fd: fd,
		e:  e,
	}
	pageSize := unix.Getpagesize()
	if tpBlockSize%pageSize != 0 {
		return nil, fmt.Errorf("tpBlockSize: %d is not page aligned, pagesize: %d", tpBlockSize, pageSize)
	}
	tReq := tPacketReq{
		tpBlockSize: uint32(tpBlockSize),
		tpBlockNR:   uint32(tpBlockNR),
		tpFrameSize: uint32(tpFrameSize),
		tpFrameNR:   uint32(tpFrameNR),
	}
	// Setup PACKET_RX_RING.
	if err := setsockopt(d.fd, unix.SOL_PACKET, unix.PACKET_RX_RING, unsafe.Pointer(&tReq), unsafe.Sizeof(tReq)); err != nil {
		return nil, fmt.Errorf("failed to enable PACKET_RX_RING: %v", err)
	}
	// Let's mmap the blocks.
	sz := tpBlockSize * tpBlockNR
	buf, err := unix.Mmap(d.fd, 0, sz, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("unix.Mmap(...,0, %v, ...) failed = %v", sz, err)
	}
	d.ringBuffer = buf
	return d, nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}
