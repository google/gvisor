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

// +build linux,amd64

package fdbased

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
)

const (
	tPacketAlignment = uintptr(16)
	tpStatusKernel   = 0
	tpStatusUser     = 1
	tpStatusCopy     = 2
	tpStatusLosing   = 4
)

// We overallocate the frame size to accommodate space for the
// TPacketHdr+RawSockAddrLinkLayer+MAC header and any padding.
//
// Memory allocated for the ring buffer: tpBlockSize * tpBlockNR = 2 MiB
//
// NOTE:
//   Frames need to be aligned at 16 byte boundaries.
//   BlockSize needs to be page aligned.
//
//   For details see PACKET_MMAP setting constraints in
//   https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
const (
	tpFrameSize = 65536 + 128
	tpBlockSize = tpFrameSize * 32
	tpBlockNR   = 1
	tpFrameNR   = (tpBlockSize * tpBlockNR) / tpFrameSize
)

// tPacketAlign aligns the pointer v at a tPacketAlignment boundary. Direct
// translation of the TPACKET_ALIGN macro in <linux/if_packet.h>.
func tPacketAlign(v uintptr) uintptr {
	return (v + tPacketAlignment - 1) & uintptr(^(tPacketAlignment - 1))
}

// tPacketHdrlen is the TPACKET_HDRLEN variable defined in <linux/if_packet.h>.
var tPacketHdrlen = tPacketAlign(unsafe.Sizeof(tPacketHdr{}) + unsafe.Sizeof(syscall.RawSockaddrLinklayer{}))

// tPacketReq is the tpacket_req structure as described in
// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
type tPacketReq struct {
	tpBlockSize uint32
	tpBlockNR   uint32
	tpFrameSize uint32
	tpFrameNR   uint32
}

// tPacketHdr is tpacket_hdr structure as described in <linux/if_packet.h>
type tPacketHdr []byte

const (
	tpStatusOffset  = 0
	tpLenOffset     = 8
	tpSnapLenOffset = 12
	tpMacOffset     = 16
	tpNetOffset     = 18
	tpSecOffset     = 20
	tpUSecOffset    = 24
)

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

func (t tPacketHdr) tpLen() uint32 {
	return binary.LittleEndian.Uint32(t[tpLenOffset:])
}

func (t tPacketHdr) tpSnapLen() uint32 {
	return binary.LittleEndian.Uint32(t[tpSnapLenOffset:])
}

func (t tPacketHdr) tpMac() uint16 {
	return binary.LittleEndian.Uint16(t[tpMacOffset:])
}

func (t tPacketHdr) tpNet() uint16 {
	return binary.LittleEndian.Uint16(t[tpNetOffset:])
}

func (t tPacketHdr) tpSec() uint32 {
	return binary.LittleEndian.Uint32(t[tpSecOffset:])
}

func (t tPacketHdr) tpUSec() uint32 {
	return binary.LittleEndian.Uint32(t[tpUSecOffset:])
}

func (t tPacketHdr) Payload() []byte {
	return t[uint32(t.tpMac()) : uint32(t.tpMac())+t.tpSnapLen()]
}

func (e *endpoint) setupPacketRXRing() error {
	pageSize := unix.Getpagesize()
	if tpBlockSize%pageSize != 0 {
		return fmt.Errorf("tpBlockSize: %d is not page aligned, pagesize: %d", tpBlockSize, pageSize)
	}
	tReq := tPacketReq{
		tpBlockSize: uint32(tpBlockSize),
		tpBlockNR:   uint32(tpBlockNR),
		tpFrameSize: uint32(tpFrameSize),
		tpFrameNR:   uint32(tpFrameNR),
	}
	// Setup PACKET_RX_RING.
	if err := setsockopt(e.fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, unsafe.Pointer(&tReq), unsafe.Sizeof(tReq)); err != nil {
		return fmt.Errorf("failed to enable PACKET_RX_RING: %v", err)
	}
	// Let's mmap the blocks.
	sz := tpBlockSize * tpBlockNR
	buf, err := syscall.Mmap(e.fd, 0, sz, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("syscall.Mmap(...,0, %v, ...) failed = %v", sz, err)
	}
	e.ringBuffer = buf
	return nil
}

func (e *endpoint) readMMappedPacket() ([]byte, *tcpip.Error) {
	hdr := (tPacketHdr)(e.ringBuffer[e.ringOffset*tpFrameSize:])
	for hdr.tpStatus()&tpStatusUser == 0 {
		event := rawfile.PollEvent{
			FD:     int32(e.fd),
			Events: unix.POLLIN | unix.POLLERR,
		}
		_, errno := rawfile.BlockingPoll(&event, 1, -1)
		if errno != 0 {
			if errno == syscall.EINTR {
				continue
			}
			return nil, rawfile.TranslateErrno(errno)
		}
		if hdr.tpStatus()&tpStatusCopy != 0 {
			// This frame is truncated so skip it after flipping the
			// buffer to the kernel.
			hdr.setTPStatus(tpStatusKernel)
			e.ringOffset = (e.ringOffset + 1) % tpFrameNR
			hdr = (tPacketHdr)(e.ringBuffer[e.ringOffset*tpFrameSize:])
			continue
		}
	}

	// Copy out the packet from the mmapped frame to a locally owned buffer.
	pkt := make([]byte, hdr.tpSnapLen())
	copy(pkt, hdr.Payload())
	// Release packet to kernel.
	hdr.setTPStatus(tpStatusKernel)
	e.ringOffset = (e.ringOffset + 1) % tpFrameNR
	return pkt, nil
}

// packetMMapDispatch reads packets from an mmaped ring buffer and dispatches
// them to the network stack.
func (e *endpoint) packetMMapDispatch() (bool, *tcpip.Error) {
	pkt, err := e.readMMappedPacket()
	if err != nil {
		return false, err
	}
	var (
		p             tcpip.NetworkProtocolNumber
		remote, local tcpip.LinkAddress
	)
	if e.hdrSize > 0 {
		eth := header.Ethernet(pkt)
		p = eth.Type()
		remote = eth.SourceAddress()
		local = eth.DestinationAddress()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		switch header.IPVersion(pkt) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	pkt = pkt[e.hdrSize:]
	e.dispatcher.DeliverNetworkPacket(e, remote, local, p, buffer.NewVectorisedView(len(pkt), []buffer.View{buffer.View(pkt)}))
	return true, nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}
