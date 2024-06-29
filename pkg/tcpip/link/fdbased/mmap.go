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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package fdbased

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
//
//	Frames need to be aligned at 16 byte boundaries.
//	BlockSize needs to be page aligned.
//
//	For details see PACKET_MMAP setting constraints in
//	https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
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

// packetMMapDispatcher uses PACKET_RX_RING's to read/dispatch inbound packets.
// See: mmap_amd64_unsafe.go for implementation details.
type packetMMapDispatcher struct {
	stopfd.StopFD
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// ringBuffer is only used when PacketMMap dispatcher is used and points
	// to the start of the mmapped PACKET_RX_RING buffer.
	ringBuffer []byte

	// ringOffset is the current offset into the ring buffer where the next
	// inbound packet will be placed by the kernel.
	ringOffset int

	// mgr is the processor goroutine manager.
	mgr *processorManager
}

func (d *packetMMapDispatcher) release() {
	d.mgr.close()
}

func (d *packetMMapDispatcher) readMMappedPackets() (stack.PacketBufferList, bool, tcpip.Error) {
	var pkts stack.PacketBufferList
	hdr := tPacketHdr(d.ringBuffer[d.ringOffset*tpFrameSize:])
	for hdr.tpStatus()&tpStatusUser == 0 {
		stopped, errno := rawfile.BlockingPollUntilStopped(d.EFD, d.fd, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return pkts, stopped, tcpip.TranslateErrno(errno)
		}
		if stopped {
			return pkts, true, nil
		}
		if hdr.tpStatus()&tpStatusCopy != 0 {
			// This frame is truncated so skip it after flipping the
			// buffer to the kernel.
			hdr.setTPStatus(tpStatusKernel)
			d.ringOffset = (d.ringOffset + 1) % tpFrameNR
			hdr = (tPacketHdr)(d.ringBuffer[d.ringOffset*tpFrameSize:])
			continue
		}
	}

	for hdr.tpStatus()&tpStatusUser == 1 {
		// Copy out the packet from the mmapped frame to a locally owned buffer.
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(buffer.NewViewWithData(hdr.Payload())),
		}))
		// Release packet to kernel.
		hdr.setTPStatus(tpStatusKernel)
		d.ringOffset = (d.ringOffset + 1) % tpFrameNR
		hdr = tPacketHdr(d.ringBuffer[d.ringOffset*tpFrameSize:])
	}
	return pkts, false, nil
}

// dispatch reads packets from an mmaped ring buffer and dispatches them to the
// network stack.
func (d *packetMMapDispatcher) dispatch() (bool, tcpip.Error) {
	pkts, stopped, err := d.readMMappedPackets()
	defer pkts.Reset()
	if err != nil || stopped {
		return false, err
	}
	for _, pkt := range pkts.AsSlice() {
		if d.e.hdrSize > 0 {
			hdr, ok := pkt.LinkHeader().Consume(d.e.hdrSize)
			if !ok {
				panic(fmt.Sprintf("LinkHeader().Consume(%d) must succeed", d.e.hdrSize))
			}
			pkt.NetworkProtocolNumber = header.Ethernet(hdr).Type()
		}
		d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
	}
	if pkts.Len() > 0 {
		d.mgr.wakeReady()
	}
	return true, nil
}
