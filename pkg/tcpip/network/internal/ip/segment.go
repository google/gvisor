// Copyright 2026 The gVisor Authors.
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

package ip

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// SegmentCoalescedTCP splits pkt, a TCP packet that receive offload coalesced
// from segments of pkt.GROSegmentSize payload bytes, into new packets of at
// most that payload size.
//
// pkt's network header must be set and be directly followed by the TCP
// header, which may already be parsed into pkt's transport header. Each
// segment gets copies of both headers with its sequence number, flags and
// checksum updated; FIN and PSH are kept only on the last segment and CWR only
// on the first. setNetworkLength is then called with the segment's index and
// network header, and the length of its TCP header and payload, and must
// update the network header's length and checksum.
//
// It returns false, and no packets, if pkt has no valid TCP header or if a
// segment's TCP header and payload would exceed maxTransportLen. Otherwise the
// caller owns the returned packets.
func SegmentCoalescedTCP(pkt *stack.PacketBuffer, maxTransportLen uint32, reserveHeaderBytes int, setNetworkLength func(i int, netHdr []byte, transportLen int)) (stack.PacketBufferList, bool) {
	var segs stack.PacketBufferList
	mss := int(pkt.GROSegmentSize)
	if mss == 0 {
		return segs, false
	}

	tcpHdr := header.TCP(pkt.TransportHeader().Slice())
	if len(tcpHdr) == 0 {
		b, ok := pkt.Data().PullUp(header.TCPMinimumSize)
		if !ok {
			return segs, false
		}
		if b, ok = pkt.Data().PullUp(int(header.TCP(b).DataOffset())); !ok {
			return segs, false
		}
		tcpHdr = header.TCP(b)
	}
	if len(tcpHdr) < header.TCPMinimumSize || int(tcpHdr.DataOffset()) != len(tcpHdr) {
		return segs, false
	}
	if uint32(len(tcpHdr)+mss) > maxTransportLen {
		return segs, false
	}

	payload := pkt.Data().ToBuffer()
	defer payload.Release()
	if len(pkt.TransportHeader().Slice()) == 0 {
		payload.TrimFront(int64(len(tcpHdr)))
	}

	netHdr := pkt.NetworkHeader().Slice()
	seq := tcpHdr.SequenceNumber()
	flags := tcpHdr.Flags()
	for i := 0; payload.Size() > 0; i++ {
		n := min(mss, int(payload.Size()))
		data := payload.Clone()
		data.Truncate(int64(n))
		payload.TrimFront(int64(n))

		seg := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: reserveHeaderBytes + len(netHdr) + len(tcpHdr),
			Payload:            data,
			IsForwardedPacket:  true,
		})
		seg.Mark = pkt.Mark
		seg.Hash = pkt.Hash
		seg.InputNICID = pkt.InputNICID

		segFlags := flags
		if i != 0 {
			segFlags &^= header.TCPFlagCwr
		}
		if payload.Size() != 0 {
			segFlags &^= header.TCPFlagFin | header.TCPFlagPsh
		}
		segTCP := header.TCP(seg.TransportHeader().Push(len(tcpHdr)))
		copy(segTCP, tcpHdr)
		segTCP.SetSequenceNumber(seq + uint32(i*mss))
		segTCP.SetFlags(uint8(segFlags))
		seg.TransportProtocolNumber = header.TCPProtocolNumber

		segNetHdr := seg.NetworkHeader().Push(len(netHdr))
		copy(segNetHdr, netHdr)
		seg.NetworkProtocolNumber = pkt.NetworkProtocolNumber
		setNetworkLength(i, segNetHdr, len(tcpHdr)+n)

		net := seg.Network()
		xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, net.SourceAddress(), net.DestinationAddress(), uint16(len(tcpHdr)+n))
		xsum = checksum.Combine(xsum, seg.Data().Checksum())
		segTCP.SetChecksum(0)
		segTCP.SetChecksum(^segTCP.CalculateChecksum(xsum))

		segs.PushBack(seg)
	}
	return segs, true
}

// WriteSegments calls write for each packet in segs, stopping at the first
// error, and then releases segs. It returns the number of packets written and
// the number not written, which includes the one that failed.
func WriteSegments(segs stack.PacketBufferList, write func(*stack.PacketBuffer) tcpip.Error) (sent, remain int, err tcpip.Error) {
	defer segs.DecRef()
	for i, seg := range segs.AsSlice() {
		if err := write(seg); err != nil {
			return i, segs.Len() - i, err
		}
	}
	return segs.Len(), 0, nil
}
