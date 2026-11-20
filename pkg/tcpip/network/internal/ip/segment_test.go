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

package ip_test

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const segmentTestSeqNum = 100

var (
	segmentTestSrc = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	segmentTestDst = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// newForwardedTCPPacket returns a forwarded IPv4 TCP packet with its network
// header parsed, and its TCP header parsed only if parseTCP is set.
func newForwardedTCPPacket(t *testing.T, payload []byte, groSegmentSize uint16, parseTCP bool) *stack.PacketBuffer {
	t.Helper()
	buf := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
	header.IPv4(buf).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     segmentTestSrc,
		DstAddr:     segmentTestDst,
	})
	header.TCP(buf[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort:    1234,
		DstPort:    80,
		SeqNum:     segmentTestSeqNum,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 65535,
	})
	copy(buf[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           buffer.MakeWithData(buf),
		IsForwardedPacket: true,
	})
	if _, ok := pkt.NetworkHeader().Consume(header.IPv4MinimumSize); !ok {
		t.Fatal("pkt.NetworkHeader().Consume() failed")
	}
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if parseTCP {
		if _, ok := pkt.TransportHeader().Consume(header.TCPMinimumSize); !ok {
			t.Fatal("pkt.TransportHeader().Consume() failed")
		}
		pkt.TransportProtocolNumber = header.TCPProtocolNumber
	}
	pkt.GROSegmentSize = groSegmentSize
	return pkt
}

func setIPv4Length(_ int, netHdr []byte, transportLen int) {
	h := header.IPv4(netHdr)
	h.SetTotalLength(uint16(len(netHdr) + transportLen))
	h.SetChecksum(0)
	h.SetChecksum(^h.CalculateChecksum())
}

func TestSegmentCoalescedTCP(t *testing.T) {
	payload := make([]byte, 250)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, parseTCP := range []bool{true, false} {
		name := "TCP header not parsed"
		if parseTCP {
			name = "TCP header parsed"
		}
		t.Run(name, func(t *testing.T) {
			pkt := newForwardedTCPPacket(t, payload, 100, parseTCP)
			defer pkt.DecRef()

			segs, ok := ip.SegmentCoalescedTCP(pkt, 1000, 0, setIPv4Length)
			if !ok {
				t.Fatal("ip.SegmentCoalescedTCP(...) = _, false, want _, true")
			}
			defer segs.DecRef()

			wantSizes := []int{100, 100, 50}
			if got := segs.Len(); got != len(wantSizes) {
				t.Fatalf("got %d segments, want %d", got, len(wantSizes))
			}
			off := 0
			for i, seg := range segs.AsSlice() {
				v := stack.PayloadSince(seg.NetworkHeader())
				defer v.Release()
				ipHdr := header.IPv4(v.AsSlice())
				if !ipHdr.IsValid(len(v.AsSlice())) || !ipHdr.IsChecksumValid() {
					t.Fatalf("segment %d: invalid IPv4 header %x", i, []byte(ipHdr))
				}
				tcpHdr := header.TCP(ipHdr.Payload())
				if got, want := tcpHdr.SequenceNumber(), uint32(segmentTestSeqNum+off); got != want {
					t.Errorf("segment %d: got sequence number %d, want %d", i, got, want)
				}
				if got, want := tcpHdr.Payload(), payload[off:off+wantSizes[i]]; !bytes.Equal(got, want) {
					t.Errorf("segment %d: got %d payload bytes, want %d", i, len(got), len(want))
				}
				xsum := checksum.Checksum(tcpHdr.Payload(), 0)
				if !tcpHdr.IsChecksumValid(segmentTestSrc, segmentTestDst, xsum, uint16(len(tcpHdr.Payload()))) {
					t.Errorf("segment %d: invalid TCP checksum", i)
				}
				off += wantSizes[i]
			}
		})
	}
}

func TestSegmentCoalescedTCPDoesNotSegment(t *testing.T) {
	for _, test := range []struct {
		name            string
		groSegmentSize  uint16
		maxTransportLen uint32
	}{
		{
			name:            "not coalesced",
			groSegmentSize:  0,
			maxTransportLen: 1000,
		},
		{
			name:            "segments do not fit",
			groSegmentSize:  100,
			maxTransportLen: header.TCPMinimumSize + 99,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkt := newForwardedTCPPacket(t, make([]byte, 250), test.groSegmentSize, true)
			defer pkt.DecRef()
			if segs, ok := ip.SegmentCoalescedTCP(pkt, test.maxTransportLen, 0, setIPv4Length); ok {
				segs.DecRef()
				t.Fatal("ip.SegmentCoalescedTCP(...) = _, true, want _, false")
			}
		})
	}
}

func TestWriteSegmentsStopsAtFirstError(t *testing.T) {
	pkt := newForwardedTCPPacket(t, make([]byte, 400), 100, true)
	defer pkt.DecRef()
	segs, ok := ip.SegmentCoalescedTCP(pkt, 1000, 0, setIPv4Length)
	if !ok {
		t.Fatal("ip.SegmentCoalescedTCP(...) = _, false, want _, true")
	}

	calls := 0
	sent, remain, err := ip.WriteSegments(segs, func(*stack.PacketBuffer) tcpip.Error {
		calls++
		if calls == 2 {
			return &tcpip.ErrNoBufferSpace{}
		}
		return nil
	})
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Errorf("got err = %v, want %s", err, &tcpip.ErrNoBufferSpace{})
	}
	if sent != 1 || remain != 3 {
		t.Errorf("got sent, remain = %d, %d, want 1, 3", sent, remain)
	}
	if calls != 2 {
		t.Errorf("write called %d times, want 2", calls)
	}
}
