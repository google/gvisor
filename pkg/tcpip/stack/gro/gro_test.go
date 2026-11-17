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

package gro

import (
	"math/bits"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type countingDispatcher struct {
	delivered int
}

func (d *countingDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.delivered++
}

func (*countingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func TestNBuckets(t *testing.T) {
	// groNBuckets must be a power of 2 so that we can use groNBuckets-1 as
	// a mask when indexing into the list of buckets.
	if bits.OnesCount(groNBuckets) != 1 {
		t.Fatalf("groNBuckets is not a power of two")
	}
}

func TestFlushDrainsBucket(t *testing.T) {
	dispatcher := &countingDispatcher{}
	gd := GRO{Dispatcher: dispatcher}
	gd.Init(true)
	bucket := &gd.buckets[0]
	for i := 0; i < groBucketSize; i++ {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		bucket.insert(packet, nil, nil)
	}
	t.Cleanup(func() {
		for bucket.count != 0 {
			bucket.removeOldest().DecRef()
		}
	})

	gd.Flush()

	if got := dispatcher.delivered; got != groBucketSize {
		t.Errorf("Flush delivered %d packets, want %d", got, groBucketSize)
	}
	if got := bucket.count; got != 0 {
		t.Errorf("Flush left %d packets in bucket, want 0", got)
	}
}

type capturingDispatcher struct {
	pkts []*stack.PacketBuffer
}

func (d *capturingDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.pkts = append(d.pkts, pkt.IncRef())
}

func (*capturingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func newTCPv4Packet(seq uint32, payloadLen int) *stack.PacketBuffer {
	buf := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+payloadLen)
	header.IPv4(buf).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
	})
	header.TCP(buf[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort:    1234,
		DstPort:    80,
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 65535,
	})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.RXChecksumValidated = true
	return pkt
}

func TestGROSegmentSize(t *testing.T) {
	for _, test := range []struct {
		desc        string
		payloadLens []int
		// want holds the GROSegmentSize of each delivered packet.
		want []uint16
	}{
		{
			desc:        "not coalesced",
			payloadLens: []int{100},
			want:        []uint16{0},
		},
		{
			desc:        "coalesced",
			payloadLens: []int{100, 100, 100},
			want:        []uint16{100},
		},
		{
			desc:        "coalesced with a shorter last segment",
			payloadLens: []int{100, 100, 40},
			want:        []uint16{100},
		},
		{
			desc:        "larger segment is not coalesced",
			payloadLens: []int{1, 1448},
			want:        []uint16{0, 0},
		},
		{
			desc:        "coalesced, then a larger segment",
			payloadLens: []int{100, 100, 1448, 1448},
			want:        []uint16{100, 1448},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			dispatcher := &capturingDispatcher{}
			gd := GRO{Dispatcher: dispatcher}
			gd.Init(true)
			seq := uint32(1)
			for _, n := range test.payloadLens {
				pkt := newTCPv4Packet(seq, n)
				gd.Enqueue(pkt)
				pkt.DecRef()
				seq += uint32(n)
			}
			gd.Flush()
			defer func() {
				for _, pkt := range dispatcher.pkts {
					pkt.DecRef()
				}
			}()

			var got []uint16
			for _, pkt := range dispatcher.pkts {
				got = append(got, pkt.GROSegmentSize)
			}
			if !slices.Equal(got, test.want) {
				t.Errorf("GROSegmentSize of delivered packets = %v, want %v", got, test.want)
			}
		})
	}
}
