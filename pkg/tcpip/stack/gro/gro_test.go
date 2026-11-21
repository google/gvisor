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
	"bytes"
	"math/bits"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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

type dispatcherCaptureEndpoint struct {
	*channel.Endpoint
	dispatcher stack.NetworkDispatcher
}

func (e *dispatcherCaptureEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.Endpoint.Attach(dispatcher)
}

func newTCPPacket(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address, seq uint32, payload []byte, corrupt bool) *stack.PacketBuffer {
	ipHdrLen := header.IPv4MinimumSize
	if netProto == header.IPv6ProtocolNumber {
		ipHdrLen = header.IPv6MinimumSize
	}
	buf := make([]byte, ipHdrLen+header.TCPMinimumSize+len(payload))
	switch netProto {
	case header.IPv4ProtocolNumber:
		h := header.IPv4(buf)
		h.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(buf)),
			TTL:         64,
			Protocol:    uint8(tcp.ProtocolNumber),
			SrcAddr:     src,
			DstAddr:     dst,
		})
	case header.IPv6ProtocolNumber:
		h := header.IPv6(buf)
		h.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(buf) - ipHdrLen),
			TransportProtocol: tcp.ProtocolNumber,
			HopLimit:          64,
			SrcAddr:           src,
			DstAddr:           dst,
		})
	default:
		panic("unknown network protocol")
	}

	tcpHdr := header.TCP(buf[ipHdrLen:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    5555,
		DstPort:    80,
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 30000,
	})
	copy(buf[len(buf)-len(payload):], payload)
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, uint16(len(tcpHdr)))
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))
	if netProto == header.IPv4ProtocolNumber {
		h := header.IPv4(buf)
		h.SetChecksum(^h.CalculateChecksum())
	}
	if corrupt {
		buf[len(buf)-1]++
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf),
	})
	pkt.NetworkProtocolNumber = netProto
	return pkt
}

func TestTCPChecksumValidationThroughNIC(t *testing.T) {
	const nicID = 1
	tests := []struct {
		name       string
		netProto   tcpip.NetworkProtocolNumber
		localAddr  tcpip.Address
		remoteAddr tcpip.Address
	}{
		{
			name:       "IPv4",
			netProto:   header.IPv4ProtocolNumber,
			localAddr:  tcpip.AddrFrom4([4]byte{192, 0, 2, 2}),
			remoteAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}),
		},
		{
			name:       "IPv6",
			netProto:   header.IPv6ProtocolNumber,
			localAddr:  tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
			remoteAddr: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			})
			defer s.Destroy()
			linkEP := &dispatcherCaptureEndpoint{Endpoint: channel.New(16, header.IPv6MinimumMTU, "")}
			if err := s.CreateNIC(nicID, linkEP); err != nil {
				t.Fatalf("CreateNIC: %v", err)
			}
			if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
				Protocol:          test.netProto,
				AddressWithPrefix: test.localAddr.WithPrefix(),
			}, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress: %v", err)
			}
			s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}, {Destination: header.IPv6EmptySubnet, NIC: nicID}})

			gd := GRO{Dispatcher: linkEP.dispatcher}
			gd.Init(true)
			corrupt := newTCPPacket(test.netProto, test.remoteAddr, test.localAddr, 0, []byte("corrupt"), true)
			gd.Enqueue(corrupt)
			corrupt.DecRef()
			gd.Flush()
			if pkt := linkEP.Read(); pkt != nil {
				pkt.DecRef()
				t.Fatal("corrupt packet elicited a response")
			}

			const payloadSize = 128
			for i := uint32(0); i < 2; i++ {
				pkt := newTCPPacket(test.netProto, test.remoteAddr, test.localAddr, i*payloadSize, bytes.Repeat([]byte{byte(i + 1)}, payloadSize), false)
				gd.Enqueue(pkt)
				pkt.DecRef()
			}
			gd.Flush()

			pkt := linkEP.Read()
			if pkt == nil {
				t.Fatal("valid coalesced packet did not elicit a RST")
			}
			view := pkt.ToView()
			ipHdrLen := header.IPv4MinimumSize
			if test.netProto == header.IPv6ProtocolNumber {
				ipHdrLen = header.IPv6MinimumSize
			}
			flags := header.TCP(view.AsSlice()[ipHdrLen:]).Flags()
			view.Release()
			pkt.DecRef()
			if flags != header.TCPFlagRst {
				t.Fatalf("response flags = %v, want RST", flags)
			}
			if pkt := linkEP.Read(); pkt != nil {
				pkt.DecRef()
				t.Fatal("valid coalesced packet elicited more than one response")
			}
		})
	}
}
