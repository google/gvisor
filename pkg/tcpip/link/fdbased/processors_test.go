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

//go:build linux
// +build linux

package fdbased

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	testSrcAddrV4 = tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	testDstAddrV4 = tcpip.AddrFrom4([4]byte{5, 6, 7, 8})
)

const (
	testSrcPort = uint16(0x1234)
	testDstPort = uint16(0x5678)
)

// ipv4TCPPacket returns a well formed IPv4/TCP packet whose IHL field is
// overwritten with ihl (in 32-bit words). An ihl smaller than 5 makes the
// header shorter than header.IPv4MinimumSize, which is invalid.
func ipv4TCPPacket(ihl uint8) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     testSrcAddrV4,
		DstAddr:     testDstAddrV4,
	})
	// Overwrite the version/IHL field with the IHL under test.
	pkt[0] = header.IPv4Version<<4 | ihl
	tcp := header.TCP(pkt[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    testSrcPort,
		DstPort:    testDstPort,
		DataOffset: header.TCPMinimumSize,
	})
	return pkt
}

// TestTCPIPConnectionIDIPv4 verifies that connection IDs are only derived from
// IPv4 headers that are long enough to hold the fields they are derived from.
// Packets with a smaller header length must be reported as non-connection
// packets instead of being parsed with a truncated header, which reads memory
// past the end of the header.
func TestTCPIPConnectionIDIPv4(t *testing.T) {
	for ihl := uint8(0); ihl <= 5; ihl++ {
		t.Run(fmt.Sprintf("IHL=%d", ihl), func(t *testing.T) {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(ipv4TCPPacket(ihl)),
			})
			defer pkt.DecRef()

			cid, nonConnectionPkt := tcpipConnectionID(pkt)

			// An IPv4 header is at least header.IPv4MinimumSize (5 words) long.
			wantNonConnectionPkt := ihl < header.IPv4MinimumSize/4
			if nonConnectionPkt != wantNonConnectionPkt {
				t.Fatalf("tcpipConnectionID(...) returned nonConnectionPkt = %t, want %t", nonConnectionPkt, wantNonConnectionPkt)
			}
			if nonConnectionPkt {
				// Nothing may be extracted from a malformed header.
				if cid.srcAddr != nil || cid.dstAddr != nil || cid.srcPort != 0 || cid.dstPort != 0 || cid.proto != 0 {
					t.Errorf("tcpipConnectionID(...) returned cid = %+v, want zero value", cid)
				}
				return
			}

			if got, want := cid.srcAddr, testSrcAddrV4.AsSlice(); !bytes.Equal(got, want) {
				t.Errorf("got cid.srcAddr = %v, want %v", got, want)
			}
			if got, want := cid.dstAddr, testDstAddrV4.AsSlice(); !bytes.Equal(got, want) {
				t.Errorf("got cid.dstAddr = %v, want %v", got, want)
			}
			if got, want := cid.srcPort, testSrcPort; got != want {
				t.Errorf("got cid.srcPort = %d, want %d", got, want)
			}
			if got, want := cid.dstPort, testDstPort; got != want {
				t.Errorf("got cid.dstPort = %d, want %d", got, want)
			}
			if got, want := cid.proto, header.IPv4ProtocolNumber; got != want {
				t.Errorf("got cid.proto = %d, want %d", got, want)
			}
		})
	}
}

// TestTCPIPConnectionIDIPv6 verifies that connection IDs are computed for well
// formed IPv6 packets.
func TestTCPIPConnectionIDIPv6(t *testing.T) {
	srcAddr := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	dstAddr := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	buf := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	header.IPv6(buf).Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})
	binary.BigEndian.PutUint16(buf[header.IPv6MinimumSize:], testSrcPort)
	binary.BigEndian.PutUint16(buf[header.IPv6MinimumSize+2:], testDstPort)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf),
	})
	defer pkt.DecRef()

	cid, nonConnectionPkt := tcpipConnectionID(pkt)
	if nonConnectionPkt {
		t.Fatalf("tcpipConnectionID(...) returned nonConnectionPkt = true, want false")
	}
	if got, want := cid.srcAddr, srcAddr.AsSlice(); !bytes.Equal(got, want) {
		t.Errorf("got cid.srcAddr = %v, want %v", got, want)
	}
	if got, want := cid.dstAddr, dstAddr.AsSlice(); !bytes.Equal(got, want) {
		t.Errorf("got cid.dstAddr = %v, want %v", got, want)
	}
	if got, want := cid.srcPort, testSrcPort; got != want {
		t.Errorf("got cid.srcPort = %d, want %d", got, want)
	}
	if got, want := cid.dstPort, testDstPort; got != want {
		t.Errorf("got cid.dstPort = %d, want %d", got, want)
	}
	if got, want := cid.proto, header.IPv6ProtocolNumber; got != want {
		t.Errorf("got cid.proto = %d, want %d", got, want)
	}
}

// TestDispatchMalformedIPv4 verifies how the dispatcher handles an IPv4 packet
// whose header length is too small to be valid. On a link with an Ethernet
// header the packet is still delivered, and the network layer drops it. On a
// link without one there is no connection ID to take the network protocol
// from, so the packet is dropped by the dispatcher.
func TestDispatchMalformedIPv4(t *testing.T) {
	ethHdr := []byte{
		1, 2, 3, 4, 5, 60,
		1, 2, 3, 4, 5, 61,
		8, 0,
	}
	// Version 4 with a header length of 0, padded to the 4 bytes the
	// dispatcher pulls up first.
	netHdr := []byte{0x40, 0, 0, 0}

	for _, test := range []struct {
		name     string
		ethHdr   []byte
		wantPkts int
	}{
		{name: "Eth", ethHdr: ethHdr, wantPkts: 1},
		{name: "NoEth", wantPkts: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Create a socket pair to send/recv.
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}

			data := append(append([]byte(nil), test.ethHdr...), netHdr...)
			if err := unix.Sendmsg(fds[1], data, nil, nil, 0); err != nil {
				t.Fatal(err)
			}

			// Create and run dispatcher once. A single processor delivers
			// packets inline, so no synchronization is needed below.
			sink := &fakeNetworkDispatcher{}
			var addr tcpip.LinkAddress
			if len(test.ethHdr) > 0 {
				addr = tcpip.LinkAddress(test.ethHdr[:header.EthernetAddressSize])
			}
			d, err := newReadVDispatcher(fds[0], &endpoint{
				addr:       addr,
				hdrSize:    len(test.ethHdr),
				dispatcher: sink,
			}, &Options{ProcessorsPerChannel: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer d.release()
			if ok, err := d.dispatch(); !ok || err != nil {
				t.Fatalf("d.dispatch() = %v, %v", ok, err)
			}

			for _, pkt := range sink.pkts {
				defer pkt.DecRef()
			}
			if got := len(sink.pkts); got != test.wantPkts {
				t.Errorf("len(sink.pkts) = %d, want %d", got, test.wantPkts)
			}
		})
	}
}
