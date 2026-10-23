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

package stack

import (
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

// genL4Packet returns an inbound TCP or UDP packet with a valid transport
// checksum, or with a UDP checksum of zero if zeroUDPChecksum is set.
func genL4Packet(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, src, dst tcpip.Address, srcPort, dstPort uint16, zeroUDPChecksum bool) *PacketBuffer {
	payload := []byte{1, 2, 3, 4, 5}
	l4Size := header.UDPMinimumSize
	if transProto == header.TCPProtocolNumber {
		l4Size = header.TCPMinimumSize
	}
	netSize := header.IPv4MinimumSize
	if netProto == header.IPv6ProtocolNumber {
		netSize = header.IPv6MinimumSize
	}

	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: netSize + l4Size,
		Payload:            buffer.MakeWithData(payload),
	})
	pkt.NetworkProtocolNumber = netProto
	pkt.TransportProtocolNumber = transProto

	totalL4 := uint16(l4Size + len(payload))
	xsum := checksum.Checksum(payload, header.PseudoHeaderChecksum(transProto, src, dst, totalL4))
	switch transProto {
	case header.TCPProtocolNumber:
		tcp := header.TCP(pkt.TransportHeader().Push(l4Size))
		tcp.Encode(&header.TCPFields{
			SrcPort:    srcPort,
			DstPort:    dstPort,
			SeqNum:     1,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagSyn,
			WindowSize: 50000,
		})
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	case header.UDPProtocolNumber:
		udp := header.UDP(pkt.TransportHeader().Push(l4Size))
		udp.Encode(&header.UDPFields{
			SrcPort: srcPort,
			DstPort: dstPort,
			Length:  totalL4,
		})
		if !zeroUDPChecksum {
			udp.SetChecksum(^udp.CalculateChecksum(xsum))
		}
	}

	switch netProto {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(pkt.NetworkHeader().Push(netSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(netSize) + totalL4,
			TTL:         64,
			Protocol:    uint8(transProto),
			SrcAddr:     src,
			DstAddr:     dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(pkt.NetworkHeader().Push(netSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     totalL4,
			TransportProtocol: transProto,
			HopLimit:          64,
			SrcAddr:           src,
			DstAddr:           dst,
		})
	}
	return pkt
}

// TestInputSNATUpdatesTransportChecksum tests that source NAT at the Input
// hook keeps the TCP or UDP checksum valid for the rewritten address and port,
// and leaves a UDP checksum of zero as zero, like
// net/netfilter/nf_nat_proto.c:l4proto_manip_pkt.
func TestInputSNATUpdatesTransportChecksum(t *testing.T) {
	const (
		srcPort = 5555
		dstPort = 80
		natPort = 4000
	)

	hooks := []struct {
		name  string
		apply func(*PacketBuffer) bool
	}{
		{"iptables", func(pkt *PacketBuffer) bool { return IPTHandlePacket(pkt, Input, nil) }},
		{"nftables", func(pkt *PacketBuffer) bool { return NFTApplyNAT(pkt, NFInput, nil) }},
	}
	nets := []struct {
		name     string
		proto    tcpip.NetworkProtocolNumber
		src      tcpip.Address
		dst      tcpip.Address
		natAddr  tcpip.Address
		withZero bool
	}{
		{
			name:    "IPv4",
			proto:   header.IPv4ProtocolNumber,
			src:     testutil.MustParse4("203.0.113.20"),
			dst:     testutil.MustParse4("192.0.2.1"),
			natAddr: testutil.MustParse4("198.51.100.10"),
			// A zero UDP checksum is only valid over IPv4.
			withZero: true,
		},
		{
			name:    "IPv6",
			proto:   header.IPv6ProtocolNumber,
			src:     testutil.MustParse6("2001:db8:2::20"),
			dst:     testutil.MustParse6("2001:db8::1"),
			natAddr: testutil.MustParse6("2001:db8:1::10"),
		},
	}
	type transTest struct {
		name            string
		proto           tcpip.TransportProtocolNumber
		zeroUDPChecksum bool
	}

	for _, hook := range hooks {
		for _, nt := range nets {
			transTests := []transTest{
				{name: "TCP", proto: header.TCPProtocolNumber},
				{name: "UDP", proto: header.UDPProtocolNumber},
			}
			if nt.withZero {
				transTests = append(transTests, transTest{name: "UDPZeroChecksum", proto: header.UDPProtocolNumber, zeroUDPChecksum: true})
			}
			for _, trans := range transTests {
				t.Run(hook.name+"/"+nt.name+"/"+trans.name, func(t *testing.T) {
					ct := NewConnTrack(faketime.NewManualClock(), rand.New(rand.NewSource(0)), nil)
					pkt := genL4Packet(nt.proto, trans.proto, nt.src, nt.dst, srcPort, dstPort, trans.zeroUDPChecksum)
					defer pkt.DecRef()
					pkt.tuple = ct.getConnAndUpdate(pkt, false /* skipChecksumValidation */)
					if pkt.tuple == nil {
						t.Fatal("ct.getConnAndUpdate(...) = nil, want a tracked connection")
					}
					natRange := PortOrIdentRange{Start: natPort, Size: 1}
					if !pkt.tuple.conn.ConfigureNAT(natRange, nt.natAddr, SNAT, true /* changePort */, true /* changeAddress */) {
						t.Fatalf("ConfigureNAT(%#v, %s, SNAT, true, true) = false", natRange, nt.natAddr)
					}

					if !hook.apply(pkt) {
						t.Fatal("NAT not performed")
					}

					netHdr, transHdr, _, ok := pkt.GetHeaders()
					if !ok {
						t.Fatal("pkt.GetHeaders() failed")
					}
					if got := netHdr.SourceAddress(); got != nt.natAddr {
						t.Errorf("got source address = %s, want = %s", got, nt.natAddr)
					}
					if got := transHdr.SourcePort(); got != natPort {
						t.Errorf("got source port = %d, want = %d", got, natPort)
					}
					payloadXsum := pkt.Data().Checksum()
					switch trans.proto {
					case header.TCPProtocolNumber:
						if !transHdr.(header.TCP).IsChecksumValid(netHdr.SourceAddress(), netHdr.DestinationAddress(), payloadXsum, uint16(pkt.Data().Size())) {
							t.Errorf("TCP checksum %#04x is invalid after NAT", transHdr.Checksum())
						}
					case header.UDPProtocolNumber:
						udp := transHdr.(header.UDP)
						if trans.zeroUDPChecksum {
							if got := udp.Checksum(); got != 0 {
								t.Errorf("got UDP checksum = %#04x, want = 0", got)
							}
						} else if !udp.IsChecksumValid(netHdr.SourceAddress(), netHdr.DestinationAddress(), payloadXsum) {
							t.Errorf("UDP checksum %#04x is invalid after NAT", udp.Checksum())
						}
					}
				})
			}
		}
	}
}
