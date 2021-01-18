// Copyright 2020 The gVisor Authors.
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

package integration_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultMTU = 1280
	ttl        = 255

	remotePort = 5555
	localPort  = 80
)

var (
	ipv4Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
		PrefixLen: 24,
	}
	ipv4Subnet      = ipv4Addr.Subnet()
	ipv4SubnetBcast = ipv4Subnet.Broadcast()

	ipv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("200a::1").To16()),
		PrefixLen: 64,
	}
	ipv6Subnet      = ipv6Addr.Subnet()
	ipv6SubnetBcast = ipv6Subnet.Broadcast()

	// Remote addrs.
	remoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	remoteIPv6Addr = tcpip.Address(net.ParseIP("200b::1").To16())
)

// TestPingMulticastBroadcast tests that responding to an Echo Request destined
// to a multicast or broadcast address uses a unicast source address for the
// reply.
func TestPingMulticastBroadcast(t *testing.T) {
	const nicID = 1

	rxIPv4ICMP := func(e *channel.Endpoint, dst tcpip.Address) {
		totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		pkt.SetType(header.ICMPv4Echo)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^header.Checksum(pkt, 0))
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    uint8(icmp.ProtocolNumber4),
			TTL:         ttl,
			SrcAddr:     remoteIPv4Addr,
			DstAddr:     dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())

		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	rxIPv6ICMP := func(e *channel.Endpoint, dst tcpip.Address) {
		totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
		pkt.SetType(header.ICMPv6EchoRequest)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, remoteIPv6Addr, dst, buffer.VectorisedView{}))
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     header.ICMPv6MinimumSize,
			TransportProtocol: icmp.ProtocolNumber6,
			HopLimit:          ttl,
			SrcAddr:           remoteIPv6Addr,
			DstAddr:           dst,
		})

		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	tests := []struct {
		name    string
		dstAddr tcpip.Address
	}{
		{
			name:    "IPv4 unicast",
			dstAddr: ipv4Addr.Address,
		},
		{
			name:    "IPv4 directed broadcast",
			dstAddr: ipv4SubnetBcast,
		},
		{
			name:    "IPv4 broadcast",
			dstAddr: header.IPv4Broadcast,
		},
		{
			name:    "IPv4 all-systems multicast",
			dstAddr: header.IPv4AllSystems,
		},
		{
			name:    "IPv6 unicast",
			dstAddr: ipv6Addr.Address,
		},
		{
			name:    "IPv6 all-nodes multicast",
			dstAddr: header.IPv6AllNodesMulticastAddress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
			})
			// We only expect a single packet in response to our ICMP Echo Request.
			e := channel.New(1, defaultMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, ipv4ProtoAddr, err)
			}
			ipv6ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: ipv6Addr}
			if err := s.AddProtocolAddress(nicID, ipv6ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, ipv6ProtoAddr, err)
			}

			// Default routes for IPv4 and IPv6 so ICMP can find a route to the remote
			// node when attempting to send the ICMP Echo Reply.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			var rxICMP func(*channel.Endpoint, tcpip.Address)
			var expectedSrc tcpip.Address
			var expectedDst tcpip.Address
			var protoNum tcpip.NetworkProtocolNumber
			switch l := len(test.dstAddr); l {
			case header.IPv4AddressSize:
				rxICMP = rxIPv4ICMP
				expectedSrc = ipv4Addr.Address
				expectedDst = remoteIPv4Addr
				protoNum = header.IPv4ProtocolNumber
			case header.IPv6AddressSize:
				rxICMP = rxIPv6ICMP
				expectedSrc = ipv6Addr.Address
				expectedDst = remoteIPv6Addr
				protoNum = header.IPv6ProtocolNumber
			default:
				t.Fatalf("got unexpected address length = %d bytes", l)
			}

			rxICMP(e, test.dstAddr)
			pkt, ok := e.Read()
			if !ok {
				t.Fatal("expected ICMP response")
			}

			if pkt.Route.LocalAddress != expectedSrc {
				t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", pkt.Route.LocalAddress, expectedSrc)
			}
			if pkt.Route.RemoteAddress != expectedDst {
				t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", pkt.Route.RemoteAddress, expectedDst)
			}

			src, dst := s.NetworkProtocolInstance(protoNum).ParseAddresses(stack.PayloadSince(pkt.Pkt.NetworkHeader()))
			if src != expectedSrc {
				t.Errorf("got pkt source = %s, want = %s", src, expectedSrc)
			}
			if dst != expectedDst {
				t.Errorf("got pkt destination = %s, want = %s", dst, expectedDst)
			}
		})
	}

}

func rxIPv4UDP(e *channel.Endpoint, src, dst tcpip.Address, data []byte) {
	payloadLen := header.UDPMinimumSize + len(data)
	totalLen := header.IPv4MinimumSize + payloadLen
	hdr := buffer.NewPrependable(totalLen)
	u := header.UDP(hdr.Prepend(payloadLen))
	u.Encode(&header.UDPFields{
		SrcPort: remotePort,
		DstPort: localPort,
		Length:  uint16(payloadLen),
	})
	copy(u.Payload(), data)
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(payloadLen))
	sum = header.Checksum(data, sum)
	u.SetChecksum(^u.CalculateChecksum(sum))

	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		Protocol:    uint8(udp.ProtocolNumber),
		TTL:         ttl,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))
}

func rxIPv6UDP(e *channel.Endpoint, src, dst tcpip.Address, data []byte) {
	payloadLen := header.UDPMinimumSize + len(data)
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + payloadLen)
	u := header.UDP(hdr.Prepend(payloadLen))
	u.Encode(&header.UDPFields{
		SrcPort: remotePort,
		DstPort: localPort,
		Length:  uint16(payloadLen),
	})
	copy(u.Payload(), data)
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(payloadLen))
	sum = header.Checksum(data, sum)
	u.SetChecksum(^u.CalculateChecksum(sum))

	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLen),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          ttl,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))
}

// TestIncomingMulticastAndBroadcast tests receiving a packet destined to some
// multicast or broadcast address.
func TestIncomingMulticastAndBroadcast(t *testing.T) {
	const nicID = 1

	data := []byte{1, 2, 3, 4}

	tests := []struct {
		name       string
		proto      tcpip.NetworkProtocolNumber
		remoteAddr tcpip.Address
		localAddr  tcpip.AddressWithPrefix
		rxUDP      func(*channel.Endpoint, tcpip.Address, tcpip.Address, []byte)
		bindAddr   tcpip.Address
		dstAddr    tcpip.Address
		expectRx   bool
	}{
		{
			name:       "IPv4 unicast binding to unicast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   ipv4Addr.Address,
			dstAddr:    ipv4Addr.Address,
			expectRx:   true,
		},
		{
			name:       "IPv4 unicast binding to broadcast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   header.IPv4Broadcast,
			dstAddr:    ipv4Addr.Address,
			expectRx:   false,
		},
		{
			name:       "IPv4 unicast binding to wildcard",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			dstAddr:    ipv4Addr.Address,
			expectRx:   true,
		},

		{
			name:       "IPv4 directed broadcast binding to subnet broadcast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   ipv4SubnetBcast,
			dstAddr:    ipv4SubnetBcast,
			expectRx:   true,
		},
		{
			name:       "IPv4 directed broadcast binding to broadcast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   header.IPv4Broadcast,
			dstAddr:    ipv4SubnetBcast,
			expectRx:   false,
		},
		{
			name:       "IPv4 directed broadcast binding to wildcard",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			dstAddr:    ipv4SubnetBcast,
			expectRx:   true,
		},

		{
			name:       "IPv4 broadcast binding to broadcast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   header.IPv4Broadcast,
			dstAddr:    header.IPv4Broadcast,
			expectRx:   true,
		},
		{
			name:       "IPv4 broadcast binding to subnet broadcast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   ipv4SubnetBcast,
			dstAddr:    header.IPv4Broadcast,
			expectRx:   false,
		},
		{
			name:       "IPv4 broadcast binding to wildcard",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			dstAddr:    ipv4SubnetBcast,
			expectRx:   true,
		},

		{
			name:       "IPv4 all-systems multicast binding to all-systems multicast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   header.IPv4AllSystems,
			dstAddr:    header.IPv4AllSystems,
			expectRx:   true,
		},
		{
			name:       "IPv4 all-systems multicast binding to wildcard",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			dstAddr:    header.IPv4AllSystems,
			expectRx:   true,
		},
		{
			name:       "IPv4 all-systems multicast binding to unicast",
			proto:      header.IPv4ProtocolNumber,
			remoteAddr: remoteIPv4Addr,
			localAddr:  ipv4Addr,
			rxUDP:      rxIPv4UDP,
			bindAddr:   ipv4Addr.Address,
			dstAddr:    header.IPv4AllSystems,
			expectRx:   false,
		},

		// IPv6 has no notion of a broadcast.
		{
			name:       "IPv6 unicast binding to wildcard",
			dstAddr:    ipv6Addr.Address,
			proto:      header.IPv6ProtocolNumber,
			remoteAddr: remoteIPv6Addr,
			localAddr:  ipv6Addr,
			rxUDP:      rxIPv6UDP,
			expectRx:   true,
		},
		{
			name:       "IPv6 broadcast-like address binding to wildcard",
			dstAddr:    ipv6SubnetBcast,
			proto:      header.IPv6ProtocolNumber,
			remoteAddr: remoteIPv6Addr,
			localAddr:  ipv6Addr,
			rxUDP:      rxIPv6UDP,
			expectRx:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			e := channel.New(0, defaultMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			protoAddr := tcpip.ProtocolAddress{Protocol: test.proto, AddressWithPrefix: test.localAddr}
			if err := s.AddProtocolAddress(nicID, protoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, protoAddr, err)
			}

			var wq waiter.Queue
			ep, err := s.NewEndpoint(udp.ProtocolNumber, test.proto, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.proto, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: test.bindAddr, Port: localPort}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("ep.Bind(%#v): %s", bindAddr, err)
			}

			test.rxUDP(e, test.remoteAddr, test.dstAddr, data)
			var buf bytes.Buffer
			var opts tcpip.ReadOptions
			if res, err := ep.Read(&buf, opts); test.expectRx {
				if err != nil {
					t.Fatalf("ep.Read(_, %#v): %s", opts, err)
				}
				if diff := cmp.Diff(tcpip.ReadResult{
					Count: buf.Len(),
					Total: buf.Len(),
				}, res, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
					t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(data, buf.Bytes()); diff != "" {
					t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
				}
			} else if err != tcpip.ErrWouldBlock {
				t.Fatalf("got Read = (%v, %s) [with data %x], want = (_, %s)", res, err, buf.Bytes(), tcpip.ErrWouldBlock)
			}
		})
	}
}

// TestReuseAddrAndBroadcast makes sure broadcast packets are received by all
// interested endpoints.
func TestReuseAddrAndBroadcast(t *testing.T) {
	const (
		nicID             = 1
		localPort         = 9000
		loopbackBroadcast = tcpip.Address("\x7f\xff\xff\xff")
	)

	tests := []struct {
		name          string
		broadcastAddr tcpip.Address
	}{
		{
			name:          "Subnet directed broadcast",
			broadcastAddr: loopbackBroadcast,
		},
		{
			name:          "IPv4 broadcast",
			broadcastAddr: header.IPv4Broadcast,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			protoAddr := tcpip.ProtocolAddress{
				Protocol: header.IPv4ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   "\x7f\x00\x00\x01",
					PrefixLen: 8,
				},
			}
			if err := s.AddProtocolAddress(nicID, protoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, protoAddr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					// We use the empty subnet instead of just the loopback subnet so we
					// also have a route to the IPv4 Broadcast address.
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			type endpointAndWaiter struct {
				ep tcpip.Endpoint
				ch chan struct{}
			}
			var eps []endpointAndWaiter
			// We create endpoints that bind to both the wildcard address and the
			// broadcast address to make sure both of these types of "broadcast
			// interested" endpoints receive broadcast packets.
			for _, bindWildcard := range []bool{false, true} {
				// Create multiple endpoints for each type of "broadcast interested"
				// endpoint so we can test that all endpoints receive the broadcast
				// packet.
				for i := 0; i < 2; i++ {
					var wq waiter.Queue
					we, ch := waiter.NewChannelEntry(nil)
					wq.EventRegister(&we, waiter.EventIn)
					ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
					if err != nil {
						t.Fatalf("(eps[%d]) NewEndpoint(%d, %d, _): %s", len(eps), udp.ProtocolNumber, ipv4.ProtocolNumber, err)
					}
					defer ep.Close()

					ep.SocketOptions().SetReuseAddress(true)
					ep.SocketOptions().SetBroadcast(true)

					bindAddr := tcpip.FullAddress{Port: localPort}
					if bindWildcard {
						if err := ep.Bind(bindAddr); err != nil {
							t.Fatalf("eps[%d].Bind(%#v): %s", len(eps), bindAddr, err)
						}
					} else {
						bindAddr.Addr = test.broadcastAddr
						if err := ep.Bind(bindAddr); err != nil {
							t.Fatalf("eps[%d].Bind(%#v): %s", len(eps), bindAddr, err)
						}
					}

					eps = append(eps, endpointAndWaiter{ep: ep, ch: ch})
				}
			}

			for i, wep := range eps {
				writeOpts := tcpip.WriteOptions{
					To: &tcpip.FullAddress{
						Addr: test.broadcastAddr,
						Port: localPort,
					},
				}
				data := tcpip.SlicePayload([]byte{byte(i), 2, 3, 4})
				if n, err := wep.ep.Write(data, writeOpts); err != nil {
					t.Fatalf("eps[%d].Write(_, _): %s", i, err)
				} else if want := int64(len(data)); n != want {
					t.Fatalf("got eps[%d].Write(_, _) = (%d, nil), want = (%d, nil)", i, n, want)
				}

				for j, rep := range eps {
					// Wait for the endpoint to become readable.
					<-rep.ch

					var buf bytes.Buffer
					result, err := rep.ep.Read(&buf, tcpip.ReadOptions{})
					if err != nil {
						t.Errorf("(eps[%d] write) eps[%d].Read: %s", i, j, err)
						continue
					}
					if diff := cmp.Diff(tcpip.ReadResult{
						Count: buf.Len(),
						Total: buf.Len(),
					}, result, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
						t.Errorf("(eps[%d] write) eps[%d].Read: unexpected result (-want +got):\n%s", i, j, diff)
					}
					if diff := cmp.Diff([]byte(data), buf.Bytes()); diff != "" {
						t.Errorf("(eps[%d] write) got UDP payload from eps[%d] mismatch (-want +got):\n%s", i, j, diff)
					}
				}
			}
		})
	}
}

func TestUDPAddRemoveMembershipSocketOption(t *testing.T) {
	const (
		nicID = 1
	)

	data := []byte{1, 2, 3, 4}

	tests := []struct {
		name          string
		proto         tcpip.NetworkProtocolNumber
		remoteAddr    tcpip.Address
		localAddr     tcpip.AddressWithPrefix
		rxUDP         func(*channel.Endpoint, tcpip.Address, tcpip.Address, []byte)
		multicastAddr tcpip.Address
	}{
		{
			name:          "IPv4 unicast binding to unicast",
			multicastAddr: "\xe0\x01\x02\x03",
			proto:         header.IPv4ProtocolNumber,
			remoteAddr:    remoteIPv4Addr,
			localAddr:     ipv4Addr,
			rxUDP:         rxIPv4UDP,
		},
		{
			name:          "IPv6 broadcast-like address binding to wildcard",
			multicastAddr: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04",
			proto:         header.IPv6ProtocolNumber,
			remoteAddr:    remoteIPv6Addr,
			localAddr:     ipv6Addr,
			rxUDP:         rxIPv6UDP,
		},
	}

	subTests := []struct {
		name             string
		specifyNICID     bool
		specifyNICAddr   bool
		expectSockOptErr *tcpip.Error
	}{
		{
			name:             "Specify NIC ID and NIC address",
			specifyNICID:     true,
			specifyNICAddr:   true,
			expectSockOptErr: nil,
		},
		{
			name:             "Don't specify NIC ID or NIC address",
			specifyNICID:     false,
			specifyNICAddr:   false,
			expectSockOptErr: tcpip.ErrUnknownDevice,
		},
		{
			name:             "Specify NIC ID but don't specify NIC address",
			specifyNICID:     true,
			specifyNICAddr:   false,
			expectSockOptErr: nil,
		},
		{
			name:             "Don't specify NIC ID but specify NIC address",
			specifyNICID:     false,
			specifyNICAddr:   true,
			expectSockOptErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
						TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
					})
					e := channel.New(0, defaultMTU, "")
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
					}
					protoAddr := tcpip.ProtocolAddress{Protocol: test.proto, AddressWithPrefix: test.localAddr}
					if err := s.AddProtocolAddress(nicID, protoAddr); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, protoAddr, err)
					}

					var wq waiter.Queue
					ep, err := s.NewEndpoint(udp.ProtocolNumber, test.proto, &wq)
					if err != nil {
						t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.proto, err)
					}
					defer ep.Close()

					bindAddr := tcpip.FullAddress{Port: localPort}
					if err := ep.Bind(bindAddr); err != nil {
						t.Fatalf("ep.Bind(%#v): %s", bindAddr, err)
					}

					memOpt := tcpip.MembershipOption{MulticastAddr: test.multicastAddr}
					if subTest.specifyNICID {
						memOpt.NIC = nicID
					}
					if subTest.specifyNICAddr {
						memOpt.InterfaceAddr = test.localAddr.Address
					}

					// We should receive UDP packets to the group once we join the
					// multicast group.
					addOpt := tcpip.AddMembershipOption(memOpt)
					if err := ep.SetSockOpt(&addOpt); err != subTest.expectSockOptErr {
						t.Fatalf("got ep.SetSockOpt(&%#v) = %s, want = %s", addOpt, err, subTest.expectSockOptErr)
					}

					test.rxUDP(e, test.remoteAddr, test.multicastAddr, data)

					var wantReadErr *tcpip.Error
					if subTest.expectSockOptErr != nil {
						wantReadErr = tcpip.ErrWouldBlock
					}

					var buf bytes.Buffer
					var readOpts tcpip.ReadOptions
					result, err := ep.Read(&buf, readOpts)
					if err != wantReadErr {
						t.Fatalf("got ep.Read(_, %#v) = %s, want = %s", readOpts, err, wantReadErr)
					} else if wantReadErr == nil {
						if diff := cmp.Diff(tcpip.ReadResult{
							Count: buf.Len(),
							Total: buf.Len(),
						}, result, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
							t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
						}
						if diff := cmp.Diff(data, buf.Bytes()); diff != "" {
							t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
						}
					}

					// We should not receive UDP packets to the group once we leave
					// the multicast group.
					removeOpt := tcpip.RemoveMembershipOption(memOpt)
					if err := ep.SetSockOpt(&removeOpt); err != subTest.expectSockOptErr {
						t.Fatalf("got ep.SetSockOpt(&%#v) = %s, want = %s", removeOpt, err, subTest.expectSockOptErr)
					}
					test.rxUDP(e, test.remoteAddr, test.multicastAddr, data)
					if _, err := ep.Read(&buf, readOpts); err != tcpip.ErrWouldBlock {
						t.Fatalf("got ep.Read(_, %#v) = (_, %s), want = (_, %s)", readOpts, err, tcpip.ErrWouldBlock)
					}
				})
			}
		})
	}
}
