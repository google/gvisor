// Copyright 2021 The gVisor Authors.
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

package icmp_test

import (
	"bytes"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TODO(https://gvisor.dev/issues/5623): Finish unit testing the icmp package.
// See the issue for remaining areas of work.

var (
	localV4Addr1 = testutil.MustParse4("10.0.0.1")
	localV4Addr2 = testutil.MustParse4("10.0.0.2")
	remoteV4Addr = testutil.MustParse4("10.0.0.3")
)

const (
	testTOS = 0x80
	testTTL = 42
)

func addNICWithDefaultRoute(t *testing.T, s *stack.Stack, id tcpip.NICID, name string, addrV4 tcpip.Address) *channel.Endpoint {
	t.Helper()

	ep := channel.New(1 /* size */, header.IPv4MinimumMTU, "" /* linkAddr */)
	t.Cleanup(ep.Close)

	wep := stack.LinkEndpoint(ep)
	if testing.Verbose() {
		wep = sniffer.New(ep)
	}

	opts := stack.NICOptions{Name: name}
	if err := s.CreateNICWithOptions(id, wep, opts); err != nil {
		t.Fatalf("s.CreateNIC(%d, _) = %s", id, err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addrV4.WithPrefix(),
	}
	if err := s.AddProtocolAddress(id, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", id, protocolAddr, err)
	}

	s.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         id,
	})

	return ep
}

func writePayload(buf []byte) {
	for i := range buf {
		buf[i] = byte(i)
	}
}

// TestWriteUnboundWithBindToDevice exercises writing to an unbound ICMP socket
// when SO_BINDTODEVICE is set to the non-default NIC for that subnet.
//
// Only IPv4 is tested. The logic to determine which NIC to use is agnostic to
// the version of IP.
func TestWriteUnboundWithBindToDevice(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
		HandleLocal:        true,
	})
	defer s.Destroy()

	// Add two NICs, both with default routes on the same subnet. The first NIC
	// added will be the default NIC for that subnet.
	defaultEP := addNICWithDefaultRoute(t, s, 1, "default", localV4Addr1)
	alternateEP := addNICWithDefaultRoute(t, s, 2, "alternate", localV4Addr2)

	socket, err := s.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _) = %s", icmp.ProtocolNumber4, ipv4.ProtocolNumber, err)
	}
	defer socket.Close()

	echoPayloadSize := defaultEP.MTU() - header.IPv4MinimumSize - header.ICMPv4MinimumSize

	newICMPv4EchoRequest := func() []byte {
		buf := make([]byte, header.ICMPv4MinimumSize+int(echoPayloadSize))
		writePayload(buf[header.ICMPv4MinimumSize:])

		icmp := header.ICMPv4(buf)
		icmp.SetType(header.ICMPv4Echo)
		// No need to set the checksum; it is reset by the socket before the packet
		// is sent.

		return buf
	}

	// Send a packet without SO_BINDTODEVICE. This verifies that the first NIC
	// to be added is the default NIC to send packets when not explicitly bound.
	{
		buf := newICMPv4EchoRequest()
		var r bytes.Reader
		r.Reset(buf)
		n, err := socket.Write(&r, tcpip.WriteOptions{
			To: &tcpip.FullAddress{Addr: remoteV4Addr},
		})
		if err != nil {
			t.Fatalf("socket.Write(_, {To:%s}) = %s", remoteV4Addr, err)
		}
		if n != int64(len(buf)) {
			t.Fatalf("got n = %d, want n = %d", n, len(buf))
		}

		// Verify the packet was sent out the default NIC.
		p := defaultEP.Read()
		if p.IsNil() {
			t.Fatalf("got defaultEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}
		defer p.DecRef()
		v := p.ToView()
		defer v.Release()

		checker.IPv4(t, v, []checker.NetworkChecker{
			checker.SrcAddr(localV4Addr1),
			checker.DstAddr(remoteV4Addr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
				checker.ICMPv4Payload(buf[header.ICMPv4MinimumSize:]),
			),
		}...)

		// Verify the packet was not sent out the alternate NIC.
		if p := alternateEP.Read(); !p.IsNil() {
			t.Fatalf("got alternateEP.Read(_) = %+v, true; want = _, false", p)
		}
	}

	// Send a packet with SO_BINDTODEVICE. This exercises reliance on
	// SO_BINDTODEVICE to route the packet to the alternate NIC.
	{
		// Use SO_BINDTODEVICE to send over the alternate NIC by default.
		socket.SocketOptions().SetBindToDevice(2)

		buf := newICMPv4EchoRequest()
		var r bytes.Reader
		r.Reset(buf)
		n, err := socket.Write(&r, tcpip.WriteOptions{
			To: &tcpip.FullAddress{Addr: remoteV4Addr},
		})
		if err != nil {
			t.Fatalf("socket.Write(_, {To:%s}) = %s", tcpip.Address(remoteV4Addr), err)
		}
		if n != int64(len(buf)) {
			t.Fatalf("got n = %d, want n = %d", n, len(buf))
		}

		// Verify the packet was not sent out the default NIC.
		if p := defaultEP.Read(); !p.IsNil() {
			t.Fatalf("got defaultEP.Read(_) = %+v, true; want = _, false", p)
		}

		// Verify the packet was sent out the alternate NIC.
		p := alternateEP.Read()
		if p.IsNil() {
			t.Fatalf("got alternateEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}
		defer p.DecRef()
		v := p.ToView()
		defer v.Release()

		checker.IPv4(t, v, []checker.NetworkChecker{
			checker.SrcAddr(localV4Addr2),
			checker.DstAddr(remoteV4Addr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
				checker.ICMPv4Payload(buf[header.ICMPv4MinimumSize:]),
			),
		}...)
	}

	// Send a packet with SO_BINDTODEVICE cleared. This verifies that clearing
	// the device binding will fallback to using the default NIC to send
	// packets.
	{
		socket.SocketOptions().SetBindToDevice(0)

		buf := newICMPv4EchoRequest()
		var r bytes.Reader
		r.Reset(buf)
		n, err := socket.Write(&r, tcpip.WriteOptions{
			To: &tcpip.FullAddress{Addr: remoteV4Addr},
		})
		if err != nil {
			t.Fatalf("socket.Write(_, {To:%s}) = %s", tcpip.Address(remoteV4Addr), err)
		}
		if n != int64(len(buf)) {
			t.Fatalf("got n = %d, want n = %d", n, len(buf))
		}

		// Verify the packet was sent out the default NIC.
		p := defaultEP.Read()
		if p.IsNil() {
			t.Fatalf("got defaultEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}
		defer p.DecRef()
		v := p.ToView()
		defer v.Release()

		checker.IPv4(t, v, []checker.NetworkChecker{
			checker.SrcAddr(localV4Addr1),
			checker.DstAddr(remoteV4Addr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
				checker.ICMPv4Payload(buf[header.ICMPv4MinimumSize:]),
			),
		}...)

		// Verify the packet was not sent out the alternate NIC.
		if p := alternateEP.Read(); !p.IsNil() {
			t.Fatalf("got alternateEP.Read(_) = %+v, true; want = _, false", p)
		}
	}
}

func buildV4EchoReplyPacket(payload []byte, h context.Header4Tuple) ([]byte, []byte) {
	// Allocate a buffer for data and headers.
	buf := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TOS:         testTOS,
		TotalLength: uint16(len(buf)),
		TTL:         testTTL,
		Protocol:    uint8(icmp.ProtocolNumber4),
		SrcAddr:     h.Src.Addr,
		DstAddr:     h.Dst.Addr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the ICMP header.
	icmp := header.ICMPv4(buf[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4EchoReply)
	icmp.SetCode(header.ICMPv4UnusedCode)
	icmp.SetIdent(h.Dst.Port)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))

	return buf, icmp
}

func buildV6EchoReplyPacket(payload []byte, h context.Header4Tuple) ([]byte, []byte) {
	// Allocate a buffer for data and headers.
	buf := make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		TrafficClass:      testTOS,
		PayloadLength:     uint16(header.ICMPv6EchoMinimumSize + len(payload)),
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          testTTL,
		SrcAddr:           h.Src.Addr,
		DstAddr:           h.Dst.Addr,
	})

	// Initialize the ICMPv6 header.
	icmpv6 := header.ICMPv6(buf[header.IPv6MinimumSize:])
	icmpv6.SetType(header.ICMPv6EchoReply)
	icmpv6.SetCode(header.ICMPv6UnusedCode)
	icmpv6.SetIdent(h.Dst.Port)
	icmpv6.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpv6[:header.ICMPv6EchoMinimumSize],
		Src:         h.Src.Addr,
		Dst:         h.Dst.Addr,
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))

	return buf, icmpv6
}

// buildEchoReplyPacket builds an ICMPv4 or ICMPv6 echo reply packet, and
// returns the full packet and the ICMP portion of the packet.
func buildEchoReplyPacket(payload []byte, flow context.TestFlow) ([]byte, []byte) {
	h := flow.MakeHeader4Tuple(context.Incoming)
	if flow.IsV4() {
		return buildV4EchoReplyPacket(payload, h)
	}
	return buildV6EchoReplyPacket(payload, h)
}

func TestReceiveControlMessages(t *testing.T) {
	var payload = [...]byte{0, 1, 2, 3, 4, 5}

	for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV6, context.UnicastV6Only, context.MulticastV4, context.MulticastV6, context.MulticastV6Only, context.Broadcast} {
		t.Run(flow.String(), func(t *testing.T) {
			for _, test := range []struct {
				name             string
				optionProtocol   tcpip.NetworkProtocolNumber
				getReceiveOption func(tcpip.Endpoint) bool
				setReceiveOption func(tcpip.Endpoint, bool)
				presenceChecker  checker.ControlMessagesChecker
				absenceChecker   checker.ControlMessagesChecker
			}{
				{
					name:             "TOS",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTOS() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTOS(value) },
					presenceChecker:  checker.ReceiveTOS(testTOS),
					absenceChecker:   checker.NoTOSReceived(),
				},
				{
					name:             "TClass",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTClass() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTClass(value) },
					presenceChecker:  checker.ReceiveTClass(testTOS),
					absenceChecker:   checker.NoTClassReceived(),
				},
				{
					name:             "TTL",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTTL() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTTL(value) },
					presenceChecker:  checker.ReceiveTTL(testTTL),
					absenceChecker:   checker.NoTTLReceived(),
				},
				{
					name:             "HopLimit",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveHopLimit() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveHopLimit(value) },
					presenceChecker:  checker.ReceiveHopLimit(testTTL),
					absenceChecker:   checker.NoHopLimitReceived(),
				},
				{
					name:             "IPPacketInfo",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceivePacketInfo() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceivePacketInfo(value) },
					presenceChecker: func() checker.ControlMessagesChecker {
						h := flow.MakeHeader4Tuple(context.Incoming)
						return checker.ReceiveIPPacketInfo(tcpip.IPPacketInfo{
							NIC: context.NICID,
							// TODO(https://gvisor.dev/issue/3556): Expect the NIC's address
							// instead of the header destination address for the LocalAddr
							// field.
							DestinationAddr: h.Dst.Addr,
						})
					}(),
					absenceChecker: checker.NoIPPacketInfoReceived(),
				},
				{
					name:             "IPv6PacketInfo",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetIPv6ReceivePacketInfo() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetIPv6ReceivePacketInfo(value) },
					presenceChecker: func() checker.ControlMessagesChecker {
						h := flow.MakeHeader4Tuple(context.Incoming)
						return checker.ReceiveIPv6PacketInfo(tcpip.IPv6PacketInfo{
							NIC:  context.NICID,
							Addr: h.Dst.Addr,
						})
					}(),
					absenceChecker: checker.NoIPv6PacketInfoReceived(),
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					c := context.New(t, []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6})
					defer c.Cleanup()

					icmpProto := func() tcpip.TransportProtocolNumber {
						if flow.IsV4() {
							return icmp.ProtocolNumber4
						}
						return icmp.ProtocolNumber6
					}()

					c.CreateEndpointForFlow(flow, icmpProto)
					if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
						c.T.Fatalf("Bind failed: %s", err)
					}
					if flow.IsMulticast() {
						netProto := flow.NetProto()
						addr := flow.GetMulticastAddr()
						if err := c.Stack.JoinGroup(netProto, context.NICID, addr); err != nil {
							c.T.Fatalf("JoinGroup(%d, %d, %s): %s", netProto, context.NICID, addr, err)
						}
					}

					buf, icmp := buildEchoReplyPacket(payload[:], flow)

					if test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = true, want = false")
					}

					test.setReceiveOption(c.EP, true)
					if !test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = false, want = true")
					}

					c.InjectPacket(flow.NetProto(), buf)
					if flow.NetProto() == test.optionProtocol {
						c.ReadFromEndpointExpectSuccess(icmp, flow, test.presenceChecker)
					} else {
						c.ReadFromEndpointExpectSuccess(icmp, flow, test.absenceChecker)
					}
				})
			}
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
