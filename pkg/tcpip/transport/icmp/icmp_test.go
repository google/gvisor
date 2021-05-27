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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TODO(https://gvisor.dev/issues/5623): Finish unit testing the icmp package.
// See the issue for remaining areas of work.

var (
	localV4Addr1 = testutil.MustParse4("10.0.0.1")
	localV4Addr2 = testutil.MustParse4("10.0.0.2")
	remoteV4Addr = testutil.MustParse4("10.0.0.3")
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

	if err := s.AddAddress(id, ipv4.ProtocolNumber, addrV4); err != nil {
		t.Fatalf("s.AddAddress(%d, %d, %s) = %s", id, ipv4.ProtocolNumber, addrV4, err)
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

func newICMPv4EchoRequest(payloadSize uint32) buffer.View {
	buf := buffer.NewView(header.ICMPv4MinimumSize + int(payloadSize))
	writePayload(buf[header.ICMPv4MinimumSize:])

	icmp := header.ICMPv4(buf)
	icmp.SetType(header.ICMPv4Echo)
	// No need to set the checksum; it is reset by the socket before the packet
	// is sent.

	return buf
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

	// Send a packet without SO_BINDTODEVICE. This verifies that the first NIC
	// to be added is the default NIC to send packets when not explicitly bound.
	{
		buf := newICMPv4EchoRequest(echoPayloadSize)
		r := buf.Reader()
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
		p, ok := defaultEP.Read()
		if !ok {
			t.Fatalf("got defaultEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}

		vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
		b := vv.ToView()

		checker.IPv4(t, b, []checker.NetworkChecker{
			checker.SrcAddr(localV4Addr1),
			checker.DstAddr(remoteV4Addr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
				checker.ICMPv4Payload(buf[header.ICMPv4MinimumSize:]),
			),
		}...)

		// Verify the packet was not sent out the alternate NIC.
		if p, ok := alternateEP.Read(); ok {
			t.Fatalf("got alternateEP.Read(_) = %+v, true; want = _, false", p)
		}
	}

	// Send a packet with SO_BINDTODEVICE. This exercises reliance on
	// SO_BINDTODEVICE to route the packet to the alternate NIC.
	{
		// Use SO_BINDTODEVICE to send over the alternate NIC by default.
		socket.SocketOptions().SetBindToDevice(2)

		buf := newICMPv4EchoRequest(echoPayloadSize)
		r := buf.Reader()
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
		if p, ok := defaultEP.Read(); ok {
			t.Fatalf("got defaultEP.Read(_) = %+v, true; want = _, false", p)
		}

		// Verify the packet was sent out the alternate NIC.
		p, ok := alternateEP.Read()
		if !ok {
			t.Fatalf("got alternateEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}

		vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
		b := vv.ToView()

		checker.IPv4(t, b, []checker.NetworkChecker{
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

		buf := newICMPv4EchoRequest(echoPayloadSize)
		r := buf.Reader()
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
		p, ok := defaultEP.Read()
		if !ok {
			t.Fatalf("got defaultEP.Read(_) = _, false; want = _, true (packet wasn't written out)")
		}

		vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
		b := vv.ToView()

		checker.IPv4(t, b, []checker.NetworkChecker{
			checker.SrcAddr(localV4Addr1),
			checker.DstAddr(remoteV4Addr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
				checker.ICMPv4Payload(buf[header.ICMPv4MinimumSize:]),
			),
		}...)

		// Verify the packet was not sent out the alternate NIC.
		if p, ok := alternateEP.Read(); ok {
			t.Fatalf("got alternateEP.Read(_) = %+v, true; want = _, false", p)
		}
	}
}
