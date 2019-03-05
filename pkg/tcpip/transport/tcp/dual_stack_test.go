// Copyright 2018 Google LLC
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

package tcp_test

import (
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/checker"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

func TestV4MappedConnectOnV6Only(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	// Start connection attempt, it must fail.
	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort})
	if err != tcpip.ErrNoRoute {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}
}

func testV4Connect(t *testing.T, c *context.Context) {
	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventOut)
	defer c.WQ.EventUnregister(&we)

	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort})
	if err != tcpip.ErrConnectStarted {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)

	tcp := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: tcp.DestinationPort(),
		DstPort: tcp.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK packet.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		err = c.EP.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
}

func TestV4MappedConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Test the connection request.
	testV4Connect(t, c)
}

func TestV4ConnectWhenBoundToWildcard(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(t, c)
}

func TestV4ConnectWhenBoundToV4MappedWildcard(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.V4MappedWildcardAddr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(t, c)
}

func TestV4ConnectWhenBoundToV4Mapped(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to v4 mapped address.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV4MappedAddr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(t, c)
}

func testV6Connect(t *testing.T, c *context.Context) {
	// Start connection attempt to IPv6 address.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventOut)
	defer c.WQ.EventUnregister(&we)

	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort})
	if err != tcpip.ErrConnectStarted {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.GetV6Packet()
	checker.IPv6(t, b,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)

	tcp := header.TCP(header.IPv6(b).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: tcp.DestinationPort(),
		DstPort: tcp.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK packet.
	checker.IPv6(t, c.GetV6Packet(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		err = c.EP.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
}

func TestV6Connect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Test the connection request.
	testV6Connect(t, c)
}

func TestV6ConnectV6Only(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	// Test the connection request.
	testV6Connect(t, c)
}

func TestV6ConnectWhenBoundToWildcard(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV6Connect(t, c)
}

func TestV6ConnectWhenBoundToLocalAddress(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to local address.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV6Addr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV6Connect(t, c)
}

func TestV4RefuseOnV6Only(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Start listening.
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the RST reply.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.AckNum(uint32(irs)+1),
		),
	)
}

func TestV6RefuseOnBoundToV4Mapped(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind and listen.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.V4MappedWildcardAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the RST reply.
	checker.IPv6(t, c.GetV6Packet(),
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.AckNum(uint32(irs)+1),
		),
	)
}

func testV4Accept(t *testing.T, c *context.Context) {
	// Start listening.
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv4(t, b,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.AckNum(uint32(irs)+1),
		),
	)

	// Send ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	nep, _, err := c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Make sure we get the same error when calling the original ep and the
	// new one. This validates that v4-mapped endpoints are still able to
	// query the V6Only flag, whereas pure v4 endpoints are not.
	var v tcpip.V6OnlyOption
	expected := c.EP.GetSockOpt(&v)
	if err := nep.GetSockOpt(&v); err != expected {
		t.Fatalf("GetSockOpt returned unexpected value: got %v, want %v", err, expected)
	}

	// Check the peer address.
	addr, err := nep.GetRemoteAddress()
	if err != nil {
		t.Fatalf("GetRemoteAddress failed failed: %v", err)
	}

	if addr.Addr != context.TestAddr {
		t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, context.TestAddr)
	}
}

func TestV4AcceptOnV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(t, c)
}

func TestV4AcceptOnBoundToV4MappedWildcard(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.V4MappedWildcardAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(t, c)
}

func TestV4AcceptOnBoundToV4Mapped(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind and listen.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV4MappedAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(t, c)
}

func TestV6AcceptOnV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind and listen.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetV6Packet()
	tcp := header.TCP(header.IPv6(b).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv6(t, b,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.AckNum(uint32(irs)+1),
		),
	)

	// Send ACK.
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	nep, _, err := c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Make sure we can still query the v6 only status of the new endpoint,
	// that is, that it is in fact a v6 socket.
	var v tcpip.V6OnlyOption
	if err := nep.GetSockOpt(&v); err != nil {
		t.Fatalf("GetSockOpt failed failed: %v", err)
	}

	// Check the peer address.
	addr, err := nep.GetRemoteAddress()
	if err != nil {
		t.Fatalf("GetRemoteAddress failed failed: %v", err)
	}

	if addr.Addr != context.TestV6Addr {
		t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, context.TestV6Addr)
	}
}

func TestV4AcceptOnV4(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(t, c)
}
