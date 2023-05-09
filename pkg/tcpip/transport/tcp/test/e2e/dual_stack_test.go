// Copyright 2018 The gVisor Authors.
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

package dual_stack_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestV4MappedConnectOnV6Only(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	// Start connection attempt, it must fail.
	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort})
	if d := cmp.Diff(&tcpip.ErrHostUnreachable{}, err); d != "" {
		t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
	}
}

func TestV4MappedConnect(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Test the connection request.
	e2e.TestV4Connect(t, c)
}

func TestV4ConnectWhenBoundToWildcard(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV4Connect(t, c)
}

func TestV4ConnectWhenBoundToV4MappedWildcard(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.V4MappedWildcardAddr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV4Connect(t, c)
}

func TestV4ConnectWhenBoundToV4Mapped(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to v4 mapped address.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV4MappedAddr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV4Connect(t, c)
}

func TestV6Connect(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Test the connection request.
	e2e.TestV6Connect(t, c)
}

func TestV6ConnectV6Only(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	// Test the connection request.
	e2e.TestV6Connect(t, c)
}

func TestV6ConnectWhenBoundToWildcard(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV6Connect(t, c)
}

func TestStackV6OnlyConnectWhenBoundToWildcard(t *testing.T) {
	c := context.NewWithOpts(t, context.Options{
		EnableV6: true,
		MTU:      e2e.DefaultMTU,
	})
	defer c.Cleanup()

	// Create a v6 endpoint but don't set the v6-only TCP option.
	c.CreateV6Endpoint(false)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV6Connect(t, c)
}

func TestV6ConnectWhenBoundToLocalAddress(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	// Bind to local address.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV6Addr}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	e2e.TestV6Connect(t, c)
}

func TestV4RefuseOnV6Only(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
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
	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.TCPAckNum(uint32(irs)+1),
		),
	)
}

func TestV6RefuseOnBoundToV4Mapped(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
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
	p := c.GetV6Packet()
	defer p.Release()
	checker.IPv6(t, p,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.TCPAckNum(uint32(irs)+1),
		),
	)
}

func testV4Accept(t *testing.T, c *context.Context) {
	c.SetGSOEnabled(true)
	defer c.SetGSOEnabled(false)

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
	v := c.GetPacket()
	defer v.Release()
	tcp := header.TCP(header.IPv4(v.AsSlice()).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv4(t, v,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.TCPAckNum(uint32(irs)+1),
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
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)

	nep, _, err := c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Check the peer address.
	addr, err := nep.GetRemoteAddress()
	if err != nil {
		t.Fatalf("GetRemoteAddress failed failed: %v", err)
	}

	if addr.Addr != context.TestAddr {
		t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, context.TestAddr)
	}

	var r strings.Reader
	data := "Don't panic"
	r.Reset(data)
	nep.Write(&r, tcpip.WriteOptions{})
	v = c.GetPacket()
	defer v.Release()
	tcp = header.IPv4(v.AsSlice()).Payload()
	if string(tcp.Payload()) != data {
		t.Fatalf("Unexpected data: got %v, want %v", string(tcp.Payload()), data)
	}
}

func TestV4AcceptOnV6(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
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
	c := context.New(t, e2e.DefaultMTU)
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
	c := context.New(t, e2e.DefaultMTU)
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
	c := context.New(t, e2e.DefaultMTU)
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
	v := c.GetV6Packet()
	defer v.Release()
	tcp := header.TCP(header.IPv6(v.AsSlice()).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv6(t, v,
		checker.TCP(
			checker.SrcPort(context.StackPort),
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.TCPAckNum(uint32(irs)+1),
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
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)
	var addr tcpip.FullAddress
	_, _, err := c.EP.Accept(&addr)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept(&addr)
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	if addr.Addr != context.TestV6Addr {
		t.Errorf("Unexpected remote address: got %s, want %s", addr.Addr, context.TestV6Addr)
	}
}

func TestV4AcceptOnV4(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
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

func testV4ListenClose(t *testing.T, c *context.Context) {
	opt := tcpip.TCPAlwaysUseSynCookies(true)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	const n = 32

	// Start listening.
	if err := c.EP.Listen(n); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	irs := seqnum.Value(789)
	for i := uint16(0); i < n; i++ {
		// Send a SYN request.
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort + i,
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  irs,
			RcvWnd:  30000,
		})
	}

	// Each of these ACKs will cause a syn-cookie based connection to be
	// accepted and delivered to the listening endpoint.
	for i := 0; i < n; i++ {
		v := c.GetPacket()
		defer v.Release()
		tcp := header.TCP(header.IPv4(v.AsSlice()).Payload())
		iss := seqnum.Value(tcp.SequenceNumber())
		// Send ACK.
		c.SendPacket(nil, &context.Headers{
			SrcPort: tcp.DestinationPort(),
			DstPort: context.StackPort,
			Flags:   header.TCPFlagAck,
			SeqNum:  irs + 1,
			AckNum:  iss + 1,
			RcvWnd:  30000,
		})
	}

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)
	nep, _, err := c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(10 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}
	nep.Close()
	c.EP.Close()
}

func TestV4ListenCloseOnV4(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4ListenClose(t, c)
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	// Allow TCP async work to complete to avoid false reports of leaks.
	// TODO(gvisor.dev/issue/5940): Use fake clock in tests.
	time.Sleep(1 * time.Second)
	refs.DoLeakCheck()
	os.Exit(code)
}
