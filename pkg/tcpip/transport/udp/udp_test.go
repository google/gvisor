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

package udp_test

import (
	"bytes"
	"math"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	stackV6Addr           = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr            = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	stackV4MappedAddr     = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + stackAddr
	testV4MappedAddr      = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + testAddr
	multicastV4MappedAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + multicastAddr
	V4MappedWildcardAddr  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"

	stackAddr       = "\x0a\x00\x00\x01"
	stackPort       = 1234
	testAddr        = "\x0a\x00\x00\x02"
	testPort        = 4096
	multicastAddr   = "\xe8\x2b\xd3\xea"
	multicastV6Addr = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	multicastPort   = 1234

	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65536
)

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack

	ep tcpip.Endpoint
	wq waiter.Queue
}

type headers struct {
	srcPort uint16
	dstPort uint16
}

func newDualTestContext(t *testing.T, mtu uint32) *testContext {
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{udp.ProtocolName}, stack.Options{})

	id, linkEP := channel.New(256, mtu, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, ipv6.ProtocolNumber, stackV6Addr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: "\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
		{
			Destination: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
	})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

func (c *testContext) cleanup() {
	if c.ep != nil {
		c.ep.Close()
	}
}

func (c *testContext) createV6Endpoint(v6only bool) {
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	var v tcpip.V6OnlyOption
	if v6only {
		v = 1
	}
	if err := c.ep.SetSockOpt(v); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}
}

func (c *testContext) getPacket(protocolNumber tcpip.NetworkProtocolNumber, multicast bool) []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != protocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, protocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		var checkerFn func(*testing.T, []byte, ...checker.NetworkChecker)
		var srcAddr, dstAddr tcpip.Address
		switch protocolNumber {
		case ipv4.ProtocolNumber:
			checkerFn = checker.IPv4
			srcAddr, dstAddr = stackAddr, testAddr
			if multicast {
				dstAddr = multicastAddr
			}
		case ipv6.ProtocolNumber:
			checkerFn = checker.IPv6
			srcAddr, dstAddr = stackV6Addr, testV6Addr
			if multicast {
				dstAddr = multicastV6Addr
			}
		default:
			c.t.Fatalf("unknown protocol %d", protocolNumber)
		}
		checkerFn(c.t, b, checker.SrcAddr(srcAddr), checker.DstAddr(dstAddr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

func (c *testContext) sendV6Packet(payload []byte, h *headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.UDPMinimumSize + len(payload)),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       testV6Addr,
		DstAddr:       stackV6Addr,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testV6Addr, stackV6Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEP.Inject(ipv6.ProtocolNumber, buf.ToVectorisedView())
}

func (c *testContext) sendPacket(payload []byte, h *headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv4MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     testAddr,
		DstAddr:     stackAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testAddr, stackAddr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEP.Inject(ipv4.ProtocolNumber, buf.ToVectorisedView())
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func TestBindPortReuse(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	var eps [5]tcpip.Endpoint
	reusePortOpt := tcpip.ReusePortOption(1)

	pollChannel := make(chan tcpip.Endpoint)
	for i := 0; i < len(eps); i++ {
		// Try to receive the data.
		wq := waiter.Queue{}
		we, ch := waiter.NewChannelEntry(nil)
		wq.EventRegister(&we, waiter.EventIn)
		defer wq.EventUnregister(&we)
		defer close(ch)

		var err *tcpip.Error
		eps[i], err = c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
		if err != nil {
			c.t.Fatalf("NewEndpoint failed: %v", err)
		}

		go func(ep tcpip.Endpoint) {
			for range ch {
				pollChannel <- ep
			}
		}(eps[i])

		defer eps[i].Close()
		if err := eps[i].SetSockOpt(reusePortOpt); err != nil {
			c.t.Fatalf("SetSockOpt failed failed: %v", err)
		}
		if err := eps[i].Bind(tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}

	npackets := 100000
	nports := 10000
	ports := make(map[uint16]tcpip.Endpoint)
	stats := make(map[tcpip.Endpoint]int)
	for i := 0; i < npackets; i++ {
		// Send a packet.
		port := uint16(i % nports)
		payload := newPayload()
		c.sendV6Packet(payload, &headers{
			srcPort: testPort + port,
			dstPort: stackPort,
		})

		var addr tcpip.FullAddress
		ep := <-pollChannel
		_, _, err := ep.Read(&addr)
		if err != nil {
			c.t.Fatalf("Read failed: %v", err)
		}
		stats[ep]++
		if i < nports {
			ports[uint16(i)] = ep
		} else {
			// Check that all packets from one client are handled
			// by the same socket.
			if ports[port] != ep {
				t.Fatalf("Port mismatch")
			}
		}
	}

	if len(stats) != len(eps) {
		t.Fatalf("Only %d(expected %d) sockets received packets", len(stats), len(eps))
	}

	// Check that a packet distribution is fair between sockets.
	for _, c := range stats {
		n := float64(npackets) / float64(len(eps))
		// The deviation is less than 10%.
		if math.Abs(float64(c)-n) > n/10 {
			t.Fatal(c, n)
		}
	}
}

func testV4Read(c *testContext) {
	// Send a packet.
	payload := newPayload()
	c.sendPacket(payload, &headers{
		srcPort: testPort,
		dstPort: stackPort,
	})

	// Try to receive the data.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	var addr tcpip.FullAddress
	v, _, err := c.ep.Read(&addr)
	if err == tcpip.ErrWouldBlock {
		// Wait for data to become available.
		select {
		case <-ch:
			v, _, err = c.ep.Read(&addr)
			if err != nil {
				c.t.Fatalf("Read failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for data")
		}
	}

	// Check the peer address.
	if addr.Addr != testAddr {
		c.t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, testAddr)
	}

	// Check the payload.
	if !bytes.Equal(payload, v) {
		c.t.Fatalf("Bad payload: got %x, want %x", v, payload)
	}
}

func TestBindEphemeralPort(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	if err := c.ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("ep.Bind(...) failed: %v", err)
	}
}

func TestBindReservedPort(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	addr, err := c.ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("GetLocalAddress failed: %v", err)
	}

	// We can't bind the address reserved by the connected endpoint above.
	{
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		if got, want := ep.Bind(addr), tcpip.ErrPortInUse; got != want {
			t.Fatalf("got ep.Bind(...) = %v, want = %v", got, want)
		}
	}

	func() {
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		// We can't bind ipv4-any on the port reserved by the connected endpoint
		// above, since the endpoint is dual-stack.
		if got, want := ep.Bind(tcpip.FullAddress{Port: addr.Port}), tcpip.ErrPortInUse; got != want {
			t.Fatalf("got ep.Bind(...) = %v, want = %v", got, want)
		}
		// We can bind an ipv4 address on this port, though.
		if err := ep.Bind(tcpip.FullAddress{Addr: stackAddr, Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}()

	// Once the connected endpoint releases its port reservation, we are able to
	// bind ipv4-any once again.
	c.ep.Close()
	func() {
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		if err := ep.Bind(tcpip.FullAddress{Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}()
}

func TestV4ReadOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Read(c)
}

func TestV4ReadOnBoundToV4MappedWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: V4MappedWildcardAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Read(c)
}

func TestV4ReadOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to local address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Read(c)
}

func TestV6ReadOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Send a packet.
	payload := newPayload()
	c.sendV6Packet(payload, &headers{
		srcPort: testPort,
		dstPort: stackPort,
	})

	// Try to receive the data.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	var addr tcpip.FullAddress
	v, _, err := c.ep.Read(&addr)
	if err == tcpip.ErrWouldBlock {
		// Wait for data to become available.
		select {
		case <-ch:
			v, _, err = c.ep.Read(&addr)
			if err != nil {
				c.t.Fatalf("Read failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for data")
		}
	}

	// Check the peer address.
	if addr.Addr != testV6Addr {
		c.t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, testAddr)
	}

	// Check the payload.
	if !bytes.Equal(payload, v) {
		c.t.Fatalf("Bad payload: got %x, want %x", v, payload)
	}
}

func TestV4ReadOnV4(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create v4 UDP endpoint.
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Read(c)
}

func testV4Write(c *testContext) uint16 {
	// Write to V4 mapped address.
	payload := buffer.View(newPayload())
	n, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort},
	})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket(ipv4.ProtocolNumber, false)
	udp := header.UDP(header.IPv4(b).Payload())
	checker.IPv4(c.t, b,
		checker.UDP(
			checker.DstPort(testPort),
		),
	)

	// Check the payload.
	if !bytes.Equal(payload, udp.Payload()) {
		c.t.Fatalf("Bad payload: got %x, want %x", udp.Payload(), payload)
	}

	return udp.SourcePort()
}

func testV6Write(c *testContext) uint16 {
	// Write to v6 address.
	payload := buffer.View(newPayload())
	n, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
	})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket(ipv6.ProtocolNumber, false)
	udp := header.UDP(header.IPv6(b).Payload())
	checker.IPv6(c.t, b,
		checker.UDP(
			checker.DstPort(testPort),
		),
	)

	// Check the payload.
	if !bytes.Equal(payload, udp.Payload()) {
		c.t.Fatalf("Bad payload: got %x, want %x", udp.Payload(), payload)
	}

	return udp.SourcePort()
}

func testDualWrite(c *testContext) uint16 {
	v4Port := testV4Write(c)
	v6Port := testV6Write(c)
	if v4Port != v6Port {
		c.t.Fatalf("expected v4 and v6 ports to be equal: got v4Port = %d, v6Port = %d", v4Port, v6Port)
	}

	return v4Port
}

func TestDualWriteUnbound(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	testDualWrite(c)
}

func TestDualWriteBoundToWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	p := testDualWrite(c)
	if p != stackPort {
		c.t.Fatalf("Bad port: got %v, want %v", p, stackPort)
	}
}

func TestDualWriteConnectedToV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Connect to v6 address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testV6Write(c)

	// Write to V4 mapped address.
	payload := buffer.View(newPayload())
	_, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort},
	})
	if err != tcpip.ErrNetworkUnreachable {
		c.t.Fatalf("Write returned unexpected error: got %v, want %v", err, tcpip.ErrNetworkUnreachable)
	}
}

func TestDualWriteConnectedToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Connect to v4 mapped address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testV4Write(c)

	// Write to v6 address.
	payload := buffer.View(newPayload())
	_, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
	})
	if err != tcpip.ErrInvalidEndpointState {
		c.t.Fatalf("Write returned unexpected error: got %v, want %v", err, tcpip.ErrInvalidEndpointState)
	}
}

func TestV4WriteOnV6Only(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(true)

	// Write to V4 mapped address.
	payload := buffer.View(newPayload())
	_, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort},
	})
	if err != tcpip.ErrNoRoute {
		c.t.Fatalf("Write returned unexpected error: got %v, want %v", err, tcpip.ErrNoRoute)
	}
}

func TestV6WriteOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to v4 mapped address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Write to v6 address.
	payload := buffer.View(newPayload())
	_, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
	})
	if err != tcpip.ErrInvalidEndpointState {
		c.t.Fatalf("Write returned unexpected error: got %v, want %v", err, tcpip.ErrInvalidEndpointState)
	}
}

func TestV6WriteOnConnected(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Connect to v6 address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	// Write without destination.
	payload := buffer.View(newPayload())
	n, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket(ipv6.ProtocolNumber, false)
	udp := header.UDP(header.IPv6(b).Payload())
	checker.IPv6(c.t, b,
		checker.UDP(
			checker.DstPort(testPort),
		),
	)

	// Check the payload.
	if !bytes.Equal(payload, udp.Payload()) {
		c.t.Fatalf("Bad payload: got %x, want %x", udp.Payload(), payload)
	}
}

func TestV4WriteOnConnected(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Connect to v4 mapped address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	// Write without destination.
	payload := buffer.View(newPayload())
	n, _, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket(ipv4.ProtocolNumber, false)
	udp := header.UDP(header.IPv4(b).Payload())
	checker.IPv4(c.t, b,
		checker.UDP(
			checker.DstPort(testPort),
		),
	)

	// Check the payload.
	if !bytes.Equal(payload, udp.Payload()) {
		c.t.Fatalf("Bad payload: got %x, want %x", udp.Payload(), payload)
	}
}

func TestReadIncrementsPacketsReceived(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create IPv4 UDP endpoint
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testV4Read(c)

	var want uint64 = 1
	if got := c.s.Stats().UDP.PacketsReceived.Value(); got != want {
		c.t.Fatalf("Read did not increment PacketsReceived: got %v, want %v", got, want)
	}
}

func TestWriteIncrementsPacketsSent(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	testDualWrite(c)

	var want uint64 = 2
	if got := c.s.Stats().UDP.PacketsSent.Value(); got != want {
		c.t.Fatalf("Write did not increment PacketsSent: got %v, want %v", got, want)
	}
}

func TestTTL(t *testing.T) {
	payload := tcpip.SlicePayload(buffer.View(newPayload()))

	for _, name := range []string{"v4", "v6", "dual"} {
		t.Run(name, func(t *testing.T) {
			var networkProtocolNumber tcpip.NetworkProtocolNumber
			switch name {
			case "v4":
				networkProtocolNumber = ipv4.ProtocolNumber
			case "v6", "dual":
				networkProtocolNumber = ipv6.ProtocolNumber
			default:
				t.Fatal("unknown test variant")
			}

			var variants []string
			switch name {
			case "v4":
				variants = []string{"v4"}
			case "v6":
				variants = []string{"v6"}
			case "dual":
				variants = []string{"v6", "mapped"}
			}

			for _, variant := range variants {
				t.Run(variant, func(t *testing.T) {
					for _, typ := range []string{"unicast", "multicast"} {
						t.Run(typ, func(t *testing.T) {
							var addr tcpip.Address
							var port uint16
							switch typ {
							case "unicast":
								port = testPort
								switch variant {
								case "v4":
									addr = testAddr
								case "mapped":
									addr = testV4MappedAddr
								case "v6":
									addr = testV6Addr
								default:
									t.Fatal("unknown test variant")
								}
							case "multicast":
								port = multicastPort
								switch variant {
								case "v4":
									addr = multicastAddr
								case "mapped":
									addr = multicastV4MappedAddr
								case "v6":
									addr = multicastV6Addr
								default:
									t.Fatal("unknown test variant")
								}
							default:
								t.Fatal("unknown test variant")
							}

							c := newDualTestContext(t, defaultMTU)
							defer c.cleanup()

							var err *tcpip.Error
							c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, networkProtocolNumber, &c.wq)
							if err != nil {
								c.t.Fatalf("NewEndpoint failed: %v", err)
							}

							switch name {
							case "v4":
							case "v6":
								if err := c.ep.SetSockOpt(tcpip.V6OnlyOption(1)); err != nil {
									c.t.Fatalf("SetSockOpt failed: %v", err)
								}
							case "dual":
								if err := c.ep.SetSockOpt(tcpip.V6OnlyOption(0)); err != nil {
									c.t.Fatalf("SetSockOpt failed: %v", err)
								}
							default:
								t.Fatal("unknown test variant")
							}

							const multicastTTL = 42
							if err := c.ep.SetSockOpt(tcpip.MulticastTTLOption(multicastTTL)); err != nil {
								c.t.Fatalf("SetSockOpt failed: %v", err)
							}

							n, _, err := c.ep.Write(payload, tcpip.WriteOptions{To: &tcpip.FullAddress{Addr: addr, Port: port}})
							if err != nil {
								c.t.Fatalf("Write failed: %v", err)
							}
							if n != uintptr(len(payload)) {
								c.t.Fatalf("got c.ep.Write(...) = %d, want = %d", n, len(payload))
							}

							checkerFn := checker.IPv4
							switch variant {
							case "v4", "mapped":
							case "v6":
								checkerFn = checker.IPv6
							default:
								t.Fatal("unknown test variant")
							}
							var wantTTL uint8
							var multicast bool
							switch typ {
							case "unicast":
								multicast = false
								switch variant {
								case "v4", "mapped":
									ep, err := ipv4.NewProtocol().NewEndpoint(0, "", nil, nil, nil)
									if err != nil {
										t.Fatal(err)
									}
									wantTTL = ep.DefaultTTL()
									ep.Close()
								case "v6":
									ep, err := ipv6.NewProtocol().NewEndpoint(0, "", nil, nil, nil)
									if err != nil {
										t.Fatal(err)
									}
									wantTTL = ep.DefaultTTL()
									ep.Close()
								default:
									t.Fatal("unknown test variant")
								}
							case "multicast":
								wantTTL = multicastTTL
								multicast = true
							default:
								t.Fatal("unknown test variant")
							}

							var networkProtocolNumber tcpip.NetworkProtocolNumber
							switch variant {
							case "v4", "mapped":
								networkProtocolNumber = ipv4.ProtocolNumber
							case "v6":
								networkProtocolNumber = ipv6.ProtocolNumber
							default:
								t.Fatal("unknown test variant")
							}

							b := c.getPacket(networkProtocolNumber, multicast)
							checkerFn(c.t, b,
								checker.TTL(wantTTL),
								checker.UDP(
									checker.DstPort(port),
								),
							)
						})
					}
				})
			}
		})
	}
}
