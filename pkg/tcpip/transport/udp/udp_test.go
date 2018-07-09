// Copyright 2018 Google Inc.
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
	"math/rand"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/checker"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	stackV6Addr          = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr           = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	stackV4MappedAddr    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + stackAddr
	testV4MappedAddr     = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + testAddr
	V4MappedWildcardAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"

	stackAddr = "\x0a\x00\x00\x01"
	stackPort = 1234
	testAddr  = "\x0a\x00\x00\x02"
	testPort  = 4096

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
	s := stack.New(&tcpip.StdClock{}, []string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{udp.ProtocolName})

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

func (c *testContext) createV6Endpoint(v4only bool) {
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	var v tcpip.V6OnlyOption
	if v4only {
		v = 1
	}
	if err := c.ep.SetSockOpt(v); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}
}

func (c *testContext) getV6Packet() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv6.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv6.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv6(c.t, b, checker.SrcAddr(stackV6Addr), checker.DstAddr(testV6Addr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

func (c *testContext) getPacket() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv4.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv4.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv4(c.t, b, checker.SrcAddr(stackAddr), checker.DstAddr(testAddr))
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
	xsum := header.Checksum([]byte(testV6Addr), 0)
	xsum = header.Checksum([]byte(stackV6Addr), xsum)
	xsum = header.Checksum([]byte{0, uint8(udp.ProtocolNumber)}, xsum)

	// Calculate the UDP checksum and set it.
	length := uint16(header.UDPMinimumSize + len(payload))
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv6.ProtocolNumber, &vv)
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
	xsum := header.Checksum([]byte(testAddr), 0)
	xsum = header.Checksum([]byte(stackAddr), xsum)
	xsum = header.Checksum([]byte{0, uint8(udp.ProtocolNumber)}, xsum)

	// Calculate the UDP checksum and set it.
	length := uint16(header.UDPMinimumSize + len(payload))
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv4.ProtocolNumber, &vv)
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
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

func TestV4ReadOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
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
	if err := c.ep.Bind(tcpip.FullAddress{Addr: V4MappedWildcardAddr, Port: stackPort}, nil); err != nil {
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
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}, nil); err != nil {
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
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
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
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Read(c)
}

func testV4Write(c *testContext) uint16 {
	// Write to V4 mapped address.
	payload := buffer.View(newPayload())
	n, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort},
	})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket()
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
	n, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
	})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getV6Packet()
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
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
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
	_, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
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
	_, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
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
	_, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
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
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Write to v6 address.
	payload := buffer.View(newPayload())
	_, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
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
	n, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getV6Packet()
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
	n, err := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{})
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != uintptr(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Check that we received the packet.
	b := c.getPacket()
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
