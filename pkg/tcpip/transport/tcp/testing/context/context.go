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

// Package context provides a test context for use in tcp tests. It also
// provides helper methods to assert/check certain behaviours.
package context

import (
	"bytes"
	"context"
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
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// StackAddr is the IPv4 address assigned to the stack.
	StackAddr = "\x0a\x00\x00\x01"

	// StackPort is used as the listening port in tests for passive
	// connects.
	StackPort = 1234

	// TestAddr is the source address for packets sent to the stack via the
	// link layer endpoint.
	TestAddr = "\x0a\x00\x00\x02"

	// TestPort is the TCP port used for packets sent to the stack
	// via the link layer endpoint.
	TestPort = 4096

	// StackV6Addr is the IPv6 address assigned to the stack.
	StackV6Addr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

	// TestV6Addr is the source address for packets sent to the stack via
	// the link layer endpoint.
	TestV6Addr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	// StackV4MappedAddr is StackAddr as a mapped v6 address.
	StackV4MappedAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + StackAddr

	// TestV4MappedAddr is TestAddr as a mapped v6 address.
	TestV4MappedAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + TestAddr

	// V4MappedWildcardAddr is the mapped v6 representation of 0.0.0.0.
	V4MappedWildcardAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"

	// TestInitialSequenceNumber is the initial sequence number sent in packets that
	// are sent in response to a SYN or in the initial SYN sent to the stack.
	TestInitialSequenceNumber = 789
)

// StackAddrWithPrefix is StackAddr with its associated prefix length.
var StackAddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   StackAddr,
	PrefixLen: 24,
}

// StackV6AddrWithPrefix is StackV6Addr with its associated prefix length.
var StackV6AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   StackV6Addr,
	PrefixLen: header.IIDOffsetInIPv6Address * 8,
}

// Headers is used to represent the TCP header fields when building a
// new packet.
type Headers struct {
	// SrcPort holds the src port value to be used in the packet.
	SrcPort uint16

	// DstPort holds the destination port value to be used in the packet.
	DstPort uint16

	// SeqNum is the value of the sequence number field in the TCP header.
	SeqNum seqnum.Value

	// AckNum represents the acknowledgement number field in the TCP header.
	AckNum seqnum.Value

	// Flags are the TCP flags in the TCP header.
	Flags header.TCPFlags

	// RcvWnd is the window to be advertised in the ReceiveWindow field of
	// the TCP header.
	RcvWnd seqnum.Size

	// TCPOpts holds the options to be sent in the option field of the TCP
	// header.
	TCPOpts []byte
}

// Options contains options for creating a new test context.
type Options struct {
	// EnableV4 indicates whether IPv4 should be enabled.
	EnableV4 bool

	// EnableV6 indicates whether IPv4 should be enabled.
	EnableV6 bool

	// MTU indicates the maximum transmission unit on the link layer.
	MTU uint32
}

// Context provides an initialized Network stack and a link layer endpoint
// for use in TCP tests.
type Context struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack

	// IRS holds the initial sequence number in the SYN sent by endpoint in
	// case of an active connect or the sequence number sent by the endpoint
	// in the SYN-ACK sent in response to a SYN when listening in passive
	// mode.
	IRS seqnum.Value

	// Port holds the port bound by EP below in case of an active connect or
	// the listening port number in case of a passive connect.
	Port uint16

	// EP is the test endpoint in the stack owned by this context. This endpoint
	// is used in various tests to either initiate an active connect or is used
	// as a passive listening endpoint to accept inbound connections.
	EP tcpip.Endpoint

	// Wq is the wait queue associated with EP and is used to block for events
	// on EP.
	WQ waiter.Queue

	// TimeStampEnabled is true if ep is connected with the timestamp option
	// enabled.
	TimeStampEnabled bool

	// WindowScale is the expected window scale in SYN packets sent by
	// the stack.
	WindowScale uint8

	// RcvdWindowScale is the actual window scale sent by the stack in
	// SYN/SYN-ACK.
	RcvdWindowScale uint8
}

// New allocates and initializes a test context containing a new
// stack and a link-layer endpoint.
func New(t *testing.T, mtu uint32) *Context {
	return NewWithOpts(t, Options{
		EnableV4: true,
		EnableV6: true,
		MTU:      mtu,
	})
}

// NewWithOpts allocates and initializes a test context containing a new
// stack and a link-layer endpoint with specific options.
func NewWithOpts(t *testing.T, opts Options) *Context {
	if opts.MTU == 0 {
		panic("MTU must be greater than 0")
	}

	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	if opts.EnableV4 {
		stackOpts.NetworkProtocols = append(stackOpts.NetworkProtocols, ipv4.NewProtocol)
	}
	if opts.EnableV6 {
		stackOpts.NetworkProtocols = append(stackOpts.NetworkProtocols, ipv6.NewProtocol)
	}
	s := stack.New(stackOpts)

	const sendBufferSize = 1 << 20 // 1 MiB
	const recvBufferSize = 1 << 20 // 1 MiB
	// Allow minimum send/receive buffer sizes to be 1 during tests.
	sendBufOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 1, Default: sendBufferSize, Max: 10 * sendBufferSize}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendBufOpt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%#v) failed: %s", tcp.ProtocolNumber, sendBufOpt, err)
	}

	rcvBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: recvBufferSize, Max: 10 * recvBufferSize}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBufOpt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%#v) failed: %s", tcp.ProtocolNumber, rcvBufOpt, err)
	}

	// Increase minimum RTO in tests to avoid test flakes due to early
	// retransmit in case the test executors are overloaded and cause timers
	// to fire earlier than expected.
	minRTOOpt := tcpip.TCPMinRTOOption(3 * time.Second)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTOOpt); err != nil {
		t.Fatalf("s.SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, minRTOOpt, minRTOOpt, err)
	}

	// Some of the congestion control tests send up to 640 packets, we so
	// set the channel size to 1000.
	ep := channel.New(1000, opts.MTU, "")
	wep := stack.LinkEndpoint(ep)
	if testing.Verbose() {
		wep = sniffer.New(ep)
	}
	nicOpts := stack.NICOptions{Name: "nic1"}
	if err := s.CreateNICWithOptions(1, wep, nicOpts); err != nil {
		t.Fatalf("CreateNICWithOptions(_, _, %+v) failed: %v", opts, err)
	}
	wep2 := stack.LinkEndpoint(channel.New(1000, opts.MTU, ""))
	if testing.Verbose() {
		wep2 = sniffer.New(channel.New(1000, opts.MTU, ""))
	}
	opts2 := stack.NICOptions{Name: "nic2"}
	if err := s.CreateNICWithOptions(2, wep2, opts2); err != nil {
		t.Fatalf("CreateNICWithOptions(_, _, %+v) failed: %v", opts2, err)
	}

	var routeTable []tcpip.Route

	if opts.EnableV4 {
		v4ProtocolAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: StackAddrWithPrefix,
		}
		if err := s.AddProtocolAddress(1, v4ProtocolAddr); err != nil {
			t.Fatalf("AddProtocolAddress(1, %#v): %s", v4ProtocolAddr, err)
		}
		routeTable = append(routeTable, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		})
	}

	if opts.EnableV6 {
		v6ProtocolAddr := tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: StackV6AddrWithPrefix,
		}
		if err := s.AddProtocolAddress(1, v6ProtocolAddr); err != nil {
			t.Fatalf("AddProtocolAddress(1, %#v): %s", v6ProtocolAddr, err)
		}
		routeTable = append(routeTable, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		})
	}

	s.SetRouteTable(routeTable)

	return &Context{
		t:           t,
		s:           s,
		linkEP:      ep,
		WindowScale: uint8(tcp.FindWndScale(recvBufferSize)),
	}
}

// Cleanup closes the context endpoint if required.
func (c *Context) Cleanup() {
	if c.EP != nil {
		c.EP.Close()
	}
	c.Stack().Close()
}

// Stack returns a reference to the stack in the Context.
func (c *Context) Stack() *stack.Stack {
	return c.s
}

// CheckNoPacketTimeout verifies that no packet is received during the time
// specified by wait.
func (c *Context) CheckNoPacketTimeout(errMsg string, wait time.Duration) {
	c.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if _, ok := c.linkEP.ReadContext(ctx); ok {
		c.t.Fatal(errMsg)
	}
}

// CheckNoPacket verifies that no packet is received for 1 second.
func (c *Context) CheckNoPacket(errMsg string) {
	c.CheckNoPacketTimeout(errMsg, 1*time.Second)
}

// GetPacketWithTimeout reads a packet from the link layer endpoint and verifies
// that it is an IPv4 packet with the expected source and destination
// addresses. If no packet is received in the specified timeout it will return
// nil.
func (c *Context) GetPacketWithTimeout(timeout time.Duration) []byte {
	c.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	p, ok := c.linkEP.ReadContext(ctx)
	if !ok {
		return nil
	}

	if p.Proto != ipv4.ProtocolNumber {
		c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv4.ProtocolNumber)
	}

	// Just check that the stack set the transport protocol number for outbound
	// TCP messages.
	// TODO(gvisor.dev/issues/3810): Remove when protocol numbers are part
	// of the headerinfo.
	if p.Pkt.TransportProtocolNumber != tcp.ProtocolNumber {
		c.t.Fatalf("got p.Pkt.TransportProtocolNumber = %d, want = %d", p.Pkt.TransportProtocolNumber, tcp.ProtocolNumber)
	}

	vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
	b := vv.ToView()

	if p.Pkt.GSOOptions.Type != stack.GSONone && p.Pkt.GSOOptions.L3HdrLen != header.IPv4MinimumSize {
		c.t.Errorf("got L3HdrLen = %d, want = %d", p.Pkt.GSOOptions.L3HdrLen, header.IPv4MinimumSize)
	}

	checker.IPv4(c.t, b, checker.SrcAddr(StackAddr), checker.DstAddr(TestAddr))
	return b
}

// GetPacket reads a packet from the link layer endpoint and verifies
// that it is an IPv4 packet with the expected source and destination
// addresses.
func (c *Context) GetPacket() []byte {
	c.t.Helper()

	p := c.GetPacketWithTimeout(5 * time.Second)
	if p == nil {
		c.t.Fatalf("Packet wasn't written out")
		return nil
	}

	return p
}

// GetPacketNonBlocking reads a packet from the link layer endpoint
// and verifies that it is an IPv4 packet with the expected source
// and destination address. If no packet is available it will return
// nil immediately.
func (c *Context) GetPacketNonBlocking() []byte {
	c.t.Helper()

	p, ok := c.linkEP.Read()
	if !ok {
		return nil
	}

	if p.Proto != ipv4.ProtocolNumber {
		c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv4.ProtocolNumber)
	}

	// Just check that the stack set the transport protocol number for outbound
	// TCP messages.
	// TODO(gvisor.dev/issues/3810): Remove when protocol numbers are part
	// of the headerinfo.
	if p.Pkt.TransportProtocolNumber != tcp.ProtocolNumber {
		c.t.Fatalf("got p.Pkt.TransportProtocolNumber = %d, want = %d", p.Pkt.TransportProtocolNumber, tcp.ProtocolNumber)
	}

	vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
	b := vv.ToView()

	checker.IPv4(c.t, b, checker.SrcAddr(StackAddr), checker.DstAddr(TestAddr))
	return b
}

// SendICMPPacket builds and sends an ICMPv4 packet via the link layer endpoint.
func (c *Context) SendICMPPacket(typ header.ICMPv4Type, code header.ICMPv4Code, p1, p2 []byte, maxTotalSize int) {
	// Allocate a buffer data and headers.
	buf := buffer.NewView(header.IPv4MinimumSize + header.ICMPv4PayloadOffset + len(p2))
	if len(buf) > maxTotalSize {
		buf = buf[:maxTotalSize]
	}

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     TestAddr,
		DstAddr:     StackAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmp := header.ICMPv4(buf[header.IPv4MinimumSize:])
	icmp.SetType(typ)
	icmp.SetCode(code)
	const icmpv4VariableHeaderOffset = 4
	copy(icmp[icmpv4VariableHeaderOffset:], p1)
	copy(icmp[header.ICMPv4PayloadOffset:], p2)
	icmp.SetChecksum(0)
	checksum := ^header.Checksum(icmp, 0 /* initial */)
	icmp.SetChecksum(checksum)

	// Inject packet.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	})
	c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

// BuildSegment builds a TCP segment based on the given Headers and payload.
func (c *Context) BuildSegment(payload []byte, h *Headers) buffer.VectorisedView {
	return c.BuildSegmentWithAddrs(payload, h, TestAddr, StackAddr)
}

// BuildSegmentWithAddrs builds a TCP segment based on the given Headers,
// payload and source and destination IPv4 addresses.
func (c *Context) BuildSegmentWithAddrs(payload []byte, h *Headers, src, dst tcpip.Address) buffer.VectorisedView {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv4MinimumSize + len(h.TCPOpts) + len(payload))
	copy(buf[len(buf)-len(payload):], payload)
	copy(buf[len(buf)-len(payload)-len(h.TCPOpts):], h.TCPOpts)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the TCP header.
	t := header.TCP(buf[header.IPv4MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    h.SrcPort,
		DstPort:    h.DstPort,
		SeqNum:     uint32(h.SeqNum),
		AckNum:     uint32(h.AckNum),
		DataOffset: uint8(header.TCPMinimumSize + len(h.TCPOpts)),
		Flags:      h.Flags,
		WindowSize: uint16(h.RcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, uint16(len(t)))

	// Calculate the TCP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum))

	// Inject packet.
	return buf.ToVectorisedView()
}

// SendSegment sends a TCP segment that has already been built and written to a
// buffer.VectorisedView.
func (c *Context) SendSegment(s buffer.VectorisedView) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: s,
	})
	c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

// SendPacket builds and sends a TCP segment(with the provided payload & TCP
// headers) in an IPv4 packet via the link layer endpoint.
func (c *Context) SendPacket(payload []byte, h *Headers) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: c.BuildSegment(payload, h),
	})
	c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

// SendPacketWithAddrs builds and sends a TCP segment(with the provided payload
// & TCPheaders) in an IPv4 packet via the link layer endpoint using the
// provided source and destination IPv4 addresses.
func (c *Context) SendPacketWithAddrs(payload []byte, h *Headers, src, dst tcpip.Address) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: c.BuildSegmentWithAddrs(payload, h, src, dst),
	})
	c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

// SendAck sends an ACK packet.
func (c *Context) SendAck(seq seqnum.Value, bytesReceived int) {
	c.SendAckWithSACK(seq, bytesReceived, nil)
}

// SendAckWithSACK sends an ACK packet which includes the sackBlocks specified.
func (c *Context) SendAckWithSACK(seq seqnum.Value, bytesReceived int, sackBlocks []header.SACKBlock) {
	options := make([]byte, 40)
	offset := 0
	if len(sackBlocks) > 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKBlocks(sackBlocks, options[offset:])
	}

	c.SendPacket(nil, &Headers{
		SrcPort: TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seq,
		AckNum:  c.IRS.Add(1 + seqnum.Size(bytesReceived)),
		RcvWnd:  30000,
		TCPOpts: options[:offset],
	})
}

// ReceiveAndCheckPacket reads a packet from the link layer endpoint and
// verifies that the packet packet payload of packet matches the slice
// of data indicated by offset & size.
func (c *Context) ReceiveAndCheckPacket(data []byte, offset, size int) {
	c.t.Helper()

	c.ReceiveAndCheckPacketWithOptions(data, offset, size, 0)
}

// ReceiveAndCheckPacketWithOptions reads a packet from the link layer endpoint
// and verifies that the packet packet payload of packet matches the slice of
// data indicated by offset & size and skips optlen bytes in addition to the IP
// TCP headers when comparing the data.
func (c *Context) ReceiveAndCheckPacketWithOptions(data []byte, offset, size, optlen int) {
	c.t.Helper()

	b := c.GetPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(size+header.TCPMinimumSize+optlen),
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPSeqNum(uint32(c.IRS.Add(seqnum.Size(1+offset)))),
			checker.TCPAckNum(uint32(seqnum.Value(TestInitialSequenceNumber).Add(1))),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	pdata := data[offset:][:size]
	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize+optlen:]; bytes.Compare(pdata, p) != 0 {
		c.t.Fatalf("Data is different: expected %v, got %v", pdata, p)
	}
}

// ReceiveNonBlockingAndCheckPacket reads a packet from the link layer endpoint
// and verifies that the packet packet payload of packet matches the slice of
// data indicated by offset & size. It returns true if a packet was received and
// processed.
func (c *Context) ReceiveNonBlockingAndCheckPacket(data []byte, offset, size int) bool {
	c.t.Helper()

	b := c.GetPacketNonBlocking()
	if b == nil {
		return false
	}
	checker.IPv4(c.t, b,
		checker.PayloadLen(size+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPSeqNum(uint32(c.IRS.Add(seqnum.Size(1+offset)))),
			checker.TCPAckNum(uint32(seqnum.Value(TestInitialSequenceNumber).Add(1))),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	pdata := data[offset:][:size]
	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; bytes.Compare(pdata, p) != 0 {
		c.t.Fatalf("Data is different: expected %v, got %v", pdata, p)
	}
	return true
}

// CreateV6Endpoint creates and initializes c.ep as a IPv6 Endpoint. If v6Only
// is true then it sets the IP_V6ONLY option on the socket to make it a IPv6
// only endpoint instead of a default dual stack socket.
func (c *Context) CreateV6Endpoint(v6only bool) {
	var err tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	c.EP.SocketOptions().SetV6Only(v6only)
}

// GetV6Packet reads a single packet from the link layer endpoint of the context
// and asserts that it is an IPv6 Packet with the expected src/dest addresses.
func (c *Context) GetV6Packet() []byte {
	c.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, ok := c.linkEP.ReadContext(ctx)
	if !ok {
		c.t.Fatalf("Packet wasn't written out")
		return nil
	}

	if p.Proto != ipv6.ProtocolNumber {
		c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv6.ProtocolNumber)
	}
	vv := buffer.NewVectorisedView(p.Pkt.Size(), p.Pkt.Views())
	b := vv.ToView()

	checker.IPv6(c.t, b, checker.SrcAddr(StackV6Addr), checker.DstAddr(TestV6Addr))
	return b
}

// SendV6Packet builds and sends an IPv6 Packet via the link layer endpoint of
// the context.
func (c *Context) SendV6Packet(payload []byte, h *Headers) {
	c.SendV6PacketWithAddrs(payload, h, TestV6Addr, StackV6Addr)
}

// SendV6PacketWithAddrs builds and sends an IPv6 Packet via the link layer
// endpoint of the context using the provided source and destination IPv6
// addresses.
func (c *Context) SendV6PacketWithAddrs(payload []byte, h *Headers, src, dst tcpip.Address) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize + len(payload)),
		TransportProtocol: tcp.ProtocolNumber,
		HopLimit:          65,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	// Initialize the TCP header.
	t := header.TCP(buf[header.IPv6MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    h.SrcPort,
		DstPort:    h.DstPort,
		SeqNum:     uint32(h.SeqNum),
		AckNum:     uint32(h.AckNum),
		DataOffset: header.TCPMinimumSize,
		Flags:      h.Flags,
		WindowSize: uint16(h.RcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, uint16(len(t)))

	// Calculate the TCP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum))

	// Inject packet.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	})
	c.linkEP.InjectInbound(ipv6.ProtocolNumber, pkt)
}

// CreateConnected creates a connected TCP endpoint.
func (c *Context) CreateConnected(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf int) {
	c.CreateConnectedWithRawOptions(iss, rcvWnd, epRcvBuf, nil)
}

// Connect performs the 3-way handshake for c.EP with the provided Initial
// Sequence Number (iss) and receive window(rcvWnd) and any options if
// specified.
//
// It also sets the receive buffer for the endpoint to the specified
// value in epRcvBuf.
//
// PreCondition: c.EP must already be created.
func (c *Context) Connect(iss seqnum.Value, rcvWnd seqnum.Size, options []byte) {
	c.t.Helper()

	// Start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.WritableEvents)
	defer c.WQ.EventUnregister(&waitEntry)

	err := c.EP.Connect(tcpip.FullAddress{Addr: TestAddr, Port: TestPort})
	if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.GetPacket()
	checker.IPv4(c.t, b,
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateSynSent; got != want {
		c.t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	tcpHdr := header.TCP(header.IPv4(b).Payload())
	synOpts := header.ParseSynOptions(tcpHdr.Options(), false /* isAck */)
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	c.SendPacket(nil, &Headers{
		SrcPort: tcpHdr.DestinationPort(),
		DstPort: tcpHdr.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  rcvWnd,
		TCPOpts: options,
	})

	// Receive ACK packet.
	checker.IPv4(c.t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-notifyCh:
		if err := c.EP.LastError(); err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateEstablished; got != want {
		c.t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	c.RcvdWindowScale = uint8(synOpts.WS)
	c.Port = tcpHdr.SourcePort()
}

// Create creates a TCP endpoint.
func (c *Context) Create(epRcvBuf int) {
	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	if epRcvBuf != -1 {
		c.EP.SocketOptions().SetReceiveBufferSize(int64(epRcvBuf)*2, true /* notify */)
	}
}

// CreateConnectedWithRawOptions creates a connected TCP endpoint and sends
// the specified option bytes as the Option field in the initial SYN packet.
//
// It also sets the receive buffer for the endpoint to the specified
// value in epRcvBuf.
func (c *Context) CreateConnectedWithRawOptions(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf int, options []byte) {
	c.Create(epRcvBuf)
	c.Connect(iss, rcvWnd, options)
}

// RawEndpoint is just a small wrapper around a TCP endpoint's state to make
// sending data and ACK packets easy while being able to manipulate the sequence
// numbers and timestamp values as needed.
type RawEndpoint struct {
	C          *Context
	SrcPort    uint16
	DstPort    uint16
	Flags      header.TCPFlags
	NextSeqNum seqnum.Value
	AckNum     seqnum.Value
	WndSize    seqnum.Size
	RecentTS   uint32 // Stores the latest timestamp to echo back.
	TSVal      uint32 // TSVal stores the last timestamp sent by this endpoint.

	// SackPermitted is true if SACKPermitted option was negotiated for this endpoint.
	SACKPermitted bool
}

// SendPacketWithTS embeds the provided tsVal in the Timestamp option
// for the packet to be sent out.
func (r *RawEndpoint) SendPacketWithTS(payload []byte, tsVal uint32) {
	r.TSVal = tsVal
	tsOpt := [12]byte{header.TCPOptionNOP, header.TCPOptionNOP}
	header.EncodeTSOption(r.TSVal, r.RecentTS, tsOpt[2:])
	r.SendPacket(payload, tsOpt[:])
}

// SendPacket is a small wrapper function to build and send packets.
func (r *RawEndpoint) SendPacket(payload []byte, opts []byte) {
	packetHeaders := &Headers{
		SrcPort: r.SrcPort,
		DstPort: r.DstPort,
		Flags:   r.Flags,
		SeqNum:  r.NextSeqNum,
		AckNum:  r.AckNum,
		RcvWnd:  r.WndSize,
		TCPOpts: opts,
	}
	r.C.SendPacket(payload, packetHeaders)
	r.NextSeqNum = r.NextSeqNum.Add(seqnum.Size(len(payload)))
}

// VerifyAndReturnACKWithTS verifies that the tsEcr field int he ACK matches
// the provided tsVal as well as returns the original packet.
func (r *RawEndpoint) VerifyAndReturnACKWithTS(tsVal uint32) []byte {
	r.C.t.Helper()
	// Read ACK and verify that tsEcr of ACK packet is [1,2,3,4]
	ackPacket := r.C.GetPacket()
	checker.IPv4(r.C.t, ackPacket,
		checker.TCP(
			checker.DstPort(r.SrcPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(r.AckNum)),
			checker.TCPAckNum(uint32(r.NextSeqNum)),
			checker.TCPTimestampChecker(true, 0, tsVal),
		),
	)
	// Store the parsed TSVal from the ack as recentTS.
	tcpSeg := header.TCP(header.IPv4(ackPacket).Payload())
	opts := tcpSeg.ParsedOptions()
	r.RecentTS = opts.TSVal
	return ackPacket
}

// VerifyACKWithTS verifies that the tsEcr field in the ack matches the provided
// tsVal.
func (r *RawEndpoint) VerifyACKWithTS(tsVal uint32) {
	r.C.t.Helper()
	_ = r.VerifyAndReturnACKWithTS(tsVal)
}

// VerifyACKRcvWnd verifies that the window advertised by the incoming ACK
// matches the provided rcvWnd.
func (r *RawEndpoint) VerifyACKRcvWnd(rcvWnd uint16) {
	r.C.t.Helper()
	ackPacket := r.C.GetPacket()
	checker.IPv4(r.C.t, ackPacket,
		checker.TCP(
			checker.DstPort(r.SrcPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(r.AckNum)),
			checker.TCPAckNum(uint32(r.NextSeqNum)),
			checker.TCPWindow(rcvWnd),
		),
	)
}

// VerifyACKNoSACK verifies that the ACK does not contain a SACK block.
func (r *RawEndpoint) VerifyACKNoSACK() {
	r.VerifyACKHasSACK(nil)
}

// VerifyACKHasSACK verifies that the ACK contains the specified SACKBlocks.
func (r *RawEndpoint) VerifyACKHasSACK(sackBlocks []header.SACKBlock) {
	// Read ACK and verify that the TCP options in the segment do
	// not contain a SACK block.
	ackPacket := r.C.GetPacket()
	checker.IPv4(r.C.t, ackPacket,
		checker.TCP(
			checker.DstPort(r.SrcPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(r.AckNum)),
			checker.TCPAckNum(uint32(r.NextSeqNum)),
			checker.TCPSACKBlockChecker(sackBlocks),
		),
	)
}

// CreateConnectedWithOptions creates and connects c.ep with the specified TCP
// options enabled and returns a RawEndpoint which represents the other end of
// the connection.
//
// It also verifies where required(eg.Timestamp) that the ACK to the SYN-ACK
// does not carry an option that was not requested.
func (c *Context) CreateConnectedWithOptions(wantOptions header.TCPSynOptions) *RawEndpoint {
	var err tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("c.s.NewEndpoint(tcp, ipv4...) = %v", err)
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateInitial; got != want {
		c.t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// Start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.WritableEvents)
	defer c.WQ.EventUnregister(&waitEntry)

	testFullAddr := tcpip.FullAddress{Addr: TestAddr, Port: TestPort}
	err = c.EP.Connect(testFullAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		c.t.Fatalf("c.ep.Connect(%v) = %v", testFullAddr, err)
	}
	// Receive SYN packet.
	b := c.GetPacket()
	// Validate that the syn has the timestamp option and a valid
	// TS value.
	mss := uint16(c.linkEP.MTU() - header.IPv4MinimumSize - header.TCPMinimumSize)

	checker.IPv4(c.t, b,
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.TCPSynOptions(header.TCPSynOptions{
				MSS:           mss,
				TS:            true,
				WS:            int(c.WindowScale),
				SACKPermitted: c.SACKEnabled(),
			}),
		),
	)
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateSynSent; got != want {
		c.t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	tcpSeg := header.TCP(header.IPv4(b).Payload())
	synOptions := header.ParseSynOptions(tcpSeg.Options(), false)

	// Build options w/ tsVal to be sent in the SYN-ACK.
	synAckOptions := make([]byte, header.TCPOptionsMaximumSize)
	offset := 0
	if wantOptions.WS != -1 {
		offset += header.EncodeWSOption(wantOptions.WS, synAckOptions[offset:])
	}
	if wantOptions.TS {
		offset += header.EncodeTSOption(wantOptions.TSVal, synOptions.TSVal, synAckOptions[offset:])
	}
	if wantOptions.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(synAckOptions[offset:])
	}

	offset += header.AddTCPOptionPadding(synAckOptions, offset)

	// Build SYN-ACK.
	c.IRS = seqnum.Value(tcpSeg.SequenceNumber())
	iss := seqnum.Value(TestInitialSequenceNumber)
	c.SendPacket(nil, &Headers{
		SrcPort: tcpSeg.DestinationPort(),
		DstPort: tcpSeg.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
		TCPOpts: synAckOptions[:offset],
	})

	// Read ACK.
	ackPacket := c.GetPacket()

	// Verify TCP header fields.
	tcpCheckers := []checker.TransportChecker{
		checker.DstPort(TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(c.IRS) + 1),
		checker.TCPAckNum(uint32(iss) + 1),
	}

	// Verify that tsEcr of ACK packet is wantOptions.TSVal if the
	// timestamp option was enabled, if not then we verify that
	// there is no timestamp in the ACK packet.
	if wantOptions.TS {
		tcpCheckers = append(tcpCheckers, checker.TCPTimestampChecker(true, 0, wantOptions.TSVal))
	} else {
		tcpCheckers = append(tcpCheckers, checker.TCPTimestampChecker(false, 0, 0))
	}

	checker.IPv4(c.t, ackPacket, checker.TCP(tcpCheckers...))

	ackSeg := header.TCP(header.IPv4(ackPacket).Payload())
	ackOptions := ackSeg.ParsedOptions()

	// Wait for connection to be established.
	select {
	case <-notifyCh:
		if err := c.EP.LastError(); err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateEstablished; got != want {
		c.t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// Store the source port in use by the endpoint.
	c.Port = tcpSeg.SourcePort()

	// Mark in context that timestamp option is enabled for this endpoint.
	c.TimeStampEnabled = true
	c.RcvdWindowScale = uint8(synOptions.WS)
	return &RawEndpoint{
		C:             c,
		SrcPort:       tcpSeg.DestinationPort(),
		DstPort:       tcpSeg.SourcePort(),
		Flags:         header.TCPFlagAck | header.TCPFlagPsh,
		NextSeqNum:    iss + 1,
		AckNum:        c.IRS.Add(1),
		WndSize:       30000,
		RecentTS:      ackOptions.TSVal,
		TSVal:         wantOptions.TSVal,
		SACKPermitted: wantOptions.SACKPermitted,
	}
}

// AcceptWithOptions initializes a listening endpoint and connects to it with the
// provided options enabled. It also verifies that the SYN-ACK has the expected
// values for the provided options.
//
// The function returns a RawEndpoint representing the other end of the accepted
// endpoint.
func (c *Context) AcceptWithOptions(wndScale int, synOptions header.TCPSynOptions) *RawEndpoint {
	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: StackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateBound; got != want {
		c.t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateListen; got != want {
		c.t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	rep := c.PassiveConnectWithOptions(100, wndScale, synOptions)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateEstablished; got != want {
		c.t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	return rep
}

// PassiveConnect just disables WindowScaling and delegates the call to
// PassiveConnectWithOptions.
func (c *Context) PassiveConnect(maxPayload, wndScale int, synOptions header.TCPSynOptions) {
	synOptions.WS = -1
	c.PassiveConnectWithOptions(maxPayload, wndScale, synOptions)
}

// PassiveConnectWithOptions initiates a new connection (with the specified TCP
// options enabled) to the port on which the Context.ep is listening for new
// connections. It also validates that the SYN-ACK has the expected values for
// the enabled options.
//
// NOTE: MSS is not a negotiated option and it can be asymmetric
// in each direction. This function uses the maxPayload to set the MSS to be
// sent to the peer on a connect and validates that the MSS in the SYN-ACK
// response is equal to the MTU - (tcphdr len + iphdr len).
//
// wndScale is the expected window scale in the SYN-ACK and synOptions.WS is the
// value of the window scaling option to be sent in the SYN. If synOptions.WS >
// 0 then we send the WindowScale option.
func (c *Context) PassiveConnectWithOptions(maxPayload, wndScale int, synOptions header.TCPSynOptions) *RawEndpoint {
	c.t.Helper()
	opts := make([]byte, header.TCPOptionsMaximumSize)
	offset := 0
	offset += header.EncodeMSSOption(uint32(maxPayload), opts)

	if synOptions.WS >= 0 {
		offset += header.EncodeWSOption(3, opts[offset:])
	}
	if synOptions.TS {
		offset += header.EncodeTSOption(synOptions.TSVal, synOptions.TSEcr, opts[offset:])
	}

	if synOptions.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(opts[offset:])
	}

	paddingToAdd := 4 - offset%4
	// Now add any padding bytes that might be required to quad align the
	// options.
	for i := offset; i < offset+paddingToAdd; i++ {
		opts[i] = header.TCPOptionNOP
	}
	offset += paddingToAdd

	// Send a SYN request.
	iss := seqnum.Value(TestInitialSequenceNumber)
	c.SendPacket(nil, &Headers{
		SrcPort: TestPort,
		DstPort: StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
		TCPOpts: opts[:offset],
	})

	// Receive the SYN-ACK reply. Make sure MSS and other expected options
	// are present.
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	rcvdSynOptions := header.ParseSynOptions(tcp.Options(), true /* isAck */)
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(StackPort),
		checker.DstPort(TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(iss) + 1),
		checker.TCPSynOptions(header.TCPSynOptions{MSS: synOptions.MSS, WS: wndScale, SACKPermitted: synOptions.SACKPermitted && c.SACKEnabled()}),
	}

	// If TS option was enabled in the original SYN then add a checker to
	// validate the Timestamp option in the SYN-ACK.
	if synOptions.TS {
		tcpCheckers = append(tcpCheckers, checker.TCPTimestampChecker(synOptions.TS, 0, synOptions.TSVal))
	} else {
		tcpCheckers = append(tcpCheckers, checker.TCPTimestampChecker(false, 0, 0))
	}

	checker.IPv4(c.t, b, checker.TCP(tcpCheckers...))
	rcvWnd := seqnum.Size(30000)
	ackHeaders := &Headers{
		SrcPort: TestPort,
		DstPort: StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
		RcvWnd:  rcvWnd,
	}

	// If WS was expected to be in effect then scale the advertised window
	// correspondingly.
	if synOptions.WS > 0 {
		ackHeaders.RcvWnd = rcvWnd >> byte(synOptions.WS)
	}

	parsedOpts := tcp.ParsedOptions()
	if synOptions.TS {
		// Echo the tsVal back to the peer in the tsEcr field of the
		// timestamp option.
		// Increment TSVal by 1 from the value sent in the SYN and echo
		// the TSVal in the SYN-ACK in the TSEcr field.
		opts := [12]byte{header.TCPOptionNOP, header.TCPOptionNOP}
		header.EncodeTSOption(synOptions.TSVal+1, parsedOpts.TSVal, opts[2:])
		ackHeaders.TCPOpts = opts[:]
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	c.RcvdWindowScale = uint8(rcvdSynOptions.WS)
	c.Port = StackPort

	return &RawEndpoint{
		C:             c,
		SrcPort:       TestPort,
		DstPort:       StackPort,
		Flags:         header.TCPFlagPsh | header.TCPFlagAck,
		NextSeqNum:    iss + 1,
		AckNum:        c.IRS + 1,
		WndSize:       rcvWnd,
		SACKPermitted: synOptions.SACKPermitted && c.SACKEnabled(),
		RecentTS:      parsedOpts.TSVal,
		TSVal:         synOptions.TSVal + 1,
	}
}

// SACKEnabled returns true if the TCP Protocol option SACKEnabled is set to true
// for the Stack in the context.
func (c *Context) SACKEnabled() bool {
	var v tcpip.TCPSACKEnabled
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &v); err != nil {
		// Stack doesn't support SACK. So just return.
		return false
	}
	return bool(v)
}

// SetGSOEnabled enables or disables generic segmentation offload.
func (c *Context) SetGSOEnabled(enable bool) {
	if enable {
		c.linkEP.SupportedGSOKind = stack.HWGSOSupported
	} else {
		c.linkEP.SupportedGSOKind = stack.GSONotSupported
	}
}

// MSSWithoutOptions returns the value for the MSS used by the stack when no
// options are in use.
func (c *Context) MSSWithoutOptions() uint16 {
	return uint16(c.linkEP.MTU() - header.IPv4MinimumSize - header.TCPMinimumSize)
}

// MSSWithoutOptionsV6 returns the value for the MSS used by the stack when no
// options are in use for IPv6 packets.
func (c *Context) MSSWithoutOptionsV6() uint16 {
	return uint16(c.linkEP.MTU() - header.IPv6MinimumSize - header.TCPMinimumSize)
}
