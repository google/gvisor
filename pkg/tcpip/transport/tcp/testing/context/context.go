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

// Package context provides a test context for use in tcp tests. It also
// provides helper methods to assert/check certain behaviours.
package context

import (
	"bytes"
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
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
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
	StackV6Addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

	// TestV6Addr is the source address for packets sent to the stack via
	// the link layer endpoint.
	TestV6Addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	// StackV4MappedAddr is StackAddr as a mapped v6 address.
	StackV4MappedAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + StackAddr

	// TestV4MappedAddr is TestAddr as a mapped v6 address.
	TestV4MappedAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + TestAddr

	// V4MappedWildcardAddr is the mapped v6 representation of 0.0.0.0.
	V4MappedWildcardAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"

	// testInitialSequenceNumber is the initial sequence number sent in packets that
	// are sent in response to a SYN or in the initial SYN sent to the stack.
	testInitialSequenceNumber = 789
)

// defaultWindowScale value specified here depends on the tcp.DefaultBufferSize
// constant defined in the tcp/endpoint.go because the tcp.DefaultBufferSize is
// used in tcp.newHandshake to determine the window scale to use when sending a
// SYN/SYN-ACK.
var defaultWindowScale = tcp.FindWndScale(tcp.DefaultBufferSize)

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
	Flags int

	// RcvWnd is the window to be advertised in the ReceiveWindow field of
	// the TCP header.
	RcvWnd seqnum.Size

	// TCPOpts holds the options to be sent in the option field of the TCP
	// header.
	TCPOpts []byte
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
}

// New allocates and initializes a test context containing a new
// stack and a link-layer endpoint.
func New(t *testing.T, mtu uint32) *Context {
	s := stack.New(&tcpip.StdClock{}, []string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{tcp.ProtocolName})

	// Allow minimum send/receive buffer sizes to be 1 during tests.
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SendBufferSizeOption{1, tcp.DefaultBufferSize, tcp.DefaultBufferSize * 10}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.ReceiveBufferSizeOption{1, tcp.DefaultBufferSize, tcp.DefaultBufferSize * 10}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	// Some of the congestion control tests send up to 640 packets, we so
	// set the channel size to 1000.
	id, linkEP := channel.New(1000, mtu, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, StackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, ipv6.ProtocolNumber, StackV6Addr); err != nil {
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

	return &Context{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

// Cleanup closes the context endpoint if required.
func (c *Context) Cleanup() {
	if c.EP != nil {
		c.EP.Close()
	}
}

// Stack returns a reference to the stack in the Context.
func (c *Context) Stack() *stack.Stack {
	return c.s
}

// CheckNoPacketTimeout verifies that no packet is received during the time
// specified by wait.
func (c *Context) CheckNoPacketTimeout(errMsg string, wait time.Duration) {
	select {
	case <-c.linkEP.C:
		c.t.Fatalf(errMsg)

	case <-time.After(wait):
	}
}

// CheckNoPacket verifies that no packet is received for 1 second.
func (c *Context) CheckNoPacket(errMsg string) {
	c.CheckNoPacketTimeout(errMsg, 1*time.Second)
}

// GetPacket reads a packet from the link layer endpoint and verifies
// that it is an IPv4 packet with the expected source and destination
// addresses. It will fail with an error if no packet is received for
// 2 seconds.
func (c *Context) GetPacket() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv4.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv4.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv4(c.t, b, checker.SrcAddr(StackAddr), checker.DstAddr(TestAddr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

// SendICMPPacket builds and sends an ICMPv4 packet via the link layer endpoint.
func (c *Context) SendICMPPacket(typ header.ICMPv4Type, code uint8, p1, p2 []byte, maxTotalSize int) {
	// Allocate a buffer data and headers.
	buf := buffer.NewView(header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(p1) + len(p2))
	if len(buf) > maxTotalSize {
		buf = buf[:maxTotalSize]
	}

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
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

	copy(icmp[header.ICMPv4MinimumSize:], p1)
	copy(icmp[header.ICMPv4MinimumSize+len(p1):], p2)

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv4.ProtocolNumber, &vv)
}

// SendPacket builds and sends a TCP segment(with the provided payload & TCP
// headers) in an IPv4 packet via the link layer endpoint.
func (c *Context) SendPacket(payload []byte, h *Headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv4MinimumSize + len(h.TCPOpts) + len(payload))
	copy(buf[len(buf)-len(payload):], payload)
	copy(buf[len(buf)-len(payload)-len(h.TCPOpts):], h.TCPOpts)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     TestAddr,
		DstAddr:     StackAddr,
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
		Flags:      uint8(h.Flags),
		WindowSize: uint16(h.RcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.Checksum([]byte(TestAddr), 0)
	xsum = header.Checksum([]byte(StackAddr), xsum)
	xsum = header.Checksum([]byte{0, uint8(tcp.ProtocolNumber)}, xsum)

	// Calculate the TCP checksum and set it.
	length := uint16(header.TCPMinimumSize + len(h.TCPOpts) + len(payload))
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv4.ProtocolNumber, &vv)
}

// SendAck sends an ACK packet.
func (c *Context) SendAck(seq seqnum.Value, bytesReceived int) {
	c.SendPacket(nil, &Headers{
		SrcPort: TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(testInitialSequenceNumber).Add(1),
		AckNum:  c.IRS.Add(1 + seqnum.Size(bytesReceived)),
		RcvWnd:  30000,
	})
}

// ReceiveAndCheckPacket reads a packet from the link layer endpoint and
// verifies that the packet packet payload of packet matches the slice
// of data indicated by offset & size.
func (c *Context) ReceiveAndCheckPacket(data []byte, offset, size int) {
	b := c.GetPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(size+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(TestPort),
			checker.SeqNum(uint32(c.IRS.Add(seqnum.Size(1+offset)))),
			checker.AckNum(uint32(seqnum.Value(testInitialSequenceNumber).Add(1))),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	pdata := data[offset:][:size]
	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; bytes.Compare(pdata, p) != 0 {
		c.t.Fatalf("Data is different: expected %v, got %v", pdata, p)
	}
}

// CreateV6Endpoint creates and initializes c.ep as a IPv6 Endpoint. If v6Only
// is true then it sets the IP_V6ONLY option on the socket to make it a IPv6
// only endpoint instead of a default dual stack socket.
func (c *Context) CreateV6Endpoint(v6only bool) {
	var err *tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	var v tcpip.V6OnlyOption
	if v6only {
		v = 1
	}
	if err := c.EP.SetSockOpt(v); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}
}

// GetV6Packet reads a single packet from the link layer endpoint of the context
// and asserts that it is an IPv6 Packet with the expected src/dest addresses.
func (c *Context) GetV6Packet() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv6.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv6.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv6(c.t, b, checker.SrcAddr(StackV6Addr), checker.DstAddr(TestV6Addr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

// SendV6Packet builds and sends an IPv6 Packet via the link layer endpoint of
// the context.
func (c *Context) SendV6Packet(payload []byte, h *Headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.TCPMinimumSize + len(payload)),
		NextHeader:    uint8(tcp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       TestV6Addr,
		DstAddr:       StackV6Addr,
	})

	// Initialize the TCP header.
	t := header.TCP(buf[header.IPv6MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    h.SrcPort,
		DstPort:    h.DstPort,
		SeqNum:     uint32(h.SeqNum),
		AckNum:     uint32(h.AckNum),
		DataOffset: header.TCPMinimumSize,
		Flags:      uint8(h.Flags),
		WindowSize: uint16(h.RcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.Checksum([]byte(TestV6Addr), 0)
	xsum = header.Checksum([]byte(StackV6Addr), xsum)
	xsum = header.Checksum([]byte{0, uint8(tcp.ProtocolNumber)}, xsum)

	// Calculate the TCP checksum and set it.
	length := uint16(header.TCPMinimumSize + len(payload))
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv6.ProtocolNumber, &vv)
}

// CreateConnected creates a connected TCP endpoint.
func (c *Context) CreateConnected(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf *tcpip.ReceiveBufferSizeOption) {
	c.CreateConnectedWithRawOptions(iss, rcvWnd, epRcvBuf, nil)
}

// CreateConnectedWithRawOptions creates a connected TCP endpoint and sends
// the specified option bytes as the Option field in the initial SYN packet.
//
// It also sets the receive buffer for the endpoint to the specified
// value in epRcvBuf.
func (c *Context) CreateConnectedWithRawOptions(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf *tcpip.ReceiveBufferSizeOption, options []byte) {
	// Create TCP endpoint.
	var err *tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	if epRcvBuf != nil {
		if err := c.EP.SetSockOpt(*epRcvBuf); err != nil {
			c.t.Fatalf("SetSockOpt failed failed: %v", err)
		}
	}

	// Start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.EventOut)
	defer c.WQ.EventUnregister(&waitEntry)

	err = c.EP.Connect(tcpip.FullAddress{Addr: TestAddr, Port: TestPort})
	if err != tcpip.ErrConnectStarted {
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

	tcp := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	c.SendPacket(nil, &Headers{
		SrcPort: tcp.DestinationPort(),
		DstPort: tcp.SourcePort(),
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
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-notifyCh:
		err = c.EP.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}

	c.Port = tcp.SourcePort()
}

// RawEndpoint is just a small wrapper around a TCP endpoint's state to make
// sending data and ACK packets easy while being able to manipulate the sequence
// numbers and timestamp values as needed.
type RawEndpoint struct {
	C          *Context
	SrcPort    uint16
	DstPort    uint16
	Flags      int
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

// VerifyACKWithTS verifies that the tsEcr field in the ack matches the provided
// tsVal.
func (r *RawEndpoint) VerifyACKWithTS(tsVal uint32) {
	// Read ACK and verify that tsEcr of ACK packet is [1,2,3,4]
	ackPacket := r.C.GetPacket()
	checker.IPv4(r.C.t, ackPacket,
		checker.TCP(
			checker.DstPort(r.SrcPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.SeqNum(uint32(r.AckNum)),
			checker.AckNum(uint32(r.NextSeqNum)),
			checker.TCPTimestampChecker(true, 0, tsVal),
		),
	)
	// Store the parsed TSVal from the ack as recentTS.
	tcpSeg := header.TCP(header.IPv4(ackPacket).Payload())
	opts := tcpSeg.ParsedOptions()
	r.RecentTS = opts.TSVal
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
			checker.SeqNum(uint32(r.AckNum)),
			checker.AckNum(uint32(r.NextSeqNum)),
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
	var err *tcpip.Error
	c.EP, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		c.t.Fatalf("c.s.NewEndpoint(tcp, ipv4...) = %v", err)
	}

	// Start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.EventOut)
	defer c.WQ.EventUnregister(&waitEntry)

	testFullAddr := tcpip.FullAddress{Addr: TestAddr, Port: TestPort}
	err = c.EP.Connect(testFullAddr)
	if err != tcpip.ErrConnectStarted {
		c.t.Fatalf("c.ep.Connect(%v) = %v", testFullAddr, err)
	}
	// Receive SYN packet.
	b := c.GetPacket()
	// Validate that the syn has the timestamp option and a valid
	// TS value.
	checker.IPv4(c.t, b,
		checker.TCP(
			checker.DstPort(TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.TCPSynOptions(header.TCPSynOptions{
				MSS:           uint16(c.linkEP.MTU() - header.IPv4MinimumSize - header.TCPMinimumSize),
				TS:            true,
				WS:            defaultWindowScale,
				SACKPermitted: c.SACKEnabled(),
			}),
		),
	)
	tcpSeg := header.TCP(header.IPv4(b).Payload())
	synOptions := header.ParseSynOptions(tcpSeg.Options(), false)

	// Build options w/ tsVal to be sent in the SYN-ACK.
	synAckOptions := make([]byte, 40)
	offset := 0
	if wantOptions.TS {
		offset += header.EncodeTSOption(wantOptions.TSVal, synOptions.TSVal, synAckOptions[offset:])
	}
	if wantOptions.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(synAckOptions[offset:])
	}

	offset += header.AddTCPOptionPadding(synAckOptions, offset)

	// Build SYN-ACK.
	c.IRS = seqnum.Value(tcpSeg.SequenceNumber())
	iss := seqnum.Value(testInitialSequenceNumber)
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
		checker.SeqNum(uint32(c.IRS) + 1),
		checker.AckNum(uint32(iss) + 1),
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
		err = c.EP.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}

	// Store the source port in use by the endpoint.
	c.Port = tcpSeg.SourcePort()

	// Mark in context that timestamp option is enabled for this endpoint.
	c.TimeStampEnabled = true

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

	if err := ep.Bind(tcpip.FullAddress{Port: StackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	rep := c.PassiveConnectWithOptions(100, wndScale, synOptions)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
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
	opts := make([]byte, 40)
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
	iss := seqnum.Value(testInitialSequenceNumber)
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
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(StackPort),
		checker.DstPort(TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.AckNum(uint32(iss) + 1),
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
	var v tcp.SACKEnabled
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &v); err != nil {
		// Stack doesn't support SACK. So just return.
		return false
	}
	return bool(v)
}
