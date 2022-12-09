// Copyright 2022 The gVisor Authors.
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

// Package context provides a context used by datagram-based network endpoints
// tests. It also defines the TestFlow type to facilitate IP configurations.
package context

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// NICID is the id of the nic created by the Context.
	NICID = 1

	// DefaultMTU is the MTU used by the Context, except where another value is
	// explicitly specified during initialization. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	DefaultMTU = 65536
)

// Context is a testing context for datagram-based network endpoints.
type Context struct {
	// T is the testing context.
	T *testing.T

	// LinkEP is the link endpoint that is attached to the stack's NIC.
	LinkEP *channel.Endpoint

	// Stack is the networking stack owned by the context.
	Stack *stack.Stack

	// EP is the transport endpoint owned by the context.
	EP tcpip.Endpoint

	// WQ is the wait queue associated with EP and is used to block for events on
	// EP.
	WQ waiter.Queue
}

// Options contains options for creating a new test context.
type Options struct {
	// MTU is the mtu that the link endpoint will be initialized with.
	MTU uint32

	// HandleLocal specifies if non-loopback interfaces are allowed to loop
	// packets.
	HandleLocal bool
}

// New allocates and initializes a test context containing a configured stack.
func New(t *testing.T, transportProtocols []stack.TransportProtocolFactory) *Context {
	t.Helper()

	options := Options{
		MTU:         DefaultMTU,
		HandleLocal: true,
	}

	return NewWithOptions(t, transportProtocols, options)
}

// NewWithOptions allocates and initializes a test context containing a
// configured stack with the provided options.
func NewWithOptions(t *testing.T, transportProtocols []stack.TransportProtocolFactory, options Options) *Context {
	t.Helper()

	stackOptions := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: transportProtocols,
		HandleLocal:        options.HandleLocal,
		Clock:              &faketime.NullClock{},
		RawFactory:         &raw.EndpointFactory{},
	}

	s := stack.New(stackOptions)
	// Disable ICMP rate limiter since we're using Null clock, which never
	// advances time and thus never allows ICMP messages.
	s.SetICMPLimit(rate.Inf)
	ep := channel.New(256, options.MTU, "")
	wep := stack.LinkEndpoint(ep)

	if testing.Verbose() {
		wep = sniffer.New(ep)
	}
	if err := s.CreateNIC(NICID, wep); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", NICID, err)
	}

	protocolAddrV4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.Address(StackAddr).WithPrefix(),
	}
	if err := s.AddProtocolAddress(NICID, protocolAddrV4, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v, {}): %s", NICID, protocolAddrV4, err)
	}

	protocolAddrV6 := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.Address(StackV6Addr).WithPrefix(),
	}
	if err := s.AddProtocolAddress(NICID, protocolAddrV6, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v, {}): %s", NICID, protocolAddrV6, err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         NICID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         NICID,
		},
	})

	return &Context{
		T:      t,
		Stack:  s,
		LinkEP: ep,
	}
}

// Cleanup closes the context endpoint if required.
func (c *Context) Cleanup() {
	_ = c.LinkEP.Drain()
	if c.EP != nil {
		c.EP.Close()
	}
	c.Stack.Destroy()
	c.Stack = nil
	refs.DoRepeatedLeakCheck()
}

// CreateEndpoint creates the Context's Endpoint.
func (c *Context) CreateEndpoint(network tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber) {
	c.T.Helper()

	var err tcpip.Error
	c.EP, err = c.Stack.NewEndpoint(transport, network, &c.WQ)
	if err != nil {
		c.T.Fatalf("c.Stack.NewEndpoint(%d, %d, _) failed: %s", transport, network, err)
	}
}

// CreateEndpointForFlow creates the Context's Endpoint and configured it
// according to the given TestFlow.
func (c *Context) CreateEndpointForFlow(flow TestFlow, transport tcpip.TransportProtocolNumber) {
	c.T.Helper()

	c.CreateEndpoint(flow.SockProto(), transport)
	if flow.isV6Only() {
		c.EP.SocketOptions().SetV6Only(true)
	} else if flow.isBroadcast() {
		c.EP.SocketOptions().SetBroadcast(true)
	}
}

// CreateRawEndpoint creates the Context's Endpoint.
func (c *Context) CreateRawEndpoint(network tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber) {
	c.T.Helper()

	var err tcpip.Error
	c.EP, err = c.Stack.NewRawEndpoint(transport, network, &c.WQ, true /* associated */)
	if err != nil {
		c.T.Fatal("c.Stack.NewRawEndpoint failed: ", err)
	}
}

// CreateRawEndpointForFlow creates the Context's Endpoint and configured it
// according to the given TestFlow.
func (c *Context) CreateRawEndpointForFlow(flow TestFlow, transport tcpip.TransportProtocolNumber) {
	c.T.Helper()

	c.CreateRawEndpoint(flow.SockProto(), transport)
	if flow.isV6Only() {
		c.EP.SocketOptions().SetV6Only(true)
	} else if flow.isBroadcast() {
		c.EP.SocketOptions().SetBroadcast(true)
	}
}

// CheckEndpointWriteStats checks that the write statistic related to the given
// error has been incremented as expected.
func (c *Context) CheckEndpointWriteStats(incr uint64, want *tcpip.TransportEndpointStats, err tcpip.Error) {
	var got tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&got)
	switch err.(type) {
	case nil:
		want.PacketsSent.IncrementBy(incr)
	case *tcpip.ErrMessageTooLong, *tcpip.ErrInvalidOptionValue:
		want.WriteErrors.InvalidArgs.IncrementBy(incr)
	case *tcpip.ErrClosedForSend:
		want.WriteErrors.WriteClosed.IncrementBy(incr)
	case *tcpip.ErrInvalidEndpointState:
		want.WriteErrors.InvalidEndpointState.IncrementBy(incr)
	case *tcpip.ErrHostUnreachable, *tcpip.ErrBroadcastDisabled, *tcpip.ErrNetworkUnreachable:
		want.SendErrors.NoRoute.IncrementBy(incr)
	default:
		want.SendErrors.SendToNetworkFailed.IncrementBy(incr)
	}
	if !reflect.DeepEqual(&got, want) {
		c.T.Errorf("Endpoint stats not matching for error %s: got %#v, want %#v", err, &got, want)
	}
}

// CheckEndpointReadStats checks that the read statistic related to the given
// error has been incremented as expected.
func (c *Context) CheckEndpointReadStats(incr uint64, want *tcpip.TransportEndpointStats, err tcpip.Error) {
	c.T.Helper()

	var got tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&got)
	switch err.(type) {
	case nil, *tcpip.ErrWouldBlock:
	case *tcpip.ErrClosedForReceive:
		want.ReadErrors.ReadClosed.IncrementBy(incr)
	default:
		c.T.Errorf("Endpoint error missing stats update for err %s", err)
	}
	if !reflect.DeepEqual(&got, want) {
		c.T.Errorf("Endpoint stats not matching for error %s: got %#v, want %#v", err, &got, want)
	}
}

// InjectPacket injects a packet into the context's link endpoint.
func (c *Context) InjectPacket(netProto tcpip.NetworkProtocolNumber, buf []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	defer pkt.DecRef()
	c.LinkEP.InjectInbound(netProto, pkt)
}

// readExpectations holds information about the expected outcome when reading
// from the context's endpoint.
type readExpectations struct {
	nothingToRead  bool
	payload        []byte
	addresses      Header4Tuple
	readShouldFail bool
}

// readFromEndpoint attempts to read a packet from the endpoint and compares the
// outcome with the given expectations.
func (c *Context) readFromEndpoint(expectations readExpectations, checkers ...checker.ControlMessagesChecker) {
	c.T.Helper()

	// Try to receive the data.
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)

	// Take a snapshot of the stats to validate them at the end of the test.
	var epstats tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&epstats)

	var buf bytes.Buffer
	res, err := c.EP.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		select {
		case <-ch:
			res, err = c.EP.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
		default:
			if expectations.nothingToRead {
				return
			}
			c.T.Fatal("timed out waiting for data")
		}
	}

	if expectations.readShouldFail && err != nil {
		c.CheckEndpointReadStats(1, &epstats, err)
		return
	}

	if err != nil {
		c.T.Fatal("Read failed:", err)
	}

	if expectations.nothingToRead {
		c.T.Fatalf("Read unexpectedly received data from %s", res.RemoteAddr.Addr)
	}

	// Check the read result.
	if diff := cmp.Diff(tcpip.ReadResult{
		Count:      buf.Len(),
		Total:      buf.Len(),
		RemoteAddr: tcpip.FullAddress{Addr: expectations.addresses.Src.Addr},
	}, res, checker.IgnoreCmpPath(
		"ControlMessages", // ControlMessages are checked below.
		"RemoteAddr.NIC",
		"RemoteAddr.Port",
	)); diff != "" {
		c.T.Fatalf("Read: unexpected result (-want +got):\n%s", diff)
	}

	// Check the payload.
	v := buf.Bytes()
	if !bytes.Equal(expectations.payload, v) {
		c.T.Fatalf("got payload = %x, want = %x", v, expectations.payload)
	}

	// Run any checkers against the ControlMessages.
	for _, f := range checkers {
		f(c.T, res.ControlMessages)
	}

	c.CheckEndpointReadStats(1, &epstats, err)
}

// ReadFromEndpointExpectSuccess attempts to reads from the endpoint and
// performs checks on the received packet, according to the given flow and
// checkers.
func (c *Context) ReadFromEndpointExpectSuccess(payload []byte, flow TestFlow, checkers ...checker.ControlMessagesChecker) {
	c.T.Helper()

	c.readFromEndpoint(readExpectations{
		payload:   payload,
		addresses: flow.MakeHeader4Tuple(Incoming),
	}, checkers...)
}

// ReadFromEndpointExpectNoPacket reads from the endpoint and checks that no
// packets was received.
func (c *Context) ReadFromEndpointExpectNoPacket() {
	c.T.Helper()

	c.readFromEndpoint(readExpectations{
		nothingToRead: true,
	})
}

// ReadFromEndpointExpectError reads from the endpoint and checks that an
// error was returned.
func (c *Context) ReadFromEndpointExpectError() {
	c.T.Helper()

	c.readFromEndpoint(readExpectations{
		readShouldFail: true,
	})
}
