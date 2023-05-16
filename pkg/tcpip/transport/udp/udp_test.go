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
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/testing/context"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	testTOS              = 0x80
	testTTL              = 65
	arbitraryPayloadSize = 30
)

// newRandomPayload returns a payload with the specified size and with
// randomized content.
func newRandomPayload(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(rand.Intn(math.MaxUint8 + 1))
	}
	return b
}

func testRead(c *context.Context, flow context.TestFlow, checkers ...checker.ControlMessagesChecker) {
	c.T.Helper()

	payload := newRandomPayload(arbitraryPayloadSize)
	c.InjectPacket(flow.NetProto(), context.BuildUDPPacket(payload, flow, context.Incoming, testTOS, testTTL, false))
	c.ReadFromEndpointExpectSuccess(payload, flow, checkers...)
}

func testFailingRead(c *context.Context, flow context.TestFlow, expectReadError bool) {
	c.T.Helper()

	c.InjectPacket(flow.NetProto(), context.BuildUDPPacket(newRandomPayload(arbitraryPayloadSize), flow, context.Incoming, testTOS, testTTL, false))
	if expectReadError {
		c.ReadFromEndpointExpectError()
	} else {
		c.ReadFromEndpointExpectNoPacket()
	}
}

func TestBindToDeviceOption(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              &faketime.NullClock{},
	})
	defer s.Destroy()

	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	defer ep.Close()

	opts := stack.NICOptions{Name: "my_device"}
	if err := s.CreateNICWithOptions(321, loopback.New(), opts); err != nil {
		t.Errorf("CreateNICWithOptions(_, _, %+v) failed: %s", opts, err)
	}

	// nicIDPtr is used instead of taking the address of NICID literals, which is
	// a compiler error.
	nicIDPtr := func(s tcpip.NICID) *tcpip.NICID {
		return &s
	}

	testActions := []struct {
		name                 string
		setBindToDevice      *tcpip.NICID
		setBindToDeviceError tcpip.Error
		getBindToDevice      int32
	}{
		{"GetDefaultValue", nil, nil, 0},
		{"BindToNonExistent", nicIDPtr(999), &tcpip.ErrUnknownDevice{}, 0},
		{"BindToExistent", nicIDPtr(321), nil, 321},
		{"UnbindToDevice", nicIDPtr(0), nil, 0},
	}
	for _, testAction := range testActions {
		t.Run(testAction.name, func(t *testing.T) {
			if testAction.setBindToDevice != nil {
				bindToDevice := int32(*testAction.setBindToDevice)
				if gotErr, wantErr := ep.SocketOptions().SetBindToDevice(bindToDevice), testAction.setBindToDeviceError; gotErr != wantErr {
					t.Errorf("got SetSockOpt(&%T(%d)) = %s, want = %s", bindToDevice, bindToDevice, gotErr, wantErr)
				}
			}
			bindToDevice := ep.SocketOptions().GetBindToDevice()
			if bindToDevice != testAction.getBindToDevice {
				t.Errorf("got bindToDevice = %d, want = %d", bindToDevice, testAction.getBindToDevice)
			}
		})
	}
}

func TestBindEphemeralPort(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	if err := c.EP.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("ep.Bind(...) failed: %s", err)
	}
}

func TestBindReservedPort(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
		c.T.Fatalf("Connect failed: %s", err)
	}

	addr, err := c.EP.GetLocalAddress()
	if err != nil {
		t.Fatalf("GetLocalAddress failed: %s", err)
	}

	// We can't bind the address reserved by the connected endpoint above.
	{
		ep, err := c.Stack.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.WQ)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %s", err)
		}
		defer ep.Close()
		{
			err := ep.Bind(addr)
			if _, ok := err.(*tcpip.ErrPortInUse); !ok {
				t.Fatalf("got ep.Bind(...) = %s, want = %s", err, &tcpip.ErrPortInUse{})
			}
		}
	}

	func() {
		ep, err := c.Stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %s", err)
		}
		defer ep.Close()
		// We can't bind ipv4-any on the port reserved by the connected endpoint
		// above, since the endpoint is dual-stack.
		{
			err := ep.Bind(tcpip.FullAddress{Port: addr.Port})
			if _, ok := err.(*tcpip.ErrPortInUse); !ok {
				t.Fatalf("got ep.Bind(...) = %s, want = %s", err, &tcpip.ErrPortInUse{})
			}
		}
		// We can bind an ipv4 address on this port, though.
		if err := ep.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %s", err)
		}
	}()

	// Once the connected endpoint releases its port reservation, we are able to
	// bind ipv4-any once again.
	c.EP.Close()
	func() {
		ep, err := c.Stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %s", err)
		}
		defer ep.Close()
		if err := ep.Bind(tcpip.FullAddress{Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %s", err)
		}
	}()
}

func TestV4ReadOnV6(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpointForFlow(context.UnicastV4in6, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	buf := context.BuildUDPPacket(payload, context.UnicastV4in6, context.Incoming, testTOS, testTTL, false)
	c.InjectPacket(header.IPv4ProtocolNumber, buf)
	c.ReadFromEndpointExpectSuccess(payload, context.UnicastV4in6)
}

func TestV4ReadOnBoundToV4MappedWildcard(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpointForFlow(context.UnicastV4in6, udp.ProtocolNumber)

	// Bind to v4 mapped wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.V4MappedWildcardAddr, Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	testRead(c, context.UnicastV4in6)
}

func TestV4ReadOnBoundToV4Mapped(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpointForFlow(context.UnicastV4in6, udp.ProtocolNumber)

	// Bind to local address.
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV4MappedAddr, Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	testRead(c, context.UnicastV4in6)
}

func TestV6ReadOnV6(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpointForFlow(context.UnicastV6, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	testRead(c, context.UnicastV6)
}

// TestV4ReadSelfSource checks that packets coming from a local IP address are
// correctly dropped when handleLocal is true and not otherwise.
func TestV4ReadSelfSource(t *testing.T) {
	for _, tt := range []struct {
		name              string
		handleLocal       bool
		wantErr           tcpip.Error
		wantInvalidSource uint64
	}{
		{"HandleLocal", false, nil, 0},
		{"NoHandleLocal", true, &tcpip.ErrWouldBlock{}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := context.NewWithOptions(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4}, context.Options{
				MTU:         context.DefaultMTU,
				HandleLocal: tt.handleLocal,
			})
			defer c.Cleanup()

			c.CreateEndpointForFlow(context.UnicastV4, udp.ProtocolNumber)

			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				t.Fatalf("Bind failed: %s", err)
			}

			payload := newRandomPayload(arbitraryPayloadSize)
			h := context.UnicastV4.MakeHeader4Tuple(context.Incoming)
			h.Src = h.Dst
			c.InjectPacket(header.IPv4ProtocolNumber, context.BuildV4UDPPacket(payload, h, testTOS, testTTL, false))

			if got := c.Stack.Stats().IP.InvalidSourceAddressesReceived.Value(); got != tt.wantInvalidSource {
				t.Errorf("c.Stack.Stats().IP.InvalidSourceAddressesReceived got %d, want %d", got, tt.wantInvalidSource)
			}

			if _, err := c.EP.Read(ioutil.Discard, tcpip.ReadOptions{}); err != tt.wantErr {
				t.Errorf("got c.EP.Read = %s, want = %s", err, tt.wantErr)
			}
		})
	}
}

func TestV4ReadOnV4(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpointForFlow(context.UnicastV4, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	testRead(c, context.UnicastV4)
}

// TestReadOnBoundToMulticast checks that an endpoint can bind to a multicast
// address and receive data sent to that address.
func TestReadOnBoundToMulticast(t *testing.T) {
	// FIXME(b/128189410): context.MulticastV4in6 currently doesn't work as
	// AddMembershipOption doesn't handle V4in6 addresses.
	for _, flow := range []context.TestFlow{context.MulticastV4, context.MulticastV6, context.MulticastV6Only} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

			// Bind to multicast address.
			mcastAddr := flow.MapAddrIfApplicable(flow.GetMulticastAddr())
			if err := c.EP.Bind(tcpip.FullAddress{Addr: mcastAddr, Port: context.StackPort}); err != nil {
				c.T.Fatal("Bind failed:", err)
			}

			// Join multicast group.
			ifoptSet := tcpip.AddMembershipOption{NIC: 1, MulticastAddr: mcastAddr}
			if err := c.EP.SetSockOpt(&ifoptSet); err != nil {
				c.T.Fatalf("SetSockOpt(&%#v): %s", ifoptSet, err)
			}

			// Check that we receive multicast packets but not unicast or broadcast
			// ones.
			testRead(c, flow)
			testFailingRead(c, context.Broadcast, false /* expectReadError */)
			testFailingRead(c, context.UnicastV4, false /* expectReadError */)
		})
	}
}

// TestV4ReadOnBoundToBroadcast checks that an endpoint can bind to a broadcast
// address and can receive only broadcast data.
func TestV4ReadOnBoundToBroadcast(t *testing.T) {
	for _, flow := range []context.TestFlow{context.Broadcast, context.BroadcastIn6} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

			// Bind to broadcast address.
			broadcastAddr := flow.MapAddrIfApplicable(context.BroadcastAddr)
			if err := c.EP.Bind(tcpip.FullAddress{Addr: broadcastAddr, Port: context.StackPort}); err != nil {
				c.T.Fatalf("Bind failed: %s", err)
			}

			// Check that we receive broadcast packets but not unicast ones.
			testRead(c, flow)
			testFailingRead(c, context.UnicastV4, false /* expectReadError */)
		})
	}
}

// TestReadFromMulticast checks that an endpoint will NOT receive a packet
// that was sent with multicast SOURCE address.
func TestReadFromMulticast(t *testing.T) {
	for _, flow := range []context.TestFlow{context.ReverseMulticastV4, context.ReverseMulticastV6} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				t.Fatalf("Bind failed: %s", err)
			}
			testFailingRead(c, flow, false /* expectReadError */)
		})
	}
}

// TestV4ReadBroadcastOnBoundToWildcard checks that an endpoint can bind to ANY
// and receive broadcast and unicast data.
func TestV4ReadBroadcastOnBoundToWildcard(t *testing.T) {
	for _, flow := range []context.TestFlow{context.Broadcast, context.BroadcastIn6} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

			// Bind to wildcard.
			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				c.T.Fatalf("Bind failed: %s (", err)
			}

			// Check that we receive both broadcast and unicast packets.
			testRead(c, flow)
			testRead(c, context.UnicastV4)
		})
	}
}

func getEndpointWithPreflight(c *context.Context) tcpip.EndpointWithPreflight {
	epWithPreflight, ok := c.EP.(tcpip.EndpointWithPreflight)

	if !ok {
		c.T.Fatalf("expect endpoint implements tcpip.EndpointWithPreflight; found endpoint with type %T does not", c.EP)
	}
	return epWithPreflight
}

func getWriteOptionsForFlow(flow context.TestFlow) tcpip.WriteOptions {
	h := flow.MakeHeader4Tuple(context.Outgoing)
	writeDstAddr := flow.MapAddrIfApplicable(h.Dst.Addr)
	return tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.Dst.Port},
	}
}

// testWriteFails calls the endpoint's Write method with a packet of the
// given test flow, verifying that the method fails with the provided error
// code.
// TODO(https://gvisor.dev/issue/5623): Extract the test write methods in the
// testing context.
func testWriteFails(c *context.Context, flow context.TestFlow, payloadSize int, wantErr tcpip.Error) {
	c.T.Helper()
	// Take a snapshot of the stats to validate them at the end of the test.
	var epstats tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&epstats)

	var r bytes.Reader
	r.Reset(newRandomPayload(payloadSize))
	_, gotErr := c.EP.Write(&r, getWriteOptionsForFlow(flow))
	c.CheckEndpointWriteStats(1, &epstats, gotErr)
	if gotErr != wantErr {
		c.T.Fatalf("Write returned unexpected error: got %v, want %v", gotErr, wantErr)
	}
}

// testPreflightSucceeds calls the endpoint's Preflight method with a
// destination of the given flow, verifying that it succeeds.
func testPreflightSucceeds(c *context.Context, flow context.TestFlow) {
	c.T.Helper()
	testPreflightImpl(c, flow, true, nil)
}

// testPreflightFails calls the endpoint's Preflight method with a destination
// of the given flow, verifying that it fails with the provided error.
func testPreflightFails(c *context.Context, flow context.TestFlow, wantErr tcpip.Error) {
	c.T.Helper()
	testPreflightImpl(c, flow, true, wantErr)
}

func testPreflightImpl(c *context.Context, flow context.TestFlow, setDest bool, wantErr tcpip.Error) {
	c.T.Helper()
	// Take a snapshot of the stats to validate them at the end of the test.
	var epstats tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&epstats)

	writeOpts := tcpip.WriteOptions{}
	if setDest {
		writeOpts = getWriteOptionsForFlow(flow)
	}

	gotErr := getEndpointWithPreflight(c).Preflight(writeOpts)
	if gotErr != wantErr {
		c.T.Fatalf("Preflight returned unexpected error: got %v, want %v", gotErr, wantErr)
	}

	c.CheckEndpointWriteStats(0, &epstats, gotErr)
}

type writeOperation int

const (
	write writeOperation = iota
	preflight
)

// testWriteOpSequenceSucceeds calls the provided sequence of write operations with a packet of the
// given test flow, verifying that each operation succeeds.
func testWriteOpSequenceSucceeds(c *context.Context, flow context.TestFlow, ops []writeOperation, checkers ...checker.NetworkChecker) {
	c.T.Helper()
	for _, op := range ops {
		switch op {
		case write:
			testWriteSucceedsAndGetReceivedSrcPort(c, flow, checkers...)
		case preflight:
			testPreflightSucceeds(c, flow)
		}
	}
}

// testWriteOpSequenceSucceedsNoDestination calls the provided sequence of write operations with a
// packet of the given test flow, without giving a destination address:port, verifying that each
// operation succeeds.
func testWriteOpSequenceSucceedsNoDestination(c *context.Context, flow context.TestFlow, ops []writeOperation) {
	c.T.Helper()
	for _, op := range ops {
		switch op {
		case write:
			testWriteAndVerifyInternal(c, flow, false /* setDest */)
		case preflight:
			testPreflightImpl(c, flow, false /* setDest */, nil /* wantErr */)
		}
	}
}

// testWriteOpSequenceFails calls the provided sequence of write operations with a packet of the
// given test flow, verifying that each operation fails with the provided err.
func testWriteOpSequenceFails(c *context.Context, flow context.TestFlow, ops []writeOperation, err tcpip.Error) {
	c.T.Helper()
	for _, op := range ops {
		switch op {
		case write:
			testWriteFails(c, flow, arbitraryPayloadSize, err)
		case preflight:
			testPreflightFails(c, flow, err)
		}
	}
}

// testWriteSucceedsAndGetReceivedSrcPort calls the endpoint's Write method with a packet of the
// given test flow and a destination constructed from the flow's destination address:port. It then
// receives the packet from the link endpoint and verifies its correctness using the
// provided checker functions, returning the found source port.
// TODO(https://gvisor.dev/issue/5623): Extract the test write methods in the
// testing context.
func testWriteSucceedsAndGetReceivedSrcPort(c *context.Context, flow context.TestFlow, checkers ...checker.NetworkChecker) uint16 {
	c.T.Helper()
	return testWriteAndVerifyInternal(c, flow, true, checkers...)
}

// TODO(https://gvisor.dev/issue/5623): Extract the test write methods in the
// testing context.
func testWriteNoVerify(c *context.Context, flow context.TestFlow, setDest bool) []byte {
	c.T.Helper()
	// Take a snapshot of the stats to validate them at the end of the test.
	var epstats tcpip.TransportEndpointStats
	c.EP.Stats().(*tcpip.TransportEndpointStats).Clone(&epstats)

	writeOpts := tcpip.WriteOptions{}
	if setDest {
		h := flow.MakeHeader4Tuple(context.Outgoing)
		writeDstAddr := flow.MapAddrIfApplicable(h.Dst.Addr)
		writeOpts = tcpip.WriteOptions{
			To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.Dst.Port},
		}
	}

	var r bytes.Reader
	payload := newRandomPayload(arbitraryPayloadSize)
	r.Reset(payload)
	n, err := c.EP.Write(&r, writeOpts)
	if err != nil {
		c.T.Fatalf("Write failed: %s", err)
	}
	if n != int64(len(payload)) {
		c.T.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}
	c.CheckEndpointWriteStats(1, &epstats, err)
	return payload
}

// TODO(https://gvisor.dev/issue/5623): Extract the test write methods in the
// testing context.
func testWriteAndVerifyInternal(c *context.Context, flow context.TestFlow, setDest bool, checkers ...checker.NetworkChecker) uint16 {
	c.T.Helper()
	payload := testWriteNoVerify(c, flow, setDest)
	// Received the packet and check the payload.

	p := c.LinkEP.Read()
	if p.IsNil() {
		c.T.Fatalf("Packet wasn't written out")
	}
	defer p.DecRef()

	if got, want := p.NetworkProtocolNumber, flow.NetProto(); got != want {
		c.T.Fatalf("got p.NetworkProtocolNumber = %d, want = %d", got, want)
	}

	if got, want := p.TransportProtocolNumber, header.UDPProtocolNumber; got != want {
		c.T.Errorf("got p.TransportProtocolNumber = %d, want = %d", got, want)
	}

	v := p.ToView()
	defer v.Release()

	h := flow.MakeHeader4Tuple(context.Outgoing)
	checkers = append(
		checkers,
		checker.SrcAddr(h.Src.Addr),
		checker.DstAddr(h.Dst.Addr),
		checker.UDP(checker.DstPort(h.Dst.Port)),
	)
	flow.CheckerFn()(c.T, v, checkers...)

	var udpH header.UDP
	if flow.IsV4() {
		udpH = header.IPv4(v.AsSlice()).Payload()
	} else {
		udpH = header.IPv6(v.AsSlice()).Payload()
	}
	if !bytes.Equal(payload, udpH.Payload()) {
		c.T.Fatalf("Bad payload: got %x, want %x", udpH.Payload(), payload)
	}

	return udpH.SourcePort()
}

func testDualWrite(c *context.Context) uint16 {
	c.T.Helper()

	v4Port := testWriteSucceedsAndGetReceivedSrcPort(c, context.UnicastV4in6)
	v6Port := testWriteSucceedsAndGetReceivedSrcPort(c, context.UnicastV6)
	if v4Port != v6Port {
		c.T.Fatalf("expected v4 and v6 ports to be equal: got v4Port = %d, v6Port = %d", v4Port, v6Port)
	}

	return v4Port
}

func TestDualWriteUnbound(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	testDualWrite(c)
}

func TestDualWriteBoundToWildcard(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	p := testDualWrite(c)
	if p != context.StackPort {
		c.T.Fatalf("Bad port: got %v, want %v", p, context.StackPort)
	}
}

func TestDualWriteConnectedToV6(t *testing.T) {
	for _, testCase := range []struct {
		writeOpSequence         []writeOperation
		expectedNoRouteErrCount uint64
	}{
		{writeOpSequence: []writeOperation{write}, expectedNoRouteErrCount: 1},
		{writeOpSequence: []writeOperation{preflight}, expectedNoRouteErrCount: 0},
		{writeOpSequence: []writeOperation{preflight, write}, expectedNoRouteErrCount: 1},
	} {
		c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})

		c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

		// Connect to v6 address.
		if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
			c.T.Fatalf("Bind failed: %s", err)
		}

		testWriteOpSequenceSucceeds(c, context.UnicastV6, testCase.writeOpSequence)

		// Write to V4 mapped address.
		testWriteOpSequenceFails(c, context.UnicastV4in6, testCase.writeOpSequence, &tcpip.ErrNetworkUnreachable{})

		if got := c.EP.Stats().(*tcpip.TransportEndpointStats).SendErrors.NoRoute.Value(); got != testCase.expectedNoRouteErrCount {
			c.T.Fatalf("Endpoint stat not updated. got %d want %d", got, testCase.expectedNoRouteErrCount)
		}
		c.Cleanup()
	}
}

var writeOpSequences = map[string]([]writeOperation){
	"write":           []writeOperation{write},
	"preflight":       []writeOperation{preflight},
	"write|preflight": []writeOperation{preflight, write},
}

func TestDualWriteConnectedToV4Mapped(t *testing.T) {
	for name, writeOpSequence := range writeOpSequences {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

			// Connect to v4 mapped address.
			if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort}); err != nil {
				c.T.Fatalf("Bind failed: %s", err)
			}

			testWriteOpSequenceSucceeds(c, context.UnicastV4in6, writeOpSequence)

			// Write to v6 address.
			testWriteOpSequenceFails(c, context.UnicastV6, writeOpSequence, &tcpip.ErrInvalidEndpointState{})
		})
	}
}

func TestPreflightBindsEndpoint(t *testing.T) {
	protocols := map[string]tcpip.NetworkProtocolNumber{
		"ipv4": ipv4.ProtocolNumber,
		"ipv6": ipv6.ProtocolNumber,
	}
	for name, ipProtocolNumber := range protocols {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol})
			defer c.Cleanup()

			c.CreateEndpoint(ipProtocolNumber, udp.ProtocolNumber)

			flow := context.UnicastV6
			h := flow.MakeHeader4Tuple(context.Outgoing)
			writeDstAddr := flow.MapAddrIfApplicable(h.Dst.Addr)
			writeOpts := tcpip.WriteOptions{
				To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.Dst.Port},
			}

			if err := getEndpointWithPreflight(c).Preflight(writeOpts); err != nil {
				c.T.Fatalf("Preflight failed: %s", err)
			}

			if c.EP.State() != uint32(transport.DatagramEndpointStateBound) {
				c.T.Fatalf("Expect UDP endpoint in state %d, found %d", transport.DatagramEndpointStateBound, c.EP.State())
			}
		})
	}
}

func TestV4WriteOnV6Only(t *testing.T) {
	for name, writeOpSequence := range writeOpSequences {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpointForFlow(context.UnicastV6Only, udp.ProtocolNumber)

			// Write to V4 mapped address.
			testWriteOpSequenceFails(c, context.UnicastV4in6, writeOpSequence, &tcpip.ErrHostUnreachable{})
		})
	}
}

func TestV6WriteOnBoundToV4Mapped(t *testing.T) {
	for name, writeOpSequence := range writeOpSequences {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

			// Bind to v4 mapped address.
			if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackV4MappedAddr, Port: context.StackPort}); err != nil {
				c.T.Fatalf("Bind failed: %s", err)
			}

			// Write to v6 address.
			testWriteOpSequenceFails(c, context.UnicastV6, writeOpSequence, &tcpip.ErrInvalidEndpointState{})
		})
	}
}

func TestV6WriteOnConnected(t *testing.T) {
	for name, writeOpSequence := range writeOpSequences {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

			// Connect to v6 address.
			if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
				c.T.Fatalf("Connect failed: %s", err)
			}

			testWriteOpSequenceSucceedsNoDestination(c, context.UnicastV6, writeOpSequence)
		})
	}
}

func TestV4WriteOnConnected(t *testing.T) {
	for name, writeOpSequence := range writeOpSequences {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

			// Connect to v4 mapped address.
			if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort}); err != nil {
				c.T.Fatalf("Connect failed: %s", err)
			}

			testWriteOpSequenceSucceedsNoDestination(c, context.UnicastV4, writeOpSequence)
		})
	}
}

func TestWriteOnConnectedInvalidPort(t *testing.T) {
	const invalidPort = 8192
	protocols := map[string]tcpip.NetworkProtocolNumber{
		"ipv4": ipv4.ProtocolNumber,
		"ipv6": ipv6.ProtocolNumber,
	}
	for name, proto := range protocols {
		t.Run(name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(proto, udp.ProtocolNumber)
			if err := c.EP.Connect(tcpip.FullAddress{Addr: context.StackAddr, Port: invalidPort}); err != nil {
				c.T.Fatalf("Connect failed: %s", err)
			}
			writeOpts := tcpip.WriteOptions{
				To: &tcpip.FullAddress{Addr: context.StackAddr, Port: invalidPort},
			}
			var r bytes.Reader
			payload := newRandomPayload(arbitraryPayloadSize)
			r.Reset(payload)
			n, err := c.EP.Write(&r, writeOpts)
			if err != nil {
				c.T.Fatalf("c.EP.Write(...) = %s, want nil", err)
			}
			if got, want := n, int64(len(payload)); got != want {
				c.T.Fatalf("c.EP.Write(...) wrote %d bytes, want %d bytes", got, want)
			}

			{
				err := c.EP.LastError()
				if _, ok := err.(*tcpip.ErrConnectionRefused); !ok {
					c.T.Fatalf("expected c.EP.LastError() == ErrConnectionRefused, got: %+v", err)
				}
			}
		})
	}
}

// TestWriteOnBoundToV4Multicast checks that we can send packets out of a socket
// that is bound to a V4 multicast address.
func TestWriteOnBoundToV4Multicast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4, context.MulticastV4, context.Broadcast} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V4 mcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.MulticastAddr, Port: context.StackPort}); err != nil {
					c.T.Fatal("Bind failed:", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

// TestWriteOnBoundToV4MappedMulticast checks that we can send packets out of a
// socket that is bound to a V4-mapped multicast address.
func TestWriteOnBoundToV4MappedMulticast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4in6, context.MulticastV4in6, context.BroadcastIn6} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V4Mapped mcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.MulticastV4MappedAddr, Port: context.StackPort}); err != nil {
					c.T.Fatalf("Bind failed: %s", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

// TestWriteOnBoundToV6Multicast checks that we can send packets out of a
// socket that is bound to a V6 multicast address.
func TestWriteOnBoundToV6Multicast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV6, context.MulticastV6} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V6 mcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.MulticastV6Addr, Port: context.StackPort}); err != nil {
					c.T.Fatalf("Bind failed: %s", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

// TestWriteOnBoundToV6Multicast checks that we can send packets out of a
// V6-only socket that is bound to a V6 multicast address.
func TestWriteOnBoundToV6OnlyMulticast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV6Only, context.MulticastV6Only} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V6 mcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.MulticastV6Addr, Port: context.StackPort}); err != nil {
					c.T.Fatalf("Bind failed: %s", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

// TestWriteOnBoundToBroadcast checks that we can send packets out of a
// socket that is bound to the broadcast address.
func TestWriteOnBoundToBroadcast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4, context.MulticastV4, context.Broadcast} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V4 broadcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.BroadcastAddr, Port: context.StackPort}); err != nil {
					c.T.Fatal("Bind failed:", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

// TestWriteOnBoundToV4MappedBroadcast checks that we can send packets out of a
// socket that is bound to the V4-mapped broadcast address.
func TestWriteOnBoundToV4MappedBroadcast(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4in6, context.MulticastV4in6, context.BroadcastIn6} {
			t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Bind to V4Mapped mcast address.
				if err := c.EP.Bind(tcpip.FullAddress{Addr: context.BroadcastV4MappedAddr, Port: context.StackPort}); err != nil {
					c.T.Fatalf("Bind failed: %s", err)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence)
			})
		}
	}
}

func TestReadIncrementsPacketsReceived(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	// Create IPv4 UDP endpoint
	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	testRead(c, context.UnicastV4)

	var want uint64 = 1
	if got := c.Stack.Stats().UDP.PacketsReceived.Value(); got != want {
		c.T.Fatalf("Read did not increment PacketsReceived: got %v, want %v", got, want)
	}
}

func TestReadRecvOriginalDstAddr(t *testing.T) {
	tests := []struct {
		name                    string
		proto                   tcpip.NetworkProtocolNumber
		flow                    context.TestFlow
		expectedOriginalDstAddr tcpip.FullAddress
	}{
		{
			name:                    "IPv4 unicast",
			proto:                   header.IPv4ProtocolNumber,
			flow:                    context.UnicastV4,
			expectedOriginalDstAddr: tcpip.FullAddress{NIC: context.NICID, Addr: context.StackAddr, Port: context.StackPort},
		},
		{
			name:  "IPv4 multicast",
			proto: header.IPv4ProtocolNumber,
			flow:  context.MulticastV4,
			// This should actually be a unicast address assigned to the interface.
			//
			// TODO(gvisor.dev/issue/3556): This check is validating incorrect
			// behaviour. We still include the test so that once the bug is resolved,
			// this test will start to fail and the individual tasked with fixing this
			// bug knows to also fix this test :).
			expectedOriginalDstAddr: tcpip.FullAddress{NIC: context.NICID, Addr: context.MulticastAddr, Port: context.StackPort},
		},
		{
			name:  "IPv4 broadcast",
			proto: header.IPv4ProtocolNumber,
			flow:  context.Broadcast,
			// This should actually be a unicast address assigned to the interface.
			//
			// TODO(gvisor.dev/issue/3556): This check is validating incorrect
			// behaviour. We still include the test so that once the bug is resolved,
			// this test will start to fail and the individual tasked with fixing this
			// bug knows to also fix this test :).
			expectedOriginalDstAddr: tcpip.FullAddress{NIC: context.NICID, Addr: context.BroadcastAddr, Port: context.StackPort},
		},
		{
			name:                    "IPv6 unicast",
			proto:                   header.IPv6ProtocolNumber,
			flow:                    context.UnicastV6,
			expectedOriginalDstAddr: tcpip.FullAddress{NIC: context.NICID, Addr: context.StackV6Addr, Port: context.StackPort},
		},
		{
			name:  "IPv6 multicast",
			proto: header.IPv6ProtocolNumber,
			flow:  context.MulticastV6,
			// This should actually be a unicast address assigned to the interface.
			//
			// TODO(gvisor.dev/issue/3556): This check is validating incorrect
			// behaviour. We still include the test so that once the bug is resolved,
			// this test will start to fail and the individual tasked with fixing this
			// bug knows to also fix this test :).
			expectedOriginalDstAddr: tcpip.FullAddress{NIC: context.NICID, Addr: context.MulticastV6Addr, Port: context.StackPort},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(test.proto, udp.ProtocolNumber)

			bindAddr := tcpip.FullAddress{Port: context.StackPort}
			if err := c.EP.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%#v): %s", bindAddr, err)
			}

			if test.flow.IsMulticast() {
				ifoptSet := tcpip.AddMembershipOption{NIC: context.NICID, MulticastAddr: test.flow.GetMulticastAddr()}
				if err := c.EP.SetSockOpt(&ifoptSet); err != nil {
					c.T.Fatalf("SetSockOpt(&%#v): %s:", ifoptSet, err)
				}
			}

			c.EP.SocketOptions().SetReceiveOriginalDstAddress(true)

			testRead(c, test.flow, checker.ReceiveOriginalDstAddr(test.expectedOriginalDstAddr))

			if got := c.Stack.Stats().UDP.PacketsReceived.Value(); got != 1 {
				t.Fatalf("Read did not increment PacketsReceived: got = %d, want = 1", got)
			}
		})
	}
}

func TestWriteIncrementsPacketsSent(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	testDualWrite(c)

	var want uint64 = 2
	if got := c.Stack.Stats().UDP.PacketsSent.Value(); got != want {
		c.T.Fatalf("Write did not increment PacketsSent: got %v, want %v", got, want)
	}
}

func TestNoChecksum(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV6} {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				// Disable the checksum generation.
				c.EP.SocketOptions().SetNoChecksum(true)
				// This option is effective on IPv4 only.
				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.UDP(checker.NoChecksum(flow.IsV4())))

				// Enable the checksum generation.
				c.EP.SocketOptions().SetNoChecksum(false)
				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.UDP(checker.NoChecksum(false)))
			})
		}
	}
}

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	stack.NetworkInterface
}

func (*testInterface) ID() tcpip.NICID {
	return 0
}

func (*testInterface) Enabled() bool {
	return true
}

func TestDefaultTTL(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV4in6, context.UnicastV6, context.UnicastV6Only, context.Broadcast, context.BroadcastIn6} {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)
				proto := c.Stack.NetworkProtocolInstance(flow.NetProto())
				if proto == nil {
					t.Fatalf("c.Stack.NetworkProtocolInstance(flow.NetProto()) did not return a protocol")
				}

				var initialDefaultTTL tcpip.DefaultTTLOption
				if err := proto.Option(&initialDefaultTTL); err != nil {
					t.Fatalf("proto.Option(&initialDefaultTTL) (%T) failed: %s", initialDefaultTTL, err)
				}
				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TTL(uint8(initialDefaultTTL)))

				newDefaultTTL := tcpip.DefaultTTLOption(initialDefaultTTL + 1)
				if err := proto.SetOption(&newDefaultTTL); err != nil {
					c.T.Fatalf("proto.SetOption(&%T(%d))) failed: %s", newDefaultTTL, newDefaultTTL, err)
				}
				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TTL(uint8(newDefaultTTL)))
			})
		}
	}
}

func TestSetNonMulticastTTL(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV4in6, context.UnicastV6, context.UnicastV6Only, context.Broadcast, context.BroadcastIn6} {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				for _, wantTTL := range []uint8{1, 2, 50, 64, 128, 254, 255} {
					t.Run(fmt.Sprintf("TTL:%d", wantTTL), func(t *testing.T) {
						c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
						defer c.Cleanup()

						c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

						var relevantOpt tcpip.SockOptInt
						var irrelevantOpt tcpip.SockOptInt
						if flow.IsV4() {
							relevantOpt = tcpip.IPv4TTLOption
							irrelevantOpt = tcpip.IPv6HopLimitOption
						} else {
							relevantOpt = tcpip.IPv6HopLimitOption
							irrelevantOpt = tcpip.IPv4TTLOption
						}
						if err := c.EP.SetSockOptInt(relevantOpt, int(wantTTL)); err != nil {
							c.T.Fatalf("SetSockOptInt(%d, %d) failed: %s", relevantOpt, wantTTL, err)
						}
						// Set a different ttl/hoplimit for the unused protocol, showing that
						// it does not affect the other protocol.
						if err := c.EP.SetSockOptInt(irrelevantOpt, int(wantTTL+1)); err != nil {
							c.T.Fatalf("SetSockOptInt(%d, %d) failed: %s", irrelevantOpt, wantTTL, err)
						}

						testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TTL(wantTTL))
					})
				}
			})
		}
	}
}

func TestSetMulticastTTL(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range []context.TestFlow{context.MulticastV4, context.MulticastV4in6, context.MulticastV6} {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				for _, wantTTL := range []uint8{1, 2, 50, 64, 128, 254, 255} {
					t.Run(fmt.Sprintf("TTL:%d", wantTTL), func(t *testing.T) {
						c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
						defer c.Cleanup()

						c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

						if err := c.EP.SetSockOptInt(tcpip.MulticastTTLOption, int(wantTTL)); err != nil {
							c.T.Fatalf("SetSockOptInt failed: %s", err)
						}

						testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TTL(wantTTL))
					})
				}
			})
		}
	}
}

var v4PacketFlows = [...]context.TestFlow{context.UnicastV4, context.MulticastV4, context.Broadcast, context.UnicastV4in6, context.MulticastV4in6, context.BroadcastIn6}

func TestSetTOS(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range v4PacketFlows {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				const tos = testTOS
				v, err := c.EP.GetSockOptInt(tcpip.IPv4TOSOption)
				if err != nil {
					c.T.Errorf("GetSockOptInt(IPv4TOSOption) failed: %s", err)
				}
				// Test for expected default value.
				if v != 0 {
					c.T.Errorf("got GetSockOptInt(IPv4TOSOption) = 0x%x, want = 0x%x", v, 0)
				}

				if err := c.EP.SetSockOptInt(tcpip.IPv4TOSOption, tos); err != nil {
					c.T.Errorf("SetSockOptInt(IPv4TOSOption, 0x%x) failed: %s", tos, err)
				}

				v, err = c.EP.GetSockOptInt(tcpip.IPv4TOSOption)
				if err != nil {
					c.T.Errorf("GetSockOptInt(IPv4TOSOption) failed: %s", err)
				}

				if v != tos {
					c.T.Errorf("got GetSockOptInt(IPv4TOSOption) = 0x%x, want = 0x%x", v, tos)
				}

				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TOS(tos, 0))
			})
		}
	}
}

var v6PacketFlows = [...]context.TestFlow{context.UnicastV6, context.UnicastV6Only, context.MulticastV6}

func TestSetTClass(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		for _, flow := range v6PacketFlows {
			t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
				c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
				defer c.Cleanup()

				c.CreateEndpointForFlow(flow, udp.ProtocolNumber)

				const tClass = testTOS
				v, err := c.EP.GetSockOptInt(tcpip.IPv6TrafficClassOption)
				if err != nil {
					c.T.Errorf("GetSockOptInt(IPv6TrafficClassOption) failed: %s", err)
				}
				// Test for expected default value.
				if v != 0 {
					c.T.Errorf("got GetSockOptInt(IPv6TrafficClassOption) = 0x%x, want = 0x%x", v, 0)
				}

				if err := c.EP.SetSockOptInt(tcpip.IPv6TrafficClassOption, tClass); err != nil {
					c.T.Errorf("SetSockOptInt(IPv6TrafficClassOption, 0x%x) failed: %s", tClass, err)
				}

				v, err = c.EP.GetSockOptInt(tcpip.IPv6TrafficClassOption)
				if err != nil {
					c.T.Errorf("GetSockOptInt(IPv6TrafficClassOption) failed: %s", err)
				}

				if v != tClass {
					c.T.Errorf("got GetSockOptInt(IPv6TrafficClassOption) = 0x%x, want = 0x%x", v, tClass)
				}

				// The header getter for TClass is called TOS, so use that checker.
				testWriteOpSequenceSucceeds(c, flow, writeOpSequence, checker.TOS(tClass, 0))
			})
		}
	}
}

func TestReceiveControlMessage(t *testing.T) {
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
					name:             "PacketInfo",
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
							LocalAddr:       h.Dst.Addr,
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
					c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol})
					defer c.Cleanup()

					c.CreateEndpointForFlow(flow, udp.ProtocolNumber)
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

					payload := newRandomPayload(arbitraryPayloadSize)
					buf := context.BuildUDPPacket(payload, flow, context.Incoming, testTOS, testTTL, false)

					if test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = true, want = false")
					}

					test.setReceiveOption(c.EP, true)
					if !test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = false, want = true")
					}

					c.InjectPacket(flow.NetProto(), buf)
					if flow.NetProto() == test.optionProtocol {
						c.ReadFromEndpointExpectSuccess(payload, flow, test.presenceChecker)
					} else {
						c.ReadFromEndpointExpectSuccess(payload, flow, test.absenceChecker)
					}
				})
			}
		})
	}
}

func TestMulticastInterfaceOption(t *testing.T) {
	for _, flow := range []context.TestFlow{context.MulticastV4, context.MulticastV4in6, context.MulticastV6, context.MulticastV6Only} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			for _, bindTyp := range []string{"bound", "unbound"} {
				t.Run(bindTyp, func(t *testing.T) {
					for _, optTyp := range []string{"use local-addr", "use NICID", "use local-addr and NIC"} {
						t.Run(optTyp, func(t *testing.T) {
							h := flow.MakeHeader4Tuple(context.Outgoing)
							mcastAddr := h.Dst.Addr
							localIfAddr := h.Src.Addr

							var ifoptSet tcpip.MulticastInterfaceOption
							switch optTyp {
							case "use local-addr":
								ifoptSet.InterfaceAddr = localIfAddr
							case "use NICID":
								ifoptSet.NIC = 1
							case "use local-addr and NIC":
								ifoptSet.InterfaceAddr = localIfAddr
								ifoptSet.NIC = 1
							default:
								t.Fatal("unknown test variant")
							}

							c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
							defer c.Cleanup()

							c.CreateEndpoint(flow.SockProto(), udp.ProtocolNumber)

							if bindTyp == "bound" {
								// Bind the socket by connecting to the multicast address.
								// This may have an influence on how the multicast interface
								// is set.
								addr := tcpip.FullAddress{
									Addr: flow.MapAddrIfApplicable(mcastAddr),
									Port: context.StackPort,
								}
								if err := c.EP.Connect(addr); err != nil {
									c.T.Fatalf("Connect failed: %s", err)
								}
							}

							if err := c.EP.SetSockOpt(&ifoptSet); err != nil {
								c.T.Fatalf("SetSockOpt(&%#v): %s", ifoptSet, err)
							}

							// Verify multicast interface addr and NIC were set correctly.
							// Note that NIC must be 1 since this is our outgoing interface.
							var ifoptGot tcpip.MulticastInterfaceOption
							if err := c.EP.GetSockOpt(&ifoptGot); err != nil {
								c.T.Fatalf("GetSockOpt(&%T): %s", ifoptGot, err)
							} else if ifoptWant := (tcpip.MulticastInterfaceOption{NIC: 1, InterfaceAddr: ifoptSet.InterfaceAddr}); ifoptGot != ifoptWant {
								c.T.Errorf("got multicast interface option = %#v, want = %#v", ifoptGot, ifoptWant)
							}
						})
					}
				})
			}
		})
	}
}

// TestV4UnknownDestination verifies that we generate an ICMPv4 Destination
// Unreachable message when a udp datagram is received on ports for which there
// is no bound udp socket.
func TestV4UnknownDestination(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	testCases := []struct {
		flow         context.TestFlow
		icmpRequired bool
		// largePayload if true, will result in a payload large enough
		// so that the final generated IPv4 packet is larger than
		// header.IPv4MinimumProcessableDatagramSize.
		largePayload bool
		// badChecksum if true, will set an invalid checksum in the
		// header.
		badChecksum bool
	}{
		{context.UnicastV4, true, false, false},
		{context.UnicastV4, true, true, false},
		{context.UnicastV4, false, false, true},
		{context.UnicastV4, false, true, true},
		{context.MulticastV4, false, false, false},
		{context.MulticastV4, false, true, false},
		{context.Broadcast, false, false, false},
		{context.Broadcast, false, true, false},
	}
	checksumErrors := uint64(0)
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("flow:%s icmpRequired:%t largePayload:%t badChecksum:%t", tc.flow, tc.icmpRequired, tc.largePayload, tc.badChecksum), func(t *testing.T) {
			payloadSize := arbitraryPayloadSize
			if tc.largePayload {
				payloadSize += header.IPv4MinimumProcessableDatagramSize
			}
			payload := newRandomPayload(payloadSize)
			c.InjectPacket(tc.flow.NetProto(), context.BuildUDPPacket(payload, tc.flow, context.Incoming, testTOS, testTTL, tc.badChecksum))
			if tc.badChecksum {
				checksumErrors++
				if got, want := c.Stack.Stats().UDP.ChecksumErrors.Value(), checksumErrors; got != want {
					t.Fatalf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
				}
			}
			if !tc.icmpRequired {
				if p := c.LinkEP.Read(); !p.IsNil() {
					t.Fatalf("unexpected packet received: %+v", p)
				}
				return
			}

			// ICMP required.
			p := c.LinkEP.Read()
			if p.IsNil() {
				t.Fatalf("packet wasn't written out")
			}

			buf := p.ToBuffer()
			defer buf.Release()
			p.DecRef()
			pkt := buf.Flatten()
			if got, want := len(pkt), header.IPv4MinimumProcessableDatagramSize; got > want {
				t.Fatalf("got an ICMP packet of size: %d, want: sz <= %d", got, want)
			}

			hdr := bufferv2.NewViewWithData(pkt)
			defer hdr.Release()
			checker.IPv4(t, hdr, checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4DstUnreachable),
				checker.ICMPv4Code(header.ICMPv4PortUnreachable)))

			// We need to compare the included data part of the UDP packet that is in
			// the ICMP packet with the matching original data.
			icmpPkt := header.ICMPv4(header.IPv4(hdr.AsSlice()).Payload())
			payloadIPHeader := header.IPv4(icmpPkt.Payload())
			incomingHeaderLength := header.IPv4MinimumSize + header.UDPMinimumSize
			wantLen := len(payload)
			if tc.largePayload {
				// To work out the data size we need to simulate what the sender would
				// have done. The wanted size is the total available minus the sum of
				// the headers in the UDP AND ICMP packets, given that we know the test
				// had only a minimal IP header but the ICMP sender will have allowed
				// for a maximally sized packet header.
				wantLen = header.IPv4MinimumProcessableDatagramSize - header.IPv4MaximumHeaderSize - header.ICMPv4MinimumSize - incomingHeaderLength
			}

			// In the case of large payloads the IP packet may be truncated. Update
			// the length field before retrieving the udp datagram payload.
			// Add back the two headers within the payload.
			payloadIPHeader.SetTotalLength(uint16(wantLen + incomingHeaderLength))

			origDgram := header.UDP(payloadIPHeader.Payload())
			if got, want := len(origDgram.Payload()), wantLen; got != want {
				t.Fatalf("unexpected payload length got: %d, want: %d", got, want)
			}
			if got, want := origDgram.Payload(), payload[:wantLen]; !bytes.Equal(got, want) {
				t.Fatalf("unexpected payload got: %d, want: %d", got, want)
			}
		})
	}
}

// TestV6UnknownDestination verifies that we generate an ICMPv6 Destination
// Unreachable message when a udp datagram is received on ports for which there
// is no bound udp socket.
func TestV6UnknownDestination(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	testCases := []struct {
		flow         context.TestFlow
		icmpRequired bool
		// largePayload if true will result in a payload large enough to
		// create an IPv6 packet > header.IPv6MinimumMTU bytes.
		largePayload bool
		// badChecksum if true, will set an invalid checksum in the
		// header.
		badChecksum bool
	}{
		{context.UnicastV6, true, false, false},
		{context.UnicastV6, true, true, false},
		{context.UnicastV6, false, false, true},
		{context.UnicastV6, false, true, true},
		{context.MulticastV6, false, false, false},
		{context.MulticastV6, false, true, false},
	}
	checksumErrors := uint64(0)
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("flow:%s icmpRequired:%t largePayload:%t badChecksum:%t", tc.flow, tc.icmpRequired, tc.largePayload, tc.badChecksum), func(t *testing.T) {
			payloadSize := arbitraryPayloadSize
			if tc.largePayload {
				payloadSize += header.IPv6MinimumMTU
			}
			payload := newRandomPayload(payloadSize)
			c.InjectPacket(tc.flow.NetProto(), context.BuildUDPPacket(payload, tc.flow, context.Incoming, testTOS, testTTL, tc.badChecksum))
			if tc.badChecksum {
				checksumErrors++
				if got, want := c.Stack.Stats().UDP.ChecksumErrors.Value(), checksumErrors; got != want {
					t.Fatalf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
				}
			}
			if !tc.icmpRequired {
				if p := c.LinkEP.Read(); !p.IsNil() {
					t.Fatalf("unexpected packet received: %+v", p)
				}
				return
			}

			// ICMP required.
			p := c.LinkEP.Read()
			if p.IsNil() {
				t.Fatalf("packet wasn't written out")
			}

			buf := p.ToBuffer()
			defer buf.Release()
			p.DecRef()
			pkt := buf.Flatten()
			if got, want := len(pkt), header.IPv6MinimumMTU; got > want {
				t.Fatalf("got an ICMP packet of size: %d, want: sz <= %d", got, want)
			}

			hdr := bufferv2.NewViewWithData(pkt)
			defer hdr.Release()
			checker.IPv6(t, hdr, checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6DstUnreachable),
				checker.ICMPv6Code(header.ICMPv6PortUnreachable)))

			icmpPkt := header.ICMPv6(header.IPv6(hdr.AsSlice()).Payload())
			payloadIPHeader := header.IPv6(icmpPkt.Payload())
			wantLen := len(payload)
			if tc.largePayload {
				wantLen = header.IPv6MinimumMTU - header.IPv6MinimumSize*2 - header.ICMPv6MinimumSize - header.UDPMinimumSize
			}
			// In case of large payloads the IP packet may be truncated. Update
			// the length field before retrieving the udp datagram payload.
			payloadIPHeader.SetPayloadLength(uint16(wantLen + header.UDPMinimumSize))

			origDgram := header.UDP(payloadIPHeader.Payload())
			if got, want := len(origDgram.Payload()), wantLen; got != want {
				t.Fatalf("unexpected payload length got: %d, want: %d", got, want)
			}
			if got, want := origDgram.Payload(), payload[:wantLen]; !bytes.Equal(got, want) {
				t.Fatalf("unexpected payload got: %v, want: %v", got, want)
			}
		})
	}
}

// TestIncrementMalformedPacketsReceived verifies if the malformed received
// global and endpoint stats are incremented.
func TestIncrementMalformedPacketsReceived(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	h := context.UnicastV6.MakeHeader4Tuple(context.Incoming)
	buf := context.BuildV6UDPPacket(payload, h, testTOS, testTTL, false)

	// Invalidate the UDP header length field.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.SetLength(u.Length() + 1)
	c.InjectPacket(header.IPv6ProtocolNumber, buf)

	const want = 1
	if got := c.Stack.Stats().UDP.MalformedPacketsReceived.Value(); got != want {
		t.Errorf("got stats.UDP.MalformedPacketsReceived.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.MalformedPacketsReceived.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.MalformedPacketsReceived stats = %d, want = %d", got, want)
	}
}

// TestShortHeader verifies that when a packet with a too-short UDP header is
// received, the malformed received global stat gets incremented.
func TestShortHeader(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	h := context.UnicastV6.MakeHeader4Tuple(context.Incoming)

	// Allocate a buffer for an IPv6 and too-short UDP header.
	const udpSize = header.UDPMinimumSize - 1
	buf := make([]byte, header.IPv6MinimumSize+udpSize)
	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		TrafficClass:      testTOS,
		PayloadLength:     uint16(udpSize),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          testTTL,
		SrcAddr:           h.Src.Addr,
		DstAddr:           h.Dst.Addr,
	})

	// Initialize the UDP header.
	udpHdr := header.UDP(make([]byte, header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: h.Src.Port,
		DstPort: h.Dst.Port,
		Length:  header.UDPMinimumSize,
	})
	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, h.Src.Addr, h.Dst.Addr, uint16(len(udpHdr)))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	// Copy all but the last byte of the UDP header into the packet.
	copy(buf[header.IPv6MinimumSize:], udpHdr)

	// Inject packet.
	c.InjectPacket(header.IPv6ProtocolNumber, buf)

	if got, want := c.Stack.Stats().NICs.MalformedL4RcvdPackets.Value(), uint64(1); got != want {
		t.Errorf("got c.Stack.Stats().NIC.MalformedL4RcvdPackets.Value() = %d, want = %d", got, want)
	}
}

// TestBadChecksumErrors verifies if a checksum error is detected,
// global and endpoint stats are incremented.
func TestBadChecksumErrors(t *testing.T) {
	for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV6} {
		t.Run(flow.String(), func(t *testing.T) {
			c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
			defer c.Cleanup()

			c.CreateEndpoint(flow.SockProto(), udp.ProtocolNumber)
			// Bind to wildcard.
			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				c.T.Fatalf("Bind failed: %s", err)
			}

			c.InjectPacket(flow.NetProto(), context.BuildUDPPacket(newRandomPayload(arbitraryPayloadSize), flow, context.Incoming, testTOS, testTTL, true))

			const want = 1
			if got := c.Stack.Stats().UDP.ChecksumErrors.Value(); got != want {
				t.Errorf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
			}
			if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ChecksumErrors.Value(); got != want {
				t.Errorf("got EP Stats.ReceiveErrors.ChecksumErrors stats = %d, want = %d", got, want)
			}
		})
	}
}

// TestPayloadModifiedV4 verifies if a checksum error is detected,
// global and endpoint stats are incremented.
func TestPayloadModifiedV4(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv4.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	h := context.UnicastV4.MakeHeader4Tuple(context.Incoming)
	buf := context.BuildV4UDPPacket(payload, h, testTOS, testTTL, false)
	// Modify the payload so that the checksum value in the UDP header will be
	// incorrect.
	buf[len(buf)-1]++
	c.InjectPacket(header.IPv4ProtocolNumber, buf)

	const want = 1
	if got := c.Stack.Stats().UDP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ChecksumErrors.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.ChecksumErrors stats = %d, want = %d", got, want)
	}
}

// TestPayloadModifiedV6 verifies if a checksum error is detected,
// global and endpoint stats are incremented.
func TestPayloadModifiedV6(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	h := context.UnicastV6.MakeHeader4Tuple(context.Incoming)
	buf := context.BuildV6UDPPacket(payload, h, testTOS, testTTL, false)
	// Modify the payload so that the checksum value in the UDP header will be
	// incorrect.
	buf[len(buf)-1]++
	c.InjectPacket(header.IPv6ProtocolNumber, buf)

	const want = 1
	if got := c.Stack.Stats().UDP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ChecksumErrors.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.ChecksumErrors stats = %d, want = %d", got, want)
	}
}

// TestChecksumZeroV4 verifies if the checksum value is zero, global and
// endpoint states are *not* incremented (UDP checksum is optional on IPv4).
func TestChecksumZeroV4(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv4.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	h := context.UnicastV4.MakeHeader4Tuple(context.Incoming)
	buf := context.BuildV4UDPPacket(payload, h, testTOS, testTTL, false)
	// Set the checksum field in the UDP header to zero.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.SetChecksum(0)
	c.InjectPacket(header.IPv4ProtocolNumber, buf)

	const want = 0
	if got := c.Stack.Stats().UDP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ChecksumErrors.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.ChecksumErrors stats = %d, want = %d", got, want)
	}
}

// TestChecksumZeroV6 verifies if the checksum value is zero, global and
// endpoint states are incremented (UDP checksum is *not* optional on IPv6).
func TestChecksumZeroV6(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)
	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	payload := newRandomPayload(arbitraryPayloadSize)
	h := context.UnicastV6.MakeHeader4Tuple(context.Incoming)
	buf := context.BuildV6UDPPacket(payload, h, testTOS, testTTL, false)
	// Set the checksum field in the UDP header to zero.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.SetChecksum(0)
	c.InjectPacket(header.IPv6ProtocolNumber, buf)

	const want = 1
	if got := c.Stack.Stats().UDP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.UDP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ChecksumErrors.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.ChecksumErrors stats = %d, want = %d", got, want)
	}
}

// TestShutdownRead verifies endpoint read shutdown and error
// stats increment on packet receive.
func TestShutdownRead(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		c.T.Fatalf("Bind failed: %s", err)
	}

	if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
		c.T.Fatalf("Connect failed: %s", err)
	}

	if err := c.EP.Shutdown(tcpip.ShutdownRead); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	testFailingRead(c, context.UnicastV6, true /* expectReadError */)

	var want uint64 = 1
	if got := c.Stack.Stats().UDP.ReceiveBufferErrors.Value(); got != want {
		t.Errorf("got stats.UDP.ReceiveBufferErrors.Value() = %v, want = %v", got, want)
	}
	if got := c.EP.Stats().(*tcpip.TransportEndpointStats).ReceiveErrors.ClosedReceiver.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.ClosedReceiver stats = %v, want = %v", got, want)
	}
}

// TestShutdownWrite verifies endpoint write shutdown and error
// stats increment on packet write.
func TestShutdownWrite(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})

		c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

		if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
			c.T.Fatalf("Connect failed: %s", err)
		}

		if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
			t.Fatalf("Shutdown failed: %s", err)
		}

		testWriteOpSequenceFails(c, context.UnicastV6, writeOpSequence, &tcpip.ErrClosedForSend{})
		c.Cleanup()
	}
}

func TestOutgoingSubnetBroadcast(t *testing.T) {
	const nicID1 = 1

	ipv4Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x3a")),
		PrefixLen: 24,
	}
	ipv4Subnet := ipv4Addr.Subnet()
	ipv4SubnetBcast := ipv4Subnet.Broadcast()
	ipv4Gateway := testutil.MustParse4("192.168.1.1")
	ipv4AddrPrefix31 := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x3a")),
		PrefixLen: 31,
	}
	ipv4Subnet31 := ipv4AddrPrefix31.Subnet()
	ipv4Subnet31Bcast := ipv4Subnet31.Broadcast()
	ipv4AddrPrefix32 := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x3a")),
		PrefixLen: 32,
	}
	ipv4Subnet32 := ipv4AddrPrefix32.Subnet()
	ipv4Subnet32Bcast := ipv4Subnet32.Broadcast()
	ipv6Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\x20\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
		PrefixLen: 64,
	}
	ipv6Subnet := ipv6Addr.Subnet()
	ipv6SubnetBcast := ipv6Subnet.Broadcast()
	remNetAddr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\x64\x0a\x7b\x18")),
		PrefixLen: 24,
	}
	remNetSubnet := remNetAddr.Subnet()
	remNetSubnetBcast := remNetSubnet.Broadcast()

	tests := []struct {
		name                 string
		nicAddr              tcpip.ProtocolAddress
		routes               []tcpip.Route
		remoteAddr           tcpip.Address
		requiresBroadcastOpt bool
	}{
		{
			name: "IPv4 Broadcast to local subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet,
					NIC:         nicID1,
				},
			},
			remoteAddr:           ipv4SubnetBcast,
			requiresBroadcastOpt: true,
		},
		{
			name: "IPv4 Broadcast to local /31 subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4AddrPrefix31,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet31,
					NIC:         nicID1,
				},
			},
			remoteAddr:           ipv4Subnet31Bcast,
			requiresBroadcastOpt: false,
		},
		{
			name: "IPv4 Broadcast to local /32 subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4AddrPrefix32,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet32,
					NIC:         nicID1,
				},
			},
			remoteAddr:           ipv4Subnet32Bcast,
			requiresBroadcastOpt: false,
		},
		// IPv6 has no notion of a broadcast.
		{
			name: "IPv6 'Broadcast' to local subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: ipv6Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv6Subnet,
					NIC:         nicID1,
				},
			},
			remoteAddr:           ipv6SubnetBcast,
			requiresBroadcastOpt: false,
		},
		{
			name: "IPv4 Broadcast to remote subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: remNetSubnet,
					Gateway:     ipv4Gateway,
					NIC:         nicID1,
				},
			},
			remoteAddr: remNetSubnetBcast,
			// TODO(gvisor.dev/issue/3938): Once we support marking a route as
			// broadcast, this test should require the broadcast option to be set.
			requiresBroadcastOpt: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				Clock:              &faketime.NullClock{},
			})
			defer s.Destroy()
			e := channel.New(0, context.DefaultMTU, "")
			defer e.Close()
			if err := s.CreateNIC(nicID1, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
			}
			if err := s.AddProtocolAddress(nicID1, test.nicAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID1, test.nicAddr, err)
			}

			s.SetRouteTable(test.routes)

			var netProto tcpip.NetworkProtocolNumber
			switch l := test.remoteAddr.Len(); l {
			case header.IPv4AddressSize:
				netProto = header.IPv4ProtocolNumber
			case header.IPv6AddressSize:
				netProto = header.IPv6ProtocolNumber
			default:
				t.Fatalf("got unexpected address length = %d bytes", l)
			}

			wq := waiter.Queue{}
			ep, err := s.NewEndpoint(udp.ProtocolNumber, netProto, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, netProto, err)
			}
			defer ep.Close()

			var r bytes.Reader
			data := []byte{1, 2, 3, 4}
			to := tcpip.FullAddress{
				Addr: test.remoteAddr,
				Port: 80,
			}
			opts := tcpip.WriteOptions{To: &to}
			expectedErrWithoutBcastOpt := func(err tcpip.Error) tcpip.Error {
				if _, ok := err.(*tcpip.ErrBroadcastDisabled); ok {
					return nil
				}
				return &tcpip.ErrBroadcastDisabled{}
			}
			if !test.requiresBroadcastOpt {
				expectedErrWithoutBcastOpt = nil
			}

			r.Reset(data)
			{
				n, err := ep.Write(&r, opts)
				if expectedErrWithoutBcastOpt != nil {
					if want := expectedErrWithoutBcastOpt(err); want != nil {
						t.Fatalf("got ep.Write(_, %#v) = (%d, %s), want = (_, %s)", opts, n, err, want)
					}
				} else if err != nil {
					t.Fatalf("got ep.Write(_, %#v) = (%d, %s), want = (_, nil)", opts, n, err)
				}
			}

			ep.SocketOptions().SetBroadcast(true)

			r.Reset(data)
			if n, err := ep.Write(&r, opts); err != nil {
				t.Fatalf("got ep.Write(_, %#v) = (%d, %s), want = (_, nil)", opts, n, err)
			}

			ep.SocketOptions().SetBroadcast(false)

			r.Reset(data)
			{
				n, err := ep.Write(&r, opts)
				if expectedErrWithoutBcastOpt != nil {
					if want := expectedErrWithoutBcastOpt(err); want != nil {
						t.Fatalf("got ep.Write(_, %#v) = (%d, %s), want = (_, %s)", opts, n, err, want)
					}
				} else if err != nil {
					t.Fatalf("got ep.Write(_, %#v) = (%d, %s), want = (_, nil)", opts, n, err)
				}
			}
		})
	}
}

func TestChecksumWithZeroValueOnesComplementSum(t *testing.T) {
	c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol})
	defer c.Cleanup()

	c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)
	var writeOpts tcpip.WriteOptions
	h := context.UnicastV6.MakeHeader4Tuple(context.Outgoing)
	writeDstAddr := context.UnicastV6.MapAddrIfApplicable(h.Dst.Addr)
	writeOpts = tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.Dst.Port},
	}

	// Write a packet to calculate what the checksum value will be with a zero
	// value payload. We will then take that checksum value to construct another
	// packet which would result in the ones complement of the packet to be zero.
	var payload [2]byte
	{
		var r bytes.Reader
		r.Reset(payload[:])
		n, err := c.EP.Write(&r, writeOpts)
		if err != nil {
			t.Fatalf("Write failed: %s", err)
		}
		if want := int64(len(payload)); n != want {
			t.Fatalf("got n = %d, want = %d", n, want)
		}

		pkt := c.LinkEP.Read()
		if pkt.IsNil() {
			t.Fatal("Packet wasn't written out")
		}

		v := stack.PayloadSince(pkt.NetworkHeader())
		defer v.Release()
		pkt.DecRef()
		checker.IPv6(t, v, checker.UDP())

		// Simply replacing the payload with the checksum value is enough to make
		// sure that we end up with an all ones value for the ones complement sum
		// because the checksum value is held the ones complement of the ones
		// complement sum.
		//
		// In ones complement arithmetic, adding a value A with a ones complement of
		// another value B is the same as subtracting B from A.
		//
		// The resulting ones complement will be  C' = C - C so we know C' will be
		// zero. The stack should never send a zero value though so we expect all
		// ones below.
		binary.BigEndian.PutUint16(payload[:], header.UDP(header.IPv6(v.AsSlice()).Payload()).Checksum())
	}

	{
		var r bytes.Reader
		r.Reset(payload[:])
		n, err := c.EP.Write(&r, writeOpts)
		if err != nil {
			t.Fatalf("Write failed: %s", err)
		}
		if want := int64(len(payload)); n != want {
			t.Fatalf("got n = %d, want = %d", n, want)
		}
	}

	{
		pkt := c.LinkEP.Read()
		if pkt.IsNil() {
			t.Fatal("Packet wasn't written out")
		}
		defer pkt.DecRef()

		v := stack.PayloadSince(pkt.NetworkHeader())
		defer v.Release()
		checker.IPv6(t, v, checker.UDP(checker.TransportChecksum(math.MaxUint16)))

		// Make sure the all ones checksum is valid.
		hdr := header.IPv6(v.AsSlice())
		udp := header.UDP(hdr.Payload())
		if src, dst, payloadXsum := hdr.SourceAddress(), hdr.DestinationAddress(), checksum.Checksum(udp.Payload(), 0); !udp.IsChecksumValid(src, dst, payloadXsum) {
			t.Errorf("got udp.IsChecksumValid(%s, %s, %d) = false, want = true", src, dst, payloadXsum)
		}
	}
}

// TestWritePayloadSizeTooBig verifies that writing anything bigger than
// header.UDPMaximumPacketSize fails.
func TestWritePayloadSizeTooBig(t *testing.T) {
	for _, writeOpSequence := range writeOpSequences {
		c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4})

		c.CreateEndpoint(ipv6.ProtocolNumber, udp.ProtocolNumber)

		if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort}); err != nil {
			c.T.Fatalf("Connect failed: %s", err)
		}

		testWriteOpSequenceSucceeds(c, context.UnicastV6, writeOpSequence)

		for _, writeOp := range writeOpSequence {
			switch writeOp {
			case write:
				testWriteFails(c, context.UnicastV6, header.UDPMaximumPacketSize+1, &tcpip.ErrMessageTooLong{})
			case preflight:
				testPreflightSucceeds(c, context.UnicastV6)
			}
		}
		c.Cleanup()
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
