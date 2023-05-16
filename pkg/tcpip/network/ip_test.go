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

package ip_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

var (
	localIPv4Addr  = testutil.MustParse4("10.0.0.1")
	remoteIPv4Addr = testutil.MustParse4("10.0.0.2")
	ipv4SubnetAddr = testutil.MustParse4("10.0.0.0")
	ipv4SubnetMask = testutil.MustParse4("255.255.255.0")
	ipv4Gateway    = testutil.MustParse4("10.0.0.3")
	localIPv6Addr  = testutil.MustParse6("a00::1")
	remoteIPv6Addr = testutil.MustParse6("a00::2")
	ipv6SubnetAddr = testutil.MustParse6("a00::")
	ipv6SubnetMask = testutil.MustParse6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00")
	ipv6Gateway    = testutil.MustParse6("a00::3")
)

var localIPv4AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv4Addr,
	PrefixLen: 24,
}

var localIPv6AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv6Addr,
	PrefixLen: 120,
}

type transportError struct {
	origin tcpip.SockErrOrigin
	typ    uint8
	code   uint8
	info   uint32
	kind   stack.TransportErrorKind
}

// testObject implements two interfaces: LinkEndpoint and TransportDispatcher.
// The former is used to pretend that it's a link endpoint so that we can
// inspect packets written by the network endpoints. The latter is used to
// pretend that it's the network stack so that it can inspect incoming packets
// that have been handled by the network endpoints.
//
// Packets are checked by comparing their fields/values against the expected
// values stored in the test object itself.
type testObject struct {
	t        *testing.T
	protocol tcpip.TransportProtocolNumber
	contents []byte
	srcAddr  tcpip.Address
	dstAddr  tcpip.Address
	v4       bool
	transErr transportError

	dataCalls    int
	controlCalls int
	rawCalls     int
}

// checkValues verifies that the transport protocol, data contents, src & dst
// addresses of a packet match what's expected. If any field doesn't match, the
// test fails.
func (t *testObject) checkValues(protocol tcpip.TransportProtocolNumber, v []byte, srcAddr, dstAddr tcpip.Address) {
	if protocol != t.protocol {
		t.t.Errorf("protocol = %v, want %v", protocol, t.protocol)
	}

	if srcAddr != t.srcAddr {
		t.t.Errorf("srcAddr = %v, want %v", srcAddr, t.srcAddr)
	}

	if dstAddr != t.dstAddr {
		t.t.Errorf("dstAddr = %v, want %v", dstAddr, t.dstAddr)
	}

	if len(v) != len(t.contents) {
		t.t.Fatalf("len(payload) = %v, want %v", len(v), len(t.contents))
	}

	for i := range t.contents {
		if t.contents[i] != v[i] {
			t.t.Fatalf("payload[%v] = %v, want %v", i, v[i], t.contents[i])
		}
	}
}

// DeliverTransportPacket is called by network endpoints after parsing incoming
// packets. This is used by the test object to verify that the results of the
// parsing are expected.
func (t *testObject) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt stack.PacketBufferPtr) stack.TransportPacketDisposition {
	netHdr := pkt.Network()
	v := pkt.Data().AsRange().ToView()
	defer v.Release()
	t.checkValues(protocol, v.AsSlice(), netHdr.SourceAddress(), netHdr.DestinationAddress())
	t.dataCalls++
	return stack.TransportPacketHandled
}

// DeliverTransportError is called by network endpoints after parsing
// incoming control (ICMP) packets. This is used by the test object to verify
// that the results of the parsing are expected.
func (t *testObject) DeliverTransportError(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, transErr stack.TransportError, pkt stack.PacketBufferPtr) {
	v := pkt.Data().AsRange().ToView()
	defer v.Release()
	t.checkValues(trans, v.AsSlice(), remote, local)
	if diff := cmp.Diff(
		t.transErr,
		transportError{
			origin: transErr.Origin(),
			typ:    transErr.Type(),
			code:   transErr.Code(),
			info:   transErr.Info(),
			kind:   transErr.Kind(),
		},
		cmp.AllowUnexported(transportError{}),
	); diff != "" {
		t.t.Errorf("transport error mismatch (-want +got):\n%s", diff)
	}
	t.controlCalls++
}

func (t *testObject) DeliverRawPacket(tcpip.TransportProtocolNumber, stack.PacketBufferPtr) {
	t.rawCalls++
}

// Attach is only implemented to satisfy the LinkEndpoint interface.
func (*testObject) Attach(stack.NetworkDispatcher) {}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (*testObject) IsAttached() bool {
	return true
}

// MTU implements stack.LinkEndpoint.MTU. It just returns a constant that
// matches the linux loopback MTU.
func (*testObject) MTU() uint32 {
	return 65536
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (*testObject) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

// MaxHeaderLength is only implemented to satisfy the LinkEndpoint interface.
func (*testObject) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*testObject) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Wait implements stack.LinkEndpoint.Wait.
func (*testObject) Wait() {}

// WritePacket is called by network endpoints after producing a packet and
// writing it to the link endpoint. This is used by the test object to verify
// that the produced packet is as expected.
func (t *testObject) WritePacket(_ *stack.Route, pkt stack.PacketBufferPtr) tcpip.Error {
	var prot tcpip.TransportProtocolNumber
	var srcAddr tcpip.Address
	var dstAddr tcpip.Address

	if t.v4 {
		h := header.IPv4(pkt.NetworkHeader().Slice())
		prot = tcpip.TransportProtocolNumber(h.Protocol())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()

	} else {
		h := header.IPv6(pkt.NetworkHeader().Slice())
		prot = tcpip.TransportProtocolNumber(h.NextHeader())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()
	}
	t.checkValues(prot, pkt.Data().AsRange().ToSlice(), srcAddr, dstAddr)
	return nil
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*testObject) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*testObject) AddHeader(stack.PacketBufferPtr) {
	panic("not implemented")
}

type testContext struct {
	s *stack.Stack
}

func newTestContext() testContext {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
		RawFactory:         raw.EndpointFactory{},
	})
	return testContext{s: s}
}

func (ctx *testContext) cleanup() {
	ctx.s.Close()
	ctx.s.Wait()
	refs.DoRepeatedLeakCheck()
}

func buildIPv4Route(ctx testContext, local, remote tcpip.Address) (*stack.Route, tcpip.Error) {
	s := ctx.s
	s.CreateNIC(nicID, loopback.New())
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: local.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     ipv4Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv4.ProtocolNumber, false /* multicastLoop */)
}

func buildIPv6Route(ctx testContext, local, remote tcpip.Address) (*stack.Route, tcpip.Error) {
	s := ctx.s
	s.CreateNIC(nicID, loopback.New())
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: local.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		Gateway:     ipv6Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv6.ProtocolNumber, false /* multicastLoop */)
}

func addLinkEndpointToStackWithMTU(t *testing.T, s *stack.Stack, mtu uint32) *channel.Endpoint {
	t.Helper()
	e := channel.New(1, mtu, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	v4Addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: localIPv4AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}) = %s", nicID, v4Addr, err)
	}

	v6Addr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: localIPv6AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}) = %s", nicID, v6Addr, err)
	}

	return e
}

func addLinkEndpointToStack(t *testing.T, s *stack.Stack) *channel.Endpoint {
	t.Helper()
	return addLinkEndpointToStackWithMTU(t, s, header.IPv6MinimumMTU)
}

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	testObject

	mu struct {
		sync.RWMutex
		disabled bool
	}
}

func (*testInterface) ID() tcpip.NICID {
	return nicID
}

func (*testInterface) IsLoopback() bool {
	return false
}

func (*testInterface) Name() string {
	return ""
}

func (t *testInterface) Enabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return !t.mu.disabled
}

func (*testInterface) Promiscuous() bool {
	return false
}

func (*testInterface) Spoofing() bool {
	return false
}

func (t *testInterface) setEnabled(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mu.disabled = !v
}

func (*testInterface) WritePacketToRemote(tcpip.LinkAddress, stack.PacketBufferPtr) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*testInterface) HandleNeighborProbe(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress) tcpip.Error {
	return nil
}

func (*testInterface) HandleNeighborConfirmation(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress, stack.ReachabilityConfirmationFlags) tcpip.Error {
	return nil
}

func (*testInterface) PrimaryAddress(tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	return tcpip.AddressWithPrefix{}, nil
}

func (*testInterface) CheckLocalAddress(tcpip.NetworkProtocolNumber, tcpip.Address) bool {
	return false
}

func TestSourceAddressValidation(t *testing.T) {
	rxIPv4ICMP := func(e *channel.Endpoint, src tcpip.Address) {
		totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
		hdr := prependable.New(totalLen)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		pkt.SetType(header.ICMPv4Echo)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^checksum.Checksum(pkt, 0))
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    uint8(icmp.ProtocolNumber4),
			TTL:         ipv4.DefaultTTL,
			SrcAddr:     src,
			DstAddr:     localIPv4Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())

		pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: bufferv2.MakeWithData(hdr.View()),
		})
		e.InjectInbound(header.IPv4ProtocolNumber, pktBuf)
		pktBuf.DecRef()
	}

	rxIPv6ICMP := func(e *channel.Endpoint, src tcpip.Address) {
		totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
		hdr := prependable.New(totalLen)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
		pkt.SetType(header.ICMPv6EchoRequest)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: pkt,
			Src:    src,
			Dst:    localIPv6Addr,
		}))
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     header.ICMPv6MinimumSize,
			TransportProtocol: icmp.ProtocolNumber6,
			HopLimit:          ipv6.DefaultTTL,
			SrcAddr:           src,
			DstAddr:           localIPv6Addr,
		})
		pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: bufferv2.MakeWithData(hdr.View()),
		})
		e.InjectInbound(header.IPv6ProtocolNumber, pktBuf)
		pktBuf.DecRef()
	}

	tests := []struct {
		name       string
		srcAddress tcpip.Address
		rxICMP     func(*channel.Endpoint, tcpip.Address)
		valid      bool
	}{
		{
			name:       "IPv4 valid",
			srcAddress: tcpip.AddrFromSlice([]byte("\x01\x02\x03\x04")),
			rxICMP:     rxIPv4ICMP,
			valid:      true,
		},
		{
			name:       "IPv6 valid",
			srcAddress: tcpip.AddrFromSlice([]byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")),
			rxICMP:     rxIPv6ICMP,
			valid:      true,
		},
		{
			name:       "IPv4 unspecified",
			srcAddress: header.IPv4Any,
			rxICMP:     rxIPv4ICMP,
			valid:      true,
		},
		{
			name:       "IPv6 unspecified",
			srcAddress: header.IPv4Any,
			rxICMP:     rxIPv6ICMP,
			valid:      true,
		},
		{
			name:       "IPv4 multicast",
			srcAddress: tcpip.AddrFromSlice([]byte("\xe0\x00\x00\x01")),
			rxICMP:     rxIPv4ICMP,
			valid:      false,
		},
		{
			name:       "IPv6 multicast",
			srcAddress: tcpip.AddrFromSlice([]byte("\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
			rxICMP:     rxIPv6ICMP,
			valid:      false,
		},
		{
			name:       "IPv4 broadcast",
			srcAddress: header.IPv4Broadcast,
			rxICMP:     rxIPv4ICMP,
			valid:      false,
		},
		{
			name: "IPv4 subnet broadcast",
			srcAddress: func() tcpip.Address {
				subnet := localIPv4AddrWithPrefix.Subnet()
				return subnet.Broadcast()
			}(),
			rxICMP: rxIPv4ICMP,
			valid:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			e := addLinkEndpointToStack(t, s)
			defer e.Close()
			test.rxICMP(e, test.srcAddress)

			var wantValid uint64
			if test.valid {
				wantValid = 1
			}

			if got, want := s.Stats().IP.InvalidSourceAddressesReceived.Value(), 1-wantValid; got != want {
				t.Errorf("got s.Stats().IP.InvalidSourceAddressesReceived.Value() = %d, want = %d", got, want)
			}
			if got := s.Stats().IP.PacketsDelivered.Value(); got != wantValid {
				t.Errorf("got s.Stats().IP.PacketsDelivered.Value() = %d, want = %d", got, wantValid)
			}
		})
	}
}

func TestEnableWhenNICDisabled(t *testing.T) {
	tests := []struct {
		name            string
		protocolFactory stack.NetworkProtocolFactory
		protoNum        tcpip.NetworkProtocolNumber
	}{
		{
			name:            "IPv4",
			protocolFactory: ipv4.NewProtocol,
			protoNum:        ipv4.ProtocolNumber,
		},
		{
			name:            "IPv6",
			protocolFactory: ipv6.NewProtocol,
			protoNum:        ipv6.ProtocolNumber,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var nic testInterface
			nic.setEnabled(false)

			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{test.protocolFactory},
			})
			defer func() {
				s.Close()
				s.Wait()
			}()

			p := s.NetworkProtocolInstance(test.protoNum)

			// We pass nil for all parameters except the NetworkInterface and Stack
			// since Enable only depends on these.
			ep := p.NewEndpoint(&nic, nil)

			// The endpoint should initially be disabled, regardless the NIC's enabled
			// status.
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}
			nic.setEnabled(true)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Attempting to enable the endpoint while the NIC is disabled should
			// fail.
			nic.setEnabled(false)
			err := ep.Enable()
			if _, ok := err.(*tcpip.ErrNotPermitted); !ok {
				t.Fatalf("got ep.Enable() = %s, want = %s", err, &tcpip.ErrNotPermitted{})
			}
			// ep should consider the NIC's enabled status when determining its own
			// enabled status so we "enable" the NIC to read just the endpoint's
			// enabled status.
			nic.setEnabled(true)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Enabling the interface after the NIC has been enabled should succeed.
			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}
			if !ep.Enabled() {
				t.Fatal("got ep.Enabled() = false, want = true")
			}

			// ep should consider the NIC's enabled status when determining its own
			// enabled status.
			nic.setEnabled(false)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Disabling the endpoint when the NIC is enabled should make the endpoint
			// disabled.
			nic.setEnabled(true)
			ep.Disable()
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}
		})
	}
}

func TestIPv4Send(t *testing.T) {
	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil)
	defer ep.Close()

	// Allocate and initialize the payload view.
	payload := make([]byte, 100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Payload:            bufferv2.MakeWithData(payload),
	})
	defer pkt.DecRef()

	// Issue the write.
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv4Addr
	nic.testObject.dstAddr = remoteIPv4Addr
	nic.testObject.contents = payload

	r, err := buildIPv4Route(ctx, localIPv4Addr, remoteIPv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	defer r.Release()
	if err := ep.WritePacket(r, stack.NetworkHeaderParams{
		Protocol: 123,
		TTL:      123,
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestReceive(t *testing.T) {
	tests := []struct {
		name         string
		protoFactory stack.NetworkProtocolFactory
		protoNum     tcpip.NetworkProtocolNumber
		v4           bool
		epAddr       tcpip.AddressWithPrefix
		handlePacket func(*testing.T, stack.NetworkEndpoint, *testInterface)
	}{
		{
			name:         "IPv4",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			v4:           true,
			epAddr:       localIPv4Addr.WithPrefix(),
			handlePacket: func(t *testing.T, ep stack.NetworkEndpoint, nic *testInterface) {
				const totalLen = header.IPv4MinimumSize + 30 /* payload length */

				view := make([]byte, totalLen)
				ip := header.IPv4(view)
				ip.Encode(&header.IPv4Fields{
					TotalLength: totalLen,
					TTL:         ipv4.DefaultTTL,
					Protocol:    10,
					SrcAddr:     remoteIPv4Addr,
					DstAddr:     localIPv4Addr,
				})
				ip.SetChecksum(^ip.CalculateChecksum())

				// Make payload be non-zero.
				for i := header.IPv4MinimumSize; i < len(view); i++ {
					view[i] = uint8(i)
				}

				// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
				nic.testObject.protocol = 10
				nic.testObject.srcAddr = remoteIPv4Addr
				nic.testObject.dstAddr = localIPv4Addr
				nic.testObject.contents = view[header.IPv4MinimumSize:totalLen]

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(view),
				})
				ep.HandlePacket(pkt)
				pkt.DecRef()
			},
		},
		{
			name:         "IPv6",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			v4:           false,
			epAddr:       localIPv6Addr.WithPrefix(),
			handlePacket: func(t *testing.T, ep stack.NetworkEndpoint, nic *testInterface) {
				const payloadLen = 30
				view := make([]byte, header.IPv6MinimumSize+payloadLen)
				ip := header.IPv6(view)
				ip.Encode(&header.IPv6Fields{
					PayloadLength:     payloadLen,
					TransportProtocol: 10,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           remoteIPv6Addr,
					DstAddr:           localIPv6Addr,
				})

				// Make payload be non-zero.
				for i := header.IPv6MinimumSize; i < len(view); i++ {
					view[i] = uint8(i)
				}

				// Give packet to ipv6 endpoint, dispatcher will validate that it's ok.
				nic.testObject.protocol = 10
				nic.testObject.srcAddr = remoteIPv6Addr
				nic.testObject.dstAddr = localIPv6Addr
				nic.testObject.contents = view[header.IPv6MinimumSize:][:payloadLen]

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(view),
				})
				ep.HandlePacket(pkt)
				pkt.DecRef()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{test.protoFactory},
			})
			defer func() {
				s.Close()
				s.Wait()
			}()

			nic := testInterface{
				testObject: testObject{
					t:  t,
					v4: test.v4,
				},
			}
			ep := s.NetworkProtocolInstance(test.protoNum).NewEndpoint(&nic, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatalf("expected network endpoint with number = %d to implement stack.AddressableEndpoint", test.protoNum)
			}
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(test.epAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, {}): %s", test.epAddr, err)
			} else {
				ep.DecRef()
			}

			stat := s.Stats().IP.PacketsReceived
			if got := stat.Value(); got != 0 {
				t.Fatalf("got s.Stats().IP.PacketsReceived.Value() = %d, want = 0", got)
			}
			test.handlePacket(t, ep, &nic)
			if nic.testObject.dataCalls != 1 {
				t.Errorf("Bad number of data calls: got %d, want 1", nic.testObject.dataCalls)
			}
			if nic.testObject.rawCalls != 1 {
				t.Errorf("Bad number of raw calls: got %d, want 1", nic.testObject.rawCalls)
			}
			if got := stat.Value(); got != 1 {
				t.Errorf("got s.Stats().IP.PacketsReceived.Value() = %d, want = 1", got)
			}
		})
	}
}

func TestIPv4ReceiveControl(t *testing.T) {
	const (
		mtu     = 0xbeef - header.IPv4MinimumSize
		dataLen = 8
	)

	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset uint16
		code           header.ICMPv4Code
		transErr       transportError
		trunc          int
	}{
		{
			name:           "FragmentationNeeded",
			expectedCount:  1,
			fragmentOffset: 0,
			code:           header.ICMPv4FragmentationNeeded,
			transErr: transportError{
				origin: tcpip.SockExtErrorOriginICMP,
				typ:    uint8(header.ICMPv4DstUnreachable),
				code:   uint8(header.ICMPv4FragmentationNeeded),
				info:   mtu,
				kind:   stack.PacketTooBigTransportError,
			},
			trunc: 0,
		},
		{
			name:           "Truncated (missing IPv4 header)",
			expectedCount:  0,
			fragmentOffset: 0,
			code:           header.ICMPv4FragmentationNeeded,
			trunc:          header.IPv4MinimumSize + header.ICMPv4MinimumSize,
		},
		{
			name:           "Truncated (partial offending packet's IP header)",
			expectedCount:  0,
			fragmentOffset: 0,
			code:           header.ICMPv4FragmentationNeeded,
			trunc:          header.IPv4MinimumSize + header.ICMPv4MinimumSize + header.IPv4MinimumSize - 1,
		},
		{
			name:           "Truncated (partial offending packet's data)",
			expectedCount:  0,
			fragmentOffset: 0,
			code:           header.ICMPv4FragmentationNeeded,
			trunc:          header.ICMPv4MinimumSize + header.ICMPv4MinimumSize + header.IPv4MinimumSize + dataLen - 1,
		},
		{
			name:           "Port unreachable",
			expectedCount:  1,
			fragmentOffset: 0,
			code:           header.ICMPv4PortUnreachable,
			transErr: transportError{
				origin: tcpip.SockExtErrorOriginICMP,
				typ:    uint8(header.ICMPv4DstUnreachable),
				code:   uint8(header.ICMPv4PortUnreachable),
				kind:   stack.DestinationPortUnreachableTransportError,
			},
			trunc: 0,
		},
		{
			name:           "Non-zero fragment offset",
			expectedCount:  0,
			fragmentOffset: 100,
			code:           header.ICMPv4PortUnreachable,
			trunc:          0,
		},
		{
			name:           "Zero-length packet",
			expectedCount:  0,
			fragmentOffset: 100,
			code:           header.ICMPv4PortUnreachable,
			trunc:          2*header.IPv4MinimumSize + header.ICMPv4MinimumSize + dataLen,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			const dataOffset = header.IPv4MinimumSize*2 + header.ICMPv4MinimumSize
			view := make([]byte, dataOffset+dataLen)

			// Create the outer IPv4 header.
			ip := header.IPv4(view)
			ip.Encode(&header.IPv4Fields{
				TotalLength: uint16(len(view) - c.trunc),
				TTL:         20,
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				SrcAddr:     tcpip.AddrFromSlice([]byte("\x0a\x00\x00\xbb")),
				DstAddr:     localIPv4Addr,
			})
			ip.SetChecksum(^ip.CalculateChecksum())

			// Create the ICMP header.
			icmp := header.ICMPv4(view[header.IPv4MinimumSize:])
			icmp.SetType(header.ICMPv4DstUnreachable)
			icmp.SetCode(c.code)
			icmp.SetIdent(0xdead)
			icmp.SetSequence(0xbeef)

			// Create the inner IPv4 header.
			ip = header.IPv4(view[header.IPv4MinimumSize+header.ICMPv4MinimumSize:])
			ip.Encode(&header.IPv4Fields{
				TotalLength:    100,
				TTL:            20,
				Protocol:       10,
				FragmentOffset: c.fragmentOffset,
				SrcAddr:        localIPv4Addr,
				DstAddr:        remoteIPv4Addr,
			})
			ip.SetChecksum(^ip.CalculateChecksum())

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			icmp.SetChecksum(0)
			xsum := ^checksum.Checksum(icmp, 0 /* initial */)
			icmp.SetChecksum(xsum)

			// Give packet to IPv4 endpoint, dispatcher will validate that
			// it's ok.
			nic.testObject.protocol = 10
			nic.testObject.srcAddr = remoteIPv4Addr
			nic.testObject.dstAddr = localIPv4Addr
			nic.testObject.contents = view[dataOffset:]
			nic.testObject.transErr = c.transErr

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatal("expected IPv4 network endpoint to implement stack.AddressableEndpoint")
			}
			addr := localIPv4Addr.WithPrefix()
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, {}): %s", addr, err)
			} else {
				ep.DecRef()
			}

			pkt := truncatedPacket(view, c.trunc, header.IPv4MinimumSize)
			ep.HandlePacket(pkt)
			pkt.DecRef()
			if want := c.expectedCount; nic.testObject.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, nic.testObject.controlCalls, want)
			}
		})
	}
}

func TestIPv4FragmentationReceive(t *testing.T) {
	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, &nic.testObject)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	totalLen := header.IPv4MinimumSize + 24

	frag1 := make([]byte, totalLen)
	ip1 := header.IPv4(frag1)
	ip1.Encode(&header.IPv4Fields{
		TotalLength:    uint16(totalLen),
		TTL:            20,
		Protocol:       10,
		FragmentOffset: 0,
		Flags:          header.IPv4FlagMoreFragments,
		SrcAddr:        remoteIPv4Addr,
		DstAddr:        localIPv4Addr,
	})
	ip1.SetChecksum(^ip1.CalculateChecksum())

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag1[i] = uint8(i)
	}

	frag2 := make([]byte, totalLen)
	ip2 := header.IPv4(frag2)
	ip2.Encode(&header.IPv4Fields{
		TotalLength:    uint16(totalLen),
		TTL:            20,
		Protocol:       10,
		FragmentOffset: 24,
		SrcAddr:        remoteIPv4Addr,
		DstAddr:        localIPv4Addr,
	})
	ip2.SetChecksum(^ip2.CalculateChecksum())

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag2[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	nic.testObject.protocol = 10
	nic.testObject.srcAddr = remoteIPv4Addr
	nic.testObject.dstAddr = localIPv4Addr
	nic.testObject.contents = append(frag1[header.IPv4MinimumSize:totalLen], frag2[header.IPv4MinimumSize:totalLen]...)

	addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
	if !ok {
		t.Fatal("expected IPv4 network endpoint to implement stack.AddressableEndpoint")
	}
	addr := localIPv4Addr.WithPrefix()
	if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, {}): %s", addr, err)
	} else {
		ep.DecRef()
	}

	// Send first segment.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(frag1),
	})
	ep.HandlePacket(pkt)
	pkt.DecRef()

	if nic.testObject.dataCalls != 0 {
		t.Fatalf("Bad number of data calls: got %d, want 0", nic.testObject.dataCalls)
	}
	if nic.testObject.rawCalls != 0 {
		t.Errorf("Bad number of raw calls: got %d, want 0", nic.testObject.rawCalls)
	}

	// Send second segment.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(frag2),
	})
	ep.HandlePacket(pkt)
	pkt.DecRef()

	if nic.testObject.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %d, want 1", nic.testObject.dataCalls)
	}
	if nic.testObject.rawCalls != 1 {
		t.Errorf("Bad number of raw calls: got %d, want 1", nic.testObject.rawCalls)
	}
}

func TestIPv6Send(t *testing.T) {
	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t: t,
		},
	}
	ep := proto.NewEndpoint(&nic, nil)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	// Allocate and initialize the payload view.
	payload := make([]byte, 100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Payload:            bufferv2.MakeWithData(payload),
	})
	defer pkt.DecRef()
	// Issue the write.
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv6Addr
	nic.testObject.dstAddr = remoteIPv6Addr
	nic.testObject.contents = payload

	r, err := buildIPv6Route(ctx, localIPv6Addr, remoteIPv6Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	defer r.Release()
	if err := ep.WritePacket(r, stack.NetworkHeaderParams{
		Protocol: 123,
		TTL:      123,
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv6ReceiveControl(t *testing.T) {
	const (
		mtu     = 0xffff
		dataLen = 8
	)
	outerSrcAddr := tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\x00\x00\x00"))

	newUint16 := func(v uint16) *uint16 { return &v }

	portUnreachableTransErr := transportError{
		origin: tcpip.SockExtErrorOriginICMP6,
		typ:    uint8(header.ICMPv6DstUnreachable),
		code:   uint8(header.ICMPv6PortUnreachable),
		kind:   stack.DestinationPortUnreachableTransportError,
	}

	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset *uint16
		typ            header.ICMPv6Type
		code           header.ICMPv6Code
		transErr       transportError
		trunc          int
	}{
		{
			name:           "PacketTooBig",
			expectedCount:  1,
			fragmentOffset: nil,
			typ:            header.ICMPv6PacketTooBig,
			code:           header.ICMPv6UnusedCode,
			transErr: transportError{
				origin: tcpip.SockExtErrorOriginICMP6,
				typ:    uint8(header.ICMPv6PacketTooBig),
				code:   uint8(header.ICMPv6UnusedCode),
				info:   mtu,
				kind:   stack.PacketTooBigTransportError,
			},
			trunc: 0,
		},
		{
			name:           "Truncated (missing offending packet's IPv6 header)",
			expectedCount:  0,
			fragmentOffset: nil,
			typ:            header.ICMPv6PacketTooBig,
			code:           header.ICMPv6UnusedCode,
			trunc:          header.IPv6MinimumSize + header.ICMPv6PacketTooBigMinimumSize,
		},
		{
			name:           "Truncated PacketTooBig (partial offending packet's IPv6 header)",
			expectedCount:  0,
			fragmentOffset: nil,
			typ:            header.ICMPv6PacketTooBig,
			code:           header.ICMPv6UnusedCode,
			trunc:          header.IPv6MinimumSize + header.ICMPv6PacketTooBigMinimumSize + header.IPv6MinimumSize - 1,
		},
		{
			name:           "Truncated (partial offending packet's data)",
			expectedCount:  0,
			fragmentOffset: nil,
			typ:            header.ICMPv6PacketTooBig,
			code:           header.ICMPv6UnusedCode,
			trunc:          header.IPv6MinimumSize + header.ICMPv6PacketTooBigMinimumSize + header.IPv6MinimumSize + dataLen - 1,
		},
		{
			name:           "Port unreachable",
			expectedCount:  1,
			fragmentOffset: nil,
			typ:            header.ICMPv6DstUnreachable,
			code:           header.ICMPv6PortUnreachable,
			transErr:       portUnreachableTransErr,
			trunc:          0,
		},
		{
			name:           "Truncated DstPortUnreachable (partial offending packet's IP header)",
			expectedCount:  0,
			fragmentOffset: nil,
			typ:            header.ICMPv6DstUnreachable,
			code:           header.ICMPv6PortUnreachable,
			trunc:          header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + header.IPv6MinimumSize - 1,
		},
		{
			name:           "DstPortUnreachable for Fragmented, zero offset",
			expectedCount:  1,
			fragmentOffset: newUint16(0),
			typ:            header.ICMPv6DstUnreachable,
			code:           header.ICMPv6PortUnreachable,
			transErr:       portUnreachableTransErr,
			trunc:          0,
		},
		{
			name:           "DstPortUnreachable for Non-zero fragment offset",
			expectedCount:  0,
			fragmentOffset: newUint16(100),
			typ:            header.ICMPv6DstUnreachable,
			code:           header.ICMPv6PortUnreachable,
			transErr:       portUnreachableTransErr,
			trunc:          0,
		},
		{
			name:           "Zero-length packet",
			expectedCount:  0,
			fragmentOffset: nil,
			typ:            header.ICMPv6DstUnreachable,
			code:           header.ICMPv6PortUnreachable,
			trunc:          2*header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + dataLen,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			dataOffset := header.IPv6MinimumSize*2 + header.ICMPv6MinimumSize
			if c.fragmentOffset != nil {
				dataOffset += header.IPv6FragmentHeaderSize
			}
			view := make([]byte, dataOffset+dataLen)

			// Create the outer IPv6 header.
			ip := header.IPv6(view)
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(len(view) - header.IPv6MinimumSize - c.trunc),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          20,
				SrcAddr:           outerSrcAddr,
				DstAddr:           localIPv6Addr,
			})

			// Create the ICMP header.
			icmp := header.ICMPv6(view[header.IPv6MinimumSize:])
			icmp.SetType(c.typ)
			icmp.SetCode(c.code)
			icmp.SetIdent(0xdead)
			icmp.SetSequence(0xbeef)

			var extHdrs header.IPv6ExtHdrSerializer
			// Build the fragmentation header if needed.
			if c.fragmentOffset != nil {
				extHdrs = append(extHdrs, &header.IPv6SerializableFragmentExtHdr{
					FragmentOffset: *c.fragmentOffset,
					M:              true,
					Identification: 0x12345678,
				})
			}

			// Create the inner IPv6 header.
			ip = header.IPv6(view[header.IPv6MinimumSize+header.ICMPv6PayloadOffset:])
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     100,
				TransportProtocol: 10,
				HopLimit:          20,
				SrcAddr:           localIPv6Addr,
				DstAddr:           remoteIPv6Addr,
				ExtensionHeaders:  extHdrs,
			})

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			// Give packet to IPv6 endpoint, dispatcher will validate that
			// it's ok.
			nic.testObject.protocol = 10
			nic.testObject.srcAddr = remoteIPv6Addr
			nic.testObject.dstAddr = localIPv6Addr
			nic.testObject.contents = view[dataOffset:]
			nic.testObject.transErr = c.transErr

			// Set ICMPv6 checksum.
			icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmp,
				Src:    outerSrcAddr,
				Dst:    localIPv6Addr,
			}))

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatal("expected IPv6 network endpoint to implement stack.AddressableEndpoint")
			}
			addr := localIPv6Addr.WithPrefix()
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, {}): %s", addr, err)
			} else {
				ep.DecRef()
			}
			pkt := truncatedPacket(view, c.trunc, header.IPv6MinimumSize)
			ep.HandlePacket(pkt)
			pkt.DecRef()
			if want := c.expectedCount; nic.testObject.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, nic.testObject.controlCalls, want)
			}
		})
	}
}

// truncatedPacket returns a PacketBuffer based on a truncated view. If view,
// after truncation, is large enough to hold a network header, it makes part of
// view the packet's NetworkHeader and the rest its Data. Otherwise all of view
// becomes Data.
func truncatedPacket(view []byte, trunc, netHdrLen int) stack.PacketBufferPtr {
	v := view[:len(view)-trunc]
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(v),
	})
	return pkt
}

func TestWriteHeaderIncludedPacket(t *testing.T) {
	const (
		nicID          = 1
		transportProto = 5

		dataLen = 4
	)

	dataBuf := [dataLen]byte{1, 2, 3, 4}
	data := dataBuf[:]

	ipv4Options := header.IPv4OptionsSerializer{
		&header.IPv4SerializableListEndOption{},
		&header.IPv4SerializableNOPOption{},
		&header.IPv4SerializableListEndOption{},
		&header.IPv4SerializableNOPOption{},
	}

	expectOptions := header.IPv4Options{
		byte(header.IPv4OptionListEndType),
		byte(header.IPv4OptionNOPType),
		byte(header.IPv4OptionListEndType),
		byte(header.IPv4OptionNOPType),
	}

	ipv6FragmentExtHdrBuf := [header.IPv6FragmentExtHdrLength]byte{transportProto, 0, 62, 4, 1, 2, 3, 4}
	ipv6FragmentExtHdr := ipv6FragmentExtHdrBuf[:]

	var ipv6PayloadWithExtHdrBuf [dataLen + header.IPv6FragmentExtHdrLength]byte
	ipv6PayloadWithExtHdr := ipv6PayloadWithExtHdrBuf[:]
	if n := copy(ipv6PayloadWithExtHdr, ipv6FragmentExtHdr); n != len(ipv6FragmentExtHdr) {
		t.Fatalf("copied %d bytes, expected %d bytes", n, len(ipv6FragmentExtHdr))
	}
	if n := copy(ipv6PayloadWithExtHdr[header.IPv6FragmentExtHdrLength:], data); n != len(data) {
		t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
	}

	tests := []struct {
		name         string
		protoFactory stack.NetworkProtocolFactory
		protoNum     tcpip.NetworkProtocolNumber
		nicAddr      tcpip.AddressWithPrefix
		remoteAddr   tcpip.Address
		pktGen       func(*testing.T, tcpip.Address) bufferv2.Buffer
		checker      func(*testing.T, stack.PacketBufferPtr, tcpip.Address)
		expectedErr  tcpip.Error
	}{
		{
			name:         "IPv4",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := prependable.New(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
				})
				return bufferv2.MakeWithData(hdr.View())
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.Slice()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.Slice()), header.IPv4MinimumSize)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.IPFullLength(uint16(header.IPv4MinimumSize+len(data))),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv4 with IHL too small",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := prependable.New(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
				})
				ip.SetHeaderLength(header.IPv4MinimumSize - 1)
				return bufferv2.MakeWithData(hdr.View())
			},
			expectedErr: &tcpip.ErrMalformedHeader{},
		},
		{
			name:         "IPv4 too small",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
				})
				return bufferv2.MakeWithData(ip[:len(ip)-1])
			},
			expectedErr: &tcpip.ErrMalformedHeader{},
		},
		{
			name:         "IPv4 minimum size",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
				})
				return bufferv2.MakeWithData(ip)
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.Slice()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.Slice()) = %d, want = %d", len(netHdr.Slice()), header.IPv4MinimumSize)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.IPFullLength(header.IPv4MinimumSize),
					checker.IPPayload(nil),
				)
			},
		},
		{
			name:         "IPv4 with options",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ipHdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				totalLen := ipHdrLen + len(data)
				hdr := prependable.New(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(ipHdrLen))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
					Options:  ipv4Options,
				})
				return bufferv2.MakeWithData(hdr.View())
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				if len(netHdr.Slice()) != hdrLen {
					t.Errorf("got len(netHdr.Slice()) = %d, want = %d", len(netHdr.Slice()), hdrLen)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(hdrLen),
					checker.IPFullLength(uint16(hdrLen+len(data))),
					checker.IPv4Options(expectOptions),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv4 with options and data across views",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4AddrWithPrefix,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize+ipv4Options.Length()))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  remoteIPv4Addr,
					Options:  ipv4Options,
				})
				buf := bufferv2.MakeWithData(ip)
				buf.Append(bufferv2.NewViewWithData(data))
				return buf
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				if len(netHdr.Slice()) != hdrLen {
					t.Errorf("got len(netHdr.Slice()) = %d, want = %d", len(netHdr.Slice()), hdrLen)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(hdrLen),
					checker.IPFullLength(uint16(hdrLen+len(data))),
					checker.IPv4Options(expectOptions),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv6",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6AddrWithPrefix,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				totalLen := header.IPv6MinimumSize + len(data)
				hdr := prependable.New(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           remoteIPv6Addr,
				})
				return bufferv2.MakeWithData(hdr.View())
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.Slice()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.Slice()), header.IPv6MinimumSize)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(uint16(header.IPv6MinimumSize+len(data))),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv6 with extension header",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6AddrWithPrefix,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				totalLen := header.IPv6MinimumSize + len(ipv6FragmentExtHdr) + len(data)
				hdr := prependable.New(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				if n := copy(hdr.Prepend(len(ipv6FragmentExtHdr)), ipv6FragmentExtHdr); n != len(ipv6FragmentExtHdr) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(ipv6FragmentExtHdr))
				}
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					// NB: we're lying about transport protocol here to verify the raw
					// fragment header bytes.
					TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6FragmentExtHdrIdentifier),
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           remoteIPv6Addr,
				})
				return bufferv2.MakeWithData(hdr.View())
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if want := header.IPv6MinimumSize + len(ipv6FragmentExtHdr); len(netHdr.Slice()) != want {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.Slice()), want)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(uint16(header.IPv6MinimumSize+len(ipv6PayloadWithExtHdr))),
					checker.IPPayload(ipv6PayloadWithExtHdr),
				)
			},
		},
		{
			name:         "IPv6 minimum size",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6AddrWithPrefix,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           remoteIPv6Addr,
				})
				return bufferv2.MakeWithData(ip)
			},
			checker: func(t *testing.T, pkt stack.PacketBufferPtr, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.Slice()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.Slice()), header.IPv6MinimumSize)
				}

				payload := stack.PayloadSince(netHdr)
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(header.IPv6MinimumSize),
					checker.IPPayload(nil),
				)
			},
		},
		{
			name:         "IPv6 too small",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6AddrWithPrefix,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) bufferv2.Buffer {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           remoteIPv4Addr,
				})
				return bufferv2.MakeWithData(ip[:len(ip)-1])
			},
			expectedErr: &tcpip.ErrMalformedHeader{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subTests := []struct {
				name    string
				srcAddr tcpip.Address
			}{
				{
					name:    "unspecified source",
					srcAddr: tcpip.AddrFromSlice([]byte(strings.Repeat("\x00", test.nicAddr.Address.Len()))),
				},
				{
					name:    "random source",
					srcAddr: tcpip.AddrFromSlice([]byte(strings.Repeat("\xab", test.nicAddr.Address.Len()))),
				},
			}

			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{test.protoFactory},
					})
					defer func() {
						s.Close()
						s.Wait()
					}()

					e := channel.New(1, header.IPv6MinimumMTU, "")
					defer e.Close()
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					protocolAddr := tcpip.ProtocolAddress{
						Protocol:          test.protoNum,
						AddressWithPrefix: test.nicAddr,
					}
					if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
					}

					s.SetRouteTable([]tcpip.Route{{Destination: test.remoteAddr.WithPrefix().Subnet(), NIC: nicID}})

					r, err := s.FindRoute(nicID, test.nicAddr.Address, test.remoteAddr, test.protoNum, false /* multicastLoop */)
					if err != nil {
						t.Fatalf("s.FindRoute(%d, %s, %s, %d, false): %s", nicID, test.remoteAddr, test.nicAddr.Address, test.protoNum, err)
					}
					defer r.Release()

					{
						pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
							Payload: test.pktGen(t, subTest.srcAddr),
						})
						err := r.WriteHeaderIncludedPacket(pkt)
						pkt.DecRef()
						if diff := cmp.Diff(test.expectedErr, err); diff != "" {
							t.Fatalf("unexpected error from r.WriteHeaderIncludedPacket(_), (-want, +got):\n%s", diff)
						}
					}

					if test.expectedErr != nil {
						return
					}

					pkt := e.Read()
					if pkt.IsNil() {
						t.Fatal("expected a packet to be written")
					}
					test.checker(t, pkt, subTest.srcAddr)
					pkt.DecRef()
				})
			}
		})
	}
}

// Test that the included data in an ICMP error packet conforms to the
// requirements of RFC 972, RFC 4443 section 2.4 and RFC 1812 Section 4.3.2.3
func TestICMPInclusionSize(t *testing.T) {
	const (
		replyHeaderLength4 = header.IPv4MinimumSize + header.IPv4MinimumSize + header.ICMPv4MinimumSize
		replyHeaderLength6 = header.IPv6MinimumSize + header.IPv6MinimumSize + header.ICMPv6MinimumSize
		targetSize4        = header.IPv4MinimumProcessableDatagramSize
		targetSize6        = header.IPv6MinimumMTU
		// A protocol number that will cause an error response.
		reservedProtocol = 254
	)

	// IPv4 function to create a IP packet and send it to the stack.
	// The packet should generate an error response. We can do that by using an
	// unknown transport protocol (254).
	rxIPv4Bad := func(e *channel.Endpoint, src tcpip.Address, payload []byte) []byte {
		totalLen := header.IPv4MinimumSize + len(payload)
		hdr := prependable.New(header.IPv4MinimumSize)
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    reservedProtocol,
			TTL:         ipv4.DefaultTTL,
			SrcAddr:     src,
			DstAddr:     localIPv4Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		buf := bufferv2.MakeWithData(hdr.View())
		buf.Append(bufferv2.NewViewWithData(payload))
		// Take a copy before InjectInbound takes ownership of vv
		// as vv may be changed during the call.
		v := buf.Flatten()
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buf,
		})
		e.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
		return v
	}

	// IPv6 function to create a packet and send it to the stack.
	// The packet should be errant in a way that causes the stack to send an
	// ICMP error response and have enough data to allow the testing of the
	// inclusion of the errant packet. Use `unknown next header' to generate
	// the error.
	rxIPv6Bad := func(e *channel.Endpoint, src tcpip.Address, payload []byte) []byte {
		hdr := prependable.New(header.IPv6MinimumSize)
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(payload)),
			TransportProtocol: reservedProtocol,
			HopLimit:          ipv6.DefaultTTL,
			SrcAddr:           src,
			DstAddr:           localIPv6Addr,
		})
		buf := bufferv2.MakeWithData(hdr.View())
		buf.Append(bufferv2.NewViewWithData(payload))
		// Take a copy before InjectInbound takes ownership of vv
		// as vv may be changed during the call.
		v := buf.Flatten()

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buf,
		})
		e.InjectInbound(header.IPv6ProtocolNumber, pkt)
		pkt.DecRef()
		return v
	}

	v4Checker := func(t *testing.T, pkt stack.PacketBufferPtr, payload []byte) {
		// We already know the entire packet is the right size so we can use its
		// length to calculate the right payload size to check.
		expectedPayloadLength := pkt.Size() - header.IPv4MinimumSize - header.ICMPv4MinimumSize
		p := stack.PayloadSince(pkt.NetworkHeader())
		defer p.Release()
		checker.IPv4(t, p,
			checker.SrcAddr(localIPv4Addr),
			checker.DstAddr(remoteIPv4Addr),
			checker.IPv4HeaderLength(header.IPv4MinimumSize),
			checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+expectedPayloadLength)),
			checker.ICMPv4(
				checker.ICMPv4Checksum(),
				checker.ICMPv4Type(header.ICMPv4DstUnreachable),
				checker.ICMPv4Code(header.ICMPv4ProtoUnreachable),
				checker.ICMPv4Payload(payload[:expectedPayloadLength]),
			),
		)
	}

	v6Checker := func(t *testing.T, pkt stack.PacketBufferPtr, payload []byte) {
		// We already know the entire packet is the right size so we can use its
		// length to calculate the right payload size to check.
		expectedPayloadLength := pkt.Size() - header.IPv6MinimumSize - header.ICMPv6MinimumSize
		p := stack.PayloadSince(pkt.NetworkHeader())
		defer p.Release()
		checker.IPv6(t, p,
			checker.SrcAddr(localIPv6Addr),
			checker.DstAddr(remoteIPv6Addr),
			checker.IPFullLength(uint16(header.IPv6MinimumSize+header.ICMPv6MinimumSize+expectedPayloadLength)),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6ParamProblem),
				checker.ICMPv6Code(header.ICMPv6UnknownHeader),
				checker.ICMPv6Payload(payload[:expectedPayloadLength]),
			),
		)
	}
	tests := []struct {
		name          string
		srcAddress    tcpip.Address
		injector      func(*channel.Endpoint, tcpip.Address, []byte) []byte
		checker       func(*testing.T, stack.PacketBufferPtr, []byte)
		payloadLength int    // Not including IP header.
		linkMTU       uint32 // Largest IP packet that the link can send as payload.
		replyLength   int    // Total size of IP/ICMP packet expected back.
	}{
		{
			name:          "IPv4 exact match",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: targetSize4 - replyHeaderLength4,
			linkMTU:       targetSize4,
			replyLength:   targetSize4,
		},
		{
			name:          "IPv4 larger MTU",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: targetSize4,
			linkMTU:       targetSize4 + 1000,
			replyLength:   targetSize4,
		},
		{
			name:          "IPv4 smaller MTU",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: targetSize4,
			linkMTU:       targetSize4 - 50,
			replyLength:   targetSize4 - 50,
		},
		{
			name:          "IPv4 payload exceeds",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: targetSize4 + 10,
			linkMTU:       targetSize4,
			replyLength:   targetSize4,
		},
		{
			name:          "IPv4 1 byte less",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: targetSize4 - replyHeaderLength4 - 1,
			linkMTU:       targetSize4,
			replyLength:   targetSize4 - 1,
		},
		{
			name:          "IPv4 No payload",
			srcAddress:    remoteIPv4Addr,
			injector:      rxIPv4Bad,
			checker:       v4Checker,
			payloadLength: 0,
			linkMTU:       targetSize4,
			replyLength:   replyHeaderLength4,
		},
		{
			name:          "IPv6 exact match",
			srcAddress:    remoteIPv6Addr,
			injector:      rxIPv6Bad,
			checker:       v6Checker,
			payloadLength: targetSize6 - replyHeaderLength6,
			linkMTU:       targetSize6,
			replyLength:   targetSize6,
		},
		{
			name:          "IPv6 larger MTU",
			srcAddress:    remoteIPv6Addr,
			injector:      rxIPv6Bad,
			checker:       v6Checker,
			payloadLength: targetSize6,
			linkMTU:       targetSize6 + 400,
			replyLength:   targetSize6,
		},
		// NB. No "smaller MTU" test here as less than 1280 is not permitted
		// in IPv6.
		{
			name:          "IPv6 payload exceeds",
			srcAddress:    remoteIPv6Addr,
			injector:      rxIPv6Bad,
			checker:       v6Checker,
			payloadLength: targetSize6,
			linkMTU:       targetSize6,
			replyLength:   targetSize6,
		},
		{
			name:          "IPv6 1 byte less",
			srcAddress:    remoteIPv6Addr,
			injector:      rxIPv6Bad,
			checker:       v6Checker,
			payloadLength: targetSize6 - replyHeaderLength6 - 1,
			linkMTU:       targetSize6,
			replyLength:   targetSize6 - 1,
		},
		{
			name:          "IPv6 no payload",
			srcAddress:    remoteIPv6Addr,
			injector:      rxIPv6Bad,
			checker:       v6Checker,
			payloadLength: 0,
			linkMTU:       targetSize6,
			replyLength:   replyHeaderLength6,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			e := addLinkEndpointToStackWithMTU(t, s, test.linkMTU)
			defer e.Close()
			// Allocate and initialize the payload view.
			payload := make([]byte, test.payloadLength)
			for i := 0; i < len(payload); i++ {
				payload[i] = uint8(i)
			}
			// Default routes for IPv4&6 so ICMP can find a route to the remote
			// node when attempting to send the ICMP error Reply.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})
			v := test.injector(e, test.srcAddress, payload)
			pkt := e.Read()
			if pkt.IsNil() {
				t.Fatal("expected a packet to be written")
			}
			if got, want := pkt.Size(), test.replyLength; got != want {
				t.Fatalf("got %d bytes of icmp error packet, want %d", got, want)
			}
			test.checker(t, pkt, v)
			pkt.DecRef()
		})
	}
}

func TestJoinLeaveAllRoutersGroup(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name           string
		netProto       tcpip.NetworkProtocolNumber
		protoFactory   stack.NetworkProtocolFactory
		allRoutersAddr tcpip.Address
	}{
		{
			name:           "IPv4",
			netProto:       ipv4.ProtocolNumber,
			protoFactory:   ipv4.NewProtocol,
			allRoutersAddr: header.IPv4AllRoutersGroup,
		},
		{
			name:           "IPv6 Interface Local",
			netProto:       ipv6.ProtocolNumber,
			protoFactory:   ipv6.NewProtocol,
			allRoutersAddr: header.IPv6AllRoutersInterfaceLocalMulticastAddress,
		},
		{
			name:           "IPv6 Link Local",
			netProto:       ipv6.ProtocolNumber,
			protoFactory:   ipv6.NewProtocol,
			allRoutersAddr: header.IPv6AllRoutersLinkLocalMulticastAddress,
		},
		{
			name:           "IPv6 Site Local",
			netProto:       ipv6.ProtocolNumber,
			protoFactory:   ipv6.NewProtocol,
			allRoutersAddr: header.IPv6AllRoutersSiteLocalMulticastAddress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, nicDisabled := range [...]bool{true, false} {
				t.Run(fmt.Sprintf("NIC Disabled = %t", nicDisabled), func(t *testing.T) {
					ctx := newTestContext()
					defer ctx.cleanup()
					s := ctx.s

					opts := stack.NICOptions{Disabled: nicDisabled}
					if err := s.CreateNICWithOptions(nicID, channel.New(0, 0, ""), opts); err != nil {
						t.Fatalf("CreateNICWithOptions(%d, _, %#v) = %s", nicID, opts, err)
					}

					if got, err := s.IsInGroup(nicID, test.allRoutersAddr); err != nil {
						t.Fatalf("s.IsInGroup(%d, %s): %s", nicID, test.allRoutersAddr, err)
					} else if got {
						t.Fatalf("got s.IsInGroup(%d, %s) = true, want = false", nicID, test.allRoutersAddr)
					}

					if err := s.SetForwardingDefaultAndAllNICs(test.netProto, true); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", test.netProto, err)
					}
					if got, err := s.IsInGroup(nicID, test.allRoutersAddr); err != nil {
						t.Fatalf("s.IsInGroup(%d, %s): %s", nicID, test.allRoutersAddr, err)
					} else if !got {
						t.Fatalf("got s.IsInGroup(%d, %s) = false, want = true", nicID, test.allRoutersAddr)
					}

					if err := s.SetForwardingDefaultAndAllNICs(test.netProto, false); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, false): %s", test.netProto, err)
					}
					if got, err := s.IsInGroup(nicID, test.allRoutersAddr); err != nil {
						t.Fatalf("s.IsInGroup(%d, %s): %s", nicID, test.allRoutersAddr, err)
					} else if got {
						t.Fatalf("got s.IsInGroup(%d, %s) = true, want = false", nicID, test.allRoutersAddr)
					}
				})
			}
		})
	}
}

func TestSetNICIDBeforeDeliveringToRawEndpoint(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name          string
		proto         tcpip.NetworkProtocolNumber
		addr          tcpip.AddressWithPrefix
		payloadOffset int
	}{
		{
			name:          "IPv4",
			proto:         header.IPv4ProtocolNumber,
			addr:          localIPv4AddrWithPrefix,
			payloadOffset: header.IPv4MinimumSize,
		},
		{
			name:          "IPv6",
			proto:         header.IPv6ProtocolNumber,
			addr:          localIPv6AddrWithPrefix,
			payloadOffset: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          test.proto,
				AddressWithPrefix: test.addr,
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: test.addr.Subnet(),
					NIC:         nicID,
				},
			})

			var wq waiter.Queue
			we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&we)
			ep, err := s.NewRawEndpoint(udp.ProtocolNumber, test.proto, &wq, true /* associated */)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.proto, err)
			}
			defer ep.Close()

			writeOpts := tcpip.WriteOptions{
				To: &tcpip.FullAddress{
					Addr: test.addr.Address,
				},
			}
			data := []byte{1, 2, 3, 4}
			var r bytes.Reader
			r.Reset(data)
			if n, err := ep.Write(&r, writeOpts); err != nil {
				t.Fatalf("ep.Write(_, _): %s", err)
			} else if want := int64(len(data)); n != want {
				t.Fatalf("got ep.Write(_, _) = (%d, nil), want = (%d, nil)", n, want)
			}

			// Wait for the endpoint to become readable.
			<-ch

			var w bytes.Buffer
			rr, err := ep.Read(&w, tcpip.ReadOptions{
				NeedRemoteAddr: true,
			})
			if err != nil {
				t.Fatalf("ep.Read(...): %s", err)
			}
			if diff := cmp.Diff(data, w.Bytes()[test.payloadOffset:]); diff != "" {
				t.Errorf("payload mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tcpip.FullAddress{Addr: test.addr.Address, NIC: nicID}, rr.RemoteAddr); diff != "" {
				t.Errorf("remote addr mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
