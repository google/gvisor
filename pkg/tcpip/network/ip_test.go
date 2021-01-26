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
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	localIPv4Addr  = tcpip.Address("\x0a\x00\x00\x01")
	remoteIPv4Addr = tcpip.Address("\x0a\x00\x00\x02")
	ipv4SubnetAddr = tcpip.Address("\x0a\x00\x00\x00")
	ipv4SubnetMask = tcpip.Address("\xff\xff\xff\x00")
	ipv4Gateway    = tcpip.Address("\x0a\x00\x00\x03")
	localIPv6Addr  = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	remoteIPv6Addr = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
	ipv6SubnetAddr = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	ipv6SubnetMask = tcpip.Address("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00")
	ipv6Gateway    = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
	nicID          = 1
)

var localIPv4AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv4Addr,
	PrefixLen: 24,
}

var localIPv6AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv6Addr,
	PrefixLen: 120,
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
	typ      stack.ControlType
	extra    uint32

	dataCalls    int
	controlCalls int
}

// checkValues verifies that the transport protocol, data contents, src & dst
// addresses of a packet match what's expected. If any field doesn't match, the
// test fails.
func (t *testObject) checkValues(protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView, srcAddr, dstAddr tcpip.Address) {
	v := vv.ToView()
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
func (t *testObject) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *stack.PacketBuffer) stack.TransportPacketDisposition {
	netHdr := pkt.Network()
	t.checkValues(protocol, pkt.Data, netHdr.SourceAddress(), netHdr.DestinationAddress())
	t.dataCalls++
	return stack.TransportPacketHandled
}

// DeliverTransportControlPacket is called by network endpoints after parsing
// incoming control (ICMP) packets. This is used by the test object to verify
// that the results of the parsing are expected.
func (t *testObject) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	t.checkValues(trans, pkt.Data, remote, local)
	if typ != t.typ {
		t.t.Errorf("typ = %v, want %v", typ, t.typ)
	}
	if extra != t.extra {
		t.t.Errorf("extra = %v, want %v", extra, t.extra)
	}
	t.controlCalls++
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
func (t *testObject) WritePacket(_ *stack.Route, _ *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	var prot tcpip.TransportProtocolNumber
	var srcAddr tcpip.Address
	var dstAddr tcpip.Address

	if t.v4 {
		h := header.IPv4(pkt.NetworkHeader().View())
		prot = tcpip.TransportProtocolNumber(h.Protocol())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()

	} else {
		h := header.IPv6(pkt.NetworkHeader().View())
		prot = tcpip.TransportProtocolNumber(h.NextHeader())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()
	}
	t.checkValues(prot, pkt.Data, srcAddr, dstAddr)
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (*testObject) WritePackets(_ *stack.Route, _ *stack.GSO, pkt stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*testObject) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*testObject) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("not implemented")
}

func buildIPv4Route(local, remote tcpip.Address) (*stack.Route, *tcpip.Error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})
	s.CreateNIC(nicID, loopback.New())
	s.AddAddress(nicID, ipv4.ProtocolNumber, local)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     ipv4Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv4.ProtocolNumber, false /* multicastLoop */)
}

func buildIPv6Route(local, remote tcpip.Address) (*stack.Route, *tcpip.Error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})
	s.CreateNIC(nicID, loopback.New())
	s.AddAddress(nicID, ipv6.ProtocolNumber, local)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		Gateway:     ipv6Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv6.ProtocolNumber, false /* multicastLoop */)
}

func buildDummyStackWithLinkEndpoint(t *testing.T, mtu uint32) (*stack.Stack, *channel.Endpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})
	e := channel.New(1, mtu, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	v4Addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: localIPv4AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v4Addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v) = %s", nicID, v4Addr, err)
	}

	v6Addr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: localIPv6AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v6Addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v) = %s", nicID, v6Addr, err)
	}

	return s, e
}

func buildDummyStack(t *testing.T) *stack.Stack {
	t.Helper()

	s, _ := buildDummyStackWithLinkEndpoint(t, header.IPv6MinimumMTU)
	return s
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

func (t *testInterface) setEnabled(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mu.disabled = !v
}

func (*testInterface) WritePacketToRemote(tcpip.LinkAddress, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func TestSourceAddressValidation(t *testing.T) {
	rxIPv4ICMP := func(e *channel.Endpoint, src tcpip.Address) {
		totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		pkt.SetType(header.ICMPv4Echo)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^header.Checksum(pkt, 0))
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    uint8(icmp.ProtocolNumber4),
			TTL:         ipv4.DefaultTTL,
			SrcAddr:     src,
			DstAddr:     localIPv4Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())

		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	rxIPv6ICMP := func(e *channel.Endpoint, src tcpip.Address) {
		totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
		pkt.SetType(header.ICMPv6EchoRequest)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, src, localIPv6Addr, buffer.VectorisedView{}))
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     header.ICMPv6MinimumSize,
			TransportProtocol: icmp.ProtocolNumber6,
			HopLimit:          ipv6.DefaultTTL,
			SrcAddr:           src,
			DstAddr:           localIPv6Addr,
		})
		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	tests := []struct {
		name       string
		srcAddress tcpip.Address
		rxICMP     func(*channel.Endpoint, tcpip.Address)
		valid      bool
	}{
		{
			name:       "IPv4 valid",
			srcAddress: "\x01\x02\x03\x04",
			rxICMP:     rxIPv4ICMP,
			valid:      true,
		},
		{
			name:       "IPv6 valid",
			srcAddress: "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
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
			srcAddress: "\xe0\x00\x00\x01",
			rxICMP:     rxIPv4ICMP,
			valid:      false,
		},
		{
			name:       "IPv6 multicast",
			srcAddress: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
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
			s, e := buildDummyStackWithLinkEndpoint(t, header.IPv6MinimumMTU)
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
			p := s.NetworkProtocolInstance(test.protoNum)

			// We pass nil for all parameters except the NetworkInterface and Stack
			// since Enable only depends on these.
			ep := p.NewEndpoint(&nic, nil, nil, nil)

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
			if err := ep.Enable(); err != tcpip.ErrNotPermitted {
				t.Fatalf("got ep.Enable() = %s, want = %s", err, tcpip.ErrNotPermitted)
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
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, nil)
	defer ep.Close()

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Data:               payload.ToVectorisedView(),
	})

	// Issue the write.
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv4Addr
	nic.testObject.dstAddr = remoteIPv4Addr
	nic.testObject.contents = payload

	r, err := buildIPv4Route(localIPv4Addr, remoteIPv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	if err := ep.WritePacket(r, nil /* gso */, stack.NetworkHeaderParams{
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

				view := buffer.NewView(totalLen)
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
					Data: view.ToVectorisedView(),
				})
				if ok := parse.IPv4(pkt); !ok {
					t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
				}
				ep.HandlePacket(pkt)
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
				view := buffer.NewView(header.IPv6MinimumSize + payloadLen)
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
					Data: view.ToVectorisedView(),
				})
				if _, _, _, _, ok := parse.IPv6(pkt); !ok {
					t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
				}
				ep.HandlePacket(pkt)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{test.protoFactory},
			})
			nic := testInterface{
				testObject: testObject{
					t:  t,
					v4: test.v4,
				},
			}
			ep := s.NetworkProtocolInstance(test.protoNum).NewEndpoint(&nic, nil, nil, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatalf("expected network endpoint with number = %d to implement stack.AddressableEndpoint", test.protoNum)
			}
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(test.epAddr, stack.CanBePrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, CanBePrimaryEndpoint, AddressConfigStatic, false): %s", test.epAddr, err)
			} else {
				ep.DecRef()
			}

			stat := s.Stats().IP.PacketsReceived
			if got := stat.Value(); got != 0 {
				t.Fatalf("got s.Stats().IP.PacketsReceived.Value() = %d, want = 0", got)
			}
			test.handlePacket(t, ep, &nic)
			if nic.testObject.dataCalls != 1 {
				t.Errorf("Bad number of data calls: got %x, want 1", nic.testObject.dataCalls)
			}
			if got := stat.Value(); got != 1 {
				t.Errorf("got s.Stats().IP.PacketsReceived.Value() = %d, want = 1", got)
			}
		})
	}
}

func TestIPv4ReceiveControl(t *testing.T) {
	const mtu = 0xbeef - header.IPv4MinimumSize
	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset uint16
		code           header.ICMPv4Code
		expectedTyp    stack.ControlType
		expectedExtra  uint32
		trunc          int
	}{
		{"FragmentationNeeded", 1, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 0},
		{"Truncated (10 bytes missing)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 10},
		{"Truncated (missing IPv4 header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.IPv4MinimumSize + 8},
		{"Truncated (missing 'extra info')", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 4 + header.IPv4MinimumSize + 8},
		{"Truncated (missing ICMP header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.ICMPv4MinimumSize + header.IPv4MinimumSize + 8},
		{"Port unreachable", 1, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Non-zero fragment offset", 0, 100, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Zero-length packet", 0, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 2*header.IPv4MinimumSize + header.ICMPv4MinimumSize + 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := buildDummyStack(t)
			proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			const dataOffset = header.IPv4MinimumSize*2 + header.ICMPv4MinimumSize
			view := buffer.NewView(dataOffset + 8)

			// Create the outer IPv4 header.
			ip := header.IPv4(view)
			ip.Encode(&header.IPv4Fields{
				TotalLength: uint16(len(view) - c.trunc),
				TTL:         20,
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				SrcAddr:     "\x0a\x00\x00\xbb",
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
			checksum := ^header.Checksum(icmp, 0 /* initial */)
			icmp.SetChecksum(checksum)

			// Give packet to IPv4 endpoint, dispatcher will validate that
			// it's ok.
			nic.testObject.protocol = 10
			nic.testObject.srcAddr = remoteIPv4Addr
			nic.testObject.dstAddr = localIPv4Addr
			nic.testObject.contents = view[dataOffset:]
			nic.testObject.typ = c.expectedTyp
			nic.testObject.extra = c.expectedExtra

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatal("expected IPv4 network endpoint to implement stack.AddressableEndpoint")
			}
			addr := localIPv4Addr.WithPrefix()
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.CanBePrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, CanBePrimaryEndpoint, AddressConfigStatic, false): %s", addr, err)
			} else {
				ep.DecRef()
			}

			pkt := truncatedPacket(view, c.trunc, header.IPv4MinimumSize)
			ep.HandlePacket(pkt)
			if want := c.expectedCount; nic.testObject.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, nic.testObject.controlCalls, want)
			}
		})
	}
}

func TestIPv4FragmentationReceive(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	totalLen := header.IPv4MinimumSize + 24

	frag1 := buffer.NewView(totalLen)
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

	frag2 := buffer.NewView(totalLen)
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

	// Send first segment.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag1.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}

	addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
	if !ok {
		t.Fatal("expected IPv4 network endpoint to implement stack.AddressableEndpoint")
	}
	addr := localIPv4Addr.WithPrefix()
	if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.CanBePrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */); err != nil {
		t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, CanBePrimaryEndpoint, AddressConfigStatic, false): %s", addr, err)
	} else {
		ep.DecRef()
	}

	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 0 {
		t.Fatalf("Bad number of data calls: got %x, want 0", nic.testObject.dataCalls)
	}

	// Send second segment.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag2.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", nic.testObject.dataCalls)
	}
}

func TestIPv6Send(t *testing.T) {
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t: t,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, nil)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Data:               payload.ToVectorisedView(),
	})

	// Issue the write.
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv6Addr
	nic.testObject.dstAddr = remoteIPv6Addr
	nic.testObject.contents = payload

	r, err := buildIPv6Route(localIPv6Addr, remoteIPv6Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	if err := ep.WritePacket(r, nil /* gso */, stack.NetworkHeaderParams{
		Protocol: 123,
		TTL:      123,
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv6ReceiveControl(t *testing.T) {
	newUint16 := func(v uint16) *uint16 { return &v }

	const mtu = 0xffff
	const outerSrcAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa"
	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset *uint16
		typ            header.ICMPv6Type
		code           header.ICMPv6Code
		expectedTyp    stack.ControlType
		expectedExtra  uint32
		trunc          int
	}{
		{"PacketTooBig", 1, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 0},
		{"Truncated (10 bytes missing)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 10},
		{"Truncated (missing IPv6 header)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, header.IPv6MinimumSize + 8},
		{"Truncated PacketTooBig (missing 'extra info')", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 4 + header.IPv6MinimumSize + 8},
		{"Truncated (missing ICMP header)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, header.ICMPv6PacketTooBigMinimumSize + header.IPv6MinimumSize + 8},
		{"Port unreachable", 1, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Truncated DstUnreachable (missing 'extra info')", 0, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 4 + header.IPv6MinimumSize + 8},
		{"Fragmented, zero offset", 1, newUint16(0), header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Non-zero fragment offset", 0, newUint16(100), header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Zero-length packet", 0, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 2*header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := buildDummyStack(t)
			proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			dataOffset := header.IPv6MinimumSize*2 + header.ICMPv6MinimumSize
			if c.fragmentOffset != nil {
				dataOffset += header.IPv6FragmentHeaderSize
			}
			view := buffer.NewView(dataOffset + 8)

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
			nic.testObject.typ = c.expectedTyp
			nic.testObject.extra = c.expectedExtra

			// Set ICMPv6 checksum.
			icmp.SetChecksum(header.ICMPv6Checksum(icmp, outerSrcAddr, localIPv6Addr, buffer.VectorisedView{}))

			addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
			if !ok {
				t.Fatal("expected IPv6 network endpoint to implement stack.AddressableEndpoint")
			}
			addr := localIPv6Addr.WithPrefix()
			if ep, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.CanBePrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */); err != nil {
				t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, CanBePrimaryEndpoint, AddressConfigStatic, false): %s", addr, err)
			} else {
				ep.DecRef()
			}
			pkt := truncatedPacket(view, c.trunc, header.IPv6MinimumSize)
			ep.HandlePacket(pkt)
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
func truncatedPacket(view buffer.View, trunc, netHdrLen int) *stack.PacketBuffer {
	v := view[:len(view)-trunc]
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: v.ToVectorisedView(),
	})
	_, _ = pkt.NetworkHeader().Consume(netHdrLen)
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
		nicAddr      tcpip.Address
		remoteAddr   tcpip.Address
		pktGen       func(*testing.T, tcpip.Address) buffer.VectorisedView
		checker      func(*testing.T, *stack.PacketBuffer, tcpip.Address)
		expectedErr  *tcpip.Error
	}{
		{
			name:         "IPv4",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv4MinimumSize)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				ip.SetHeaderLength(header.IPv4MinimumSize - 1)
				return hdr.View().ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
		},
		{
			name:         "IPv4 too small",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return buffer.View(ip[:len(ip)-1]).ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
		},
		{
			name:         "IPv4 minimum size",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return buffer.View(ip).ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv4MinimumSize)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ipHdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				totalLen := ipHdrLen + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(ipHdrLen))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
					Options:  ipv4Options,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				if len(netHdr.View()) != hdrLen {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), hdrLen)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize+ipv4Options.Length()))
				ip.Encode(&header.IPv4Fields{
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
					Options:  ipv4Options,
				})
				vv := buffer.View(ip).ToVectorisedView()
				vv.AppendView(data)
				return vv
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := int(header.IPv4MinimumSize + ipv4Options.Length())
				if len(netHdr.View()) != hdrLen {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), hdrLen)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv6MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv6MinimumSize)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv6MinimumSize + len(ipv6FragmentExtHdr) + len(data)
				hdr := buffer.NewPrependable(totalLen)
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
					DstAddr:           header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if want := header.IPv6MinimumSize + len(ipv6FragmentExtHdr); len(netHdr.View()) != want {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), want)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           header.IPv4Any,
				})
				return buffer.View(ip).ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv6MinimumSize)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
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
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					TransportProtocol: transportProto,
					HopLimit:          ipv6.DefaultTTL,
					SrcAddr:           src,
					DstAddr:           header.IPv4Any,
				})
				return buffer.View(ip[:len(ip)-1]).ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
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
					srcAddr: tcpip.Address(strings.Repeat("\x00", len(test.nicAddr))),
				},
				{
					name:    "random source",
					srcAddr: tcpip.Address(strings.Repeat("\xab", len(test.nicAddr))),
				},
			}

			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{test.protoFactory},
					})
					e := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					if err := s.AddAddress(nicID, test.protoNum, test.nicAddr); err != nil {
						t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, test.protoNum, test.nicAddr, err)
					}

					s.SetRouteTable([]tcpip.Route{{Destination: test.remoteAddr.WithPrefix().Subnet(), NIC: nicID}})

					r, err := s.FindRoute(nicID, test.nicAddr, test.remoteAddr, test.protoNum, false /* multicastLoop */)
					if err != nil {
						t.Fatalf("s.FindRoute(%d, %s, %s, %d, false): %s", nicID, test.remoteAddr, test.nicAddr, test.protoNum, err)
					}
					defer r.Release()

					if err := r.WriteHeaderIncludedPacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
						Data: test.pktGen(t, subTest.srcAddr),
					})); err != test.expectedErr {
						t.Fatalf("got r.WriteHeaderIncludedPacket(_) = %s, want = %s", err, test.expectedErr)
					}

					if test.expectedErr != nil {
						return
					}

					pkt, ok := e.Read()
					if !ok {
						t.Fatal("expected a packet to be written")
					}
					test.checker(t, pkt.Pkt, subTest.srcAddr)
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
	rxIPv4Bad := func(e *channel.Endpoint, src tcpip.Address, payload []byte) buffer.View {
		totalLen := header.IPv4MinimumSize + len(payload)
		hdr := buffer.NewPrependable(header.IPv4MinimumSize)
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    reservedProtocol,
			TTL:         ipv4.DefaultTTL,
			SrcAddr:     src,
			DstAddr:     localIPv4Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		vv := hdr.View().ToVectorisedView()
		vv.AppendView(buffer.View(payload))
		// Take a copy before InjectInbound takes ownership of vv
		// as vv may be changed during the call.
		v := vv.ToView()
		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: vv,
		}))
		return v
	}

	// IPv6 function to create a packet and send it to the stack.
	// The packet should be errant in a way that causes the stack to send an
	// ICMP error response and have enough data to allow the testing of the
	// inclusion of the errant packet. Use `unknown next header' to generate
	// the error.
	rxIPv6Bad := func(e *channel.Endpoint, src tcpip.Address, payload []byte) buffer.View {
		hdr := buffer.NewPrependable(header.IPv6MinimumSize)
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(payload)),
			TransportProtocol: reservedProtocol,
			HopLimit:          ipv6.DefaultTTL,
			SrcAddr:           src,
			DstAddr:           localIPv6Addr,
		})
		vv := hdr.View().ToVectorisedView()
		vv.AppendView(buffer.View(payload))
		// Take a copy before InjectInbound takes ownership of vv
		// as vv may be changed during the call.
		v := vv.ToView()

		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: vv,
		}))
		return v
	}

	v4Checker := func(t *testing.T, pkt *stack.PacketBuffer, payload buffer.View) {
		// We already know the entire packet is the right size so we can use its
		// length to calculate the right payload size to check.
		expectedPayloadLength := pkt.Size() - header.IPv4MinimumSize - header.ICMPv4MinimumSize
		checker.IPv4(t, stack.PayloadSince(pkt.NetworkHeader()),
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

	v6Checker := func(t *testing.T, pkt *stack.PacketBuffer, payload buffer.View) {
		// We already know the entire packet is the right size so we can use its
		// length to calculate the right payload size to check.
		expectedPayloadLength := pkt.Size() - header.IPv6MinimumSize - header.ICMPv6MinimumSize
		checker.IPv6(t, stack.PayloadSince(pkt.NetworkHeader()),
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
		injector      func(*channel.Endpoint, tcpip.Address, []byte) buffer.View
		checker       func(*testing.T, *stack.PacketBuffer, buffer.View)
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
			s, e := buildDummyStackWithLinkEndpoint(t, test.linkMTU)
			// Allocate and initialize the payload view.
			payload := buffer.NewView(test.payloadLength)
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
			pkt, ok := e.Read()
			if !ok {
				t.Fatal("expected a packet to be written")
			}
			if got, want := pkt.Pkt.Size(), test.replyLength; got != want {
				t.Fatalf("got %d bytes of icmp error packet, want %d", got, want)
			}
			test.checker(t, pkt.Pkt, v)
		})
	}
}
