// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ LinkEndpoint = (*testLinkEndpoint)(nil)

// A LinkEndpoint that throws away outgoing packets.
//
// We use this instead of the channel endpoint as the channel package depends on
// the stack package which this test lives in, causing a cyclic dependency.
type testLinkEndpoint struct {
	dispatcher NetworkDispatcher
}

// Attach implements LinkEndpoint.Attach.
func (e *testLinkEndpoint) Attach(dispatcher NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements LinkEndpoint.IsAttached.
func (e *testLinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements LinkEndpoint.MTU.
func (*testLinkEndpoint) MTU() uint32 {
	return math.MaxUint16
}

// Capabilities implements LinkEndpoint.Capabilities.
func (*testLinkEndpoint) Capabilities() LinkEndpointCapabilities {
	return CapabilityResolutionRequired
}

// MaxHeaderLength implements LinkEndpoint.MaxHeaderLength.
func (*testLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*testLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Wait implements LinkEndpoint.Wait.
func (*testLinkEndpoint) Wait() {}

// WritePacket implements LinkEndpoint.WritePacket.
func (e *testLinkEndpoint) WritePacket(*Route, *GSO, tcpip.NetworkProtocolNumber, *PacketBuffer) *tcpip.Error {
	return nil
}

// WritePackets implements LinkEndpoint.WritePackets.
func (e *testLinkEndpoint) WritePackets(*Route, *GSO, PacketBufferList, tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	// Our tests don't use this so we don't support it.
	return 0, tcpip.ErrNotSupported
}

// WriteRawPacket implements LinkEndpoint.WriteRawPacket.
func (e *testLinkEndpoint) WriteRawPacket(buffer.VectorisedView) *tcpip.Error {
	// Our tests don't use this so we don't support it.
	return tcpip.ErrNotSupported
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*testLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

var _ NetworkEndpoint = (*testIPv6Endpoint)(nil)

// An IPv6 NetworkEndpoint that throws away outgoing packets.
//
// We use this instead of ipv6.endpoint because the ipv6 package depends on
// the stack package which this test lives in, causing a cyclic dependency.
type testIPv6Endpoint struct {
	nicID     tcpip.NICID
	id        NetworkEndpointID
	prefixLen int
	linkEP    LinkEndpoint
	protocol  *testIPv6Protocol
}

// DefaultTTL implements NetworkEndpoint.DefaultTTL.
func (*testIPv6Endpoint) DefaultTTL() uint8 {
	return 0
}

// MTU implements NetworkEndpoint.MTU.
func (e *testIPv6Endpoint) MTU() uint32 {
	return e.linkEP.MTU() - header.IPv6MinimumSize
}

// Capabilities implements NetworkEndpoint.Capabilities.
func (e *testIPv6Endpoint) Capabilities() LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

// MaxHeaderLength implements NetworkEndpoint.MaxHeaderLength.
func (e *testIPv6Endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv6MinimumSize
}

// WritePacket implements NetworkEndpoint.WritePacket.
func (*testIPv6Endpoint) WritePacket(*Route, *GSO, NetworkHeaderParams, *PacketBuffer) *tcpip.Error {
	return nil
}

// WritePackets implements NetworkEndpoint.WritePackets.
func (*testIPv6Endpoint) WritePackets(*Route, *GSO, PacketBufferList, NetworkHeaderParams) (int, *tcpip.Error) {
	// Our tests don't use this so we don't support it.
	return 0, tcpip.ErrNotSupported
}

// WriteHeaderIncludedPacket implements
// NetworkEndpoint.WriteHeaderIncludedPacket.
func (*testIPv6Endpoint) WriteHeaderIncludedPacket(*Route, *PacketBuffer) *tcpip.Error {
	// Our tests don't use this so we don't support it.
	return tcpip.ErrNotSupported
}

// ID implements NetworkEndpoint.ID.
func (e *testIPv6Endpoint) ID() *NetworkEndpointID {
	return &e.id
}

// PrefixLen implements NetworkEndpoint.PrefixLen.
func (e *testIPv6Endpoint) PrefixLen() int {
	return e.prefixLen
}

// NICID implements NetworkEndpoint.NICID.
func (e *testIPv6Endpoint) NICID() tcpip.NICID {
	return e.nicID
}

// HandlePacket implements NetworkEndpoint.HandlePacket.
func (*testIPv6Endpoint) HandlePacket(*Route, *PacketBuffer) {
}

// Close implements NetworkEndpoint.Close.
func (*testIPv6Endpoint) Close() {}

// NetworkProtocolNumber implements NetworkEndpoint.NetworkProtocolNumber.
func (*testIPv6Endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

var _ NetworkProtocol = (*testIPv6Protocol)(nil)

// An IPv6 NetworkProtocol that supports the bare minimum to make a stack
// believe it supports IPv6.
//
// We use this instead of ipv6.protocol because the ipv6 package depends on
// the stack package which this test lives in, causing a cyclic dependency.
type testIPv6Protocol struct{}

// Number implements NetworkProtocol.Number.
func (*testIPv6Protocol) Number() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// MinimumPacketSize implements NetworkProtocol.MinimumPacketSize.
func (*testIPv6Protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

// DefaultPrefixLen implements NetworkProtocol.DefaultPrefixLen.
func (*testIPv6Protocol) DefaultPrefixLen() int {
	return header.IPv6AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*testIPv6Protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv6(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint implements NetworkProtocol.NewEndpoint.
func (p *testIPv6Protocol) NewEndpoint(nicID tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, _ LinkAddressCache, _ TransportDispatcher, linkEP LinkEndpoint, _ *Stack) (NetworkEndpoint, *tcpip.Error) {
	return &testIPv6Endpoint{
		nicID:     nicID,
		id:        NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen: addrWithPrefix.PrefixLen,
		linkEP:    linkEP,
		protocol:  p,
	}, nil
}

// SetOption implements NetworkProtocol.SetOption.
func (*testIPv6Protocol) SetOption(interface{}) *tcpip.Error {
	return nil
}

// Option implements NetworkProtocol.Option.
func (*testIPv6Protocol) Option(interface{}) *tcpip.Error {
	return nil
}

// Close implements NetworkProtocol.Close.
func (*testIPv6Protocol) Close() {}

// Wait implements NetworkProtocol.Wait.
func (*testIPv6Protocol) Wait() {}

// Parse implements NetworkProtocol.Parse.
func (*testIPv6Protocol) Parse(*PacketBuffer) (tcpip.TransportProtocolNumber, bool, bool) {
	return 0, false, false
}

var _ LinkAddressResolver = (*testIPv6Protocol)(nil)

// LinkAddressProtocol implements LinkAddressResolver.
func (*testIPv6Protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements LinkAddressResolver.
func (*testIPv6Protocol) LinkAddressRequest(_, _ tcpip.Address, _ LinkEndpoint) *tcpip.Error {
	return nil
}

// ResolveStaticAddress implements LinkAddressResolver.
func (*testIPv6Protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return "", false
}

// Test the race condition where a NIC is removed and an RS timer fires at the
// same time.
func TestRemoveNICWhileHandlingRSTimer(t *testing.T) {
	const (
		nicID = 1

		maxRtrSolicitations = 5
	)

	e := testLinkEndpoint{}
	s := New(Options{
		NetworkProtocols: []NetworkProtocol{&testIPv6Protocol{}},
		NDPConfigs: NDPConfigurations{
			MaxRtrSolicitations:     maxRtrSolicitations,
			RtrSolicitationInterval: minimumRtrSolicitationInterval,
		},
	})

	if err := s.CreateNIC(nicID, &e); err != nil {
		t.Fatalf("s.CreateNIC(%d, _) = %s", nicID, err)
	}

	s.mu.Lock()
	// Wait for the router solicitation timer to fire and block trying to obtain
	// the stack lock when doing link address resolution.
	time.Sleep(minimumRtrSolicitationInterval * 2)
	if err := s.removeNICLocked(nicID); err != nil {
		t.Fatalf("s.removeNICLocked(%d) = %s", nicID, err)
	}
	s.mu.Unlock()
}

func TestDisabledRxStatsWhenNICDisabled(t *testing.T) {
	// When the NIC is disabled, the only field that matters is the stats field.
	// This test is limited to stats counter checks.
	nic := NIC{
		stats: makeNICStats(),
	}

	if got := nic.stats.DisabledRx.Packets.Value(); got != 0 {
		t.Errorf("got DisabledRx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.DisabledRx.Bytes.Value(); got != 0 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}

	if t.Failed() {
		t.FailNow()
	}

	nic.DeliverNetworkPacket("", "", 0, &PacketBuffer{Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView()})

	if got := nic.stats.DisabledRx.Packets.Value(); got != 1 {
		t.Errorf("got DisabledRx.Packets = %d, want = 1", got)
	}
	if got := nic.stats.DisabledRx.Bytes.Value(); got != 4 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 4", got)
	}
	if got := nic.stats.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}
}
