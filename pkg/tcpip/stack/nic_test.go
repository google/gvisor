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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ AddressableEndpoint = (*testIPv6Endpoint)(nil)
var _ NetworkEndpoint = (*testIPv6Endpoint)(nil)
var _ NDPEndpoint = (*testIPv6Endpoint)(nil)

// An IPv6 NetworkEndpoint that throws away outgoing packets.
//
// We use this instead of ipv6.endpoint because the ipv6 package depends on
// the stack package which this test lives in, causing a cyclic dependency.
type testIPv6Endpoint struct {
	AddressableEndpointState

	nic      NetworkInterface
	protocol *testIPv6Protocol

	invalidatedRtr tcpip.Address
}

func (*testIPv6Endpoint) Enable() *tcpip.Error {
	return nil
}

func (*testIPv6Endpoint) Enabled() bool {
	return true
}

func (*testIPv6Endpoint) Disable() {}

// DefaultTTL implements NetworkEndpoint.DefaultTTL.
func (*testIPv6Endpoint) DefaultTTL() uint8 {
	return 0
}

// MTU implements NetworkEndpoint.MTU.
func (e *testIPv6Endpoint) MTU() uint32 {
	return e.nic.MTU() - header.IPv6MinimumSize
}

// MaxHeaderLength implements NetworkEndpoint.MaxHeaderLength.
func (e *testIPv6Endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv6MinimumSize
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

// HandlePacket implements NetworkEndpoint.HandlePacket.
func (*testIPv6Endpoint) HandlePacket(*Route, *PacketBuffer) {
}

// Close implements NetworkEndpoint.Close.
func (e *testIPv6Endpoint) Close() {
	e.AddressableEndpointState.Cleanup()
}

// NetworkProtocolNumber implements NetworkEndpoint.NetworkProtocolNumber.
func (*testIPv6Endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

func (e *testIPv6Endpoint) InvalidateDefaultRouter(rtr tcpip.Address) {
	e.invalidatedRtr = rtr
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
func (p *testIPv6Protocol) NewEndpoint(nic NetworkInterface, _ LinkAddressCache, _ NUDHandler, _ TransportDispatcher) NetworkEndpoint {
	e := &testIPv6Endpoint{
		nic:      nic,
		protocol: p,
	}
	e.AddressableEndpointState.Init(e)
	return e
}

// SetOption implements NetworkProtocol.SetOption.
func (*testIPv6Protocol) SetOption(tcpip.SettableNetworkProtocolOption) *tcpip.Error {
	return nil
}

// Option implements NetworkProtocol.Option.
func (*testIPv6Protocol) Option(tcpip.GettableNetworkProtocolOption) *tcpip.Error {
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
func (*testIPv6Protocol) LinkAddressRequest(_, _ tcpip.Address, _ tcpip.LinkAddress, _ NetworkInterface) *tcpip.Error {
	return nil
}

// ResolveStaticAddress implements LinkAddressResolver.
func (*testIPv6Protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return "", false
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

	nic.DeliverNetworkPacket("", "", 0, NewPacketBuffer(PacketBufferOptions{
		Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView(),
	}))

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
