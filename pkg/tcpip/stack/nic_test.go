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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
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

func (*testIPv6Endpoint) Enable() tcpip.Error {
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
func (*testIPv6Endpoint) WritePacket(*Route, NetworkHeaderParams, *PacketBuffer) tcpip.Error {
	return nil
}

// WritePackets implements NetworkEndpoint.WritePackets.
func (*testIPv6Endpoint) WritePackets(*Route, PacketBufferList, NetworkHeaderParams) (int, tcpip.Error) {
	// Our tests don't use this so we don't support it.
	return 0, &tcpip.ErrNotSupported{}
}

// WriteHeaderIncludedPacket implements
// NetworkEndpoint.WriteHeaderIncludedPacket.
func (*testIPv6Endpoint) WriteHeaderIncludedPacket(*Route, *PacketBuffer) tcpip.Error {
	// Our tests don't use this so we don't support it.
	return &tcpip.ErrNotSupported{}
}

// HandlePacket implements NetworkEndpoint.HandlePacket.
func (*testIPv6Endpoint) HandlePacket(*PacketBuffer) {}

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

// Stats implements NetworkEndpoint.
func (*testIPv6Endpoint) Stats() NetworkEndpointStats {
	return &testIPv6EndpointStats{}
}

var _ NetworkEndpointStats = (*testIPv6EndpointStats)(nil)

type testIPv6EndpointStats struct{}

// IsNetworkEndpointStats implements stack.NetworkEndpointStats.
func (*testIPv6EndpointStats) IsNetworkEndpointStats() {}

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

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*testIPv6Protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv6(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint implements NetworkProtocol.NewEndpoint.
func (p *testIPv6Protocol) NewEndpoint(nic NetworkInterface, _ TransportDispatcher) NetworkEndpoint {
	e := &testIPv6Endpoint{
		nic:      nic,
		protocol: p,
	}
	e.AddressableEndpointState.Init(e)
	return e
}

// SetOption implements NetworkProtocol.SetOption.
func (*testIPv6Protocol) SetOption(tcpip.SettableNetworkProtocolOption) tcpip.Error {
	return nil
}

// Option implements NetworkProtocol.Option.
func (*testIPv6Protocol) Option(tcpip.GettableNetworkProtocolOption) tcpip.Error {
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

func TestDisabledRxStatsWhenNICDisabled(t *testing.T) {
	// When the NIC is disabled, the only field that matters is the stats field.
	// This test is limited to stats counter checks.
	nic := nic{
		stats: makeNICStats(tcpip.NICStats{}.FillIn()),
	}

	if got := nic.stats.local.DisabledRx.Packets.Value(); got != 0 {
		t.Errorf("got DisabledRx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.local.DisabledRx.Bytes.Value(); got != 0 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 0", got)
	}
	if got := nic.stats.local.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.local.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}

	if t.Failed() {
		t.FailNow()
	}

	nic.DeliverNetworkPacket("", "", 0, NewPacketBuffer(PacketBufferOptions{
		Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView(),
	}))

	if got := nic.stats.local.DisabledRx.Packets.Value(); got != 1 {
		t.Errorf("got DisabledRx.Packets = %d, want = 1", got)
	}
	if got := nic.stats.local.DisabledRx.Bytes.Value(); got != 4 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 4", got)
	}
	if got := nic.stats.local.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.local.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}
}

func TestPacketWithUnknownNetworkProtocolNumber(t *testing.T) {
	nic := nic{
		stats:   makeNICStats(tcpip.NICStats{}.FillIn()),
		enabled: 1,
	}
	// IPv4 isn't recognized since we haven't initialized the NIC with an IPv4
	// endpoint.
	nic.DeliverNetworkPacket("", "", header.IPv4ProtocolNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView(),
	}))
	var count uint64
	if got, ok := nic.stats.local.UnknownL3ProtocolRcvdPacketCounts.Get(uint64(header.IPv4ProtocolNumber)); ok {
		count = got.Value()
	}
	if count != 1 {
		t.Errorf("got UnknownL3ProtocolRcvdPacketCounts[header.IPv4ProtocolNumber] = %d, want = 1", count)
	}
}

func TestPacketWithUnknownTransportProtocolNumber(t *testing.T) {
	nic := nic{
		stack:   &Stack{},
		stats:   makeNICStats(tcpip.NICStats{}.FillIn()),
		enabled: 1,
	}
	// UDP isn't recognized since we haven't initialized the NIC with a UDP
	// protocol.
	nic.DeliverTransportPacket(header.UDPProtocolNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView(),
	}))
	var count uint64
	if got, ok := nic.stats.local.UnknownL4ProtocolRcvdPacketCounts.Get(uint64(header.UDPProtocolNumber)); ok {
		count = got.Value()
	}
	if count != 1 {
		t.Errorf("got UnknownL4ProtocolRcvdPacketCounts[header.UDPProtocolNumber] = %d, want = 1", count)
	}
}

func TestMultiCounterStatsInitialization(t *testing.T) {
	global := tcpip.NICStats{}.FillIn()
	nic := nic{
		stats: makeNICStats(global),
	}
	multi := nic.stats.multiCounterNICStats
	local := nic.stats.local
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&multi).Elem(), []reflect.Value{reflect.ValueOf(&local).Elem(), reflect.ValueOf(&global).Elem()}, testutil.ValidateMultiCounterStatsOptions{
		ExpectMultiCounterStat:            true,
		ExpectMultiIntegralStatCounterMap: true,
	}); err != nil {
		t.Error(err)
	}
}
