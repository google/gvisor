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

package packetsocket_test

import (
	"math"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/packetsocket"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*nullEndpoint)(nil)

type nullEndpoint struct {
	disp stack.NetworkDispatcher
}

func (*nullEndpoint) MTU() uint32 {
	return math.MaxUint32
}
func (*nullEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}
func (*nullEndpoint) MaxHeaderLength() uint16 {
	return 0
}
func (*nullEndpoint) LinkAddress() tcpip.LinkAddress {
	var l tcpip.LinkAddress
	return l
}
func (*nullEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	return pkts.Len(), nil
}
func (e *nullEndpoint) Attach(d stack.NetworkDispatcher)      { e.disp = d }
func (e *nullEndpoint) IsAttached() bool                      { return e.disp != nil }
func (*nullEndpoint) Wait()                                   {}
func (*nullEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*nullEndpoint) AddHeader(stack.PacketBufferPtr)         {}

var _ stack.NetworkDispatcher = (*testNetworkDispatcher)(nil)

type linkPacketInfo struct {
	pkt      stack.PacketBufferPtr
	protocol tcpip.NetworkProtocolNumber
	incoming bool
}

type networkPacketInfo struct {
	pkt      stack.PacketBufferPtr
	protocol tcpip.NetworkProtocolNumber
}

type testNetworkDispatcher struct {
	t *testing.T

	linkPacket linkPacketInfo

	networkPacket networkPacketInfo
}

func (t *testNetworkDispatcher) reset() {
	if pkt := t.linkPacket.pkt; !pkt.IsNil() {
		pkt.DecRef()
	}
	if pkt := t.networkPacket.pkt; !pkt.IsNil() {
		pkt.DecRef()
	}

	*t = testNetworkDispatcher{}
}

func (t *testNetworkDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	networkPacket := networkPacketInfo{
		pkt:      pkt.IncRef(),
		protocol: protocol,
	}

	if t.networkPacket != (networkPacketInfo{}) {
		t.t.Fatalf("already delivered network packet = %#v; new = %#v", t.networkPacket, networkPacket)
	}

	t.networkPacket = networkPacket
}

func (t *testNetworkDispatcher) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr, incoming bool) {
	linkPacket := linkPacketInfo{
		pkt:      pkt.IncRef(),
		protocol: protocol,
		incoming: incoming,
	}

	if t.linkPacket != (linkPacketInfo{}) {
		t.t.Fatalf("already delivered link packet = %#v; new = %#v", t.linkPacket, linkPacket)
	}

	t.linkPacket = linkPacket
}

func TestPacketDispatch(t *testing.T) {
	const protocol = 5

	var nullEP nullEndpoint
	ep := packetsocket.New(&nullEP)

	var d testNetworkDispatcher
	defer d.reset()
	ep.Attach(&d)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = protocol

	{
		var pkts stack.PacketBufferList
		pkts.PushBack(pkt)
		if n, err := ep.WritePackets(pkts); err != nil {
			t.Fatalf("ep.WritePackets(_): %s", err)
		} else if n != 1 {
			t.Fatalf("got ep.WritePackets(_) = %d, want = 1", n)
		}

		if want := (networkPacketInfo{}); d.networkPacket != want {
			t.Errorf("got d.networkPacket = %#v, want = %#v", d.networkPacket, want)
		}
		if want := (linkPacketInfo{pkt: pkt, protocol: protocol, incoming: false}); d.linkPacket != want {
			t.Errorf("got d.linkPacket = %#v, want = %#v", d.linkPacket, want)
		}
	}

	d.reset()
	{
		nullEP.disp.DeliverNetworkPacket(protocol, pkt)
		if want := (networkPacketInfo{pkt: pkt, protocol: protocol}); d.networkPacket != want {
			t.Errorf("got d.networkPacket = %#v, want = %#v", d.networkPacket, want)
		}
		if want := (linkPacketInfo{pkt: pkt, protocol: protocol, incoming: true}); d.linkPacket != want {
			t.Errorf("got d.linkPacket = %#v, want = %#v", d.linkPacket, want)
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
