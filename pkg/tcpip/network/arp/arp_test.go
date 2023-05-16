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

package arp_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	nicID = 1

	stackLinkAddr  = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c")
	remoteLinkAddr = tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06")
)

var (
	stackAddr   = testutil.MustParse4("10.0.0.1")
	remoteAddr  = testutil.MustParse4("10.0.0.2")
	unknownAddr = testutil.MustParse4("10.0.0.3")
)

type eventType uint8

const (
	entryAdded eventType = iota
	entryChanged
	entryRemoved
)

func (t eventType) String() string {
	switch t {
	case entryAdded:
		return "add"
	case entryChanged:
		return "change"
	case entryRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

type eventInfo struct {
	eventType eventType
	nicID     tcpip.NICID
	entry     stack.NeighborEntry
}

func (e eventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, %#v", e.eventType, e.nicID, e.entry)
}

// arpDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type arpDispatcher struct {
	// C is where events are queued
	C chan eventInfo
}

var _ stack.NUDDispatcher = (*arpDispatcher)(nil)

func (d *arpDispatcher) OnNeighborAdded(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryAdded,
		nicID:     nicID,
		entry:     entry,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborChanged(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryChanged,
		nicID:     nicID,
		entry:     entry,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborRemoved(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryRemoved,
		nicID:     nicID,
		entry:     entry,
	}
	d.C <- e
}

func (d *arpDispatcher) nextEvent() (eventInfo, bool) {
	select {
	case event := <-d.C:
		return event, true
	default:
		return eventInfo{}, false
	}
}

type testContext struct {
	s       *stack.Stack
	linkEP  *channel.Endpoint
	nudDisp arpDispatcher
}

func makeTestContext(t *testing.T, eventDepth int, packetDepth int) testContext {
	t.Helper()

	tc := testContext{
		nudDisp: arpDispatcher{
			C: make(chan eventInfo, eventDepth),
		},
	}

	tc.s = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		NUDDisp:          &tc.nudDisp,
		Clock:            &faketime.NullClock{},
	})

	tc.linkEP = channel.New(packetDepth, header.IPv4MinimumMTU, stackLinkAddr)
	tc.linkEP.LinkEPCapabilities |= stack.CapabilityResolutionRequired

	wep := stack.LinkEndpoint(tc.linkEP)
	if testing.Verbose() {
		wep = sniffer.New(wep)
	}
	if err := tc.s.CreateNIC(nicID, wep); err != nil {
		t.Fatalf("CreateNIC failed: %s", err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: stackAddr.WithPrefix(),
	}
	if err := tc.s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}

	tc.s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	return tc
}

func (c *testContext) cleanup() {
	c.linkEP.Close()
	c.s.Close()
	c.s.Wait()
}

func TestMalformedPacket(t *testing.T) {
	c := makeTestContext(t, 0, 0)
	defer c.cleanup()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(make([]byte, header.ARPSize)),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
	pkt.DecRef()

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.MalformedPacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.MalformedPacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDisabledEndpoint(t *testing.T) {
	c := makeTestContext(t, 0, 0)
	defer c.cleanup()

	ep, err := c.s.GetNetworkEndpoint(nicID, header.ARPProtocolNumber)
	if err != nil {
		t.Fatalf("GetNetworkEndpoint(%d, header.ARPProtocolNumber) failed: %s", nicID, err)
	}
	ep.Disable()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(make([]byte, header.ARPSize)),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
	pkt.DecRef()

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.DisabledPacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.DisabledPacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDirectReply(t *testing.T) {
	c := makeTestContext(t, 0, 0)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make([]byte, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPReply)

	copy(h.HardwareAddressSender(), senderMAC)
	copy(h.ProtocolAddressSender(), senderIPv4)
	copy(h.HardwareAddressTarget(), stackLinkAddr)
	copy(h.ProtocolAddressTarget(), stackAddr.AsSlice())

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(v),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
	pkt.DecRef()

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.RepliesReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDirectRequest(t *testing.T) {
	tests := []struct {
		name           string
		senderAddr     tcpip.Address
		senderLinkAddr tcpip.LinkAddress
		targetAddr     tcpip.Address
		isValid        bool
	}{
		{
			name:           "Loopback",
			senderAddr:     stackAddr,
			senderLinkAddr: stackLinkAddr,
			targetAddr:     stackAddr,
			isValid:        true,
		},
		{
			name:           "Remote",
			senderAddr:     remoteAddr,
			senderLinkAddr: remoteLinkAddr,
			targetAddr:     stackAddr,
			isValid:        true,
		},
		{
			name:           "RemoteInvalidTarget",
			senderAddr:     remoteAddr,
			senderLinkAddr: remoteLinkAddr,
			targetAddr:     unknownAddr,
			isValid:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := makeTestContext(t, 1, 1)
			defer c.cleanup()

			packetsRecv := c.s.Stats().ARP.PacketsReceived.Value()
			requestsRecv := c.s.Stats().ARP.RequestsReceived.Value()
			requestsRecvUnknownAddr := c.s.Stats().ARP.RequestsReceivedUnknownTargetAddress.Value()
			outgoingReplies := c.s.Stats().ARP.OutgoingRepliesSent.Value()

			// Inject an incoming ARP request.
			v := make([]byte, header.ARPSize)
			h := header.ARP(v)
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPRequest)
			copy(h.HardwareAddressSender(), test.senderLinkAddr)
			copy(h.ProtocolAddressSender(), test.senderAddr.AsSlice())
			copy(h.ProtocolAddressTarget(), test.targetAddr.AsSlice())
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(v),
			})
			c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
			pkt.DecRef()

			if got, want := c.s.Stats().ARP.PacketsReceived.Value(), packetsRecv+1; got != want {
				t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = %d", got, want)
			}
			if got, want := c.s.Stats().ARP.RequestsReceived.Value(), requestsRecv+1; got != want {
				t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = %d", got, want)
			}

			if !test.isValid {
				// No packets should be sent after receiving an invalid ARP request.
				// There is no need to perform a blocking read here, since packets are
				// sent in the same function that handles ARP requests.
				if pkt := c.linkEP.Read(); !pkt.IsNil() {
					t.Errorf("unexpected packet sent: %+v", pkt)
				}
				if got, want := c.s.Stats().ARP.RequestsReceivedUnknownTargetAddress.Value(), requestsRecvUnknownAddr+1; got != want {
					t.Errorf("got c.s.Stats().ARP.RequestsReceivedUnknownTargetAddress.Value() = %d, want = %d", got, want)
				}
				if got, want := c.s.Stats().ARP.OutgoingRepliesSent.Value(), outgoingReplies; got != want {
					t.Errorf("got c.s.Stats().ARP.OutgoingRepliesSent.Value() = %d, want = %d", got, want)
				}

				return
			}

			if got, want := c.s.Stats().ARP.OutgoingRepliesSent.Value(), outgoingReplies+1; got != want {
				t.Errorf("got c.s.Stats().ARP.OutgoingRepliesSent.Value() = %d, want = %d", got, want)
			}

			// Verify an ARP response was sent.
			pi := c.linkEP.Read()
			if pi.IsNil() {
				t.Fatal("expected ARP response to be sent, got none")
			}

			if got, want := pi.NetworkProtocolNumber, arp.ProtocolNumber; got != want {
				t.Fatalf("expected %d, got network protocol number %d", want, got)
			}
			rep := header.ARP(pi.NetworkHeader().Slice())
			pi.DecRef()
			if !rep.IsValid() {
				t.Fatalf("invalid ARP response: len = %d; response = %x", len(rep), rep)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressSender()), stackLinkAddr; got != want {
				t.Errorf("got HardwareAddressSender() = %s, want = %s", got, want)
			}
			if got, want := tcpip.AddrFromSlice(rep.ProtocolAddressSender()), tcpip.AddrFromSlice(h.ProtocolAddressTarget()); got != want {
				t.Errorf("got ProtocolAddressSender() = %s, want = %s", got, want)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress(h.HardwareAddressSender()); got != want {
				t.Errorf("got HardwareAddressTarget() = %s, want = %s", got, want)
			}
			if got, want := tcpip.AddrFromSlice(rep.ProtocolAddressTarget()), tcpip.AddrFromSlice(h.ProtocolAddressSender()); got != want {
				t.Errorf("got ProtocolAddressTarget() = %s, want = %s", got, want)
			}

			// Verify the sender was saved in the neighbor cache.
			if got, ok := c.nudDisp.nextEvent(); ok {
				want := eventInfo{
					eventType: entryAdded,
					nicID:     nicID,
					entry: stack.NeighborEntry{
						Addr:     test.senderAddr,
						LinkAddr: test.senderLinkAddr,
						State:    stack.Stale,
					},
				}
				if diff := cmp.Diff(want, got, cmp.AllowUnexported(eventInfo{}), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAt")); diff != "" {
					t.Errorf("got invalid event (-want +got):\n%s", diff)
				}
			} else {
				t.Fatal("event didn't arrive")
			}

			neighbors, err := c.s.Neighbors(nicID, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatalf("c.s.Neighbors(%d, %d): %s", nicID, ipv4.ProtocolNumber, err)
			}

			neighborByAddr := make(map[tcpip.Address]stack.NeighborEntry)
			for _, n := range neighbors {
				if existing, ok := neighborByAddr[n.Addr]; ok {
					if diff := cmp.Diff(existing, n); diff != "" {
						t.Fatalf("duplicate neighbor entry found (-existing +got):\n%s", diff)
					}
					t.Fatalf("exact neighbor entry duplicate found for addr=%s", n.Addr)
				}
				neighborByAddr[n.Addr] = n
			}

			neigh, ok := neighborByAddr[test.senderAddr]
			if !ok {
				t.Fatalf("expected neighbor entry with Addr = %s", test.senderAddr)
			}
			if got, want := neigh.LinkAddr, test.senderLinkAddr; got != want {
				t.Errorf("got neighbor LinkAddr = %s, want = %s", got, want)
			}
			if got, want := neigh.State, stack.Stale; got != want {
				t.Errorf("got neighbor State = %s, want = %s", got, want)
			}

			// No more events should be dispatched
			for {
				event, ok := c.nudDisp.nextEvent()
				if !ok {
					break
				}
				t.Errorf("unexpected %s", event)
			}
		})
	}
}

func TestReplyPacketType(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		packetType       tcpip.PacketType
		becomesReachable bool
	}{
		{
			name:             "unicast",
			packetType:       tcpip.PacketHost,
			becomesReachable: true,
		},
		{
			name:             "broadcast",
			packetType:       tcpip.PacketBroadcast,
			becomesReachable: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			c := makeTestContext(t, 1, 1)
			defer c.cleanup()

			// Inject an incoming ARP request first.
			v := make([]byte, header.ARPSize)
			h := header.ARP(v)
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPRequest)
			if got, want := copy(h.HardwareAddressSender(), remoteLinkAddr), header.EthernetAddressSize; got != want {
				t.Fatalf("got copy(_, _) = %d, want = %d", got, want)
			}
			if got, want := copy(h.ProtocolAddressSender(), remoteAddr.AsSlice()), header.IPv4AddressSize; got != want {
				t.Fatalf("got copy(_, _) = %d, want = %d", got, want)
			}
			if got, want := copy(h.ProtocolAddressTarget(), stackAddr.AsSlice()), header.IPv4AddressSize; got != want {
				t.Fatalf("got copy(_, _) = %d, want = %d", got, want)
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(v),
			})
			pkt.PktType = tcpip.PacketBroadcast
			c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
			pkt.DecRef()

			if got, ok := c.nudDisp.nextEvent(); ok {
				want := eventInfo{
					eventType: entryAdded,
					nicID:     nicID,
					entry: stack.NeighborEntry{
						Addr:     remoteAddr,
						LinkAddr: remoteLinkAddr,
						State:    stack.Stale,
					},
				}
				if diff := cmp.Diff(want, got, cmp.AllowUnexported(eventInfo{}), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAt")); diff != "" {
					t.Errorf("got invalid event (-want +got):\n%s", diff)
				}
			} else {
				t.Fatal("event didn't arrive")
			}

			// Then inject replies with different packet types.
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPReply)
			pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(v),
			})
			pkt.PktType = testCase.packetType
			c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)
			pkt.DecRef()

			got, ok := c.nudDisp.nextEvent()
			// If the entry doesn't become reachable we're not supposed to see a new
			// event.
			if got, want := ok, testCase.becomesReachable; got != want {
				t.Errorf("got c.nudDisp.nextEvent() = %t, want %t", got, want)
			}
			if ok {
				want := eventInfo{
					eventType: entryChanged,
					nicID:     nicID,
					entry: stack.NeighborEntry{
						Addr:     remoteAddr,
						LinkAddr: remoteLinkAddr,
						State:    stack.Reachable,
					},
				}
				if diff := cmp.Diff(want, got, cmp.AllowUnexported(eventInfo{}), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAt")); diff != "" {
					t.Errorf("got invalid event (-want +got):\n%s", diff)
				}
			}
		})
	}

}

var _ stack.LinkEndpoint = (*testLinkEndpoint)(nil)

type testLinkEndpoint struct {
	stack.LinkEndpoint

	writeErr tcpip.Error
}

func (t *testLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if t.writeErr != nil {
		return 0, t.writeErr
	}

	return t.LinkEndpoint.WritePackets(pkts)
}

func TestLinkAddressRequest(t *testing.T) {
	const nicID = 1

	testAddr := tcpip.AddrFrom4Slice([]byte{1, 2, 3, 4})

	tests := []struct {
		name                                            string
		nicAddr                                         tcpip.Address
		localAddr                                       tcpip.Address
		remoteLinkAddr                                  tcpip.LinkAddress
		linkErr                                         tcpip.Error
		expectedErr                                     tcpip.Error
		expectedLocalAddr                               tcpip.Address
		expectedRemoteLinkAddr                          tcpip.LinkAddress
		expectedRequestsSent                            uint64
		expectedRequestBadLocalAddressErrors            uint64
		expectedRequestInterfaceHasNoLocalAddressErrors uint64
		expectedRequestDroppedErrors                    uint64
	}{
		{
			name:                                 "Unicast",
			nicAddr:                              stackAddr,
			localAddr:                            stackAddr,
			remoteLinkAddr:                       remoteLinkAddr,
			expectedLocalAddr:                    stackAddr,
			expectedRemoteLinkAddr:               remoteLinkAddr,
			expectedRequestsSent:                 1,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Multicast",
			nicAddr:                              stackAddr,
			localAddr:                            stackAddr,
			remoteLinkAddr:                       "",
			expectedLocalAddr:                    stackAddr,
			expectedRemoteLinkAddr:               header.EthernetBroadcastAddress,
			expectedRequestsSent:                 1,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Unicast with unspecified source",
			nicAddr:                              stackAddr,
			localAddr:                            tcpip.Address{},
			remoteLinkAddr:                       remoteLinkAddr,
			expectedLocalAddr:                    stackAddr,
			expectedRemoteLinkAddr:               remoteLinkAddr,
			expectedRequestsSent:                 1,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Multicast with unspecified source",
			nicAddr:                              stackAddr,
			localAddr:                            tcpip.Address{},
			remoteLinkAddr:                       "",
			expectedLocalAddr:                    stackAddr,
			expectedRemoteLinkAddr:               header.EthernetBroadcastAddress,
			expectedRequestsSent:                 1,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Unicast with unassigned address",
			nicAddr:                              stackAddr,
			localAddr:                            testAddr,
			remoteLinkAddr:                       remoteLinkAddr,
			expectedErr:                          &tcpip.ErrBadLocalAddress{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 1,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Multicast with unassigned address",
			nicAddr:                              stackAddr,
			localAddr:                            testAddr,
			remoteLinkAddr:                       "",
			expectedErr:                          &tcpip.ErrBadLocalAddress{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 1,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Unicast with no local address available",
			nicAddr:                              tcpip.Address{},
			localAddr:                            tcpip.Address{},
			remoteLinkAddr:                       remoteLinkAddr,
			expectedErr:                          &tcpip.ErrNetworkUnreachable{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 1,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Multicast with no local address available",
			nicAddr:                              tcpip.Address{},
			localAddr:                            tcpip.Address{},
			remoteLinkAddr:                       "",
			expectedErr:                          &tcpip.ErrNetworkUnreachable{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 1,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Link error",
			nicAddr:                              stackAddr,
			localAddr:                            stackAddr,
			remoteLinkAddr:                       remoteLinkAddr,
			linkErr:                              &tcpip.ErrInvalidEndpointState{},
			expectedErr:                          &tcpip.ErrInvalidEndpointState{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 0,
			expectedRequestDroppedErrors:                    1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
			})
			defer func() {
				s.Close()
				s.Wait()
			}()
			linkEP := channel.New(1, header.IPv4MinimumMTU, stackLinkAddr)
			defer linkEP.Close()
			if err := s.CreateNIC(nicID, &testLinkEndpoint{LinkEndpoint: linkEP, writeErr: test.linkErr}); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}

			ep, err := s.GetNetworkEndpoint(nicID, arp.ProtocolNumber)
			if err != nil {
				t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, arp.ProtocolNumber, err)
			}
			linkRes, ok := ep.(stack.LinkAddressResolver)
			if !ok {
				t.Fatalf("expected %T to implement stack.LinkAddressResolver", ep)
			}

			if test.nicAddr.Len() != 0 {
				protocolAddr := tcpip.ProtocolAddress{
					Protocol:          ipv4.ProtocolNumber,
					AddressWithPrefix: test.nicAddr.WithPrefix(),
				}
				if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
					t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
				}
			}

			{
				err := linkRes.LinkAddressRequest(remoteAddr, test.localAddr, test.remoteLinkAddr)
				if diff := cmp.Diff(test.expectedErr, err); diff != "" {
					t.Fatalf("unexpected error from p.LinkAddressRequest(%s, %s, %s, _), (-want, +got):\n%s", remoteAddr, test.localAddr, test.remoteLinkAddr, diff)
				}
			}

			if got := s.Stats().ARP.OutgoingRequestsSent.Value(); got != test.expectedRequestsSent {
				t.Errorf("got s.Stats().ARP.OutgoingRequestsSent.Value() = %d, want = %d", got, test.expectedRequestsSent)
			}
			if got := s.Stats().ARP.OutgoingRequestInterfaceHasNoLocalAddressErrors.Value(); got != test.expectedRequestInterfaceHasNoLocalAddressErrors {
				t.Errorf("got s.Stats().ARP.OutgoingRequestInterfaceHasNoLocalAddressErrors.Value() = %d, want = %d", got, test.expectedRequestInterfaceHasNoLocalAddressErrors)
			}
			if got := s.Stats().ARP.OutgoingRequestBadLocalAddressErrors.Value(); got != test.expectedRequestBadLocalAddressErrors {
				t.Errorf("got s.Stats().ARP.OutgoingRequestBadLocalAddressErrors.Value() = %d, want = %d", got, test.expectedRequestBadLocalAddressErrors)
			}
			if got := s.Stats().ARP.OutgoingRequestsDropped.Value(); got != test.expectedRequestDroppedErrors {
				t.Errorf("got s.Stats().ARP.OutgoingRequestsDropped.Value() = %d, want = %d", got, test.expectedRequestDroppedErrors)
			}

			if test.expectedErr != nil {
				return
			}

			pkt := linkEP.Read()
			if pkt.IsNil() {
				t.Fatal("expected to send a link address request")
			}

			if pkt.EgressRoute.RemoteLinkAddress != test.expectedRemoteLinkAddr {
				t.Errorf("got pkt.EgressRoute.RemoteLinkAddress = %s, want = %s", pkt.EgressRoute.RemoteLinkAddress, test.expectedRemoteLinkAddr)
			}

			payload := stack.PayloadSince(pkt.NetworkHeader())
			defer payload.Release()
			rep := header.ARP(payload.AsSlice())
			pkt.DecRef()
			if got := rep.Op(); got != header.ARPRequest {
				t.Errorf("got Op = %d, want = %d", got, header.ARPRequest)
			}
			if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
				t.Errorf("got HardwareAddressSender = %s, want = %s", got, stackLinkAddr)
			}
			if got := tcpip.AddrFromSlice(rep.ProtocolAddressSender()); got != test.expectedLocalAddr {
				t.Errorf("got ProtocolAddressSender = %s, want = %s", got, test.expectedLocalAddr)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"); got != want {
				t.Errorf("got HardwareAddressTarget = %s, want = %s", got, want)
			}
			if got := tcpip.AddrFromSlice(rep.ProtocolAddressTarget()); got != remoteAddr {
				t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, remoteAddr)
			}
		})
	}
}

func TestDADARPRequestPacket(t *testing.T) {
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocolWithOptions(arp.Options{
			DADConfigs: stack.DADConfigurations{
				DupAddrDetectTransmits: 1,
			},
		}), ipv4.NewProtocol},
		Clock: clock,
	})
	defer func() {
		s.Close()
		s.Wait()
	}()
	e := channel.New(1, header.IPv4MinimumMTU, stackLinkAddr)
	defer e.Close()
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	if res, err := s.CheckDuplicateAddress(nicID, header.IPv4ProtocolNumber, remoteAddr, func(stack.DADResult) {}); err != nil {
		t.Fatalf("s.CheckDuplicateAddress(%d, %d, %s, _): %s", nicID, header.IPv4ProtocolNumber, remoteAddr, err)
	} else if res != stack.DADStarting {
		t.Fatalf("got s.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", nicID, header.IPv4ProtocolNumber, remoteAddr, res, stack.DADStarting)
	}

	clock.RunImmediatelyScheduledJobs()
	pkt := e.Read()
	if pkt.IsNil() {
		t.Fatal("expected to send an ARP request")
	}

	if pkt.EgressRoute.RemoteLinkAddress != header.EthernetBroadcastAddress {
		t.Errorf("got pkt.EgressRoute.RemoteLinkAddress = %s, want = %s", pkt.EgressRoute.RemoteLinkAddress, header.EthernetBroadcastAddress)
	}
	payload := stack.PayloadSince(pkt.NetworkHeader())
	defer payload.Release()
	req := header.ARP(payload.AsSlice())
	pkt.DecRef()
	if !req.IsValid() {
		t.Errorf("got req.IsValid() = false, want = true")
	}
	if got := req.Op(); got != header.ARPRequest {
		t.Errorf("got req.Op() = %d, want = %d", got, header.ARPRequest)
	}
	if got := tcpip.LinkAddress(req.HardwareAddressSender()); got != stackLinkAddr {
		t.Errorf("got req.HardwareAddressSender() = %s, want = %s", got, stackLinkAddr)
	}
	if got := tcpip.AddrFromSlice(req.ProtocolAddressSender()); got != header.IPv4Any {
		t.Errorf("got req.ProtocolAddressSender() = %s, want = %s", got, header.IPv4Any)
	}
	if got, want := tcpip.LinkAddress(req.HardwareAddressTarget()), tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"); got != want {
		t.Errorf("got req.HardwareAddressTarget() = %s, want = %s", got, want)
	}
	if got := tcpip.AddrFromSlice(req.ProtocolAddressTarget()); got != remoteAddr {
		t.Errorf("got req.ProtocolAddressTarget() = %s, want = %s", got, remoteAddr)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
