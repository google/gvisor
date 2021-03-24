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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	nicID = 1

	stackAddr     = tcpip.Address("\x0a\x00\x00\x01")
	stackLinkAddr = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c")

	remoteAddr     = tcpip.Address("\x0a\x00\x00\x02")
	remoteLinkAddr = tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06")

	unknownAddr = tcpip.Address("\x0a\x00\x00\x03")

	defaultChannelSize = 1
	defaultMTU         = 65536

	// eventChanSize defines the size of event channels used by the neighbor
	// cache's event dispatcher. The size chosen here needs to be sufficient to
	// queue all the events received during tests before consumption.
	// If eventChanSize is too small, the tests may deadlock.
	eventChanSize = 32
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

func (d *arpDispatcher) waitForEvent(ctx context.Context, want eventInfo) error {
	select {
	case got := <-d.C:
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(got), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAtNanos")); diff != "" {
			return fmt.Errorf("got invalid event (-want +got):\n%s", diff)
		}
	case <-ctx.Done():
		return fmt.Errorf("%s for %s", ctx.Err(), want)
	}
	return nil
}

func (d *arpDispatcher) waitForEventWithTimeout(want eventInfo, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.waitForEvent(ctx, want)
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
	nudDisp *arpDispatcher
}

func newTestContext(t *testing.T) *testContext {
	c := stack.DefaultNUDConfigurations()
	// Transition from Reachable to Stale almost immediately to test if receiving
	// probes refreshes positive reachability.
	c.BaseReachableTime = time.Microsecond

	d := arpDispatcher{
		// Create an event channel large enough so the neighbor cache doesn't block
		// while dispatching events. Blocking could interfere with the timing of
		// NUD transitions.
		C: make(chan eventInfo, eventChanSize),
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
		NUDConfigs:         c,
		NUDDisp:            &d,
	})

	ep := channel.New(defaultChannelSize, defaultMTU, stackLinkAddr)
	ep.LinkEPCapabilities |= stack.CapabilityResolutionRequired

	wep := stack.LinkEndpoint(ep)

	if testing.Verbose() {
		wep = sniffer.New(ep)
	}
	if err := s.CreateNIC(nicID, wep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(nicID, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	return &testContext{
		s:       s,
		linkEP:  ep,
		nudDisp: &d,
	}
}

func (c *testContext) cleanup() {
	c.linkEP.Close()
}

func TestMalformedPacket(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	v := make(buffer.View, header.ARPSize)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: v.ToVectorisedView(),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.MalformedPacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.MalformedPacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDisabledEndpoint(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	ep, err := c.s.GetNetworkEndpoint(nicID, header.ARPProtocolNumber)
	if err != nil {
		t.Fatalf("GetNetworkEndpoint(%d, header.ARPProtocolNumber) failed: %s", nicID, err)
	}
	ep.Disable()

	v := make(buffer.View, header.ARPSize)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: v.ToVectorisedView(),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.DisabledPacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.DisabledPacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDirectReply(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make(buffer.View, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPReply)

	copy(h.HardwareAddressSender(), senderMAC)
	copy(h.ProtocolAddressSender(), senderIPv4)
	copy(h.HardwareAddressTarget(), stackLinkAddr)
	copy(h.ProtocolAddressTarget(), stackAddr)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: v.ToVectorisedView(),
	})

	c.linkEP.InjectInbound(arp.ProtocolNumber, pkt)

	if got := c.s.Stats().ARP.PacketsReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
	if got := c.s.Stats().ARP.RepliesReceived.Value(); got != 1 {
		t.Errorf("got c.s.Stats().ARP.PacketsReceived.Value() = %d, want = 1", got)
	}
}

func TestDirectRequest(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

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
			packetsRecv := c.s.Stats().ARP.PacketsReceived.Value()
			requestsRecv := c.s.Stats().ARP.RequestsReceived.Value()
			requestsRecvUnknownAddr := c.s.Stats().ARP.RequestsReceivedUnknownTargetAddress.Value()
			outgoingReplies := c.s.Stats().ARP.OutgoingRepliesSent.Value()

			// Inject an incoming ARP request.
			v := make(buffer.View, header.ARPSize)
			h := header.ARP(v)
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPRequest)
			copy(h.HardwareAddressSender(), test.senderLinkAddr)
			copy(h.ProtocolAddressSender(), test.senderAddr)
			copy(h.ProtocolAddressTarget(), test.targetAddr)
			c.linkEP.InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: v.ToVectorisedView(),
			}))

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
				if pkt, ok := c.linkEP.Read(); ok {
					t.Errorf("unexpected packet sent with network protocol number %d", pkt.Proto)
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
			pi, ok := c.linkEP.Read()
			if !ok {
				t.Fatal("expected ARP response to be sent, got none")
			}

			if pi.Proto != arp.ProtocolNumber {
				t.Fatalf("expected ARP response, got network protocol number %d", pi.Proto)
			}
			rep := header.ARP(pi.Pkt.NetworkHeader().View())
			if !rep.IsValid() {
				t.Fatalf("invalid ARP response: len = %d; response = %x", len(rep), rep)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressSender()), stackLinkAddr; got != want {
				t.Errorf("got HardwareAddressSender() = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressSender()), tcpip.Address(h.ProtocolAddressTarget()); got != want {
				t.Errorf("got ProtocolAddressSender() = %s, want = %s", got, want)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress(h.HardwareAddressSender()); got != want {
				t.Errorf("got HardwareAddressTarget() = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressTarget()), tcpip.Address(h.ProtocolAddressSender()); got != want {
				t.Errorf("got ProtocolAddressTarget() = %s, want = %s", got, want)
			}

			// Verify the sender was saved in the neighbor cache.
			wantEvent := eventInfo{
				eventType: entryAdded,
				nicID:     nicID,
				entry: stack.NeighborEntry{
					Addr:     test.senderAddr,
					LinkAddr: tcpip.LinkAddress(test.senderLinkAddr),
					State:    stack.Stale,
				},
			}
			if err := c.nudDisp.waitForEventWithTimeout(wantEvent, time.Second); err != nil {
				t.Fatal(err)
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

var _ stack.LinkEndpoint = (*testLinkEndpoint)(nil)

type testLinkEndpoint struct {
	stack.LinkEndpoint

	writeErr tcpip.Error
}

func (t *testLinkEndpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if t.writeErr != nil {
		return t.writeErr
	}

	return t.LinkEndpoint.WritePacket(r, protocol, pkt)
}

func TestLinkAddressRequest(t *testing.T) {
	const nicID = 1

	testAddr := tcpip.Address([]byte{1, 2, 3, 4})

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
			localAddr:                            "",
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
			localAddr:                            "",
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
			nicAddr:                              "",
			localAddr:                            "",
			remoteLinkAddr:                       remoteLinkAddr,
			expectedErr:                          &tcpip.ErrNetworkUnreachable{},
			expectedRequestsSent:                 0,
			expectedRequestBadLocalAddressErrors: 0,
			expectedRequestInterfaceHasNoLocalAddressErrors: 1,
			expectedRequestDroppedErrors:                    0,
		},
		{
			name:                                 "Multicast with no local address available",
			nicAddr:                              "",
			localAddr:                            "",
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
			linkEP := channel.New(defaultChannelSize, defaultMTU, stackLinkAddr)
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

			if len(test.nicAddr) != 0 {
				if err := s.AddAddress(nicID, ipv4.ProtocolNumber, test.nicAddr); err != nil {
					t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, test.nicAddr, err)
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

			pkt, ok := linkEP.Read()
			if !ok {
				t.Fatal("expected to send a link address request")
			}

			if pkt.Route.RemoteLinkAddress != test.expectedRemoteLinkAddr {
				t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", pkt.Route.RemoteLinkAddress, test.expectedRemoteLinkAddr)
			}

			rep := header.ARP(stack.PayloadSince(pkt.Pkt.NetworkHeader()))
			if got := rep.Op(); got != header.ARPRequest {
				t.Errorf("got Op = %d, want = %d", got, header.ARPRequest)
			}
			if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
				t.Errorf("got HardwareAddressSender = %s, want = %s", got, stackLinkAddr)
			}
			if got := tcpip.Address(rep.ProtocolAddressSender()); got != test.expectedLocalAddr {
				t.Errorf("got ProtocolAddressSender = %s, want = %s", got, test.expectedLocalAddr)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"); got != want {
				t.Errorf("got HardwareAddressTarget = %s, want = %s", got, want)
			}
			if got := tcpip.Address(rep.ProtocolAddressTarget()); got != remoteAddr {
				t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, remoteAddr)
			}
		})
	}
}

func TestDADARPRequestPacket(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocolWithOptions(arp.Options{
			DADConfigs: stack.DADConfigurations{
				DupAddrDetectTransmits: 1,
				RetransmitTimer:        time.Second,
			},
		}), ipv4.NewProtocol},
	})
	e := channel.New(1, defaultMTU, stackLinkAddr)
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	if res, err := s.CheckDuplicateAddress(nicID, header.IPv4ProtocolNumber, remoteAddr, func(stack.DADResult) {}); err != nil {
		t.Fatalf("s.CheckDuplicateAddress(%d, %d, %s, _): %s", nicID, header.IPv4ProtocolNumber, remoteAddr, err)
	} else if res != stack.DADStarting {
		t.Fatalf("got s.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", nicID, header.IPv4ProtocolNumber, remoteAddr, res, stack.DADStarting)
	}

	pkt, ok := e.ReadContext(context.Background())
	if !ok {
		t.Fatal("expected to send an ARP request")
	}

	if pkt.Route.RemoteLinkAddress != header.EthernetBroadcastAddress {
		t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", pkt.Route.RemoteLinkAddress, header.EthernetBroadcastAddress)
	}

	req := header.ARP(stack.PayloadSince(pkt.Pkt.NetworkHeader()))
	if !req.IsValid() {
		t.Errorf("got req.IsValid() = false, want = true")
	}
	if got := req.Op(); got != header.ARPRequest {
		t.Errorf("got req.Op() = %d, want = %d", got, header.ARPRequest)
	}
	if got := tcpip.LinkAddress(req.HardwareAddressSender()); got != stackLinkAddr {
		t.Errorf("got req.HardwareAddressSender() = %s, want = %s", got, stackLinkAddr)
	}
	if got := tcpip.Address(req.ProtocolAddressSender()); got != header.IPv4Any {
		t.Errorf("got req.ProtocolAddressSender() = %s, want = %s", got, header.IPv4Any)
	}
	if got, want := tcpip.LinkAddress(req.HardwareAddressTarget()), tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"); got != want {
		t.Errorf("got req.HardwareAddressTarget() = %s, want = %s", got, want)
	}
	if got := tcpip.Address(req.ProtocolAddressTarget()); got != remoteAddr {
		t.Errorf("got req.ProtocolAddressTarget() = %s, want = %s", got, remoteAddr)
	}
}
