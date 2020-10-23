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
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	addr      tcpip.Address
	linkAddr  tcpip.LinkAddress
	state     stack.NeighborState
}

func (e eventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.eventType, e.nicID, e.addr, e.linkAddr, e.state)
}

// arpDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type arpDispatcher struct {
	// C is where events are queued
	C chan eventInfo
}

var _ stack.NUDDispatcher = (*arpDispatcher)(nil)

func (d *arpDispatcher) OnNeighborAdded(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryAdded,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborChanged(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryChanged,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func (d *arpDispatcher) OnNeighborRemoved(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state stack.NeighborState, updatedAt time.Time) {
	e := eventInfo{
		eventType: entryRemoved,
		nicID:     nicID,
		addr:      addr,
		linkAddr:  linkAddr,
		state:     state,
	}
	d.C <- e
}

func (d *arpDispatcher) waitForEvent(ctx context.Context, want eventInfo) error {
	select {
	case got := <-d.C:
		if diff := cmp.Diff(got, want, cmp.AllowUnexported(got)); diff != "" {
			return fmt.Errorf("got invalid event (-got +want):\n%s", diff)
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

func newTestContext(t *testing.T, useNeighborCache bool) *testContext {
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
		UseNeighborCache:   useNeighborCache,
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
	if !useNeighborCache {
		// The remote address needs to be assigned to the NIC so we can receive and
		// verify outgoing ARP packets. The neighbor cache isn't concerned with
		// this; the tests that use linkAddrCache expect the ARP responses to be
		// received by the same NIC.
		if err := s.AddAddress(nicID, ipv4.ProtocolNumber, remoteAddr); err != nil {
			t.Fatalf("AddAddress for ipv4 failed: %v", err)
		}
	}
	if err := s.AddAddress(nicID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		t.Fatalf("AddAddress for arp failed: %v", err)
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

func TestDirectRequest(t *testing.T) {
	c := newTestContext(t, false /* useNeighborCache */)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make(buffer.View, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), senderMAC)
	copy(h.ProtocolAddressSender(), senderIPv4)

	inject := func(addr tcpip.Address) {
		copy(h.ProtocolAddressTarget(), addr)
		c.linkEP.InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: v.ToVectorisedView(),
		}))
	}

	for i, address := range []tcpip.Address{stackAddr, remoteAddr} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			inject(address)
			pi, _ := c.linkEP.ReadContext(context.Background())
			if pi.Proto != arp.ProtocolNumber {
				t.Fatalf("expected ARP response, got network protocol number %d", pi.Proto)
			}
			rep := header.ARP(pi.Pkt.NetworkHeader().View())
			if !rep.IsValid() {
				t.Fatalf("invalid ARP response: len = %d; response = %x", len(rep), rep)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressSender()), stackLinkAddr; got != want {
				t.Errorf("got HardwareAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressSender()), tcpip.Address(h.ProtocolAddressTarget()); got != want {
				t.Errorf("got ProtocolAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress(h.HardwareAddressSender()); got != want {
				t.Errorf("got HardwareAddressTarget = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressTarget()), tcpip.Address(h.ProtocolAddressSender()); got != want {
				t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, want)
			}
		})
	}

	inject(unknownAddr)
	// Sleep tests are gross, but this will only potentially flake
	// if there's a bug. If there is no bug this will reliably
	// succeed.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if pkt, ok := c.linkEP.ReadContext(ctx); ok {
		t.Errorf("stackAddrBad: unexpected packet sent, Proto=%v", pkt.Proto)
	}
}

func TestDirectRequestWithNeighborCache(t *testing.T) {
	c := newTestContext(t, true /* useNeighborCache */)
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
			// Inject an incoming ARP request.
			v := make(buffer.View, header.ARPSize)
			h := header.ARP(v)
			h.SetIPv4OverEthernet()
			h.SetOp(header.ARPRequest)
			copy(h.HardwareAddressSender(), test.senderLinkAddr)
			copy(h.ProtocolAddressSender(), test.senderAddr)
			copy(h.ProtocolAddressTarget(), test.targetAddr)
			c.linkEP.InjectInbound(arp.ProtocolNumber, &stack.PacketBuffer{
				Data: v.ToVectorisedView(),
			})

			if !test.isValid {
				// No packets should be sent after receiving an invalid ARP request.
				// There is no need to perform a blocking read here, since packets are
				// sent in the same function that handles ARP requests.
				if pkt, ok := c.linkEP.Read(); ok {
					t.Errorf("unexpected packet sent with network protocol number %d", pkt.Proto)
				}
				return
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
				addr:      test.senderAddr,
				linkAddr:  tcpip.LinkAddress(test.senderLinkAddr),
				state:     stack.Stale,
			}
			if err := c.nudDisp.waitForEventWithTimeout(wantEvent, time.Second); err != nil {
				t.Fatal(err)
			}

			neighbors, err := c.s.Neighbors(nicID)
			if err != nil {
				t.Fatalf("c.s.Neighbors(%d): %s", nicID, err)
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
			if got, want := neigh.LocalAddr, stackAddr; got != want {
				t.Errorf("got neighbor LocalAddr = %s, want = %s", got, want)
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

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	stack.LinkEndpoint
}

func (*testInterface) ID() tcpip.NICID {
	return 1
}

func (*testInterface) IsLoopback() bool {
	return false
}

func (*testInterface) Name() string {
	return ""
}

func (*testInterface) Enabled() bool {
	return true
}

func (t *testInterface) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	r := stack.Route{
		NetProto:          protocol,
		RemoteLinkAddress: remoteLinkAddr,
	}
	return t.LinkEndpoint.WritePacket(&r, gso, protocol, pkt)
}

func TestLinkAddressRequest(t *testing.T) {
	tests := []struct {
		name           string
		remoteLinkAddr tcpip.LinkAddress
		expectLinkAddr tcpip.LinkAddress
	}{
		{
			name:           "Unicast",
			remoteLinkAddr: remoteLinkAddr,
			expectLinkAddr: remoteLinkAddr,
		},
		{
			name:           "Multicast",
			remoteLinkAddr: "",
			expectLinkAddr: header.EthernetBroadcastAddress,
		},
	}

	for _, test := range tests {
		p := arp.NewProtocol(nil)
		linkRes, ok := p.(stack.LinkAddressResolver)
		if !ok {
			t.Fatal("expected ARP protocol to implement stack.LinkAddressResolver")
		}

		linkEP := channel.New(defaultChannelSize, defaultMTU, stackLinkAddr)
		if err := linkRes.LinkAddressRequest(stackAddr, remoteAddr, test.remoteLinkAddr, &testInterface{LinkEndpoint: linkEP}); err != nil {
			t.Errorf("got p.LinkAddressRequest(%s, %s, %s, _) = %s", stackAddr, remoteAddr, test.remoteLinkAddr, err)
		}

		pkt, ok := linkEP.Read()
		if !ok {
			t.Fatal("expected to send a link address request")
		}

		if got, want := pkt.Route.RemoteLinkAddress, test.expectLinkAddr; got != want {
			t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", got, want)
		}
	}
}
