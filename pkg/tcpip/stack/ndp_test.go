// Copyright 2019 The gVisor Authors.
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

package stack_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	addr1          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	addr3          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
	linkAddr1      = "\x02\x02\x03\x04\x05\x06"
	linkAddr2      = "\x02\x02\x03\x04\x05\x07"
	linkAddr3      = "\x02\x02\x03\x04\x05\x08"
	defaultTimeout = 100 * time.Millisecond
)

var (
	llAddr1 = header.LinkLocalAddr(linkAddr1)
	llAddr2 = header.LinkLocalAddr(linkAddr2)
	llAddr3 = header.LinkLocalAddr(linkAddr3)
)

// prefixSubnetAddr returns a prefix (Address + Length), the prefix's equivalent
// tcpip.Subnet, and an address where the lower half of the address is composed
// of the EUI-64 of linkAddr if it is a valid unicast ethernet address.
func prefixSubnetAddr(offset uint8, linkAddr tcpip.LinkAddress) (tcpip.AddressWithPrefix, tcpip.Subnet, tcpip.AddressWithPrefix) {
	prefixBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8 + offset, 0, 0, 0, 0, 0, 0, 0, 0}
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(prefixBytes),
		PrefixLen: 64,
	}

	subnet := prefix.Subnet()

	var addr tcpip.AddressWithPrefix
	if header.IsValidUnicastEthernetAddress(linkAddr) {
		addrBytes := []byte(subnet.ID())
		header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
		addr = tcpip.AddressWithPrefix{
			Address:   tcpip.Address(addrBytes),
			PrefixLen: 64,
		}
	}

	return prefix, subnet, addr
}

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	}

	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
	}
	if addr.Address != addr1 {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0", got)
	}
}

// ndpDADEvent is a set of parameters that was passed to
// ndpDispatcher.OnDuplicateAddressDetectionStatus.
type ndpDADEvent struct {
	nicID    tcpip.NICID
	addr     tcpip.Address
	resolved bool
	err      *tcpip.Error
}

type ndpRouterEvent struct {
	nicID tcpip.NICID
	addr  tcpip.Address
	// true if router was discovered, false if invalidated.
	discovered bool
}

type ndpPrefixEvent struct {
	nicID  tcpip.NICID
	prefix tcpip.Subnet
	// true if prefix was discovered, false if invalidated.
	discovered bool
}

type ndpAutoGenAddrEventType int

const (
	newAddr ndpAutoGenAddrEventType = iota
	invalidatedAddr
)

type ndpAutoGenAddrEvent struct {
	nicID     tcpip.NICID
	addr      tcpip.AddressWithPrefix
	eventType ndpAutoGenAddrEventType
}

type ndpRDNSS struct {
	addrs    []tcpip.Address
	lifetime time.Duration
}

type ndpRDNSSEvent struct {
	nicID tcpip.NICID
	rdnss ndpRDNSS
}

var _ stack.NDPDispatcher = (*ndpDispatcher)(nil)

// ndpDispatcher implements NDPDispatcher so tests can know when various NDP
// related events happen for test purposes.
type ndpDispatcher struct {
	dadC           chan ndpDADEvent
	routerC        chan ndpRouterEvent
	rememberRouter bool
	prefixC        chan ndpPrefixEvent
	rememberPrefix bool
	autoGenAddrC   chan ndpAutoGenAddrEvent
	rdnssC         chan ndpRDNSSEvent
	routeTable     []tcpip.Route
}

// Implements stack.NDPDispatcher.OnDuplicateAddressDetectionStatus.
func (n *ndpDispatcher) OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error) {
	if n.dadC != nil {
		n.dadC <- ndpDADEvent{
			nicID,
			addr,
			resolved,
			err,
		}
	}
}

// Implements stack.NDPDispatcher.OnDefaultRouterDiscovered.
func (n *ndpDispatcher) OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) (bool, []tcpip.Route) {
	if n.routerC != nil {
		n.routerC <- ndpRouterEvent{
			nicID,
			addr,
			true,
		}
	}

	if !n.rememberRouter {
		return false, nil
	}

	rt := append([]tcpip.Route(nil), n.routeTable...)
	rt = append(rt, tcpip.Route{
		Destination: header.IPv6EmptySubnet,
		Gateway:     addr,
		NIC:         nicID,
	})
	n.routeTable = rt
	return true, rt
}

// Implements stack.NDPDispatcher.OnDefaultRouterInvalidated.
func (n *ndpDispatcher) OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address) []tcpip.Route {
	if n.routerC != nil {
		n.routerC <- ndpRouterEvent{
			nicID,
			addr,
			false,
		}
	}

	var rt []tcpip.Route
	exclude := tcpip.Route{
		Destination: header.IPv6EmptySubnet,
		Gateway:     addr,
		NIC:         nicID,
	}

	for _, r := range n.routeTable {
		if r != exclude {
			rt = append(rt, r)
		}
	}
	n.routeTable = rt
	return rt
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixDiscovered.
func (n *ndpDispatcher) OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) (bool, []tcpip.Route) {
	if n.prefixC != nil {
		n.prefixC <- ndpPrefixEvent{
			nicID,
			prefix,
			true,
		}
	}

	if !n.rememberPrefix {
		return false, nil
	}

	rt := append([]tcpip.Route(nil), n.routeTable...)
	rt = append(rt, tcpip.Route{
		Destination: prefix,
		NIC:         nicID,
	})
	n.routeTable = rt
	return true, rt
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixInvalidated.
func (n *ndpDispatcher) OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) []tcpip.Route {
	if n.prefixC != nil {
		n.prefixC <- ndpPrefixEvent{
			nicID,
			prefix,
			false,
		}
	}

	var rt []tcpip.Route
	exclude := tcpip.Route{
		Destination: prefix,
		NIC:         nicID,
	}

	for _, r := range n.routeTable {
		if r != exclude {
			rt = append(rt, r)
		}
	}
	n.routeTable = rt
	return rt
}

func (n *ndpDispatcher) OnAutoGenAddress(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) bool {
	if n.autoGenAddrC != nil {
		n.autoGenAddrC <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			newAddr,
		}
	}
	return true
}

func (n *ndpDispatcher) OnAutoGenAddressInvalidated(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) {
	if n.autoGenAddrC != nil {
		n.autoGenAddrC <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			invalidatedAddr,
		}
	}
}

// Implements stack.NDPDispatcher.OnRecursiveDNSServerOption.
func (n *ndpDispatcher) OnRecursiveDNSServerOption(nicID tcpip.NICID, addrs []tcpip.Address, lifetime time.Duration) {
	if n.rdnssC != nil {
		n.rdnssC <- ndpRDNSSEvent{
			nicID,
			ndpRDNSS{
				addrs,
				lifetime,
			},
		}
	}
}

// TestDADResolve tests that an address successfully resolves after performing
// DAD for various values of DupAddrDetectTransmits and RetransmitTimer.
// Included in the subtests is a test to make sure that an invalid
// RetransmitTimer (<1ms) values get fixed to the default RetransmitTimer of 1s.
func TestDADResolve(t *testing.T) {
	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransTimer            time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{"1:1s:1s", 1, time.Second, time.Second},
		{"2:1s:1s", 2, time.Second, time.Second},
		{"1:2s:2s", 1, 2 * time.Second, 2 * time.Second},
		// 0s is an invalid RetransmitTimer timer and will be fixed to
		// the default RetransmitTimer value of 1s.
		{"1:0s:1s", 1, 0, time.Second},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = test.retransTimer
			opts.NDPConfigs.DupAddrDetectTransmits = test.dupAddrDetectTransmits

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			stat := s.Stats().ICMP.V6PacketsSent.NeighborSolicit

			// Should have sent an NDP NS immediately.
			if got := stat.Value(); got != 1 {
				t.Fatalf("got NeighborSolicit = %d, want = 1", got)

			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for the remaining time - some delta (500ms), to
			// make sure the address is still not resolved.
			const delta = 500 * time.Millisecond
			time.Sleep(test.expectedRetransmitTimer*time.Duration(test.dupAddrDetectTransmits) - delta)
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if !e.resolved {
					t.Fatal("got DAD event w/ resolved = false, want = true")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
			}

			// Should not have sent any more NS messages.
			if got := stat.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", got, test.dupAddrDetectTransmits)
			}

			// Validate the sent Neighbor Solicitation messages.
			for i := uint8(0); i < test.dupAddrDetectTransmits; i++ {
				p := <-e.C

				// Make sure its an IPv6 packet.
				if p.Proto != header.IPv6ProtocolNumber {
					t.Fatalf("got Proto = %d, want = %d", p.Proto, header.IPv6ProtocolNumber)
				}

				// Check NDP packet.
				checker.IPv6(t, p.Pkt.Header.View().ToVectorisedView().First(),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(addr1)))
			}
		})
	}

}

// TestDADFail tests to make sure that the DAD process fails if another node is
// detected to be performing DAD on the same address (receive an NS message from
// a node doing DAD for the same address), or if another node is detected to own
// the address already (receive an NA message for the tentative address).
func TestDADFail(t *testing.T) {
	tests := []struct {
		name    string
		makeBuf func(tgt tcpip.Address) buffer.Prependable
		getStat func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
	}{
		{
			"RxSolicit",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
				pkt.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(pkt.NDPPayload())
				ns.SetTargetAddress(tgt)
				snmc := header.SolicitedNodeAddr(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, header.IPv6Any, snmc, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       header.IPv6Any,
					DstAddr:       snmc,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborSolicit
			},
		},
		{
			"RxAdvert",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, tgt, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       tgt,
					DstAddr:       header.IPv6AllNodesMulticastAddress,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborAdvert
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			ndpConfigs := stack.DefaultNDPConfigurations()
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs:       ndpConfigs,
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = time.Second * 2

			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Receive a packet to simulate multiple nodes owning or
			// attempting to own the same address.
			hdr := test.makeBuf(addr1)
			e.InjectInbound(header.IPv6ProtocolNumber, tcpip.PacketBuffer{
				Data: hdr.View().ToVectorisedView(),
			})

			stat := test.getStat(s.Stats().ICMP.V6PacketsReceived)
			if got := stat.Value(); got != 1 {
				t.Fatalf("got stat = %d, want = 1", got)
			}

			// Wait for DAD to fail and make sure the address did
			// not get resolved.
			select {
			case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
				// If we don't get a failure event after the
				// expected resolution time + extra 1s buffer,
				// something is wrong.
				t.Fatal("timed out waiting for DAD failure")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if e.resolved {
					t.Fatal("got DAD event w/ resolved = true, want = false")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}
		})
	}
}

// TestDADStop tests to make sure that the DAD process stops when an address is
// removed.
func TestDADStop(t *testing.T) {
	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent),
	}
	ndpConfigs := stack.NDPConfigurations{
		RetransmitTimer:        time.Second,
		DupAddrDetectTransmits: 2,
	}
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPDisp:          &ndpDisp,
		NDPConfigs:       ndpConfigs,
	}

	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
	}

	// Remove the address. This should stop DAD.
	if err := s.RemoveAddress(1, addr1); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr1, err)
	}

	// Wait for DAD to fail (since the address was removed during DAD).
	select {
	case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
		// If we don't get a failure event after the expected resolution
		// time + extra 1s buffer, something is wrong.
		t.Fatal("timed out waiting for DAD failure")
	case e := <-ndpDisp.dadC:
		if e.err != nil {
			t.Fatal("got DAD error: ", e.err)
		}
		if e.nicID != 1 {
			t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
		}
		if e.addr != addr1 {
			t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
		}
		if e.resolved {
			t.Fatal("got DAD event w/ resolved = true, want = false")
		}

	}
	addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
	}

	// Should not have sent more than 1 NS message.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got > 1 {
		t.Fatalf("got NeighborSolicit = %d, want <= 1", got)
	}
}

// TestSetNDPConfigurationFailsForBadNICID tests to make sure we get an error if
// we attempt to update NDP configurations using an invalid NICID.
func TestSetNDPConfigurationFailsForBadNICID(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})

	// No NIC with ID 1 yet.
	if got := s.SetNDPConfigurations(1, stack.NDPConfigurations{}); got != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations = %v, want = %s", got, tcpip.ErrUnknownNICID)
	}
}

// TestSetNDPConfigurations tests that we can update and use per-interface NDP
// configurations without affecting the default NDP configurations or other
// interfaces' configurations.
func TestSetNDPConfigurations(t *testing.T) {
	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransmitTimer         time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{
			"OK",
			1,
			time.Second,
			time.Second,
		},
		{
			"Invalid Retransmit Timer",
			1,
			0,
			time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			})

			// This NIC(1)'s NDP configurations will be updated to
			// be different from the default.
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Created before updating NIC(1)'s NDP configurations
			// but updating NIC(1)'s NDP configurations should not
			// affect other existing NICs.
			if err := s.CreateNIC(2, e); err != nil {
				t.Fatalf("CreateNIC(2) = %s", err)
			}

			// Update the NDP configurations on NIC(1) to use DAD.
			configs := stack.NDPConfigurations{
				DupAddrDetectTransmits: test.dupAddrDetectTransmits,
				RetransmitTimer:        test.retransmitTimer,
			}
			if err := s.SetNDPConfigurations(1, configs); err != nil {
				t.Fatalf("got SetNDPConfigurations(1, _) = %s", err)
			}

			// Created after updating NIC(1)'s NDP configurations
			// but the stack's default NDP configurations should not
			// have been updated.
			if err := s.CreateNIC(3, e); err != nil {
				t.Fatalf("CreateNIC(3) = %s", err)
			}

			// Add addresses for each NIC.
			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(1, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}
			if err := s.AddAddress(2, header.IPv6ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(2, %d, %s) = %s", header.IPv6ProtocolNumber, addr2, err)
			}
			if err := s.AddAddress(3, header.IPv6ProtocolNumber, addr3); err != nil {
				t.Fatalf("AddAddress(3, %d, %s) = %s", header.IPv6ProtocolNumber, addr3, err)
			}

			// Address should not be considered bound to NIC(1) yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Should get the address on NIC(2) and NIC(3)
			// immediately since we should not have performed DAD on
			// it as the stack was configured to not do DAD by
			// default and we only updated the NDP configurations on
			// NIC(1).
			addr, err = s.GetMainNICAddress(2, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(2, _) err = %s", err)
			}
			if addr.Address != addr2 {
				t.Fatalf("got stack.GetMainNICAddress(2, _) = %s, want = %s", addr, addr2)
			}
			addr, err = s.GetMainNICAddress(3, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(3, _) err = %s", err)
			}
			if addr.Address != addr3 {
				t.Fatalf("got stack.GetMainNICAddress(3, _) = %s, want = %s", addr, addr3)
			}

			// Sleep until right (500ms before) before resolution to
			// make sure the address didn't resolve on NIC(1) yet.
			const delta = 500 * time.Millisecond
			time.Sleep(time.Duration(test.dupAddrDetectTransmits)*test.expectedRetransmitTimer - delta)
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if !e.resolved {
					t.Fatal("got DAD event w/ resolved = false, want = true")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(1, _) err = %s", err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(1, _) = %s, want = %s", addr, addr1)
			}
		})
	}
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) tcpip.PacketBuffer {
	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + int(optSer.Length())
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
	pkt := header.ICMPv6(hdr.Prepend(icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	ra := header.NDPRouterAdvert(pkt.NDPPayload())
	opts := ra.Options()
	opts.Serialize(optSer)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(pkt.NDPPayload()[2:], rl)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, ip, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	iph := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(icmp.ProtocolNumber6),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       ip,
		DstAddr:       header.IPv6AllNodesMulticastAddress,
	})

	return tcpip.PacketBuffer{Data: hdr.View().ToVectorisedView()}
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBuf(ip tcpip.Address, rl uint16) tcpip.PacketBuffer {
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{})
}

// raBufWithPI returns a valid NDP Router Advertisement with a single Prefix
// Information option.
//
// Note, raBufWithPI does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithPI(ip tcpip.Address, rl uint16, prefix tcpip.AddressWithPrefix, onLink, auto bool, vl, pl uint32) tcpip.PacketBuffer {
	flags := uint8(0)
	if onLink {
		// The OnLink flag is the 7th bit in the flags byte.
		flags |= 1 << 7
	}
	if auto {
		// The Address Auto-Configuration flag is the 6th bit in the
		// flags byte.
		flags |= 1 << 6
	}

	// A valid header.NDPPrefixInformation must be 30 bytes.
	buf := [30]byte{}
	// The first byte in a header.NDPPrefixInformation is the Prefix Length
	// field.
	buf[0] = uint8(prefix.PrefixLen)
	// The 2nd byte within a header.NDPPrefixInformation is the Flags field.
	buf[1] = flags
	// The Valid Lifetime field starts after the 2nd byte within a
	// header.NDPPrefixInformation.
	binary.BigEndian.PutUint32(buf[2:], vl)
	// The Preferred Lifetime field starts after the 6th byte within a
	// header.NDPPrefixInformation.
	binary.BigEndian.PutUint32(buf[6:], pl)
	// The Prefix Address field starts after the 14th byte within a
	// header.NDPPrefixInformation.
	copy(buf[14:], prefix.Address)
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{
		header.NDPPrefixInformation(buf[:]),
	})
}

// TestNoRouterDiscovery tests that router discovery will not be performed if
// configured not to.
func TestNoRouterDiscovery(t *testing.T) {
	// Being configured to discover routers means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// router discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverDefaultRouters(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				routerC: make(chan ndpRouterEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverDefaultRouters: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
			select {
			case <-ndpDisp.routerC:
				t.Fatal("unexpectedly discovered a router when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// discovered flag set to discovered.
func checkRouterEvent(e ndpRouterEvent, addr tcpip.Address, discovered bool) string {
	return cmp.Diff(ndpRouterEvent{nicID: 1, addr: addr, discovered: discovered}, e, cmp.AllowUnexported(e))
}

// TestRouterDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered router when the dispatcher asks it not to.
func TestRouterDiscoveryDispatcherNoRemember(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC: make(chan ndpRouterEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	routeTable := []tcpip.Route{
		{
			header.IPv6EmptySubnet,
			llAddr3,
			1,
		},
	}
	s.SetRouteTable(routeTable)

	// Receive an RA for a router we should not remember.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, lifetimeSeconds))
	select {
	case e := <-ndpDisp.routerC:
		if diff := checkRouterEvent(e, llAddr2, true); diff != "" {
			t.Errorf("router event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected router discovery event")
	}

	// Original route table should not have been modified.
	if diff := cmp.Diff(routeTable, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Wait for the invalidation time plus some buffer to make sure we do
	// not actually receive any invalidation events as we should not have
	// remembered the router in the first place.
	select {
	case <-ndpDisp.routerC:
		t.Fatal("should not have received any router events")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}

	// Original route table should not have been modified.
	if diff := cmp.Diff(routeTable, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}
}

func TestRouterDiscovery(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 1),
		rememberRouter: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	expectRouterEvent := func(addr tcpip.Address, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.routerC:
			if diff := checkRouterEvent(e, addr, discovered); diff != "" {
				t.Errorf("router event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected router discovery event")
		}
	}

	expectAsyncRouterInvalidationEvent := func(addr tcpip.Address, timeout time.Duration) {
		t.Helper()

		select {
		case e := <-ndpDisp.routerC:
			if diff := checkRouterEvent(e, addr, false); diff != "" {
				t.Errorf("router event mismatch (-want +got):\n%s", diff)
			}
		case <-time.After(timeout):
			t.Fatal("timed out waiting for router discovery event")
		}
	}

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Rx an RA from lladdr2 with zero lifetime. It should not be
	// remembered.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("unexpectedly discovered a router with 0 lifetime")
	default:
	}

	// Rx an RA from lladdr2 with a huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	expectRouterEvent(llAddr2, true)

	// Should have a default route through the discovered router.
	if diff := cmp.Diff([]tcpip.Route{{header.IPv6EmptySubnet, llAddr2, 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Rx an RA from another router (lladdr3) with non-zero lifetime.
	l3Lifetime := time.Duration(6)
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr3, uint16(l3Lifetime)))
	expectRouterEvent(llAddr3, true)

	// Should have default routes through the discovered routers.
	want := []tcpip.Route{{header.IPv6EmptySubnet, llAddr2, 1}, {header.IPv6EmptySubnet, llAddr3, 1}}
	if diff := cmp.Diff(want, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Rx an RA from lladdr2 with lesser lifetime.
	l2Lifetime := time.Duration(2)
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, uint16(l2Lifetime)))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("Should not receive a router event when updating lifetimes for known routers")
	default:
	}

	// Should still have a default route through the discovered routers.
	if diff := cmp.Diff(want, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Wait for lladdr2's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	expectAsyncRouterInvalidationEvent(llAddr2, l2Lifetime*time.Second+defaultTimeout)

	// Should no longer have the default route through lladdr2.
	if diff := cmp.Diff([]tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Rx an RA from lladdr2 with huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	expectRouterEvent(llAddr2, true)

	// Should have a default route through the discovered routers.
	if diff := cmp.Diff([]tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}, {header.IPv6EmptySubnet, llAddr2, 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Rx an RA from lladdr2 with zero lifetime. It should be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	expectRouterEvent(llAddr2, false)

	// Should have deleted the default route through the router that just
	// got invalidated.
	if diff := cmp.Diff([]tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Wait for lladdr3's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	expectAsyncRouterInvalidationEvent(llAddr3, l3Lifetime*time.Second+defaultTimeout)

	// Should not have any routes now that all discovered routers have been
	// invalidated.
	if got := len(s.GetRouteTable()); got != 0 {
		t.Fatalf("got len(s.GetRouteTable()) = %d, want = 0", got)
	}
}

// TestRouterDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredDefaultRouters discovered routers are remembered.
func TestRouterDiscoveryMaxRouters(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 1),
		rememberRouter: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectedRt := [stack.MaxDiscoveredDefaultRouters]tcpip.Route{}

	// Receive an RA from 2 more than the max number of discovered routers.
	for i := 1; i <= stack.MaxDiscoveredDefaultRouters+2; i++ {
		linkAddr := []byte{2, 2, 3, 4, 5, 0}
		linkAddr[5] = byte(i)
		llAddr := header.LinkLocalAddr(tcpip.LinkAddress(linkAddr))

		e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr, 5))

		if i <= stack.MaxDiscoveredDefaultRouters {
			expectedRt[i-1] = tcpip.Route{header.IPv6EmptySubnet, llAddr, 1}
			select {
			case e := <-ndpDisp.routerC:
				if diff := checkRouterEvent(e, llAddr, true); diff != "" {
					t.Errorf("router event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected router discovery event")
			}

		} else {
			select {
			case <-ndpDisp.routerC:
				t.Fatal("should not have discovered a new router after we already discovered the max number of routers")
			default:
			}
		}
	}

	// Should only have default routes for the first
	// stack.MaxDiscoveredDefaultRouters discovered routers.
	if diff := cmp.Diff(expectedRt[:], s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}
}

// TestNoPrefixDiscovery tests that prefix discovery will not be performed if
// configured not to.
func TestNoPrefixDiscovery(t *testing.T) {
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}

	// Being configured to discover prefixes means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// prefix discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverOnLinkPrefixes(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				prefixC: make(chan ndpPrefixEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverOnLinkPrefixes: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with prefix with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, 10, 0))

			select {
			case <-ndpDisp.prefixC:
				t.Fatal("unexpectedly discovered a prefix when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for prefix on nic with ID 1, and the
// discovered flag set to discovered.
func checkPrefixEvent(e ndpPrefixEvent, prefix tcpip.Subnet, discovered bool) string {
	return cmp.Diff(ndpPrefixEvent{nicID: 1, prefix: prefix, discovered: discovered}, e, cmp.AllowUnexported(e))
}

// TestPrefixDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered on-link prefix when the dispatcher asks it not to.
func TestPrefixDiscoveryDispatcherNoRemember(t *testing.T) {
	t.Parallel()

	prefix, subnet, _ := prefixSubnetAddr(0, "")

	ndpDisp := ndpDispatcher{
		prefixC: make(chan ndpPrefixEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	routeTable := []tcpip.Route{
		{
			header.IPv6EmptySubnet,
			llAddr3,
			1,
		},
	}
	s.SetRouteTable(routeTable)

	// Receive an RA with prefix that we should not remember.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, lifetimeSeconds, 0))
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, true); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected prefix discovery event")
	}

	// Original route table should not have been modified.
	if diff := cmp.Diff(routeTable, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Wait for the invalidation time plus some buffer to make sure we do
	// not actually receive any invalidation events as we should not have
	// remembered the prefix in the first place.
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("should not have received any prefix events")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}

	// Original route table should not have been modified.
	if diff := cmp.Diff(routeTable, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}
}

func TestPrefixDiscovery(t *testing.T) {
	t.Parallel()

	prefix1, subnet1, _ := prefixSubnetAddr(0, "")
	prefix2, subnet2, _ := prefixSubnetAddr(1, "")
	prefix3, subnet3, _ := prefixSubnetAddr(2, "")

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 1),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectPrefixEvent := func(prefix tcpip.Subnet, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.prefixC:
			if diff := checkPrefixEvent(e, prefix, discovered); diff != "" {
				t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected prefix discovery event")
		}
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with zero valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 0, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly discovered a prefix with 0 lifetime")
	default:
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 100, 0))
	expectPrefixEvent(subnet1, true)

	// Should have added a device route for subnet1 through the nic.
	if diff := cmp.Diff([]tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Receive an RA with prefix2 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, 100, 0))
	expectPrefixEvent(subnet2, true)

	// Should have added a device route for subnet2 through the nic.
	if diff := cmp.Diff([]tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}, {subnet2, tcpip.Address([]byte(nil)), 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Receive an RA with prefix3 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 100, 0))
	expectPrefixEvent(subnet3, true)

	// Should have added a device route for subnet3 through the nic.
	if diff := cmp.Diff([]tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}, {subnet2, tcpip.Address([]byte(nil)), 1}, {subnet3, tcpip.Address([]byte(nil)), 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Receive an RA with prefix1 in a PI with lifetime = 0.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 0, 0))
	expectPrefixEvent(subnet1, false)

	// Should have removed the device route for subnet1 through the nic.
	want := []tcpip.Route{{subnet2, tcpip.Address([]byte(nil)), 1}, {subnet3, tcpip.Address([]byte(nil)), 1}}
	if diff := cmp.Diff(want, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Receive an RA with prefix2 in a PI with lesser lifetime.
	lifetime := uint32(2)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, lifetime, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly received prefix event when updating lifetime")
	default:
	}

	// Should not have updated route table.
	if diff := cmp.Diff(want, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Wait for prefix2's most recent invalidation timer plus some buffer to
	// expire.
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet2, false); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(time.Duration(lifetime)*time.Second + defaultTimeout):
		t.Fatal("timed out waiting for prefix discovery event")
	}

	// Should have removed the device route for subnet2 through the nic.
	if diff := cmp.Diff([]tcpip.Route{{subnet3, tcpip.Address([]byte(nil)), 1}}, s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}

	// Receive RA to invalidate prefix3.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 0, 0))
	expectPrefixEvent(subnet3, false)

	// Should not have any routes.
	if got := len(s.GetRouteTable()); got != 0 {
		t.Fatalf("got len(s.GetRouteTable()) = %d, want = 0", got)
	}
}

func TestPrefixDiscoveryWithInfiniteLifetime(t *testing.T) {
	// Update the infinite lifetime value to a smaller value so we can test
	// that when we receive a PI with such a lifetime value, we do not
	// invalidate the prefix.
	const testInfiniteLifetimeSeconds = 2
	const testInfiniteLifetime = testInfiniteLifetimeSeconds * time.Second
	saved := header.NDPInfiniteLifetime
	header.NDPInfiniteLifetime = testInfiniteLifetime
	defer func() {
		header.NDPInfiniteLifetime = saved
	}()

	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	subnet := prefix.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 1),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectPrefixEvent := func(prefix tcpip.Subnet, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.prefixC:
			if diff := checkPrefixEvent(e, prefix, discovered); diff != "" {
				t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected prefix discovery event")
		}
	}

	// Receive an RA with prefix in an NDP Prefix Information option (PI)
	// with infinite valid lifetime which should not get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds, 0))
	expectPrefixEvent(subnet, true)
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with finite lifetime.
	// The prefix should get invalidated after 1s.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds-1, 0))
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, false); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(testInfiniteLifetime):
		t.Fatal("timed out waiting for prefix discovery event")
	}

	// Receive an RA with finite lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds-1, 0))
	expectPrefixEvent(subnet, true)

	// Receive an RA with prefix with an infinite lifetime.
	// The prefix should not be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with a prefix with a lifetime value greater than the
	// set infinite lifetime value.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds+1, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After((testInfiniteLifetimeSeconds+1)*time.Second + defaultTimeout):
	}

	// Receive an RA with 0 lifetime.
	// The prefix should get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, 0, 0))
	expectPrefixEvent(subnet, false)
}

// TestPrefixDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes are remembered.
func TestPrefixDiscoveryMaxOnLinkPrefixes(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, stack.MaxDiscoveredOnLinkPrefixes+3),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	optSer := make(header.NDPOptionsSerializer, stack.MaxDiscoveredOnLinkPrefixes+2)
	expectedRt := [stack.MaxDiscoveredOnLinkPrefixes]tcpip.Route{}
	prefixes := [stack.MaxDiscoveredOnLinkPrefixes + 2]tcpip.Subnet{}

	// Receive an RA with 2 more than the max number of discovered on-link
	// prefixes.
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		prefixAddr := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}
		prefixAddr[7] = byte(i)
		prefix := tcpip.AddressWithPrefix{
			Address:   tcpip.Address(prefixAddr[:]),
			PrefixLen: 64,
		}
		prefixes[i] = prefix.Subnet()
		buf := [30]byte{}
		buf[0] = uint8(prefix.PrefixLen)
		buf[1] = 128
		binary.BigEndian.PutUint32(buf[2:], 10)
		copy(buf[14:], prefix.Address)

		optSer[i] = header.NDPPrefixInformation(buf[:])

		if i < stack.MaxDiscoveredOnLinkPrefixes {
			expectedRt[i] = tcpip.Route{prefixes[i], tcpip.Address([]byte(nil)), 1}
		}
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		if i < stack.MaxDiscoveredOnLinkPrefixes {
			select {
			case e := <-ndpDisp.prefixC:
				if diff := checkPrefixEvent(e, prefixes[i], true); diff != "" {
					t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected prefix discovery event")
			}
		} else {
			select {
			case <-ndpDisp.prefixC:
				t.Fatal("should not have discovered a new prefix after we already discovered the max number of prefixes")
			default:
			}
		}
	}

	// Should only have device routes for the first
	// stack.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes.
	if diff := cmp.Diff(expectedRt[:], s.GetRouteTable()); diff != "" {
		t.Fatalf("GetRouteTable() mismatch (-want +got):\n%s", diff)
	}
}

// Checks to see if list contains an IPv6 address, item.
func contains(list []tcpip.ProtocolAddress, item tcpip.AddressWithPrefix) bool {
	protocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: item,
	}

	for _, i := range list {
		if i == protocolAddress {
			return true
		}
	}

	return false
}

// TestNoAutoGenAddr tests that SLAAC is not performed when configured not to.
func TestNoAutoGenAddr(t *testing.T) {
	prefix, _, _ := prefixSubnetAddr(0, "")

	// Being configured to auto-generate addresses means handle and
	// autogen are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, autogen =
	// true and forwarding = false (the required configuration to do
	// SLAAC) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		autogen := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), AutoGenAddr(%t), Forwarding(%t)", handle, autogen, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					AutoGenGlobalAddresses: autogen,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with prefix with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, false, true, 10, 0))

			select {
			case <-ndpDisp.autoGenAddrC:
				t.Fatal("unexpectedly auto-generated an address when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// event type is set to eventType.
func checkAutoGenAddrEvent(e ndpAutoGenAddrEvent, addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) string {
	return cmp.Diff(ndpAutoGenAddrEvent{nicID: 1, addr: addr, eventType: eventType}, e, cmp.AllowUnexported(e))
}

// TestAutoGenAddr tests that an address is properly generated and invalidated
// when configured to do so.
func TestAutoGenAddr(t *testing.T) {
	const newMinVL = 2
	newMinVLDuration := newMinVL * time.Second
	saved := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = saved
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = newMinVLDuration

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with zero valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 0, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address with 0 lifetime")
	default:
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 0))
	expectAutoGenAddrEvent(addr1, newAddr)
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Receive an RA with prefix2 in an NDP Prefix Information option (PI)
	// with preferred lifetime > valid lifetime
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 5, 6))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address with preferred lifetime > valid lifetime")
	default:
	}

	// Receive an RA with prefix2 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	expectAutoGenAddrEvent(addr2, newAddr)
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr2) {
		t.Fatalf("Should have %s in the list of addresses", addr2)
	}

	// Refresh valid lifetime for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, newMinVL, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address when we already have an address for a prefix")
	default:
	}

	// Wait for addr of prefix1 to be invalidated.
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr1, invalidatedAddr); diff != "" {
			t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(newMinVLDuration + defaultTimeout):
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if contains(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should not have %s in the list of addresses", addr1)
	}
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr2) {
		t.Fatalf("Should have %s in the list of addresses", addr2)
	}
}

// TestAutoGenAddrValidLifetimeUpdates tests that the valid lifetime of an
// auto-generated address only gets updated when required to, as specified in
// RFC 4862 section 5.5.3.e.
func TestAutoGenAddrValidLifetimeUpdates(t *testing.T) {
	const infiniteVL = 4294967295
	const newMinVL = 5
	saved := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = saved
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = newMinVL * time.Second

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	tests := []struct {
		name string
		ovl  uint32
		nvl  uint32
		evl  uint32
	}{
		// Should update the VL to the minimum VL for updating if the
		// new VL is less than newMinVL but was originally greater than
		// it.
		{
			"LargeVLToVLLessThanMinVLForUpdate",
			9999,
			1,
			newMinVL,
		},
		{
			"LargeVLTo0",
			9999,
			0,
			newMinVL,
		},
		{
			"InfiniteVLToVLLessThanMinVLForUpdate",
			infiniteVL,
			1,
			newMinVL,
		},
		{
			"InfiniteVLTo0",
			infiniteVL,
			0,
			newMinVL,
		},

		// Should not update VL if original VL was less than newMinVL
		// and the new VL is also less than newMinVL.
		{
			"ShouldNotUpdateWhenBothOldAndNewAreLessThanMinVLForUpdate",
			newMinVL - 1,
			newMinVL - 3,
			newMinVL - 1,
		},

		// Should take the new VL if the new VL is greater than the
		// remaining time or is greater than newMinVL.
		{
			"MorethanMinVLToLesserButStillMoreThanMinVLForUpdate",
			newMinVL + 5,
			newMinVL + 3,
			newMinVL + 3,
		},
		{
			"SmallVLToGreaterVLButStillLessThanMinVLForUpdate",
			newMinVL - 3,
			newMinVL - 1,
			newMinVL - 1,
		},
		{
			"SmallVLToGreaterVLThatIsMoreThaMinVLForUpdate",
			newMinVL - 3,
			newMinVL + 1,
			newMinVL + 1,
		},
	}

	const delta = 500 * time.Millisecond

	// This Run will not return until the parallel tests finish.
	//
	// We need this because we need to do some teardown work after the
	// parallel tests complete.
	//
	// See https://godoc.org/testing#hdr-Subtests_and_Sub_benchmarks for
	// more details.
	t.Run("group", func(t *testing.T) {
		for _, test := range tests {
			test := test

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ndpDisp := ndpDispatcher{
					autoGenAddrC: make(chan ndpAutoGenAddrEvent, 10),
				}
				e := channel.New(10, 1280, linkAddr1)
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
					NDPConfigs: stack.NDPConfigurations{
						HandleRAs:              true,
						AutoGenGlobalAddresses: true,
					},
					NDPDisp: &ndpDisp,
				})

				if err := s.CreateNIC(1, e); err != nil {
					t.Fatalf("CreateNIC(1) = %s", err)
				}

				// Receive an RA with prefix with initial VL,
				// test.ovl.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.ovl, 0))
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, newAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatal("expected addr auto gen event")
				}

				// Receive an new RA with prefix with new VL,
				// test.nvl.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.nvl, 0))

				//
				// Validate that the VL for the address got set
				// to test.evl.
				//

				// Make sure we do not get any invalidation
				// events until atleast 500ms (delta) before
				// test.evl.
				select {
				case <-ndpDisp.autoGenAddrC:
					t.Fatalf("unexpectedly received an auto gen addr event")
				case <-time.After(time.Duration(test.evl)*time.Second - delta):
				}

				// Wait for another second (2x delta), but now
				// we expect the invalidation event.
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}

				case <-time.After(2 * delta):
					t.Fatal("timeout waiting for addr auto gen event")
				}
			})
		}
	})
}

// TestAutoGenAddrRemoval tests that when auto-generated addresses are removed
// by the user, its resources will be cleaned up and an invalidation event will
// be sent to the integrator.
func TestAutoGenAddrRemoval(t *testing.T) {
	t.Parallel()

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	// Receive a PI to auto-generate an address.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, 0))
	expectAutoGenAddrEvent(addr, newAddr)

	// Removing the address should result in an invalidation event
	// immediately.
	if err := s.RemoveAddress(1, addr.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr.Address, err)
	}
	expectAutoGenAddrEvent(addr, invalidatedAddr)

	// Wait for the original valid lifetime to make sure the original timer
	// got stopped/cleaned up.
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpectedly received an auto gen addr event")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
}

// TestAutoGenAddrStaticConflict tests that if SLAAC generates an address that
// is already assigned to the NIC, the static address remains.
func TestAutoGenAddrStaticConflict(t *testing.T) {
	t.Parallel()

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Add the address as a static address before SLAAC tries to add it.
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: addr}); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr.Address, err)
	}
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Receive a PI where the generated address will be the same as the one
	// that we already have assigned statically.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event for an address we already have statically")
	default:
	}
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Should not get an invalidation event after the PI's invalidation
	// time.
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
	if !contains(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}
}

// TestNDPRecursiveDNSServerDispatch tests that we properly dispatch an event
// to the integrator when an RA is received with the NDP Recursive DNS Server
// option with at least one valid address.
func TestNDPRecursiveDNSServerDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opt      header.NDPRecursiveDNSServer
		expected *ndpRDNSS
	}{
		{
			"Unspecified",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			}),
			nil,
		},
		{
			"Multicast",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			}),
			nil,
		},
		{
			"OptionTooSmall",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8,
			}),
			nil,
		},
		{
			"0Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
			}),
			nil,
		},
		{
			"Valid1Address",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
				},
				2 * time.Second,
			},
		},
		{
			"Valid2Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 2,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x02",
				},
				time.Second,
			},
		},
		{
			"Valid3Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 3,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x02",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x03",
				},
				0,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				// We do not expect more than a single RDNSS
				// event at any time for this test.
				rdnssC: make(chan ndpRDNSSEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs: true,
				},
				NDPDisp: &ndpDisp,
			})
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, header.NDPOptionsSerializer{test.opt}))

			if test.expected != nil {
				select {
				case e := <-ndpDisp.rdnssC:
					if e.nicID != 1 {
						t.Errorf("got rdnss nicID = %d, want = 1", e.nicID)
					}
					if diff := cmp.Diff(e.rdnss.addrs, test.expected.addrs); diff != "" {
						t.Errorf("rdnss addrs mismatch (-want +got):\n%s", diff)
					}
					if e.rdnss.lifetime != test.expected.lifetime {
						t.Errorf("got rdnss lifetime = %s, want = %s", e.rdnss.lifetime, test.expected.lifetime)
					}
				default:
					t.Fatal("expected an RDNSS option event")
				}
			}

			// Should have no more RDNSS options.
			select {
			case e := <-ndpDisp.rdnssC:
				t.Fatalf("unexpectedly got a new RDNSS option event: %+v", e)
			default:
			}
		})
	}
}
