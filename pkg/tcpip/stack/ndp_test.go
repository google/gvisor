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
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/bufferv2"
	cryptorand "gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	addr1 = testutil.MustParse6("a00::1")
	addr2 = testutil.MustParse6("a00::2")
	addr3 = testutil.MustParse6("a00::3")
)

const (
	linkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	linkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	linkAddr3 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
	linkAddr4 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

	defaultPrefixLen  = 128
	infiniteVLSeconds = math.MaxUint32
)

var (
	llAddr1 = header.LinkLocalAddr(linkAddr1)
	llAddr2 = header.LinkLocalAddr(linkAddr2)
	llAddr3 = header.LinkLocalAddr(linkAddr3)
	llAddr4 = header.LinkLocalAddr(linkAddr4)
	dstAddr = tcpip.FullAddress{
		Addr: "\x0a\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		Port: 25,
	}
)

func addrForSubnet(subnet tcpip.Subnet, linkAddr tcpip.LinkAddress) tcpip.AddressWithPrefix {
	if !header.IsValidUnicastEthernetAddress(linkAddr) {
		return tcpip.AddressWithPrefix{}
	}

	addrBytes := []byte(subnet.ID())
	header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
	return tcpip.AddressWithPrefix{
		Address:   tcpip.Address(addrBytes),
		PrefixLen: 64,
	}
}

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

	return prefix, subnet, addrForSubnet(subnet, linkAddr)
}

// ndpDADEvent is a set of parameters that was passed to
// ndpDispatcher.OnDuplicateAddressDetectionResult.
type ndpDADEvent struct {
	nicID tcpip.NICID
	addr  tcpip.Address
	res   stack.DADResult
}

type ndpOffLinkRouteEvent struct {
	nicID  tcpip.NICID
	subnet tcpip.Subnet
	router tcpip.Address
	prf    header.NDPRoutePreference
	// true if route was updated, false if invalidated.
	updated bool
}

type ndpPrefixEvent struct {
	nicID  tcpip.NICID
	prefix tcpip.Subnet
	// true if prefix was discovered, false if invalidated.
	discovered bool
}

type ndpAutoGenAddrNewEvent struct {
	nicID    tcpip.NICID
	addr     tcpip.AddressWithPrefix
	addrDisp *addressDispatcher
}

type ndpAutoGenAddrEventType int

const (
	deprecatedAddr ndpAutoGenAddrEventType = iota
	invalidatedAddr
)

type ndpAutoGenAddrEvent struct {
	nicID     tcpip.NICID
	addr      tcpip.AddressWithPrefix
	eventType ndpAutoGenAddrEventType
}

func (e ndpAutoGenAddrEvent) String() string {
	return fmt.Sprintf("%T{nicID=%d addr=%s eventType=%d}", e, e.nicID, e.addr, e.eventType)
}

type ndpRDNSS struct {
	addrs    []tcpip.Address
	lifetime time.Duration
}

type ndpRDNSSEvent struct {
	nicID tcpip.NICID
	rdnss ndpRDNSS
}

type ndpDNSSLEvent struct {
	nicID       tcpip.NICID
	domainNames []string
	lifetime    time.Duration
}

type ndpDHCPv6Event struct {
	nicID         tcpip.NICID
	configuration ipv6.DHCPv6ConfigurationFromNDPRA
}

var _ ipv6.NDPDispatcher = (*ndpDispatcher)(nil)

// ndpDispatcher implements NDPDispatcher so tests can know when various NDP
// related events happen for test purposes.
type ndpDispatcher struct {
	dadC            chan ndpDADEvent
	offLinkRouteC   chan ndpOffLinkRouteEvent
	prefixC         chan ndpPrefixEvent
	autoGenAddrC    chan ndpAutoGenAddrEvent
	autoGenAddrNewC chan ndpAutoGenAddrNewEvent
	// autoGenInstallDisp controls whether address dispatchers are installed for
	// new auto-generated addresses.
	autoGenInstallDisp   bool
	rdnssC               chan ndpRDNSSEvent
	dnsslC               chan ndpDNSSLEvent
	routeTable           []tcpip.Route
	dhcpv6ConfigurationC chan ndpDHCPv6Event
}

// Implements ipv6.NDPDispatcher.OnDuplicateAddressDetectionResult.
func (n *ndpDispatcher) OnDuplicateAddressDetectionResult(nicID tcpip.NICID, addr tcpip.Address, res stack.DADResult) {
	if n.dadC != nil {
		n.dadC <- ndpDADEvent{
			nicID,
			addr,
			res,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnOffLinkRouteUpdated.
func (n *ndpDispatcher) OnOffLinkRouteUpdated(nicID tcpip.NICID, subnet tcpip.Subnet, router tcpip.Address, prf header.NDPRoutePreference) {
	if c := n.offLinkRouteC; c != nil {
		c <- ndpOffLinkRouteEvent{
			nicID,
			subnet,
			router,
			prf,
			true,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnOffLinkRouteInvalidated.
func (n *ndpDispatcher) OnOffLinkRouteInvalidated(nicID tcpip.NICID, subnet tcpip.Subnet, router tcpip.Address) {
	if c := n.offLinkRouteC; c != nil {
		var prf header.NDPRoutePreference
		c <- ndpOffLinkRouteEvent{
			nicID,
			subnet,
			router,
			prf,
			false,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnOnLinkPrefixDiscovered.
func (n *ndpDispatcher) OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) {
	if c := n.prefixC; c != nil {
		c <- ndpPrefixEvent{
			nicID,
			prefix,
			true,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnOnLinkPrefixInvalidated.
func (n *ndpDispatcher) OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) {
	if c := n.prefixC; c != nil {
		c <- ndpPrefixEvent{
			nicID,
			prefix,
			false,
		}
	}
}

func (n *ndpDispatcher) OnAutoGenAddress(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) stack.AddressDispatcher {
	if c := n.autoGenAddrNewC; c != nil {
		e := ndpAutoGenAddrNewEvent{
			nicID,
			addr,
			nil,
		}
		if n.autoGenInstallDisp {
			e.addrDisp = &addressDispatcher{
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
				nicid:     nicID,
				addr:      addr,
			}
		}
		c <- e
		if n.autoGenInstallDisp {
			return e.addrDisp
		}
	}
	return nil
}

func (n *ndpDispatcher) OnAutoGenAddressDeprecated(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) {
	if c := n.autoGenAddrC; c != nil {
		c <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			deprecatedAddr,
		}
	}
}

func (n *ndpDispatcher) OnAutoGenAddressInvalidated(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) {
	if c := n.autoGenAddrC; c != nil {
		c <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			invalidatedAddr,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnRecursiveDNSServerOption.
func (n *ndpDispatcher) OnRecursiveDNSServerOption(nicID tcpip.NICID, addrs []tcpip.Address, lifetime time.Duration) {
	if c := n.rdnssC; c != nil {
		c <- ndpRDNSSEvent{
			nicID,
			ndpRDNSS{
				addrs,
				lifetime,
			},
		}
	}
}

// Implements ipv6.NDPDispatcher.OnDNSSearchListOption.
func (n *ndpDispatcher) OnDNSSearchListOption(nicID tcpip.NICID, domainNames []string, lifetime time.Duration) {
	if n.dnsslC != nil {
		n.dnsslC <- ndpDNSSLEvent{
			nicID,
			domainNames,
			lifetime,
		}
	}
}

// Implements ipv6.NDPDispatcher.OnDHCPv6Configuration.
func (n *ndpDispatcher) OnDHCPv6Configuration(nicID tcpip.NICID, configuration ipv6.DHCPv6ConfigurationFromNDPRA) {
	if c := n.dhcpv6ConfigurationC; c != nil {
		c <- ndpDHCPv6Event{
			nicID,
			configuration,
		}
	}
}

// channelLinkWithHeaderLength is a channel.Endpoint with a configurable
// header length.
type channelLinkWithHeaderLength struct {
	*channel.Endpoint
	headerLength uint16
}

func (l *channelLinkWithHeaderLength) MaxHeaderLength() uint16 {
	return l.headerLength
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// resolved flag set to resolved with the specified err.
func checkDADEvent(e ndpDADEvent, nicID tcpip.NICID, addr tcpip.Address, res stack.DADResult) string {
	return cmp.Diff(ndpDADEvent{nicID: nicID, addr: addr, res: res}, e, cmp.AllowUnexported(e))
}

// addressLifetimes returns address lifetimes computed by adding pl and vl
// from the reference time.
//
// If pl is 0, the returned lifetimes will be deprecated and have a zero value
// for the PreferredUntil field.
//
// If vl is infinite, the returned lifetimes will contain a maximal ValidUntil
// value.
func addressLifetimes(received tcpip.MonotonicTime, pl, vl uint32) stack.AddressLifetimes {
	var preferredUntil, validUntil tcpip.MonotonicTime
	if pl > 0 {
		preferredUntil = received.Add(time.Duration(pl) * time.Second)
	}
	if vl == math.MaxUint32 {
		validUntil = tcpip.MonotonicTimeInfinite()
	} else {
		validUntil = received.Add(time.Duration(vl) * time.Second)
	}
	return stack.AddressLifetimes{
		Deprecated:     pl == 0,
		PreferredUntil: preferredUntil,
		ValidUntil:     validUntil,
	}
}

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	const nicID = 1
	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPDisp: &ndpDisp,
		})},
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   addr1,
		PrefixLen: defaultPrefixLen,
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	addrDisp := &addressDispatcher{
		changedCh: make(chan addressChangedEvent, 1),
		nicid:     nicID,
		addr:      addrWithPrefix,
	}
	properties := stack.AddressProperties{
		Disp: addrDisp,
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, properties); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, %#v) = %s", nicID, protocolAddr, properties, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	select {
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr1, &stack.DADSucceeded{}); diff != "" {
			t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected DAD event")
	}
	if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, addrWithPrefix); err != nil {
		t.Fatal(err)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6.PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0", got)
	}
}

func TestDADResolveLoopback(t *testing.T) {
	const nicID = 1
	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent, 1),
	}

	dadConfigs := stack.DADConfigurations{
		RetransmitTimer:        time.Second,
		DupAddrDetectTransmits: 1,
	}
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		Clock: clock,
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPDisp:    &ndpDisp,
			DADConfigs: dadConfigs,
		})},
	})
	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   addr1,
		PrefixLen: defaultPrefixLen,
	}
	addrDisp := &addressDispatcher{
		nicid:     nicID,
		addr:      addrWithPrefix,
		changedCh: make(chan addressChangedEvent, 1),
	}
	properties := stack.AddressProperties{
		Disp: addrDisp,
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, properties); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, %#v) = %s", nicID, protocolAddr, properties, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressTentative); err != nil {
		t.Error(err)
	}
	if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
		t.Fatal(err)
	}

	// DAD should not resolve after the normal resolution time since our DAD
	// message was looped back - we should extend our DAD process.
	dadResolutionTime := time.Duration(dadConfigs.DupAddrDetectTransmits) * dadConfigs.RetransmitTimer
	clock.Advance(dadResolutionTime)
	if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
		t.Error(err)
	}

	// Make sure the address does not resolve before the extended resolution time
	// has passed.
	const delta = time.Nanosecond
	// DAD will send extra NS probes if an NS message is looped back.
	const extraTransmits = 3
	clock.Advance(dadResolutionTime*extraTransmits - delta)
	if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
		t.Error(err)
	}

	// DAD should now resolve.
	clock.Advance(delta)
	if diff := checkDADEvent(<-ndpDisp.dadC, nicID, addr1, &stack.DADSucceeded{}); diff != "" {
		t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
	}
	if err := addrDisp.expectStateChanged(stack.AddressAssigned); err != nil {
		t.Error(err)
	}
}

// TestDADResolve tests that an address successfully resolves after performing
// DAD for various values of DupAddrDetectTransmits and RetransmitTimer.
// Included in the subtests is a test to make sure that an invalid
// RetransmitTimer (<1ms) values get fixed to the default RetransmitTimer of 1s.
// This tests also validates the NDP NS packet that is transmitted.
func TestDADResolve(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name                    string
		linkHeaderLen           uint16
		dupAddrDetectTransmits  uint8
		retransTimer            time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{
			name:                    "1:1s:1s",
			dupAddrDetectTransmits:  1,
			retransTimer:            time.Second,
			expectedRetransmitTimer: time.Second,
		},
		{
			name:                    "2:1s:1s",
			linkHeaderLen:           1,
			dupAddrDetectTransmits:  2,
			retransTimer:            time.Second,
			expectedRetransmitTimer: time.Second,
		},
		{
			name:                    "1:2s:2s",
			linkHeaderLen:           2,
			dupAddrDetectTransmits:  1,
			retransTimer:            2 * time.Second,
			expectedRetransmitTimer: 2 * time.Second,
		},
		// 0s is an invalid RetransmitTimer timer and will be fixed to
		// the default RetransmitTimer value of 1s.
		{
			name:                    "1:0s:1s",
			linkHeaderLen:           3,
			dupAddrDetectTransmits:  1,
			retransTimer:            0,
			expectedRetransmitTimer: time.Second,
		},
	}

	nonces := [][]byte{
		{1, 2, 3, 4, 5, 6},
		{7, 8, 9, 10, 11, 12},
	}

	var secureRNGBytes []byte
	for _, n := range nonces {
		secureRNGBytes = append(secureRNGBytes, n...)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent, 1),
			}
			e := channelLinkWithHeaderLength{
				Endpoint:     channel.New(int(test.dupAddrDetectTransmits), 1280, linkAddr1),
				headerLength: test.linkHeaderLen,
			}
			e.Endpoint.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			var secureRNG bytes.Reader
			secureRNG.Reset(secureRNGBytes)

			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				Clock:      clock,
				RandSource: rand.NewSource(time.Now().UnixNano()),
				SecureRNG:  &secureRNG,
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPDisp: &ndpDisp,
					DADConfigs: stack.DADConfigurations{
						RetransmitTimer:        test.retransTimer,
						DupAddrDetectTransmits: test.dupAddrDetectTransmits,
					},
				})},
			})
			if err := s.CreateNIC(nicID, &e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			// We add a default route so the call to FindRoute below will succeed
			// once we have an assigned address.
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv6EmptySubnet,
				Gateway:     addr3,
				NIC:         nicID,
			}})

			addrWithPrefix := tcpip.AddressWithPrefix{
				Address:   addr1,
				PrefixLen: defaultPrefixLen,
			}
			addrDisp := &addressDispatcher{
				nicid:     nicID,
				addr:      addrWithPrefix,
				changedCh: make(chan addressChangedEvent, 1),
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addrWithPrefix,
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{Disp: addrDisp}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}) = %s", nicID, protocolAddr, err)
			}
			if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressTentative); err != nil {
				t.Error(err)
			}

			// Make sure the address does not resolve before the resolution time has
			// passed.
			const delta = time.Nanosecond
			clock.Advance(test.expectedRetransmitTimer*time.Duration(test.dupAddrDetectTransmits) - delta)
			if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Error(err)
			}
			// Should not get a route even if we specify the local address as the
			// tentative address.
			{
				r, err := s.FindRoute(nicID, "", addr2, header.IPv6ProtocolNumber, false)
				if _, ok := err.(*tcpip.ErrHostUnreachable); !ok {
					t.Errorf("got FindRoute(%d, '', %s, %d, false) = (%+v, %v), want = (_, %s)", nicID, addr2, header.IPv6ProtocolNumber, r, err, &tcpip.ErrHostUnreachable{})
				}
				if r != nil {
					r.Release()
				}
			}
			{
				r, err := s.FindRoute(nicID, addr1, addr2, header.IPv6ProtocolNumber, false)
				if _, ok := err.(*tcpip.ErrHostUnreachable); !ok {
					t.Errorf("got FindRoute(%d, %s, %s, %d, false) = (%+v, %v), want = (_, %s)", nicID, addr1, addr2, header.IPv6ProtocolNumber, r, err, &tcpip.ErrHostUnreachable{})
				}
				if r != nil {
					r.Release()
				}
			}

			if t.Failed() {
				t.FailNow()
			}

			// Wait for DAD to resolve.
			clock.Advance(delta)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr1, &stack.DADSucceeded{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatalf("expected DAD event for %s on NIC(%d)", addr1, nicID)
			}
			if err := addrDisp.expectStateChanged(stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, addrWithPrefix); err != nil {
				t.Error(err)
			}
			// Should get a route using the address now that it is resolved.
			{
				r, err := s.FindRoute(nicID, "", addr2, header.IPv6ProtocolNumber, false)
				if err != nil {
					t.Errorf("got FindRoute(%d, '', %s, %d, false): %s", nicID, addr2, header.IPv6ProtocolNumber, err)
				} else if r.LocalAddress() != addr1 {
					t.Errorf("got r.LocalAddress() = %s, want = %s", r.LocalAddress(), addr1)
				}
				r.Release()
			}
			{
				r, err := s.FindRoute(nicID, addr1, addr2, header.IPv6ProtocolNumber, false)
				if err != nil {
					t.Errorf("got FindRoute(%d, %s, %s, %d, false): %s", nicID, addr1, addr2, header.IPv6ProtocolNumber, err)
				} else if r.LocalAddress() != addr1 {
					t.Errorf("got r.LocalAddress() = %s, want = %s", r.LocalAddress(), addr1)
				}
				if r != nil {
					r.Release()
				}
			}

			if t.Failed() {
				t.FailNow()
			}

			// Should not have sent any more NS messages.
			if got := s.Stats().ICMP.V6.PacketsSent.NeighborSolicit.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", got, test.dupAddrDetectTransmits)
			}

			// Validate the sent Neighbor Solicitation messages.
			for i := uint8(0); i < test.dupAddrDetectTransmits; i++ {
				p := e.Read()
				if p.IsNil() {
					t.Fatal("packet didn't arrive")
				}

				// Make sure its an IPv6 packet.
				if p.NetworkProtocolNumber != header.IPv6ProtocolNumber {
					t.Fatalf("got Proto = %d, want = %d", p.NetworkProtocolNumber, header.IPv6ProtocolNumber)
				}

				// Make sure the right remote link address is used.
				snmc := header.SolicitedNodeAddr(addr1)
				if want := header.EthernetAddressFromMulticastIPv6Address(snmc); p.EgressRoute.RemoteLinkAddress != want {
					t.Errorf("got remote link address = %s, want = %s", p.EgressRoute.RemoteLinkAddress, want)
				}

				// Check NDP NS packet.
				//
				// As per RFC 4861 section 4.3, a possible option is the Source Link
				// Layer option, but this option MUST NOT be included when the source
				// address of the packet is the unspecified address.
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(header.IPv6Any),
					checker.DstAddr(snmc),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(addr1),
						checker.NDPNSOptions([]header.NDPOption{header.NDPNonceOption(nonces[i])}),
					))

				if l, want := p.AvailableHeaderBytes(), int(test.linkHeaderLen); l != want {
					t.Errorf("got p.AvailableHeaderBytes() = %d; want = %d", l, want)
				}
				p.DecRef()
			}
		})
	}
}

func rxNDPSolicit(e *channel.Endpoint, tgt tcpip.Address) {
	hdr := prependable.New(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.MessageBody())
	ns.SetTargetAddress(tgt)
	snmc := header.SolicitedNodeAddr(tgt)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    header.IPv6Any,
		Dst:    snmc,
	}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          255,
		SrcAddr:           header.IPv6Any,
		DstAddr:           snmc,
	})
	e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferv2.MakeWithData(hdr.View())}))
}

// TestDADFail tests to make sure that the DAD process fails if another node is
// detected to be performing DAD on the same address (receive an NS message from
// a node doing DAD for the same address), or if another node is detected to own
// the address already (receive an NA message for the tentative address).
func TestDADFail(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name                      string
		rxPkt                     func(e *channel.Endpoint, tgt tcpip.Address)
		getStat                   func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
		expectedHolderLinkAddress tcpip.LinkAddress
	}{
		{
			name:  "RxSolicit",
			rxPkt: rxNDPSolicit,
			getStat: func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborSolicit
			},
			expectedHolderLinkAddress: "",
		},
		{
			name: "RxAdvert",
			rxPkt: func(e *channel.Endpoint, tgt tcpip.Address) {
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				hdr := prependable.New(header.IPv6MinimumSize + naSize)
				pkt := header.ICMPv6(hdr.Prepend(naSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.MessageBody())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(tgt)
				na.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(linkAddr1),
				})
				pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: pkt,
					Src:    tgt,
					Dst:    header.IPv6AllNodesMulticastAddress,
				}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength:     uint16(payloadLength),
					TransportProtocol: icmp.ProtocolNumber6,
					HopLimit:          255,
					SrcAddr:           tgt,
					DstAddr:           header.IPv6AllNodesMulticastAddress,
				})
				e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferv2.MakeWithData(hdr.View())}))
			},
			getStat: func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborAdvert
			},
			expectedHolderLinkAddress: linkAddr1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent, 1),
			}
			dadConfigs := stack.DefaultDADConfigurations()
			dadConfigs.RetransmitTimer = time.Second * 2

			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPDisp:    &ndpDisp,
					DADConfigs: dadConfigs,
				})},
				Clock: clock,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			addrDisp := &addressDispatcher{
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
				nicid:     nicID,
				addr:      addr1.WithPrefix(),
			}
			properties := stack.AddressProperties{
				Disp: addrDisp,
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addr1.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, properties); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %#v): %s", nicID, protocolAddr, properties, err)
			}
			if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressTentative); err != nil {
				t.Fatal(err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Fatal(err)
			}

			// Receive a packet to simulate an address conflict.
			test.rxPkt(e, addr1)

			stat := test.getStat(s.Stats().ICMP.V6.PacketsReceived)
			if got := stat.Value(); got != 1 {
				t.Fatalf("got stat = %d, want = 1", got)
			}

			// Wait for DAD to fail and make sure the address did
			// not get resolved.
			clock.Advance(time.Duration(dadConfigs.DupAddrDetectTransmits) * dadConfigs.RetransmitTimer)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr1, &stack.DADDupAddrDetected{HolderLinkAddress: test.expectedHolderLinkAddress}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				// If we don't get a failure event after the
				// expected resolution time + extra 1s buffer,
				// something is wrong.
				t.Fatal("timed out waiting for DAD failure")
			}
			if err := addrDisp.expectRemoved(stack.AddressRemovalDADFailed); err != nil {
				t.Fatal(err)
			}
			if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Fatal(err)
			}

			// Attempting to add the address again should not fail if the address's
			// state was cleaned up when DAD failed.
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
		})
	}
}

func TestDADStop(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name               string
		stopFn             func(t *testing.T, s *stack.Stack)
		verifyFn           func(t *testing.T, ad *addressDispatcher)
		skipFinalAddrCheck bool
	}{
		// Tests to make sure that DAD stops when an address is removed.
		{
			name: "Remove address",
			stopFn: func(t *testing.T, s *stack.Stack) {
				if err := s.RemoveAddress(nicID, addr1); err != nil {
					t.Fatalf("RemoveAddress(%d, %s): %s", nicID, addr1, err)
				}
			},
			verifyFn: func(t *testing.T, ad *addressDispatcher) {
				if err := ad.expectRemoved(stack.AddressRemovalManualAction); err != nil {
					t.Error(err)
				}
			},
		},

		// Tests to make sure that DAD stops when the NIC is disabled.
		{
			name: "Disable NIC",
			stopFn: func(t *testing.T, s *stack.Stack) {
				if err := s.DisableNIC(nicID); err != nil {
					t.Fatalf("DisableNIC(%d): %s", nicID, err)
				}
			},
			verifyFn: func(t *testing.T, ad *addressDispatcher) {
				if err := ad.expectStateChanged(stack.AddressDisabled); err != nil {
					t.Error(err)
				}
			},
		},

		// Tests to make sure that DAD stops when the NIC is removed.
		{
			name: "Remove NIC",
			stopFn: func(t *testing.T, s *stack.Stack) {
				if err := s.RemoveNIC(nicID); err != nil {
					t.Fatalf("RemoveNIC(%d): %s", nicID, err)
				}
			},
			verifyFn: func(t *testing.T, ad *addressDispatcher) {
				if err := ad.expectRemoved(stack.AddressRemovalInterfaceRemoved); err != nil {
					t.Error(err)
				}
			},
			// The NIC is removed so we can't check its addresses after calling
			// stopFn.
			skipFinalAddrCheck: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent, 1),
			}

			dadConfigs := stack.DADConfigurations{
				RetransmitTimer:        time.Second,
				DupAddrDetectTransmits: 2,
			}

			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPDisp:    &ndpDisp,
					DADConfigs: dadConfigs,
				})},
				Clock: clock,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}

			addrDisp := &addressDispatcher{
				nicid:     nicID,
				addr:      addr1.WithPrefix(),
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
			}
			properties := stack.AddressProperties{
				Disp: addrDisp,
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addr1.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, properties); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %#v): %s", nicID, protocolAddr, properties, err)
			}
			if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressTentative); err != nil {
				t.Fatal(err)
			}

			// Address should not be considered bound to the NIC yet (DAD ongoing).
			if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Fatal(err)
			}

			test.stopFn(t, s)

			// Wait for DAD to fail (since the address was removed during DAD).
			clock.Advance(time.Duration(dadConfigs.DupAddrDetectTransmits) * dadConfigs.RetransmitTimer)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr1, &stack.DADAborted{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				// If we don't get a failure event after the expected resolution
				// time + extra 1s buffer, something is wrong.
				t.Fatal("timed out waiting for DAD failure")
			}
			test.verifyFn(t, addrDisp)

			if !test.skipFinalAddrCheck {
				if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
					t.Fatal(err)
				}
			}

			// Should not have sent more than 1 NS message.
			if got := s.Stats().ICMP.V6.PacketsSent.NeighborSolicit.Value(); got > 1 {
				t.Errorf("got NeighborSolicit = %d, want <= 1", got)
			}
		})
	}
}

// TestSetNDPConfigurations tests that we can update and use per-interface NDP
// configurations without affecting the default NDP configurations or other
// interfaces' configurations.
func TestSetNDPConfigurations(t *testing.T) {
	const nicID1 = 1
	const nicID2 = 2
	const nicID3 = 3

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
				dadC: make(chan ndpDADEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPDisp: &ndpDisp,
				})},
				Clock: clock,
			})

			expectDADSucceeded := func(nicID tcpip.NICID, addr tcpip.Address) {
				select {
				case e := <-ndpDisp.dadC:
					if diff := checkDADEvent(e, nicID, addr, &stack.DADSucceeded{}); diff != "" {
						t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatalf("expected DAD event for %s", addr)
				}
			}

			// This NIC(1)'s NDP configurations will be updated to
			// be different from the default.
			if err := s.CreateNIC(nicID1, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID1, err)
			}

			// Created before updating NIC(1)'s NDP configurations
			// but updating NIC(1)'s NDP configurations should not
			// affect other existing NICs.
			if err := s.CreateNIC(nicID2, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID2, err)
			}

			// Update the configurations on NIC(1) to use DAD.
			if ipv6Ep, err := s.GetNetworkEndpoint(nicID1, header.IPv6ProtocolNumber); err != nil {
				t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID1, header.IPv6ProtocolNumber, err)
			} else {
				dad := ipv6Ep.(stack.DuplicateAddressDetector)
				dad.SetDADConfigurations(stack.DADConfigurations{
					DupAddrDetectTransmits: test.dupAddrDetectTransmits,
					RetransmitTimer:        test.retransmitTimer,
				})
			}

			// Created after updating NIC(1)'s NDP configurations
			// but the stack's default NDP configurations should not
			// have been updated.
			if err := s.CreateNIC(nicID3, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID3, err)
			}

			// Add addresses for each NIC.
			addrWithPrefix1 := tcpip.AddressWithPrefix{Address: addr1, PrefixLen: defaultPrefixLen}
			protocolAddr1 := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addrWithPrefix1,
			}
			addr1Disp := addressDispatcher{
				nicid:     nicID1,
				addr:      addrWithPrefix1,
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
			}
			properties1 := stack.AddressProperties{
				Disp: &addr1Disp,
			}
			if err := s.AddProtocolAddress(nicID1, protocolAddr1, properties1); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %#v) = %s", nicID1, protocolAddr1, properties1, err)
			}
			if err := addr1Disp.expectChanged(stack.AddressLifetimes{}, stack.AddressTentative); err != nil {
				t.Error(err)
			}
			addrWithPrefix2 := tcpip.AddressWithPrefix{Address: addr2, PrefixLen: defaultPrefixLen}
			protocolAddr2 := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addrWithPrefix2,
			}
			addr2Disp := addressDispatcher{
				nicid:     nicID2,
				addr:      addrWithPrefix2,
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
			}
			properties2 := stack.AddressProperties{
				Disp: &addr2Disp,
			}
			if err := s.AddProtocolAddress(nicID2, protocolAddr2, properties2); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %#v) = %s", nicID2, protocolAddr2, properties2, err)
			}
			expectDADSucceeded(nicID2, addr2)
			if err := addr2Disp.expectChanged(stack.AddressLifetimes{}, stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			addrWithPrefix3 := tcpip.AddressWithPrefix{Address: addr3, PrefixLen: defaultPrefixLen}
			protocolAddr3 := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: addrWithPrefix3,
			}
			addr3Disp := addressDispatcher{
				nicid:     nicID3,
				addr:      addrWithPrefix3,
				changedCh: make(chan addressChangedEvent, 1),
				removedCh: make(chan stack.AddressRemovalReason, 1),
			}
			properties3 := stack.AddressProperties{
				Disp: &addr3Disp,
			}
			if err := s.AddProtocolAddress(nicID3, protocolAddr3, properties3); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %#v) = %s", nicID3, protocolAddr3, properties3, err)
			}
			expectDADSucceeded(nicID3, addr3)
			if err := addr3Disp.expectChanged(stack.AddressLifetimes{}, stack.AddressAssigned); err != nil {
				t.Error(err)
			}

			// Address should not be considered bound to NIC(1) yet
			// (DAD ongoing).
			if err := checkGetMainNICAddress(s, nicID1, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Fatal(err)
			}

			// Should get the address on NIC(2) and NIC(3)
			// immediately since we should not have performed DAD on
			// it as the stack was configured to not do DAD by
			// default and we only updated the NDP configurations on
			// NIC(1).
			if err := checkGetMainNICAddress(s, nicID2, header.IPv6ProtocolNumber, addrWithPrefix2); err != nil {
				t.Fatal(err)
			}
			if err := checkGetMainNICAddress(s, nicID3, header.IPv6ProtocolNumber, addrWithPrefix3); err != nil {
				t.Fatal(err)
			}

			// Sleep until right before resolution to make sure the address didn't
			// resolve on NIC(1) yet.
			const delta = 1
			clock.Advance(time.Duration(test.dupAddrDetectTransmits)*test.expectedRetransmitTimer - delta)
			if err := checkGetMainNICAddress(s, nicID1, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
				t.Fatal(err)
			}

			// Wait for DAD to resolve.
			clock.Advance(delta)
			expectDADSucceeded(nicID1, addr1)
			if err := addr1Disp.expectStateChanged(stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			if err := checkGetMainNICAddress(s, nicID1, header.IPv6ProtocolNumber, addrWithPrefix1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// raBuf returns a valid NDP Router Advertisement with options, router
// preference and DHCPv6 configurations specified.
func raBuf(ip tcpip.Address, rl uint16, managedAddress, otherConfigurations bool, prf header.NDPRoutePreference, optSer header.NDPOptionsSerializer) stack.PacketBufferPtr {
	const flagsByte = 1
	const routerLifetimeOffset = 2

	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + optSer.Length()
	hdr := prependable.New(header.IPv6MinimumSize + icmpSize)
	pkt := header.ICMPv6(hdr.Prepend(icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	raPayload := pkt.MessageBody()
	ra := header.NDPRouterAdvert(raPayload)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(raPayload[routerLifetimeOffset:], rl)
	// Populate the Managed Address flag field.
	if managedAddress {
		// The Managed Addresses flag field is the 7th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 7
	}
	// Populate the Other Configurations flag field.
	if otherConfigurations {
		// The Other Configurations flag field is the 6th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 6
	}
	// The Prf field is held in the flags byte.
	raPayload[flagsByte] |= byte(prf) << 3
	opts := ra.Options()
	opts.Serialize(optSer)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    ip,
		Dst:    header.IPv6AllNodesMulticastAddress,
	}))
	payloadLength := hdr.UsedLength()
	iph := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           ip,
		DstAddr:           header.IPv6AllNodesMulticastAddress,
	})

	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(hdr.View()),
	})
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) stack.PacketBufferPtr {
	return raBuf(ip, rl, false /* managedAddress */, false /* otherConfigurations */, 0 /* prf */, optSer)
}

// raBufWithDHCPv6 returns a valid NDP Router Advertisement with DHCPv6 related
// fields set.
//
// Note, raBufWithDHCPv6 does not populate any of the RA fields other than the
// DHCPv6 related ones.
func raBufWithDHCPv6(ip tcpip.Address, managedAddresses, otherConfigurations bool) stack.PacketBufferPtr {
	return raBuf(ip, 0, managedAddresses, otherConfigurations, 0 /* prf */, header.NDPOptionsSerializer{})
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBufSimple(ip tcpip.Address, rl uint16) stack.PacketBufferPtr {
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{})
}

// raBufWithPrf returns a valid NDP Router Advertisement with a preference.
//
// Note, raBufWithPrf does not populate any of the RA fields other than the
// Router Lifetime and Default Router Preference fields.
func raBufWithPrf(ip tcpip.Address, rl uint16, prf header.NDPRoutePreference) stack.PacketBufferPtr {
	return raBuf(ip, rl, false /* managedAddress */, false /* otherConfigurations */, prf, header.NDPOptionsSerializer{})
}

// raBufWithPI returns a valid NDP Router Advertisement with a single Prefix
// Information option.
//
// Note, raBufWithPI does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithPI(ip tcpip.Address, rl uint16, prefix tcpip.AddressWithPrefix, onLink, auto bool, vl, pl uint32) stack.PacketBufferPtr {
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

// raBufWithRIO returns a valid NDP Router Advertisement with a single Route
// Information option.
//
// All fields in the RA will be zero except the RIO option.
func raBufWithRIO(t *testing.T, ip tcpip.Address, prefix tcpip.AddressWithPrefix, lifetimeSeconds uint32, prf header.NDPRoutePreference) stack.PacketBufferPtr {
	// buf will hold the route information option after the Type and Length
	// fields.
	//
	//  2.3.  Route Information Option
	//
	//      0                   1                   2                   3
	//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      |     Type      |    Length     | Prefix Length |Resvd|Prf|Resvd|
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      |                        Route Lifetime                         |
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      |                   Prefix (Variable Length)                    |
	//      .                                                               .
	//      .                                                               .
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	var buf [22]byte
	buf[0] = uint8(prefix.PrefixLen)
	buf[1] = byte(prf) << 3
	binary.BigEndian.PutUint32(buf[2:], lifetimeSeconds)
	if n := copy(buf[6:], prefix.Address); n != len(prefix.Address) {
		t.Fatalf("got copy(...) = %d, want = %d", n, len(prefix.Address))
	}
	return raBufWithOpts(ip, 0 /* router lifetime */, header.NDPOptionsSerializer{
		header.NDPRouteInformation(buf[:]),
	})
}

func TestDynamicConfigurationsDisabled(t *testing.T) {
	const (
		nicID              = 1
		maxRtrSolicitDelay = time.Second
	)

	prefix := tcpip.AddressWithPrefix{
		Address:   testutil.MustParse6("102:304:506:708::"),
		PrefixLen: 64,
	}

	tests := []struct {
		name   string
		config func(bool) ipv6.NDPConfigurations
		ra     stack.PacketBufferPtr
	}{
		{
			name: "No Router Discovery",
			config: func(enable bool) ipv6.NDPConfigurations {
				return ipv6.NDPConfigurations{DiscoverDefaultRouters: enable}
			},
			ra: raBufSimple(llAddr2, 1000),
		},
		{
			name: "No Prefix Discovery",
			config: func(enable bool) ipv6.NDPConfigurations {
				return ipv6.NDPConfigurations{DiscoverOnLinkPrefixes: enable}
			},
			ra: raBufWithPI(llAddr2, 0, prefix, true, false, 10, 0),
		},
		{
			name: "No Autogenerate Addresses",
			config: func(enable bool) ipv6.NDPConfigurations {
				return ipv6.NDPConfigurations{AutoGenGlobalAddresses: enable}
			},
			ra: raBufWithPI(llAddr2, 0, prefix, false, true, 10, 0),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Being configured to discover routers/prefixes or auto-generate
			// addresses means RAs must be handled, and router/prefix discovery or
			// SLAAC must be enabled.
			//
			// This tests all possible combinations of the configurations where
			// router/prefix discovery or SLAAC are disabled.
			for i := 0; i < 7; i++ {
				handle := ipv6.HandlingRAsDisabled
				if i&1 != 0 {
					handle = ipv6.HandlingRAsEnabledWhenForwardingDisabled
				}
				enable := i&2 != 0
				forwarding := i&4 == 0

				t.Run(fmt.Sprintf("HandleRAs(%s), Forwarding(%t), Enabled(%t)", handle, forwarding, enable), func(t *testing.T) {
					ndpDisp := ndpDispatcher{
						offLinkRouteC: make(chan ndpOffLinkRouteEvent, 1),
						prefixC:       make(chan ndpPrefixEvent, 1),
						autoGenAddrC:  make(chan ndpAutoGenAddrEvent, 1),
					}
					ndpConfigs := test.config(enable)
					ndpConfigs.HandleRAs = handle
					ndpConfigs.MaxRtrSolicitations = 1
					ndpConfigs.RtrSolicitationInterval = maxRtrSolicitDelay
					ndpConfigs.MaxRtrSolicitationDelay = maxRtrSolicitDelay
					clock := faketime.NewManualClock()
					s := stack.New(stack.Options{
						Clock: clock,
						NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
							NDPConfigs: ndpConfigs,
							NDPDisp:    &ndpDisp,
						})},
					})
					if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, forwarding); err != nil {
						t.Fatalf("SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv6.ProtocolNumber, forwarding, err)
					}

					e := channel.New(1, 1280, linkAddr1)
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
					}

					handleRAsDisabled := handle == ipv6.HandlingRAsDisabled || forwarding
					ep, err := s.GetNetworkEndpoint(nicID, ipv6.ProtocolNumber)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, ipv6.ProtocolNumber, err)
					}
					stats := ep.Stats()
					v6Stats, ok := stats.(*ipv6.Stats)
					if !ok {
						t.Fatalf("got v6Stats = %T, expected = %T", stats, v6Stats)
					}

					// Make sure that when handling RAs are enabled, we solicit routers.
					clock.Advance(maxRtrSolicitDelay)
					if got, want := v6Stats.ICMP.PacketsSent.RouterSolicit.Value(), boolToUint64(!handleRAsDisabled); got != want {
						t.Errorf("got v6Stats.ICMP.PacketsSent.RouterSolicit.Value() = %d, want = %d", got, want)
					}
					if handleRAsDisabled {
						if p := e.Read(); !p.IsNil() {
							t.Errorf("unexpectedly got a packet = %#v", p)
						}
					} else if p := e.Read(); p.IsNil() {
						t.Error("expected router solicitation packet")
					} else if p.NetworkProtocolNumber != header.IPv6ProtocolNumber {
						t.Errorf("got Proto = %d, want = %d", p.NetworkProtocolNumber, header.IPv6ProtocolNumber)
						p.DecRef()
					} else {
						if want := header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllRoutersLinkLocalMulticastAddress); p.EgressRoute.RemoteLinkAddress != want {
							t.Errorf("got remote link address = %s, want = %s", p.EgressRoute.RemoteLinkAddress, want)
						}

						checker.IPv6(t, stack.PayloadSince(p.NetworkHeader()),
							checker.SrcAddr(header.IPv6Any),
							checker.DstAddr(header.IPv6AllRoutersLinkLocalMulticastAddress),
							checker.TTL(header.NDPHopLimit),
							checker.NDPRS(checker.NDPRSOptions(nil)),
						)
						p.DecRef()
					}

					// Make sure we do not discover any routers or prefixes, or perform
					// SLAAC on reception of an RA.
					e.InjectInbound(header.IPv6ProtocolNumber, test.ra.Clone())
					// Make sure that the unhandled RA stat is only incremented when
					// handling RAs is disabled.
					if got, want := v6Stats.UnhandledRouterAdvertisements.Value(), boolToUint64(handleRAsDisabled); got != want {
						t.Errorf("got v6Stats.UnhandledRouterAdvertisements.Value() = %d, want = %d", got, want)
					}
					select {
					case e := <-ndpDisp.offLinkRouteC:
						t.Errorf("unexpectedly updated an off-link route when configured not to: %#v", e)
					default:
					}
					select {
					case e := <-ndpDisp.prefixC:
						t.Errorf("unexpectedly discovered a prefix when configured not to: %#v", e)
					default:
					}
					select {
					case e := <-ndpDisp.autoGenAddrC:
						t.Errorf("unexpectedly auto-generated an address when configured not to: %#v", e)
					default:
					}
				})
			}
		})
	}
}

func boolToUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func checkOffLinkRouteEvent(e ndpOffLinkRouteEvent, nicID tcpip.NICID, subnet tcpip.Subnet, router tcpip.Address, prf header.NDPRoutePreference, updated bool) string {
	return cmp.Diff(ndpOffLinkRouteEvent{nicID: nicID, subnet: subnet, router: router, prf: prf, updated: updated}, e, cmp.AllowUnexported(e))
}

func testWithRAs(t *testing.T, f func(*testing.T, ipv6.HandleRAsConfiguration, bool)) {
	tests := [...]struct {
		name       string
		handleRAs  ipv6.HandleRAsConfiguration
		forwarding bool
	}{
		{
			name:       "Handle RAs when forwarding disabled",
			handleRAs:  ipv6.HandlingRAsEnabledWhenForwardingDisabled,
			forwarding: false,
		},
		{
			name:       "Always Handle RAs with forwarding disabled",
			handleRAs:  ipv6.HandlingRAsAlwaysEnabled,
			forwarding: false,
		},
		{
			name:       "Always Handle RAs with forwarding enabled",
			handleRAs:  ipv6.HandlingRAsAlwaysEnabled,
			forwarding: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f(t, test.handleRAs, test.forwarding)
		})
	}
}

func TestOffLinkRouteDiscovery(t *testing.T) {
	const nicID = 1

	moreSpecificPrefix := tcpip.AddressWithPrefix{Address: testutil.MustParse6("a00::"), PrefixLen: 16}
	tests := []struct {
		name string

		discoverDefaultRouters     bool
		discoverMoreSpecificRoutes bool

		dest tcpip.Subnet
		ra   func(*testing.T, tcpip.Address, uint16, header.NDPRoutePreference) stack.PacketBufferPtr
	}{
		{
			name:                       "Default router discovery",
			discoverDefaultRouters:     true,
			discoverMoreSpecificRoutes: false,
			dest:                       header.IPv6EmptySubnet,
			ra: func(_ *testing.T, router tcpip.Address, lifetimeSeconds uint16, prf header.NDPRoutePreference) stack.PacketBufferPtr {
				return raBufWithPrf(router, lifetimeSeconds, prf)
			},
		},
		{
			name:                       "More-specific route discovery",
			discoverDefaultRouters:     false,
			discoverMoreSpecificRoutes: true,
			dest:                       moreSpecificPrefix.Subnet(),
			ra: func(t *testing.T, router tcpip.Address, lifetimeSeconds uint16, prf header.NDPRoutePreference) stack.PacketBufferPtr {
				return raBufWithRIO(t, router, moreSpecificPrefix, uint32(lifetimeSeconds), prf)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testWithRAs(t, func(t *testing.T, handleRAs ipv6.HandleRAsConfiguration, forwarding bool) {
				ndpDisp := ndpDispatcher{
					offLinkRouteC: make(chan ndpOffLinkRouteEvent, 1),
				}
				e := channel.New(0, 1280, linkAddr1)
				clock := faketime.NewManualClock()
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
						NDPConfigs: ipv6.NDPConfigurations{
							HandleRAs:                  handleRAs,
							DiscoverDefaultRouters:     test.discoverDefaultRouters,
							DiscoverMoreSpecificRoutes: test.discoverMoreSpecificRoutes,
						},
						NDPDisp: &ndpDisp,
					})},
					Clock: clock,
				})

				expectOffLinkRouteEvent := func(addr tcpip.Address, prf header.NDPRoutePreference, updated bool) {
					t.Helper()

					select {
					case e := <-ndpDisp.offLinkRouteC:
						if diff := checkOffLinkRouteEvent(e, nicID, test.dest, addr, prf, updated); diff != "" {
							t.Errorf("off-link route event mismatch (-want +got):\n%s", diff)
						}
					default:
						t.Fatal("expected router discovery event")
					}
				}

				expectAsyncOffLinkRouteInvalidationEvent := func(addr tcpip.Address, timeout time.Duration) {
					t.Helper()

					clock.Advance(timeout)
					select {
					case e := <-ndpDisp.offLinkRouteC:
						var prf header.NDPRoutePreference
						if diff := checkOffLinkRouteEvent(e, nicID, test.dest, addr, prf, false); diff != "" {
							t.Errorf("off-link route event mismatch (-want +got):\n%s", diff)
						}
					default:
						t.Fatal("timed out waiting for router discovery event")
					}
				}

				if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, forwarding); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv6.ProtocolNumber, forwarding, err)
				}

				if err := s.CreateNIC(nicID, e); err != nil {
					t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
				}

				// Rx an RA from lladdr2 with zero lifetime. It should not be
				// remembered.
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, 0, header.MediumRoutePreference))
				select {
				case <-ndpDisp.offLinkRouteC:
					t.Fatal("unexpectedly updated an off-link route with 0 lifetime")
				default:
				}

				// Discover an off-link route through llAddr2.
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, 1000, header.ReservedRoutePreference))
				if test.discoverMoreSpecificRoutes {
					// The reserved value is considered invalid with more-specific route
					// discovery so we inject the same packet but with the default
					// (medium) preference value.
					select {
					case <-ndpDisp.offLinkRouteC:
						t.Fatal("unexpectedly updated an off-link route with a reserved preference value")
					default:
					}
					e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, 1000, header.MediumRoutePreference))
				}
				expectOffLinkRouteEvent(llAddr2, header.MediumRoutePreference, true)

				// Rx an RA from another router (lladdr3) with non-zero lifetime and
				// non-default preference value.
				const l3LifetimeSeconds = 6
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr3, l3LifetimeSeconds, header.HighRoutePreference))
				expectOffLinkRouteEvent(llAddr3, header.HighRoutePreference, true)

				// Rx an RA from lladdr2 with lesser lifetime and default (medium)
				// preference value.
				const l2LifetimeSeconds = 2
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, l2LifetimeSeconds, header.MediumRoutePreference))
				select {
				case <-ndpDisp.offLinkRouteC:
					t.Fatal("should not receive a off-link route event when updating lifetimes for known routers")
				default:
				}

				// Rx an RA from lladdr2 with a different preference.
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, l2LifetimeSeconds, header.LowRoutePreference))
				expectOffLinkRouteEvent(llAddr2, header.LowRoutePreference, true)

				// Wait for lladdr2's router invalidation job to execute. The lifetime
				// of the router should have been updated to the most recent (smaller)
				// lifetime.
				//
				// Wait for the normal lifetime plus an extra bit for the
				// router to get invalidated. If we don't get an invalidation
				// event after this time, then something is wrong.
				expectAsyncOffLinkRouteInvalidationEvent(llAddr2, l2LifetimeSeconds*time.Second)

				// Rx an RA from lladdr2 with huge lifetime.
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, 1000, header.MediumRoutePreference))
				expectOffLinkRouteEvent(llAddr2, header.MediumRoutePreference, true)

				// Rx an RA from lladdr2 with zero lifetime. It should be invalidated.
				e.InjectInbound(header.IPv6ProtocolNumber, test.ra(t, llAddr2, 0, header.MediumRoutePreference))
				expectOffLinkRouteEvent(llAddr2, header.MediumRoutePreference, false)

				// Wait for lladdr3's router invalidation job to execute. The lifetime
				// of the router should have been updated to the most recent (smaller)
				// lifetime.
				//
				// Wait for the normal lifetime plus an extra bit for the
				// router to get invalidated. If we don't get an invalidation
				// event after this time, then something is wrong.
				expectAsyncOffLinkRouteInvalidationEvent(llAddr3, l3LifetimeSeconds*time.Second)
			})
		})
	}
}

// TestRouterDiscoveryMaxRouters tests that only
// ipv6.MaxDiscoveredOffLinkRoutes discovered routers are remembered.
func TestRouterDiscoveryMaxRouters(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		offLinkRouteC: make(chan ndpOffLinkRouteEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				DiscoverDefaultRouters: true,
			},
			NDPDisp: &ndpDisp,
		})},
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}

	// Receive an RA from 2 more than the max number of discovered routers.
	for i := 1; i <= ipv6.MaxDiscoveredOffLinkRoutes+2; i++ {
		linkAddr := []byte{2, 2, 3, 4, 5, 0}
		linkAddr[5] = byte(i)
		llAddr := header.LinkLocalAddr(tcpip.LinkAddress(linkAddr))

		e.InjectInbound(header.IPv6ProtocolNumber, raBufSimple(llAddr, 5))

		if i <= ipv6.MaxDiscoveredOffLinkRoutes {
			select {
			case e := <-ndpDisp.offLinkRouteC:
				if diff := checkOffLinkRouteEvent(e, nicID, header.IPv6EmptySubnet, llAddr, header.MediumRoutePreference, true); diff != "" {
					t.Errorf("off-link route event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected router discovery event")
			}

		} else {
			select {
			case <-ndpDisp.offLinkRouteC:
				t.Fatal("should not have discovered a new router after we already discovered the max number of routers")
			default:
			}
		}
	}
}

// Check e to make sure that the event is for prefix on nic with ID 1, and the
// discovered flag set to discovered.
func checkPrefixEvent(e ndpPrefixEvent, prefix tcpip.Subnet, discovered bool) string {
	return cmp.Diff(ndpPrefixEvent{nicID: 1, prefix: prefix, discovered: discovered}, e, cmp.AllowUnexported(e))
}

func TestPrefixDiscovery(t *testing.T) {
	prefix1, subnet1, _ := prefixSubnetAddr(0, "")
	prefix2, subnet2, _ := prefixSubnetAddr(1, "")
	prefix3, subnet3, _ := prefixSubnetAddr(2, "")

	testWithRAs(t, func(t *testing.T, handleRAs ipv6.HandleRAsConfiguration, forwarding bool) {
		ndpDisp := ndpDispatcher{
			prefixC: make(chan ndpPrefixEvent, 1),
		}
		e := channel.New(0, 1280, linkAddr1)
		clock := faketime.NewManualClock()
		s := stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
				NDPConfigs: ipv6.NDPConfigurations{
					HandleRAs:              handleRAs,
					DiscoverOnLinkPrefixes: true,
				},
				NDPDisp: &ndpDisp,
			})},
			Clock: clock,
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

		if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, forwarding); err != nil {
			t.Fatalf("SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv6.ProtocolNumber, forwarding, err)
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

		// Receive an RA with prefix2 in a PI.
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, 100, 0))
		expectPrefixEvent(subnet2, true)

		// Receive an RA with prefix3 in a PI.
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 100, 0))
		expectPrefixEvent(subnet3, true)

		// Receive an RA with prefix1 in a PI with lifetime = 0.
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 0, 0))
		expectPrefixEvent(subnet1, false)

		// Receive an RA with prefix2 in a PI with lesser lifetime.
		lifetime := uint32(2)
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, lifetime, 0))
		select {
		case <-ndpDisp.prefixC:
			t.Fatal("unexpectedly received prefix event when updating lifetime")
		default:
		}

		// Wait for prefix2's most recent invalidation job plus some buffer to
		// expire.
		clock.Advance(time.Duration(lifetime) * time.Second)
		select {
		case e := <-ndpDisp.prefixC:
			if diff := checkPrefixEvent(e, subnet2, false); diff != "" {
				t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("timed out waiting for prefix discovery event")
		}

		// Receive RA to invalidate prefix3.
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 0, 0))
		expectPrefixEvent(subnet3, false)
	})
}

func TestPrefixDiscoveryWithInfiniteLifetime(t *testing.T) {
	prefix := tcpip.AddressWithPrefix{
		Address:   testutil.MustParse6("102:304:506:708::"),
		PrefixLen: 64,
	}
	subnet := prefix.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC: make(chan ndpPrefixEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				DiscoverOnLinkPrefixes: true,
			},
			NDPDisp: &ndpDisp,
		})},
		Clock: clock,
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
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, infiniteLifetimeSeconds, 0))
	expectPrefixEvent(subnet, true)
	clock.Advance(header.NDPInfiniteLifetime)
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	default:
	}

	// Receive an RA with finite lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, infiniteLifetimeSeconds-1, 0))
	clock.Advance(header.NDPInfiniteLifetime - time.Second)
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, false); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("timed out waiting for prefix discovery event")
	}

	// Receive an RA with finite lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, infiniteLifetimeSeconds-1, 0))
	expectPrefixEvent(subnet, true)

	// Receive an RA with prefix with an infinite lifetime.
	// The prefix should not be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, infiniteLifetimeSeconds, 0))
	clock.Advance(header.NDPInfiniteLifetime)
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	default:
	}

	// Receive an RA with 0 lifetime.
	// The prefix should get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, 0, 0))
	expectPrefixEvent(subnet, false)
}

// TestPrefixDiscoveryMaxRouters tests that only
// ipv6.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes are remembered.
func TestPrefixDiscoveryMaxOnLinkPrefixes(t *testing.T) {
	ndpDisp := ndpDispatcher{
		prefixC: make(chan ndpPrefixEvent, ipv6.MaxDiscoveredOnLinkPrefixes+3),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				DiscoverDefaultRouters: false,
				DiscoverOnLinkPrefixes: true,
			},
			NDPDisp: &ndpDisp,
		})},
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	optSer := make(header.NDPOptionsSerializer, ipv6.MaxDiscoveredOnLinkPrefixes+2)
	prefixes := [ipv6.MaxDiscoveredOnLinkPrefixes + 2]tcpip.Subnet{}

	// Receive an RA with 2 more than the max number of discovered on-link
	// prefixes.
	for i := 0; i < ipv6.MaxDiscoveredOnLinkPrefixes+2; i++ {
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
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))
	for i := 0; i < ipv6.MaxDiscoveredOnLinkPrefixes+2; i++ {
		if i < ipv6.MaxDiscoveredOnLinkPrefixes {
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
}

// Checks to see if list contains an IPv6 address, item.
func containsV6Addr(list []tcpip.ProtocolAddress, item tcpip.AddressWithPrefix) bool {
	protocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: item,
	}

	return containsAddr(list, protocolAddress)
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// event type is set to eventType.
func checkAutoGenAddrEvent(e ndpAutoGenAddrEvent, addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) string {
	return cmp.Diff(
		ndpAutoGenAddrEvent{nicID: 1, addr: addr, eventType: eventType},
		e,
		cmp.AllowUnexported(e),
	)
}

const minVLSeconds = uint32(ipv6.MinPrefixInformationValidLifetimeForUpdate / time.Second)
const infiniteLifetimeSeconds = uint32(header.NDPInfiniteLifetime / time.Second)

func expectAutoGenAddrEvent(t *testing.T, ndpDisp *ndpDispatcher, addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
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

// expectAutoGenAddrNewEvent expects that a new auto-gen addr event is
// immediately available with addr.
//
// The return *addressDispatcher is non-nil iff ndpDisp.autoGenInstallDisp is
// true.
func expectAutoGenAddrNewEvent(ndpDisp *ndpDispatcher, addr tcpip.AddressWithPrefix) (*addressDispatcher, error) {
	select {
	case e := <-ndpDisp.autoGenAddrNewC:
		if diff := cmp.Diff(
			ndpAutoGenAddrNewEvent{nicID: 1, addr: addr},
			e,
			cmp.AllowUnexported(e),
			cmp.FilterValues(func(*addressDispatcher, *addressDispatcher) bool { return true }, cmp.Ignore()),
		); diff != "" {
			return nil, fmt.Errorf("new auto-gen addr event mismatch (-want +got):\n%s", diff)
		}
		if ndpDisp.autoGenInstallDisp != (e.addrDisp != nil) {
			return nil, fmt.Errorf("install-disp=%t but addr-disp=%#v", ndpDisp.autoGenInstallDisp, e.addrDisp)
		}
		return e.addrDisp, nil
	default:
		return nil, fmt.Errorf("expected new auto-gen addr event")
	}
}

func TestMaxSlaacPrefixes(t *testing.T) {
	const (
		nicID = 1
		// Each SLAAC prefix gets a stable and temporary address.
		slaacAddrsPerPrefix = 2
		// Send an extra prefix than what we will discover to make sure we do not
		// discover the extra prefix.
		slaacPrefixesInRA = ipv6.MaxDiscoveredSLAACPrefixes + 1
	)

	ndpDisp := ndpDispatcher{
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, slaacPrefixesInRA*slaacAddrsPerPrefix),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:                  ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses:     true,
				AutoGenTempGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d) = %s", nicID, err)
	}

	optSer := make(header.NDPOptionsSerializer, 0, slaacPrefixesInRA)
	prefixes := [slaacPrefixesInRA]tcpip.Subnet{}
	for i := 0; i < slaacPrefixesInRA; i++ {
		prefixAddr := [16]byte{1, 2, 3, 4, 5, 6, 7, byte(i), 0, 0, 0, 0, 0, 0, 0, 0}
		prefix := tcpip.AddressWithPrefix{
			Address:   tcpip.Address(prefixAddr[:]),
			PrefixLen: 64,
		}
		prefixes[i] = prefix.Subnet()
		// Serialize a perfix information option.
		buf := [30]byte{}
		buf[0] = uint8(prefix.PrefixLen)
		// Set the autonomous configuration flag.
		buf[1] = 64
		// Set the preferred and valid lifetimes to the maxiumum possible value.
		binary.BigEndian.PutUint32(buf[2:], math.MaxUint32)
		binary.BigEndian.PutUint32(buf[6:], math.MaxUint32)
		if n := copy(buf[14:], prefix.Address); n != len(prefix.Address) {
			t.Fatalf("got copy(...) = %d, want = %d", n, len(prefix.Address))
		}
		optSer = append(optSer, header.NDPPrefixInformation(buf[:]))
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))
	for i := 0; i < slaacPrefixesInRA; i++ {
		for j := 0; j < slaacAddrsPerPrefix; j++ {
			if i < ipv6.MaxDiscoveredSLAACPrefixes {
				select {
				case e := <-ndpDisp.autoGenAddrNewC:
					if e.nicID != nicID {
						t.Errorf("got e.nicID = %d, want = %d", e.nicID, nicID)
					}
					if !prefixes[i].Contains(e.addr.Address) {
						t.Errorf("got prefixes[%d].Contains(%s) = false, want = true", i, e.addr)
					}
					if e.addrDisp != nil {
						t.Error("auto-gen new addr event unexpectedly contains address dispatcher")
					}
				default:
					t.Fatalf("expected auto-gen new addr event; i=%d, j=%d", i, j)
				}
			} else {
				select {
				case <-ndpDisp.autoGenAddrNewC:
					t.Fatal("should not have discovered a new auto-gen addr after we already discovered the max number of prefixes")
				default:
				}
			}
		}
	}
}

// TestAutoGenAddr tests that an address is properly generated and invalidated
// when configured to do so.
func TestAutoGenAddr(t *testing.T) {
	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	testWithRAs(t, func(t *testing.T, handleRAs ipv6.HandleRAsConfiguration, forwarding bool) {
		const autoGenAddrCount = 1
		ndpDisp := ndpDispatcher{
			autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
			autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
			autoGenInstallDisp: true,
		}
		e := channel.New(0, 1280, linkAddr1)
		clock := faketime.NewManualClock()
		s := stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
				NDPConfigs: ipv6.NDPConfigurations{
					HandleRAs:              handleRAs,
					AutoGenGlobalAddresses: true,
				},
				NDPDisp: &ndpDisp,
			})},
			Clock: clock,
		})

		if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, forwarding); err != nil {
			t.Fatalf("SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv6.ProtocolNumber, forwarding, err)
		}

		if err := s.CreateNIC(1, e); err != nil {
			t.Fatalf("CreateNIC(1) = %s", err)
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
		var preferredLifetime1 uint32
		validLifetime1 := uint32(100)
		received := clock.NowMonotonic()
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, validLifetime1, preferredLifetime1))
		addr1Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr1)
		if err != nil {
			t.Fatalf("error expecting prefix1 stable address generated event: %s", err)
		}
		if err := addr1Disp.expectChanged(addressLifetimes(received, preferredLifetime1, validLifetime1), stack.AddressAssigned); err != nil {
			t.Error(err)
		}
		if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
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

		// Receive an RA with prefix2 in a PI with a valid lifetime that exceeds
		// the minimum.
		validLifetime2 := uint32(minVLSeconds + 1)
		preferredLifetime2 := uint32(minVLSeconds + 1)
		received = clock.NowMonotonic()
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, validLifetime2, preferredLifetime2))
		addr2Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr2)
		if err != nil {
			t.Fatalf("error expecting prefix2 stable address generated event: %s", err)
		}
		if err := addr2Disp.expectChanged(addressLifetimes(received, preferredLifetime2, validLifetime2), stack.AddressAssigned); err != nil {
			t.Error(err)
		}
		if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
			t.Fatalf("Should have %s in the list of addresses", addr1)
		}
		if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr2) {
			t.Fatalf("Should have %s in the list of addresses", addr2)
		}

		// Refresh valid lifetime for addr of prefix1.
		e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, validLifetime1, 0))
		select {
		case <-ndpDisp.autoGenAddrC:
			t.Fatal("unexpectedly auto-generated an address when we already have an address for a prefix")
		default:
		}

		// Wait for addr of prefix1 to be invalidated.
		clock.Advance(ipv6.MinPrefixInformationValidLifetimeForUpdate)
		expectAutoGenAddrEvent(t, &ndpDisp, addr1, invalidatedAddr)
		if err := addr1Disp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
			t.Fatal(err)
		}
		if containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
			t.Fatalf("Should not have %s in the list of addresses", addr1)
		}
		if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr2) {
			t.Fatalf("Should have %s in the list of addresses", addr2)
		}
	})
}

func addressCheck(addrs []tcpip.ProtocolAddress, containList, notContainList []tcpip.AddressWithPrefix) string {
	ret := ""
	for _, c := range containList {
		if !containsV6Addr(addrs, c) {
			ret += fmt.Sprintf("should have %s in the list of addresses\n", c)
		}
	}
	for _, c := range notContainList {
		if containsV6Addr(addrs, c) {
			ret += fmt.Sprintf("should not have %s in the list of addresses\n", c)
		}
	}
	return ret
}

// TestAutoGenTempAddr tests that temporary SLAAC addresses are generated when
// configured to do so as part of IPv6 Privacy Extensions.
func TestAutoGenTempAddr(t *testing.T) {
	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	tests := []struct {
		name             string
		dupAddrTransmits uint8
		retransmitTimer  time.Duration
	}{
		{
			name: "DAD disabled",
		},
		{
			name:             "DAD enabled",
			dupAddrTransmits: 1,
			retransmitTimer:  time.Second,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := []byte{uint8(i)}
			var tempIIDHistory [header.IIDSize]byte
			header.InitialTempIID(tempIIDHistory[:], seed, nicID)
			newTempAddr := func(stableAddr tcpip.Address) tcpip.AddressWithPrefix {
				return header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], stableAddr)
			}

			const autoGenAddrCount = 2
			ndpDisp := ndpDispatcher{
				dadC:               make(chan ndpDADEvent, 2),
				autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
				autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
				autoGenInstallDisp: true,
			}
			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					DADConfigs: stack.DADConfigurations{
						DupAddrDetectTransmits: test.dupAddrTransmits,
						RetransmitTimer:        test.retransmitTimer,
					},
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs:                    ipv6.HandlingRAsEnabledWhenForwardingDisabled,
						AutoGenGlobalAddresses:       true,
						AutoGenTempGlobalAddresses:   true,
						MaxTempAddrValidLifetime:     3 * ipv6.MinPrefixInformationValidLifetimeForUpdate,
						MaxTempAddrPreferredLifetime: 3 * ipv6.MinPrefixInformationValidLifetimeForUpdate,
					},
					NDPDisp:     &ndpDisp,
					TempIIDSeed: seed,
				})},
				Clock: clock,
			})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			expectDADEventAsync := func(addr tcpip.Address) {
				t.Helper()

				clock.Advance(time.Duration(test.dupAddrTransmits) * test.retransmitTimer)
				select {
				case e := <-ndpDisp.dadC:
					if diff := checkDADEvent(e, nicID, addr, &stack.DADSucceeded{}); diff != "" {
						t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatal("timed out waiting for DAD event")
				}
			}

			expectAddrDispatcherTentative := func(addrDisp *addressDispatcher, wantLifetimes stack.AddressLifetimes) {
				t.Helper()

				if test.dupAddrTransmits != 0 {
					if err := addrDisp.expectChanged(wantLifetimes, stack.AddressTentative); err != nil {
						t.Error(err)
					}
				}
			}

			// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
			// with zero valid lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 0, 0))
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Fatalf("unexpectedly auto-generated an address with 0 lifetime; event = %+v", e)
			default:
			}

			// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
			// with non-zero valid lifetime.
			prefix1VL := uint32(100)
			var prefix1PL uint32
			received := clock.NowMonotonic()
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, prefix1VL, prefix1PL))
			addr1Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr1)
			if err != nil {
				t.Fatalf("error expecting prefix1 stable address generated event: %s", err)
			}
			expectAddrDispatcherTentative(addr1Disp, addressLifetimes(received, prefix1PL, prefix1VL))
			expectDADEventAsync(addr1.Address)
			if err := addr1Disp.expectChanged(addressLifetimes(received, prefix1PL, prefix1VL), stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Fatalf("unexpectedly got an auto gen addr event = %+v", e)
			default:
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1}, nil); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
			// with non-zero valid & preferred lifetimes.
			tempAddr1 := newTempAddr(addr1.Address)
			prefix1PL = uint32(100)
			received = clock.NowMonotonic()
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, prefix1VL, prefix1PL))
			if err := addr1Disp.expectLifetimesChanged(addressLifetimes(received, prefix1PL, prefix1VL)); err != nil {
				t.Error(err)
			}
			tempAddr1Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, tempAddr1)
			if err != nil {
				t.Fatalf("error expecting prefix1 temp address generated event: %s", err)
			}
			expectAddrDispatcherTentative(tempAddr1Disp, addressLifetimes(received, prefix1PL, prefix1VL))
			expectDADEventAsync(tempAddr1.Address)
			if err := tempAddr1Disp.expectChanged(addressLifetimes(received, prefix1PL, prefix1VL), stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			if mismatch := addressCheck(s.NICInfo()[1].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1}, nil); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Receive an RA with prefix2 in an NDP Prefix Information option (PI)
			// with preferred lifetime > valid lifetime
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 5, 6))
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Fatalf("unexpectedly auto-generated an address with preferred lifetime > valid lifetime; event = %+v", e)
			default:
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1}, nil); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Receive an RA with prefix2 in a PI with a valid lifetime that exceeds
			// the minimum and won't be reached in this test.
			tempAddr2 := newTempAddr(addr2.Address)
			lifetime2 := 2 * minVLSeconds
			received2 := clock.NowMonotonic()
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, lifetime2, lifetime2))
			addr2Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr2)
			if err != nil {
				t.Fatalf("error expecting prefix2 stable address generated event: %s", err)
			}
			expectAddrDispatcherTentative(addr2Disp, addressLifetimes(received2, lifetime2, lifetime2))
			expectDADEventAsync(addr2.Address)
			if err := addr2Disp.expectChanged(addressLifetimes(received2, lifetime2, lifetime2), stack.AddressAssigned); err != nil {
				t.Error(err)
			}

			clock.RunImmediatelyScheduledJobs()
			tempAddr2Disp, err := expectAutoGenAddrNewEvent(&ndpDisp, tempAddr2)
			if err != nil {
				t.Fatalf("error expecting prefix2 temp address generated event: %s", err)
			}
			expectAddrDispatcherTentative(tempAddr2Disp, addressLifetimes(received2, lifetime2, lifetime2))
			expectDADEventAsync(tempAddr2.Address)
			if err := tempAddr2Disp.expectChanged(addressLifetimes(received2, lifetime2, lifetime2), stack.AddressAssigned); err != nil {
				t.Error(err)
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1, addr2, tempAddr2}, nil); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Deprecate prefix1.
			{
				prefix1VL := uint32(100)
				received = clock.NowMonotonic()
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, prefix1VL, 0))
				expectAutoGenAddrEvent(t, &ndpDisp, addr1, deprecatedAddr)
				if err := addr1Disp.expectLifetimesChanged(addressLifetimes(received, 0, prefix1VL)); err != nil {
					t.Error(err)
				}
				expectAutoGenAddrEvent(t, &ndpDisp, tempAddr1, deprecatedAddr)
				if err := tempAddr1Disp.expectLifetimesChanged(addressLifetimes(received, 0, prefix1VL)); err != nil {
					t.Error(err)
				}
				if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1, addr2, tempAddr2}, nil); mismatch != "" {
					t.Fatal(mismatch)
				}
			}

			// Refresh lifetimes for prefix1.
			{
				prefix1VL := uint32(100)
				prefix1PL := uint32(100)
				received := clock.NowMonotonic()
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, prefix1VL, prefix1PL))
				if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1, addr2, tempAddr2}, nil); mismatch != "" {
					t.Fatal(mismatch)
				}
				if err := addr1Disp.expectLifetimesChanged(addressLifetimes(received, prefix1PL, prefix1VL)); err != nil {
					t.Error(err)
				}
				if err := tempAddr1Disp.expectLifetimesChanged(addressLifetimes(received, prefix1PL, prefix1VL)); err != nil {
					t.Error(err)
				}
			}

			// Reduce valid lifetime and deprecate addresses of prefix1.
			received = clock.NowMonotonic()
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, minVLSeconds, 0))
			expectAutoGenAddrEvent(t, &ndpDisp, addr1, deprecatedAddr)
			expectAutoGenAddrEvent(t, &ndpDisp, tempAddr1, deprecatedAddr)
			if err := addr1Disp.expectLifetimesChanged(addressLifetimes(received, 0, minVLSeconds)); err != nil {
				t.Error(err)
			}
			if err := tempAddr1Disp.expectLifetimesChanged(addressLifetimes(received, 0, minVLSeconds)); err != nil {
				t.Error(err)
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr1, tempAddr1, addr2, tempAddr2}, nil); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Wait for addrs of prefix1 to be invalidated. They should be
			// invalidated at the same time.
			clock.Advance(ipv6.MinPrefixInformationValidLifetimeForUpdate)
			select {
			case e := <-ndpDisp.autoGenAddrC:
				var nextAddr tcpip.AddressWithPrefix
				if e.addr == addr1 {
					if diff := checkAutoGenAddrEvent(e, addr1, invalidatedAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}
					nextAddr = tempAddr1
				} else {
					if diff := checkAutoGenAddrEvent(e, tempAddr1, invalidatedAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}
					nextAddr = addr1
				}

				expectAutoGenAddrEvent(t, &ndpDisp, nextAddr, invalidatedAddr)
			default:
				t.Fatal("timed out waiting for addr auto gen event")
			}
			if err := addr1Disp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
				t.Error(err)
			}
			if err := tempAddr1Disp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
				t.Error(err)
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr2, tempAddr2}, []tcpip.AddressWithPrefix{addr1, tempAddr1}); mismatch != "" {
				t.Fatal(mismatch)
			}

			// Receive an RA with prefix2 in a PI w/ 0 lifetimes.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 0, 0))
			expectAutoGenAddrEvent(t, &ndpDisp, addr2, deprecatedAddr)
			expectAutoGenAddrEvent(t, &ndpDisp, tempAddr2, deprecatedAddr)
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Errorf("got unexpected auto gen addr event = %+v", e)
			default:
			}
			// Addresses should be deprecated, but their valid-until should be untouched
			// as their remaining valid lifetime is too low.
			if err := addr2Disp.expectDeprecated(); err != nil {
				t.Error(err)
			}
			if err := tempAddr2Disp.expectDeprecated(); err != nil {
				t.Error(err)
			}
			if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr2, tempAddr2}, []tcpip.AddressWithPrefix{addr1, tempAddr1}); mismatch != "" {
				t.Fatal(mismatch)
			}
		})
	}
}

// TestNoAutoGenTempAddrForLinkLocal test that temporary SLAAC addresses are not
// generated for auto generated link-local addresses.
func TestNoAutoGenTempAddrForLinkLocal(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name             string
		dupAddrTransmits uint8
		retransmitTimer  time.Duration
	}{
		{
			name: "DAD disabled",
		},
		{
			name:             "DAD enabled",
			dupAddrTransmits: 1,
			retransmitTimer:  time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const autoGenAddrCount = 1
			ndpDisp := ndpDispatcher{
				dadC:               make(chan ndpDADEvent, 1),
				autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
				autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
				autoGenInstallDisp: true,
			}
			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPConfigs: ipv6.NDPConfigurations{
						AutoGenTempGlobalAddresses: true,
					},
					DADConfigs: stack.DADConfigurations{
						DupAddrDetectTransmits: test.dupAddrTransmits,
						RetransmitTimer:        test.retransmitTimer,
					},
					NDPDisp:          &ndpDisp,
					AutoGenLinkLocal: true,
				})},
				Clock: clock,
			})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			// The stable link-local address should auto-generate and resolve DAD.
			addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, tcpip.AddressWithPrefix{Address: llAddr1, PrefixLen: header.IIDOffsetInIPv6Address * 8})
			if err != nil {
				t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
			}
			if test.dupAddrTransmits > 0 {
				if err := addrDisp.expectChanged(infiniteLifetimes(), stack.AddressTentative); err != nil {
					t.Error(err)
				}
			}
			clock.Advance(time.Duration(test.dupAddrTransmits) * test.retransmitTimer)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, llAddr1, &stack.DADSucceeded{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("timed out waiting for DAD event")
			}
			if err := addrDisp.expectChanged(infiniteLifetimes(), stack.AddressAssigned); err != nil {
				t.Error(err)
			}

			// No new addresses should be generated.
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Errorf("got unxpected auto gen addr event = %+v", e)
			default:
			}
		})
	}
}

// TestNoAutoGenTempAddrWithoutStableAddr tests that a temporary SLAAC address
// will not be generated until after DAD completes, even if a new Router
// Advertisement is received to refresh lifetimes.
func TestNoAutoGenTempAddrWithoutStableAddr(t *testing.T) {
	const (
		nicID           = 1
		dadTransmits    = 1
		retransmitTimer = 2 * time.Second
	)

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)
	var tempIIDHistory [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistory[:], nil, nicID)
	tempAddr := header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], addr.Address)

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		dadC:               make(chan ndpDADEvent, 1),
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			DADConfigs: stack.DADConfigurations{
				DupAddrDetectTransmits: dadTransmits,
				RetransmitTimer:        retransmitTimer,
			},
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:                  ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses:     true,
				AutoGenTempGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
		Clock: clock,
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	// Receive an RA to trigger SLAAC for prefix.
	received, pl, vl := clock.NowMonotonic(), uint32(100), uint32(100)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, vl, pl))
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	if err := addrDisp.expectChanged(addressLifetimes(received, pl, vl), stack.AddressTentative); err != nil {
		t.Error(err)
	}

	// DAD on the stable address for prefix has not yet completed. Receiving a new
	// RA that would refresh lifetimes should not generate a temporary SLAAC
	// address for the prefix.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, vl, pl))
	select {
	case e := <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpected auto gen addr event = %+v", e)
	default:
	}

	// Wait for DAD to complete for the stable address then expect the temporary
	// address to be generated.
	clock.Advance(dadTransmits * retransmitTimer)
	select {
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr.Address, &stack.DADSucceeded{}); diff != "" {
			t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("timed out waiting for DAD event")
	}
	if err := addrDisp.expectStateChanged(stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	tempAddrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, tempAddr)
	if err != nil {
		t.Fatalf("error expecting temp auto-gen address generated event: %s", err)
	}
	tempAddrDisp.disable()
}

type tempAddrState struct {
	addrWithPrefix tcpip.AddressWithPrefix
	generated      tcpip.MonotonicTime
	disp           *addressDispatcher
}

// TestAutoGenTempAddrRegen tests that temporary SLAAC addresses are
// regenerated.
func TestAutoGenTempAddrRegen(t *testing.T) {
	const (
		nicID    = 1
		regenAdv = 2 * time.Second

		numTempAddrs             = 3
		maxTempAddrValidLifetime = numTempAddrs * ipv6.MinPrefixInformationValidLifetimeForUpdate
	)

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)
	var tempIIDHistory [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistory[:], nil, nicID)
	var tempAddrs [numTempAddrs]tempAddrState
	for i := 0; i < len(tempAddrs); i++ {
		tempAddrs[i] = tempAddrState{
			addrWithPrefix: header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], addr.Address),
		}
	}

	const autoGenAddrCount = 2
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	ndpConfigs := ipv6.NDPConfigurations{
		HandleRAs:                    ipv6.HandlingRAsEnabledWhenForwardingDisabled,
		AutoGenGlobalAddresses:       true,
		AutoGenTempGlobalAddresses:   true,
		RegenAdvanceDuration:         regenAdv,
		MaxTempAddrValidLifetime:     maxTempAddrValidLifetime,
		MaxTempAddrPreferredLifetime: ipv6.MinPrefixInformationValidLifetimeForUpdate,
	}
	clock := faketime.NewManualClock()
	randSource := savingRandSource{
		s: rand.NewSource(time.Now().UnixNano()),
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ndpConfigs,
			NDPDisp:    &ndpDisp,
		})},
		Clock:      clock,
		RandSource: &randSource,
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	expectAutoGenAddrEventAsync := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType, timeout time.Duration) {
		t.Helper()

		clock.Advance(timeout)
		expectAutoGenAddrEvent(t, &ndpDisp, addr, eventType)
	}

	tempDesyncFactor := time.Duration(randSource.lastInt63) % ipv6.MaxDesyncFactor
	effectiveMaxTempAddrPL := ipv6.MinPrefixInformationValidLifetimeForUpdate - tempDesyncFactor
	// The time since the last regeneration before a new temporary address is
	// generated.
	tempAddrRegenerationTime := effectiveMaxTempAddrPL - regenAdv

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero valid & preferred lifetimes.
	received := clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, minVLSeconds))
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	// Disable receiving events on the stable address since it's not of interest
	// to this particular test.
	addrDisp.disable()
	tempAddrs[0].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[0].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting temp auto-gen address generated event: %s", err)
	}
	tempAddrs[0].generated = clock.NowMonotonic()
	// Since the max temporary address preferred lifetime is equal to the valid
	// lifetime of the prefix, the temporary address generated is preferred
	// until the max minus the desync factor.
	if err := tempAddrs[0].disp.expectChanged(stack.AddressLifetimes{
		ValidUntil:     received.Add(time.Duration(minVLSeconds) * time.Second),
		PreferredUntil: received.Add(effectiveMaxTempAddrPL),
	}, stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr, tempAddrs[0].addrWithPrefix}, nil); mismatch != "" {
		t.Fatal(mismatch)
	}

	// Wait for regeneration
	clock.Advance(tempAddrRegenerationTime)
	tempAddrs[1].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[1].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting new temp regenerated address event: %s", err)
	}
	tempAddrs[1].generated = clock.NowMonotonic()
	// New temp address generated with lifetimes of the prefix.
	if err := tempAddrs[1].disp.expectChanged(addressLifetimes(received, minVLSeconds, minVLSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	received = clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, minVLSeconds))
	// The first temporary address only has valid lifetime refreshed.
	if err := tempAddrs[0].disp.expectValidUntilChanged(received.Add(time.Duration(minVLSeconds) * time.Second)); err != nil {
		t.Error(err)
	}
	if err := tempAddrs[1].disp.expectChanged(stack.AddressLifetimes{
		ValidUntil:     received.Add(time.Duration(minVLSeconds) * time.Second),
		PreferredUntil: received.Add(effectiveMaxTempAddrPL),
	}, stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr, tempAddrs[0].addrWithPrefix, tempAddrs[1].addrWithPrefix}, nil); mismatch != "" {
		t.Fatal(mismatch)
	}
	expectAutoGenAddrEventAsync(tempAddrs[0].addrWithPrefix, deprecatedAddr, regenAdv)
	if err := tempAddrs[0].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}

	// Wait for regeneration
	clock.Advance(tempAddrRegenerationTime - regenAdv)
	tempAddrs[2].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[2].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting new temp twice-regenerated address event: %s", err)
	}
	tempAddrs[2].generated = clock.NowMonotonic()
	if err := tempAddrs[2].disp.expectChanged(addressLifetimes(received, minVLSeconds, minVLSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	expectAutoGenAddrEventAsync(tempAddrs[1].addrWithPrefix, deprecatedAddr, regenAdv)
	if err := tempAddrs[1].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}

	// Stop generating temporary addresses
	ndpConfigs.AutoGenTempGlobalAddresses = false
	if ipv6Ep, err := s.GetNetworkEndpoint(nicID, header.IPv6ProtocolNumber); err != nil {
		t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
	} else {
		ndpEP := ipv6Ep.(ipv6.NDPEndpoint)
		ndpEP.SetNDPConfigurations(ndpConfigs)
	}

	// Refresh lifetimes and wait for the last temporary address to be deprecated.
	received = clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, minVLSeconds))
	for i, tempAddrState := range tempAddrs {
		if i == 2 {
			if err := tempAddrState.disp.expectLifetimesChanged(stack.AddressLifetimes{
				ValidUntil: received.Add(time.Duration(minVLSeconds) * time.Second),
				// The effective max preferred lifetime since address generation is used
				// since it is less than the refreshed prefix preferred lifetime.
				PreferredUntil: tempAddrState.generated.Add(effectiveMaxTempAddrPL),
			}); err != nil {
				t.Error(err)
			}
		} else {
			if err := tempAddrState.disp.expectValidUntilChanged(received.Add(time.Duration(minVLSeconds) * time.Second)); err != nil {
				t.Errorf("addr %d error: %s", i, err)
			}
		}
	}
	expectAutoGenAddrEventAsync(tempAddrs[2].addrWithPrefix, deprecatedAddr, effectiveMaxTempAddrPL-regenAdv)
	if err := tempAddrs[2].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}

	// Refresh lifetimes such that the prefix is valid and preferred forever.
	//
	// This should not affect the lifetimes of temporary addresses because they
	// are capped by the maximum valid and preferred lifetimes for temporary
	// addresses.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, infiniteLifetimeSeconds, infiniteLifetimeSeconds))
	for i, tempAddrState := range tempAddrs {
		if err := tempAddrState.disp.expectValidUntilChanged(tempAddrState.generated.Add(maxTempAddrValidLifetime)); err != nil {
			t.Errorf("addr %d error: %s", i, err)
		}
	}

	// Wait for all the temporary addresses to get invalidated.
	invalidateAfter := maxTempAddrValidLifetime - clock.NowMonotonic().Sub(tcpip.MonotonicTime{})
	var tempAddrWithPrefix [numTempAddrs]tcpip.AddressWithPrefix
	for i, tempAddrState := range tempAddrs {
		tempAddrWithPrefix[i] = tempAddrState.addrWithPrefix
		expectAutoGenAddrEventAsync(tempAddrState.addrWithPrefix, invalidatedAddr, invalidateAfter)
		invalidateAfter = tempAddrRegenerationTime
		if err := tempAddrState.disp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
			t.Errorf("addr %d error: %s", i, err)
		}
	}
	if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr}, tempAddrWithPrefix[:]); mismatch != "" {
		t.Fatal(mismatch)
	}
}

// TestAutoGenTempAddrRegenJobUpdates tests that a temporary address's
// regeneration job gets updated when refreshing the address's lifetimes.
func TestAutoGenTempAddrRegenJobUpdates(t *testing.T) {
	const (
		nicID    = 1
		regenAdv = 2 * time.Second

		numTempAddrs                        = 3
		maxTempAddrPreferredLifetime        = ipv6.MinPrefixInformationValidLifetimeForUpdate
		maxTempAddrPreferredLifetimeSeconds = uint32(maxTempAddrPreferredLifetime / time.Second)
	)

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)
	var tempIIDHistory [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistory[:], nil, nicID)
	var tempAddrs [numTempAddrs]tempAddrState
	for i := 0; i < len(tempAddrs); i++ {
		tempAddrs[i] = tempAddrState{
			addrWithPrefix: header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], addr.Address),
		}
	}

	const autoGenAddrCount = 2
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	ndpConfigs := ipv6.NDPConfigurations{
		HandleRAs:                    ipv6.HandlingRAsEnabledWhenForwardingDisabled,
		AutoGenGlobalAddresses:       true,
		AutoGenTempGlobalAddresses:   true,
		RegenAdvanceDuration:         regenAdv,
		MaxTempAddrPreferredLifetime: maxTempAddrPreferredLifetime,
		MaxTempAddrValidLifetime:     maxTempAddrPreferredLifetime * 2,
	}
	clock := faketime.NewManualClock()
	initialTime := clock.NowMonotonic()
	randSource := savingRandSource{
		s: rand.NewSource(time.Now().UnixNano()),
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ndpConfigs,
			NDPDisp:    &ndpDisp,
		})},
		Clock:      clock,
		RandSource: &randSource,
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	tempDesyncFactor := time.Duration(randSource.lastInt63) % ipv6.MaxDesyncFactor
	effectiveMaxTempAddrPL := maxTempAddrPreferredLifetime - tempDesyncFactor

	expectAutoGenAddrEventAsync := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType, timeout time.Duration) {
		t.Helper()

		clock.Advance(timeout)
		expectAutoGenAddrEvent(t, &ndpDisp, addr, eventType)
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero valid & preferred lifetimes.
	received := clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, maxTempAddrPreferredLifetimeSeconds, maxTempAddrPreferredLifetimeSeconds))
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	// Ignore events about the stable address, since that's not relevant to this test.
	addrDisp.disable()
	tempAddrs[0].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[0].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting temp auto-gen address generated event: %s", err)
	}
	tempAddrs[0].generated = clock.NowMonotonic()
	if err := tempAddrs[0].disp.expectChanged(stack.AddressLifetimes{
		ValidUntil:     received.Add(maxTempAddrPreferredLifetime),
		PreferredUntil: received.Add(effectiveMaxTempAddrPL),
	}, stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, []tcpip.AddressWithPrefix{addr, tempAddrs[0].addrWithPrefix}, nil); mismatch != "" {
		t.Fatal(mismatch)
	}

	// Deprecate the prefix.
	//
	// A new temporary address should be generated after the regeneration
	// time has passed since the prefix is deprecated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, maxTempAddrPreferredLifetimeSeconds, 0))
	expectAutoGenAddrEvent(t, &ndpDisp, addr, deprecatedAddr)
	expectAutoGenAddrEvent(t, &ndpDisp, tempAddrs[0].addrWithPrefix, deprecatedAddr)
	if err := tempAddrs[0].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}
	select {
	case e := <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpected auto gen addr event = %#v", e)
	default:
	}

	// The time since the last regeneration before a new temporary address is
	// generated.
	tempAddrRegenenerationTime := effectiveMaxTempAddrPL - regenAdv

	// Advance the clock by the regeneration time but don't expect a new temporary
	// address as the prefix is deprecated.
	clock.Advance(tempAddrRegenenerationTime)
	select {
	case e := <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpected auto gen addr event = %#v", e)
	default:
	}

	// Prefer the prefix again.
	//
	// A new temporary address should immediately be generated since the
	// regeneration time has already passed since the last address was generated
	// - this regeneration does not depend on a job.
	received = clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, maxTempAddrPreferredLifetimeSeconds, maxTempAddrPreferredLifetimeSeconds))
	if err := tempAddrs[0].disp.expectLifetimesChanged(
		stack.AddressLifetimes{
			ValidUntil:     received.Add(maxTempAddrPreferredLifetime),
			PreferredUntil: tempAddrs[0].generated.Add(effectiveMaxTempAddrPL),
		}); err != nil {
		t.Error(err)
	}
	tempAddrs[1].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[1].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting temp auto-gen address regenerated event: %s", err)
	}
	tempAddrs[1].generated = clock.NowMonotonic()
	if err := tempAddrs[1].disp.expectChanged(stack.AddressLifetimes{
		ValidUntil:     received.Add(maxTempAddrPreferredLifetime),
		PreferredUntil: received.Add(effectiveMaxTempAddrPL),
	}, stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	// Wait for the first temporary address to be deprecated.
	expectAutoGenAddrEventAsync(tempAddrs[0].addrWithPrefix, deprecatedAddr, regenAdv)
	if err := tempAddrs[0].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}
	select {
	case e := <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpected auto gen addr event = %s", e)
	default:
	}

	// Increase the maximum lifetimes for temporary addresses to large values
	// then refresh the lifetimes of the prefix.
	//
	// A new address should not be generated after the regeneration time that was
	// expected for the previous check. This is because the preferred lifetime for
	// the temporary addresses has increased, so it will take more time to
	// regenerate a new temporary address. Note, new addresses are only
	// regenerated after the preferred lifetime - the regenerate advance duration
	// has passed.
	const largeLifetimeSeconds = minVLSeconds * 2
	const largeLifetime = time.Duration(largeLifetimeSeconds) * time.Second
	ndpConfigs.MaxTempAddrValidLifetime = 2 * largeLifetime
	ndpConfigs.MaxTempAddrPreferredLifetime = largeLifetime
	ipv6Ep, tcpipErr := s.GetNetworkEndpoint(nicID, header.IPv6ProtocolNumber)
	if tcpipErr != nil {
		t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, header.IPv6ProtocolNumber, tcpipErr)
	}
	ndpEP := ipv6Ep.(ipv6.NDPEndpoint)
	ndpEP.SetNDPConfigurations(ndpConfigs)
	received = clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	for i := 0; i <= 1; i++ {
		if err := tempAddrs[i].disp.expectLifetimesChanged(stack.AddressLifetimes{
			ValidUntil:     received.Add(largeLifetime),
			PreferredUntil: tempAddrs[i].generated.Add(largeLifetime - tempDesyncFactor),
		}); err != nil {
			t.Errorf("addr %d dispatcher error: %s", i, err)
		}
	}
	timeSinceInitialTime := clock.NowMonotonic().Sub(initialTime)
	clock.Advance(largeLifetime - timeSinceInitialTime)
	expectAutoGenAddrEvent(t, &ndpDisp, tempAddrs[0].addrWithPrefix, deprecatedAddr)
	if err := tempAddrs[0].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}
	// to offset the advancement of time to test the first temporary address's
	// deprecation after the second was generated
	advLess := regenAdv
	clock.Advance(timeSinceInitialTime - advLess - (tempDesyncFactor + regenAdv))
	tempAddrs[2].disp, err = expectAutoGenAddrNewEvent(&ndpDisp, tempAddrs[2].addrWithPrefix)
	if err != nil {
		t.Fatalf("error expecting temp auto-gen address twice-regenerated event: %s", err)
	}
	tempAddrs[2].generated = clock.NowMonotonic()
	if err := tempAddrs[2].disp.expectChanged(addressLifetimes(received, largeLifetimeSeconds, largeLifetimeSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	expectAutoGenAddrEventAsync(tempAddrs[1].addrWithPrefix, deprecatedAddr, regenAdv)
	if err := tempAddrs[1].disp.expectDeprecated(); err != nil {
		t.Error(err)
	}
	select {
	case e := <-ndpDisp.autoGenAddrC:
		t.Fatalf("unexpected auto gen addr event = %+v", e)
	default:
	}
}

// TestMixedSLAACAddrConflictRegen tests SLAAC address regeneration in response
// to a mix of DAD conflicts and NIC-local conflicts.
func TestMixedSLAACAddrConflictRegen(t *testing.T) {
	const (
		nicID           = 1
		nicName         = "nic"
		lifetimeSeconds = 9999
		// From stack.maxSLAACAddrLocalRegenAttempts
		maxSLAACAddrLocalRegenAttempts = 10
		// We use 2 more addreses than the maximum local regeneration attempts
		// because we want to also trigger regeneration in response to a DAD
		// conflicts for this test.
		maxAddrs         = maxSLAACAddrLocalRegenAttempts + 2
		dupAddrTransmits = 1
		retransmitTimer  = time.Second
	)

	var tempIIDHistoryWithModifiedEUI64 [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistoryWithModifiedEUI64[:], nil, nicID)

	var tempIIDHistoryWithOpaqueIID [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistoryWithOpaqueIID[:], nil, nicID)

	prefix, subnet, stableAddrWithModifiedEUI64 := prefixSubnetAddr(0, linkAddr1)
	var stableAddrsWithOpaqueIID [maxAddrs]tcpip.AddressWithPrefix
	var tempAddrsWithOpaqueIID [maxAddrs]tcpip.AddressWithPrefix
	var tempAddrsWithModifiedEUI64 [maxAddrs]tcpip.AddressWithPrefix
	addrBytes := []byte(subnet.ID())
	for i := 0; i < maxAddrs; i++ {
		stableAddrsWithOpaqueIID[i] = tcpip.AddressWithPrefix{
			Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet, nicName, uint8(i), nil)),
			PrefixLen: header.IIDOffsetInIPv6Address * 8,
		}
		// When generating temporary addresses, the resolved stable address for the
		// SLAAC prefix will be the first address stable address generated for the
		// prefix as we will not simulate address conflicts for the stable addresses
		// in tests involving temporary addresses. Address conflicts for stable
		// addresses will be done in their own tests.
		tempAddrsWithOpaqueIID[i] = header.GenerateTempIPv6SLAACAddr(tempIIDHistoryWithOpaqueIID[:], stableAddrsWithOpaqueIID[0].Address)
		tempAddrsWithModifiedEUI64[i] = header.GenerateTempIPv6SLAACAddr(tempIIDHistoryWithModifiedEUI64[:], stableAddrWithModifiedEUI64.Address)
	}

	tests := []struct {
		name          string
		addrs         []tcpip.AddressWithPrefix
		tempAddrs     bool
		initialExpect tcpip.AddressWithPrefix
		maxAddrs      int
		nicNameFromID func(tcpip.NICID, string) string
	}{
		{
			name:     "Stable addresses with opaque IIDs",
			addrs:    stableAddrsWithOpaqueIID[:],
			maxAddrs: 1,
			nicNameFromID: func(tcpip.NICID, string) string {
				return nicName
			},
		},
		{
			name:          "Temporary addresses with opaque IIDs",
			addrs:         tempAddrsWithOpaqueIID[:],
			tempAddrs:     true,
			initialExpect: stableAddrsWithOpaqueIID[0],
			maxAddrs:      1 /* initial (stable) address */ + maxSLAACAddrLocalRegenAttempts,
			nicNameFromID: func(tcpip.NICID, string) string {
				return nicName
			},
		},
		{
			name:          "Temporary addresses with modified EUI64",
			addrs:         tempAddrsWithModifiedEUI64[:],
			tempAddrs:     true,
			maxAddrs:      1 /* initial (stable) address */ + maxSLAACAddrLocalRegenAttempts,
			initialExpect: stableAddrWithModifiedEUI64,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, test.maxAddrs),
				// We may receive a deprecated and invalidated event for each SLAAC
				// address that is assigned.
				autoGenAddrC: make(chan ndpAutoGenAddrEvent, test.maxAddrs*2),
			}
			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				Clock: clock,
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs:                     ipv6.HandlingRAsEnabledWhenForwardingDisabled,
						AutoGenGlobalAddresses:        true,
						AutoGenTempGlobalAddresses:    test.tempAddrs,
						AutoGenAddressConflictRetries: 1,
					},
					NDPDisp: &ndpDisp,
					OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
						NICNameFromID: test.nicNameFromID,
					},
				})},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})

			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv6EmptySubnet,
				Gateway:     llAddr2,
				NIC:         nicID,
			}})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			manuallyAssignedAddresses := make(map[tcpip.Address]struct{})
			for j := 0; j < len(test.addrs)-1; j++ {
				// The NIC will not attempt to generate an address in response to a
				// NIC-local conflict after some maximum number of attempts. We skip
				// creating a conflict for the address that would be generated as part
				// of the last attempt so we can simulate a DAD conflict for this
				// address and restart the NIC-local generation process.
				if j == maxSLAACAddrLocalRegenAttempts-1 {
					continue
				}

				protocolAddr := tcpip.ProtocolAddress{
					Protocol:          ipv6.ProtocolNumber,
					AddressWithPrefix: test.addrs[j].Address.WithPrefix(),
				}
				if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
					t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
				}

				manuallyAssignedAddresses[test.addrs[j].Address] = struct{}{}
			}

			expectAutoGenAddrNewEventAsync := func(addr tcpip.AddressWithPrefix) {
				t.Helper()

				e := <-ndpDisp.autoGenAddrNewC
				if diff := cmp.Diff(
					ndpAutoGenAddrNewEvent{nicID: 1, addr: addr},
					e,
					cmp.AllowUnexported(e),
					cmp.FilterValues(func(*addressDispatcher, *addressDispatcher) bool { return true }, cmp.Ignore()),
				); diff != "" {
					t.Errorf("auto-gen new addr event mismatch (-want +got):\n%s", diff)
				}
				if e.addrDisp != nil {
					t.Error("auto-gen new addr event unexpectedly contains address dispatcher")
				}
			}

			expectDADEventAsync := func(addr tcpip.Address) {
				t.Helper()

				clock.Advance(dupAddrTransmits * retransmitTimer)
				if diff := checkDADEvent(<-ndpDisp.dadC, nicID, addr, &stack.DADSucceeded{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			}

			// Enable DAD.
			ndpDisp.dadC = make(chan ndpDADEvent, 2)
			if ipv6Ep, err := s.GetNetworkEndpoint(nicID, header.IPv6ProtocolNumber); err != nil {
				t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
			} else {
				ndpEP := ipv6Ep.(stack.DuplicateAddressDetector)
				ndpEP.SetDADConfigurations(stack.DADConfigurations{
					DupAddrDetectTransmits: dupAddrTransmits,
					RetransmitTimer:        retransmitTimer,
				})
			}

			// Do SLAAC for prefix.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, lifetimeSeconds))
			if test.initialExpect != (tcpip.AddressWithPrefix{}) {
				if _, err := expectAutoGenAddrNewEvent(&ndpDisp, test.initialExpect); err != nil {
					t.Fatalf("error expecting auto-gen address generated event: %s", err)
				}
				expectDADEventAsync(test.initialExpect.Address)
			}

			// The last local generation attempt should succeed, but we introduce a
			// DAD failure to restart the local generation process.
			addr := test.addrs[maxSLAACAddrLocalRegenAttempts-1]
			expectAutoGenAddrNewEventAsync(addr)
			rxNDPSolicit(e, addr.Address)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr.Address, &stack.DADDupAddrDetected{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected DAD event")
			}
			expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)

			// The last address generated should resolve DAD.
			addr = test.addrs[len(test.addrs)-1]
			expectAutoGenAddrNewEventAsync(addr)
			expectDADEventAsync(addr.Address)

			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Fatalf("unexpected auto gen addr event = %+v", e)
			default:
			}

			// Wait for all the SLAAC addresses to be invalidated.
			clock.Advance(lifetimeSeconds * time.Second)
			gotAddresses := make(map[tcpip.Address]struct{})
			for _, a := range s.NICInfo()[nicID].ProtocolAddresses {
				gotAddresses[a.AddressWithPrefix.Address] = struct{}{}
			}
			if diff := cmp.Diff(manuallyAssignedAddresses, gotAddresses); diff != "" {
				t.Fatalf("assigned addresses mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// stackAndNdpDispatcherWithDefaultRoute returns an ndpDispatcher,
// channel.Endpoint and stack.Stack.
//
// stack.Stack will have a default route through the router (llAddr3) installed
// and a static link-address (linkAddr3) added to the link address cache for the
// router.
func stackAndNdpDispatcherWithDefaultRoute(t *testing.T, nicID tcpip.NICID) (*ndpDispatcher, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) {
	t.Helper()
	const autoGenAddrCount = 1
	ndpDisp := &ndpDispatcher{
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
	}
	e := channel.New(0, 1280, linkAddr1)
	e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: ndpDisp,
		})},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              clock,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		Gateway:     llAddr3,
		NIC:         nicID,
	}})

	if err := s.AddStaticNeighbor(nicID, ipv6.ProtocolNumber, llAddr3, linkAddr3); err != nil {
		t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nicID, ipv6.ProtocolNumber, llAddr3, linkAddr3, err)
	}
	return ndpDisp, e, s, clock
}

// addrForNewConnectionTo returns the local address used when creating a new
// connection to addr.
func addrForNewConnectionTo(t *testing.T, s *stack.Stack, addr tcpip.FullAddress) tcpip.Address {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	ep.SocketOptions().SetV6Only(true)
	if err := ep.Connect(addr); err != nil {
		t.Fatalf("ep.Connect(%+v): %s", addr, err)
	}
	got, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("ep.GetLocalAddress(): %s", err)
	}
	return got.Addr
}

// addrForNewConnection returns the local address used when creating a new
// connection.
func addrForNewConnection(t *testing.T, s *stack.Stack) tcpip.Address {
	t.Helper()

	return addrForNewConnectionTo(t, s, dstAddr)
}

// addrForNewConnectionWithAddr returns the local address used when creating a
// new connection with a specific local address.
func addrForNewConnectionWithAddr(t *testing.T, s *stack.Stack, addr tcpip.FullAddress) tcpip.Address {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	ep.SocketOptions().SetV6Only(true)
	if err := ep.Bind(addr); err != nil {
		t.Fatalf("ep.Bind(%+v): %s", addr, err)
	}
	if err := ep.Connect(dstAddr); err != nil {
		t.Fatalf("ep.Connect(%+v): %s", dstAddr, err)
	}
	got, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("ep.GetLocalAddress(): %s", err)
	}
	return got.Addr
}

// TestAutoGenAddrDeprecateFromPI tests deprecating a SLAAC address when
// receiving a PI with 0 preferred lifetime.
func TestAutoGenAddrDeprecateFromPI(t *testing.T) {
	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp, e, s, _ := stackAndNdpDispatcherWithDefaultRoute(t, nicID)

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, addr); err != nil {
			t.Fatal(err)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive PI for prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 100))
	if _, err := expectAutoGenAddrNewEvent(ndpDisp, addr1); err != nil {
		t.Fatalf("error expecting prefix1 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	expectPrimaryAddr(addr1)

	// Deprecate addr for prefix1 immedaitely.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 0))
	expectAutoGenAddrEvent(t, ndpDisp, addr1, deprecatedAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	// addr should still be the primary endpoint as there are no other addresses.
	expectPrimaryAddr(addr1)

	// Refresh lifetimes of addr generated from prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 100))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)

	// Receive PI for prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 100))
	if _, err := expectAutoGenAddrNewEvent(ndpDisp, addr2); err != nil {
		t.Fatalf("error expecting prefix2 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Deprecate addr for prefix2 immedaitely.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	expectAutoGenAddrEvent(t, ndpDisp, addr2, deprecatedAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr1 should be the primary endpoint now since addr2 is deprecated but
	// addr1 is not.
	expectPrimaryAddr(addr1)
	// addr2 is deprecated but if explicitly requested, it should be used.
	fullAddr2 := tcpip.FullAddress{Addr: addr2.Address, NIC: nicID}
	if got := addrForNewConnectionWithAddr(t, s, fullAddr2); got != addr2.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", fullAddr2, got, addr2.Address)
	}

	// Another PI w/ 0 preferred lifetime should not result in a deprecation
	// event.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr2); got != addr2.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", fullAddr2, got, addr2.Address)
	}

	// Refresh lifetimes of addr generated from prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 100))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr2)
}

// TestAutoGenAddrJobDeprecation tests that an address is properly deprecated
// when its preferred lifetime expires.
func TestAutoGenAddrJobDeprecation(t *testing.T) {
	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp, e, s, clock := stackAndNdpDispatcherWithDefaultRoute(t, nicID)

	expectAutoGenAddrEventAfter := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType, timeout time.Duration) {
		t.Helper()

		clock.Advance(timeout)
		expectAutoGenAddrEvent(t, ndpDisp, addr, eventType)
	}

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, addr); err != nil {
			t.Fatal(err)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive PI for prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, infiniteLifetimeSeconds, infiniteLifetimeSeconds))
	if _, err := expectAutoGenAddrNewEvent(ndpDisp, addr2); err != nil {
		t.Fatalf("error expecting prefix2 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Receive a PI for prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 90))
	if _, err := expectAutoGenAddrNewEvent(ndpDisp, addr1); err != nil {
		t.Fatalf("error expecting prefix1 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr1)

	// Refresh lifetime for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, minVLSeconds, minVLSeconds-1))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)

	// Wait for addr of prefix1 to be deprecated.
	expectAutoGenAddrEventAfter(addr1, deprecatedAddr, ipv6.MinPrefixInformationValidLifetimeForUpdate-time.Second)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr2 should be the primary endpoint now since addr1 is deprecated but
	// addr2 is not.
	expectPrimaryAddr(addr2)

	// addr1 is deprecated but if explicitly requested, it should be used.
	fullAddr1 := tcpip.FullAddress{Addr: addr1.Address, NIC: nicID}
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", fullAddr1, got, addr1.Address)
	}

	// Refresh valid lifetime for addr of prefix1, w/ 0 preferred lifetime to make
	// sure we do not get a deprecation event again.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, minVLSeconds, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr2)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", fullAddr1, got, addr1.Address)
	}

	// Refresh lifetimes for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, minVLSeconds, minVLSeconds-1))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	// addr1 is the primary endpoint again since it is non-deprecated now.
	expectPrimaryAddr(addr1)

	// Wait for addr of prefix1 to be deprecated.
	expectAutoGenAddrEventAfter(addr1, deprecatedAddr, ipv6.MinPrefixInformationValidLifetimeForUpdate-time.Second)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr2 should be the primary endpoint now since it is not deprecated.
	expectPrimaryAddr(addr2)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", fullAddr1, got, addr1.Address)
	}

	// Wait for addr of prefix1 to be invalidated.
	expectAutoGenAddrEventAfter(addr1, invalidatedAddr, time.Second)
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Refresh both lifetimes for addr of prefix2 to the same value.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, minVLSeconds, minVLSeconds))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}

	// Wait for a deprecation then invalidation events, or just an invalidation
	// event. We need to cover both cases but cannot deterministically hit both
	// cases because the deprecation and invalidation handlers could be handled in
	// either deprecation then invalidation, or invalidation then deprecation
	// (which should be cancelled by the invalidation handler).
	//
	// Since we're about to cause both events to fire, we need the dispatcher
	// channel to be able to hold both.
	if got, want := len(ndpDisp.autoGenAddrC), 0; got != want {
		t.Fatalf("got len(ndpDisp.autoGenAddrC) = %d, want %d", got, want)
	}
	if got, want := cap(ndpDisp.autoGenAddrC), 1; got != want {
		t.Fatalf("got cap(ndpDisp.autoGenAddrC) = %d, want %d", got, want)
	}
	ndpDisp.autoGenAddrC = make(chan ndpAutoGenAddrEvent, 2)
	clock.Advance(ipv6.MinPrefixInformationValidLifetimeForUpdate)
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr2, deprecatedAddr); diff == "" {
			// If we get a deprecation event first, we should get an invalidation
			// event almost immediately after.
			select {
			case e := <-ndpDisp.autoGenAddrC:
				if diff := checkAutoGenAddrEvent(e, addr2, invalidatedAddr); diff != "" {
					t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("timed out waiting for addr auto gen event")
			}
		} else if diff := checkAutoGenAddrEvent(e, addr2, invalidatedAddr); diff == "" {
			// If we get an invalidation event first, we should not get a deprecation
			// event after.
			select {
			case <-ndpDisp.autoGenAddrC:
				t.Fatal("unexpectedly got an auto-generated event")
			default:
			}
		} else {
			t.Fatalf("got unexpected auto-generated event")
		}
	default:
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should not have %s in the list of addresses", addr2)
	}
	// Should not have any primary endpoints.
	if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, tcpip.AddressWithPrefix{}); err != nil {
		t.Fatal(err)
	}
	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	ep.SocketOptions().SetV6Only(true)

	{
		err := ep.Connect(dstAddr)
		if _, ok := err.(*tcpip.ErrHostUnreachable); !ok {
			t.Errorf("got ep.Connect(%+v) = %s, want = %s", dstAddr, err, &tcpip.ErrHostUnreachable{})
		}
	}
}

// Tests transitioning a SLAAC address's valid lifetime between finite and
// infinite values.
func TestAutoGenAddrFiniteToInfiniteToFiniteVL(t *testing.T) {
	const infiniteVLSeconds = math.MaxUint32

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
		Clock: clock,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA with finite prefix.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, 0))
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	if err := addrDisp.expectChanged(addressLifetimes(clock.NowMonotonic(), 0, minVLSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}

	// Receive an new RA with prefix with infinite VL.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, infiniteVLSeconds, 0))
	if err := addrDisp.expectLifetimesChanged(addressLifetimes(clock.NowMonotonic(), 0, infiniteVLSeconds)); err != nil {
		t.Error(err)
	}

	// Receive a new RA with prefix with finite VL.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, 0))
	if err := addrDisp.expectLifetimesChanged(addressLifetimes(clock.NowMonotonic(), 0, minVLSeconds)); err != nil {
		t.Error(err)
	}

	clock.Advance(ipv6.MinPrefixInformationValidLifetimeForUpdate)
	expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)
	if err := addrDisp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
		t.Error(err)
	}
}

// TestAutoGenAddrValidLifetimeUpdates tests that the valid lifetime of an
// auto-generated address only gets updated when required to, as specified in
// RFC 4862 section 5.5.3.e.
func TestAutoGenAddrValidLifetimeUpdates(t *testing.T) {
	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	tests := []struct {
		name string
		ovl  uint32
		nvl  uint32
		evl  uint32
	}{
		// Should update the VL to the minimum VL for updating if the
		// new VL is less than minVLSeconds but was originally greater than
		// it.
		{
			"LargeVLToVLLessThanMinVLForUpdate",
			9999,
			1,
			minVLSeconds,
		},
		{
			"LargeVLTo0",
			9999,
			0,
			minVLSeconds,
		},
		{
			"InfiniteVLToVLLessThanMinVLForUpdate",
			infiniteVLSeconds,
			1,
			minVLSeconds,
		},
		{
			"InfiniteVLTo0",
			infiniteVLSeconds,
			0,
			minVLSeconds,
		},

		// Should not update VL if original VL was less than minVLSeconds
		// and the new VL is also less than minVLSeconds.
		{
			"ShouldNotUpdateWhenBothOldAndNewAreLessThanMinVLForUpdate",
			minVLSeconds - 1,
			minVLSeconds - 3,
			minVLSeconds - 1,
		},

		// Should take the new VL if the new VL is greater than the
		// remaining time or is greater than minVLSeconds.
		{
			"MorethanMinVLToLesserButStillMoreThanMinVLForUpdate",
			minVLSeconds + 5,
			minVLSeconds + 3,
			minVLSeconds + 3,
		},
		{
			"SmallVLToGreaterVLButStillLessThanMinVLForUpdate",
			minVLSeconds - 3,
			minVLSeconds - 1,
			minVLSeconds - 1,
		},
		{
			"SmallVLToGreaterVLThatIsMoreThaMinVLForUpdate",
			minVLSeconds - 3,
			minVLSeconds + 1,
			minVLSeconds + 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const autoGenAddrCount = 10
			ndpDisp := ndpDispatcher{
				autoGenInstallDisp: true,
				autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
				autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
			}
			e := channel.New(10, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
						AutoGenGlobalAddresses: true,
					},
					NDPDisp: &ndpDisp,
				})},
				Clock: clock,
			})

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Receive an RA with prefix with initial VL,
			// test.ovl.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.ovl, 0))
			addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
			if err != nil {
				t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
			}
			if err := addrDisp.expectChanged(addressLifetimes(clock.NowMonotonic(), 0, test.ovl), stack.AddressAssigned); err != nil {
				t.Error(err)
			}

			// Receive an new RA with prefix with new VL,
			// test.nvl.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.nvl, 0))
			if test.evl != test.ovl {
				if err := addrDisp.expectValidUntilChanged(clock.NowMonotonic().Add(time.Duration(test.evl) * time.Second)); err != nil {
					t.Error(err)
				}
			}

			//
			// Validate that the VL for the address got set
			// to test.evl.
			//

			// The address should not be invalidated until the effective valid
			// lifetime has passed.
			const delta = 1
			clock.Advance(time.Duration(test.evl)*time.Second - delta)
			select {
			case <-ndpDisp.autoGenAddrC:
				t.Fatal("unexpectedly received an auto gen addr event")
			default:
			}
			if err := addrDisp.expectNoEvent(); err != nil {
				t.Error(err)
			}

			// Wait for the invalidation event.
			clock.Advance(delta)
			select {
			case e := <-ndpDisp.autoGenAddrC:
				if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
					t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("timeout waiting for addr auto gen event")
			}
			if err := addrDisp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestAutoGenAddrRemoval tests that when auto-generated addresses are removed
// by the user, its resources will be cleaned up and an invalidation event will
// be sent to the integrator.
func TestAutoGenAddrRemoval(t *testing.T) {
	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
		Clock: clock,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive a PI to auto-generate an address.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, 0))
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	if err := addrDisp.expectChanged(addressLifetimes(clock.NowMonotonic(), 0, lifetimeSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}

	// Removing the address should result in an invalidation event
	// immediately.
	if err := s.RemoveAddress(1, addr.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr.Address, err)
	}
	expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)
	if err := addrDisp.expectRemoved(stack.AddressRemovalManualAction); err != nil {
		t.Error(err)
	}

	// Wait for the original valid lifetime to make sure the original job got
	// cancelled/cleaned up.
	clock.Advance(lifetimeSeconds * time.Second)
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event")
	default:
	}
	if err := addrDisp.expectNoEvent(); err != nil {
		t.Error(err)
	}
}

// TestAutoGenAddrAfterRemoval tests adding a SLAAC address that was previously
// assigned to the NIC but is in the permanentExpired state.
func TestAutoGenAddrAfterRemoval(t *testing.T) {
	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)
	ndpDisp, e, s, clock := stackAndNdpDispatcherWithDefaultRoute(t, nicID)
	ndpDisp.autoGenInstallDisp = true

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if err := checkGetMainNICAddress(s, nicID, header.IPv6ProtocolNumber, addr); err != nil {
			t.Fatal(err)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive a PI to auto-generate addr1 with a large valid and preferred
	// lifetime.
	const largeLifetimeSeconds = 999
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix1, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	if addrDisp, err := expectAutoGenAddrNewEvent(ndpDisp, addr1); err != nil {
		t.Fatalf("error expecting prefix1 stable auto-gen address generated event: %s", err)
	} else {
		addrDisp.disable()
	}
	expectPrimaryAddr(addr1)

	// Add addr2 as a static address.
	protoAddr2 := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addr2,
	}
	properties := stack.AddressProperties{PEB: stack.FirstPrimaryEndpoint}
	if err := s.AddProtocolAddress(nicID, protoAddr2, properties); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, %+v) = %s", nicID, protoAddr2, properties, err)
	}
	// addr2 should be more preferred now since it is at the front of the primary
	// list.
	expectPrimaryAddr(addr2)

	// Get a route using addr2 to increment its reference count then remove it
	// to leave it in the permanentExpired state.
	if r, err := s.FindRoute(nicID, addr2.Address, addr3, header.IPv6ProtocolNumber, false); err != nil {
		t.Fatalf("FindRoute(%d, %s, %s, %d, false): %s", nicID, addr2.Address, addr3, header.IPv6ProtocolNumber, err)
	} else {
		defer r.Release()
	}
	if err := s.RemoveAddress(nicID, addr2.Address); err != nil {
		t.Fatalf("s.RemoveAddress(%d, %s): %s", nicID, addr2.Address, err)
	}
	// addr1 should be preferred again since addr2 is in the expired state.
	expectPrimaryAddr(addr1)

	// Receive a PI to auto-generate addr2 as valid and preferred.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	addr2Disp, err := expectAutoGenAddrNewEvent(ndpDisp, addr2)
	if err != nil {
		t.Fatalf("error expecting prefix2 stable auto-gen address generated event: %s", err)
	}
	if err := addr2Disp.expectChanged(addressLifetimes(clock.NowMonotonic(), largeLifetimeSeconds, largeLifetimeSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	// addr2 should be more preferred now that it is closer to the front of the
	// primary list and not deprecated.
	expectPrimaryAddr(addr2)

	// Removing the address should result in an invalidation event immediately.
	// It should still be in the permanentExpired state because r is still held.
	//
	// We remove addr2 here to make sure addr2 was marked as a SLAAC address
	// (it was previously marked as a static address).
	if err := s.RemoveAddress(1, addr2.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr2.Address, err)
	}
	expectAutoGenAddrEvent(t, ndpDisp, addr2, invalidatedAddr)
	if err := addr2Disp.expectRemoved(stack.AddressRemovalManualAction); err != nil {
		t.Error(err)
	}
	// addr1 should be more preferred since addr2 is in the expired state.
	expectPrimaryAddr(addr1)

	// Receive a PI to auto-generate addr2 as valid and deprecated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, 0))
	addr2Disp, err = expectAutoGenAddrNewEvent(ndpDisp, addr2)
	if err != nil {
		t.Fatalf("error expecting prefix2 stable auto-gen address generated event after removing address and new PI: %s", err)
	}
	if err := addr2Disp.expectChanged(addressLifetimes(clock.NowMonotonic(), 0, largeLifetimeSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	// addr1 should still be more preferred since addr2 is deprecated, even though
	// it is closer to the front of the primary list.
	expectPrimaryAddr(addr1)

	// Receive a PI to refresh addr2's preferred lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto gen addr event")
	default:
	}
	if err := addr2Disp.expectChanged(addressLifetimes(clock.NowMonotonic(), largeLifetimeSeconds, largeLifetimeSeconds), stack.AddressAssigned); err != nil {
		t.Error(err)
	}
	// addr2 should be more preferred now that it is not deprecated.
	expectPrimaryAddr(addr2)

	if err := s.RemoveAddress(1, addr2.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr2.Address, err)
	}
	expectAutoGenAddrEvent(t, ndpDisp, addr2, invalidatedAddr)
	if err := addr2Disp.expectRemoved(stack.AddressRemovalManualAction); err != nil {
		t.Error(err)
	}
	expectPrimaryAddr(addr1)
}

// TestAutoGenAddrStaticConflict tests that if SLAAC generates an address that
// is already assigned to the NIC, the static address remains.
func TestAutoGenAddrStaticConflict(t *testing.T) {
	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
		Clock: clock,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Add the address as a static address before SLAAC tries to add it.
	protocolAddr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: addr}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(1, %+v, {}) = %s", protocolAddr, err)
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
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
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Should not get an invalidation event after the PI's invalidation
	// time.
	clock.Advance(lifetimeSeconds * time.Second)
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event")
	default:
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}
}

func makeSecretKey(t *testing.T) []byte {
	secretKey := make([]byte, header.OpaqueIIDSecretKeyMinBytes)
	n, err := cryptorand.Read(secretKey)
	if err != nil {
		t.Fatalf("cryptorand.Read(_): %s", err)
	}
	if l := len(secretKey); n != l {
		t.Fatalf("got cryptorand.Read(_) = (%d, nil), want = (%d, nil)", n, l)
	}
	return secretKey
}

// TestAutoGenAddrWithOpaqueIID tests that SLAAC generated addresses will use
// opaque interface identifiers when configured to do so.
func TestAutoGenAddrWithOpaqueIID(t *testing.T) {
	const nicID = 1
	const nicName = "nic1"

	secretKey := makeSecretKey(t)

	prefix1, subnet1, _ := prefixSubnetAddr(0, linkAddr1)
	prefix2, subnet2, _ := prefixSubnetAddr(1, linkAddr1)
	// addr1 and addr2 are the addresses that are expected to be generated when
	// stack.Stack is configured to generate opaque interface identifiers as
	// defined by RFC 7217.
	addrBytes := []byte(subnet1.ID())
	addr1 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet1, nicName, 0, secretKey)),
		PrefixLen: 64,
	}
	addrBytes = []byte(subnet2.ID())
	addr2 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet2, nicName, 0, secretKey)),
		PrefixLen: 64,
	}

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
			OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: func(_ tcpip.NICID, nicName string) string {
					return nicName
				},
				SecretKey: secretKey,
			},
		})},
		Clock: clock,
	})
	opts := stack.NICOptions{Name: nicName}
	if err := s.CreateNICWithOptions(nicID, e, opts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %+v, _) = %s", nicID, opts, err)
	}

	// Receive an RA with prefix1 in a PI.
	const validLifetimeSecondPrefix1 = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, validLifetimeSecondPrefix1, 0))
	if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr1); err != nil {
		t.Fatalf("error expecting prefix1 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}

	// Receive an RA with prefix2 in a PI with a large valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr2); err != nil {
		t.Fatalf("error expecting prefix2 stable auto-gen address generated event: %s", err)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}

	// Wait for addr of prefix1 to be invalidated.
	clock.Advance(validLifetimeSecondPrefix1 * time.Second)
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr1, invalidatedAddr); diff != "" {
			t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
}

func TestAutoGenAddrInResponseToDADConflicts(t *testing.T) {
	const nicID = 1
	const nicName = "nic"
	const dadTransmits = 1
	const retransmitTimer = time.Second
	const maxMaxRetries = 3
	const lifetimeSeconds = 10

	secretKey := makeSecretKey(t)

	prefix, subnet, _ := prefixSubnetAddr(0, linkAddr1)

	addrForSubnet := func(subnet tcpip.Subnet, dadCounter uint8) tcpip.AddressWithPrefix {
		addrBytes := []byte(subnet.ID())
		return tcpip.AddressWithPrefix{
			Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet, nicName, dadCounter, secretKey)),
			PrefixLen: 64,
		}
	}

	expectDADEvent := func(t *testing.T, clock *faketime.ManualClock, ndpDisp *ndpDispatcher, addr tcpip.Address, res stack.DADResult) {
		t.Helper()

		clock.RunImmediatelyScheduledJobs()
		select {
		case e := <-ndpDisp.dadC:
			if diff := checkDADEvent(e, nicID, addr, res); diff != "" {
				t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected DAD event")
		}
	}

	expectDADEventAsync := func(t *testing.T, clock *faketime.ManualClock, ndpDisp *ndpDispatcher, addr tcpip.Address, res stack.DADResult) {
		t.Helper()

		clock.Advance(dadTransmits * retransmitTimer)
		select {
		case e := <-ndpDisp.dadC:
			if diff := checkDADEvent(e, nicID, addr, res); diff != "" {
				t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("timed out waiting for DAD event")
		}
	}

	stableAddrForTempAddrTest := addrForSubnet(subnet, 0)

	addrTypes := []struct {
		name             string
		ndpConfigs       ipv6.NDPConfigurations
		autoGenLinkLocal bool
		prepareFn        func(t *testing.T, clock *faketime.ManualClock, ndpDisp *ndpDispatcher, e *channel.Endpoint, tempIIDHistory []byte) []tcpip.AddressWithPrefix
		addrGenFn        func(dadCounter uint8, tempIIDHistory []byte) tcpip.AddressWithPrefix
	}{
		{
			name: "Global address",
			ndpConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses: true,
			},
			prepareFn: func(_ *testing.T, _ *faketime.ManualClock, _ *ndpDispatcher, e *channel.Endpoint, _ []byte) []tcpip.AddressWithPrefix {
				// Receive an RA with prefix1 in a PI.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, lifetimeSeconds))
				return nil

			},
			addrGenFn: func(dadCounter uint8, _ []byte) tcpip.AddressWithPrefix {
				return addrForSubnet(subnet, dadCounter)
			},
		},
		{
			name:             "LinkLocal address",
			ndpConfigs:       ipv6.NDPConfigurations{},
			autoGenLinkLocal: true,
			prepareFn: func(*testing.T, *faketime.ManualClock, *ndpDispatcher, *channel.Endpoint, []byte) []tcpip.AddressWithPrefix {
				return nil
			},
			addrGenFn: func(dadCounter uint8, _ []byte) tcpip.AddressWithPrefix {
				return addrForSubnet(header.IPv6LinkLocalPrefix.Subnet(), dadCounter)
			},
		},
		{
			name: "Temporary address",
			ndpConfigs: ipv6.NDPConfigurations{
				HandleRAs:                  ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses:     true,
				AutoGenTempGlobalAddresses: true,
			},
			prepareFn: func(t *testing.T, clock *faketime.ManualClock, ndpDisp *ndpDispatcher, e *channel.Endpoint, tempIIDHistory []byte) []tcpip.AddressWithPrefix {
				header.InitialTempIID(tempIIDHistory, nil, nicID)

				// Generate a stable SLAAC address so temporary addresses will be
				// generated.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, 100, 100))
				if _, err := expectAutoGenAddrNewEvent(ndpDisp, stableAddrForTempAddrTest); err != nil {
					t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
				}
				expectDADEventAsync(t, clock, ndpDisp, stableAddrForTempAddrTest.Address, &stack.DADSucceeded{})

				// The stable address will be assigned throughout the test.
				return []tcpip.AddressWithPrefix{stableAddrForTempAddrTest}
			},
			addrGenFn: func(_ uint8, tempIIDHistory []byte) tcpip.AddressWithPrefix {
				return header.GenerateTempIPv6SLAACAddr(tempIIDHistory, stableAddrForTempAddrTest.Address)
			},
		},
	}

	for _, addrType := range addrTypes {
		t.Run(addrType.name, func(t *testing.T) {
			for maxRetries := uint8(0); maxRetries <= maxMaxRetries; maxRetries++ {
				for numFailures := uint8(0); numFailures <= maxRetries+1; numFailures++ {
					maxRetries := maxRetries
					numFailures := numFailures
					addrType := addrType

					t.Run(fmt.Sprintf("%d max retries and %d failures", maxRetries, numFailures), func(t *testing.T) {
						const autoGenAddrCount = 2
						ndpDisp := ndpDispatcher{
							dadC:            make(chan ndpDADEvent, 1),
							autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
							autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
						}
						e := channel.New(0, 1280, linkAddr1)
						ndpConfigs := addrType.ndpConfigs
						ndpConfigs.AutoGenAddressConflictRetries = maxRetries
						clock := faketime.NewManualClock()
						s := stack.New(stack.Options{
							NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
								AutoGenLinkLocal: addrType.autoGenLinkLocal,
								DADConfigs: stack.DADConfigurations{
									DupAddrDetectTransmits: dadTransmits,
									RetransmitTimer:        retransmitTimer,
								},
								NDPConfigs: ndpConfigs,
								NDPDisp:    &ndpDisp,
								OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
									NICNameFromID: func(_ tcpip.NICID, nicName string) string {
										return nicName
									},
									SecretKey: secretKey,
								},
							})},
							Clock: clock,
						})
						opts := stack.NICOptions{Name: nicName}
						if err := s.CreateNICWithOptions(nicID, e, opts); err != nil {
							t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, opts, err)
						}

						var tempIIDHistory [header.IIDSize]byte
						stableAddrs := addrType.prepareFn(t, clock, &ndpDisp, e, tempIIDHistory[:])

						// Simulate DAD conflicts so the address is regenerated.
						for i := uint8(0); i < numFailures; i++ {
							addr := addrType.addrGenFn(i, tempIIDHistory[:])
							clock.RunImmediatelyScheduledJobs()
							if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr); err != nil {
								t.Fatalf("error expecting auto-gen address generated event after %d failure(s): %s", i, err)
							}

							// Should not have any new addresses assigned to the NIC.
							if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, stableAddrs, nil); mismatch != "" {
								t.Fatal(mismatch)
							}

							// Simulate a DAD conflict.
							rxNDPSolicit(e, addr.Address)
							expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)
							expectDADEvent(t, clock, &ndpDisp, addr.Address, &stack.DADDupAddrDetected{})

							// Attempting to add the address manually should not fail if the
							// address's state was cleaned up when DAD failed.
							protocolAddr := tcpip.ProtocolAddress{
								Protocol:          header.IPv6ProtocolNumber,
								AddressWithPrefix: addr,
							}
							if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
								t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
							}
							if err := s.RemoveAddress(nicID, addr.Address); err != nil {
								t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr.Address, err)
							}
							expectDADEvent(t, clock, &ndpDisp, addr.Address, &stack.DADAborted{})
						}

						// Should not have any new addresses assigned to the NIC.
						if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, stableAddrs, nil); mismatch != "" {
							t.Fatal(mismatch)
						}

						// If we had less failures than generation attempts, we should have
						// an address after DAD resolves.
						if maxRetries+1 > numFailures {
							addr := addrType.addrGenFn(numFailures, tempIIDHistory[:])
							clock.RunImmediatelyScheduledJobs()
							if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr); err != nil {
								t.Fatalf("error expecting final auto-gen address generated event: %s", err)
							}
							expectDADEventAsync(t, clock, &ndpDisp, addr.Address, &stack.DADSucceeded{})
							if mismatch := addressCheck(s.NICInfo()[nicID].ProtocolAddresses, append(stableAddrs, addr), nil); mismatch != "" {
								t.Fatal(mismatch)
							}
						}

						// Should not attempt address generation again.
						select {
						case e := <-ndpDisp.autoGenAddrC:
							t.Fatalf("unexpectedly got an auto-generated address event = %+v", e)
						default:
						}
					})
				}
			}
		})
	}
}

// TestAutoGenAddrWithEUI64IIDNoDADRetries tests that a regeneration attempt is
// not made for SLAAC addresses generated with an IID based on the NIC's link
// address.
func TestAutoGenAddrWithEUI64IIDNoDADRetries(t *testing.T) {
	const nicID = 1
	const dadTransmits = 1
	const retransmitTimer = time.Second
	const maxRetries = 3
	const lifetimeSeconds = 10

	prefix, subnet, _ := prefixSubnetAddr(0, linkAddr1)

	addrTypes := []struct {
		name             string
		ndpConfigs       ipv6.NDPConfigurations
		autoGenLinkLocal bool
		subnet           tcpip.Subnet
		triggerSLAACFn   func(e *channel.Endpoint)
	}{
		{
			name: "Global address",
			ndpConfigs: ipv6.NDPConfigurations{
				HandleRAs:                     ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses:        true,
				AutoGenAddressConflictRetries: maxRetries,
			},
			subnet: subnet,
			triggerSLAACFn: func(e *channel.Endpoint) {
				// Receive an RA with prefix1 in a PI.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, lifetimeSeconds))

			},
		},
		{
			name: "LinkLocal address",
			ndpConfigs: ipv6.NDPConfigurations{
				AutoGenAddressConflictRetries: maxRetries,
			},
			autoGenLinkLocal: true,
			subnet:           header.IPv6LinkLocalPrefix.Subnet(),
			triggerSLAACFn:   func(e *channel.Endpoint) {},
		},
	}

	for _, addrType := range addrTypes {
		addrType := addrType

		t.Run(addrType.name, func(t *testing.T) {
			const autoGenAddrCount = 2
			ndpDisp := ndpDispatcher{
				dadC:            make(chan ndpDADEvent, 1),
				autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
				autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
			}
			e := channel.New(0, 1280, linkAddr1)
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					AutoGenLinkLocal: addrType.autoGenLinkLocal,
					NDPConfigs:       addrType.ndpConfigs,
					NDPDisp:          &ndpDisp,
					DADConfigs: stack.DADConfigurations{
						DupAddrDetectTransmits: dadTransmits,
						RetransmitTimer:        retransmitTimer,
					},
				})},
				Clock: clock,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			addrType.triggerSLAACFn(e)

			addrBytes := []byte(addrType.subnet.ID())
			header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr1, addrBytes[header.IIDOffsetInIPv6Address:])
			addr := tcpip.AddressWithPrefix{
				Address:   tcpip.Address(addrBytes),
				PrefixLen: 64,
			}
			if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr); err != nil {
				t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
			}

			// Simulate a DAD conflict.
			rxNDPSolicit(e, addr.Address)
			expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)
			select {
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr.Address, &stack.DADDupAddrDetected{}); diff != "" {
					t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected DAD event")
			}

			// Should not attempt address regeneration.
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Fatalf("unexpectedly got an auto-generated address event = %+v", e)
			default:
			}
		})
	}
}

// TestAutoGenAddrContinuesLifetimesAfterRetry tests that retrying address
// generation in response to DAD conflicts does not refresh the lifetimes.
func TestAutoGenAddrContinuesLifetimesAfterRetry(t *testing.T) {
	const nicID = 1
	const nicName = "nic"
	const dadTransmits = 1
	const retransmitTimer = 2 * time.Second
	const failureTimer = time.Second
	const maxRetries = 1
	const lifetimeSeconds = 5

	secretKey := makeSecretKey(t)

	prefix, subnet, _ := prefixSubnetAddr(0, linkAddr1)

	const autoGenAddrCount = 2
	ndpDisp := ndpDispatcher{
		dadC:               make(chan ndpDADEvent, 1),
		autoGenAddrNewC:    make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
		autoGenAddrC:       make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenInstallDisp: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			DADConfigs: stack.DADConfigurations{
				DupAddrDetectTransmits: dadTransmits,
				RetransmitTimer:        retransmitTimer,
			},
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:                     ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				AutoGenGlobalAddresses:        true,
				AutoGenAddressConflictRetries: maxRetries,
			},
			NDPDisp: &ndpDisp,
			OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: func(_ tcpip.NICID, nicName string) string {
					return nicName
				},
				SecretKey: secretKey,
			},
		})},
		Clock: clock,
	})
	opts := stack.NICOptions{Name: nicName}
	if err := s.CreateNICWithOptions(nicID, e, opts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, opts, err)
	}

	// Receive an RA with prefix in a PI.
	received := clock.NowMonotonic()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, lifetimeSeconds))

	addrBytes := []byte(subnet.ID())
	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet, nicName, 0, secretKey)),
		PrefixLen: 64,
	}
	addrDisp, err := expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address (DAD will not resolve) generated event: %s", err)
	}
	if err := addrDisp.expectChanged(addressLifetimes(received, lifetimeSeconds, lifetimeSeconds), stack.AddressTentative); err != nil {
		t.Error(err)
	}

	// Simulate a DAD conflict after some time has passed.
	clock.Advance(failureTimer)
	rxNDPSolicit(e, addr.Address)
	expectAutoGenAddrEvent(t, &ndpDisp, addr, invalidatedAddr)
	if err := addrDisp.expectRemoved(stack.AddressRemovalDADFailed); err != nil {
		t.Error(err)
	}
	select {
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr.Address, &stack.DADDupAddrDetected{}); diff != "" {
			t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected DAD event")
	}

	// Let the next address resolve.
	addr.Address = tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet, nicName, 1, secretKey))
	addrDisp, err = expectAutoGenAddrNewEvent(&ndpDisp, addr)
	if err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}
	if err := addrDisp.expectChanged(addressLifetimes(received, lifetimeSeconds, lifetimeSeconds), stack.AddressTentative); err != nil {
		t.Error(err)
	}
	clock.Advance(dadTransmits * retransmitTimer)
	select {
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr.Address, &stack.DADSucceeded{}); diff != "" {
			t.Errorf("DAD event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("timed out waiting for DAD event")
	}
	if err := addrDisp.expectStateChanged(stack.AddressAssigned); err != nil {
		t.Error(err)
	}

	// Address should be deprecated/invalidated after the lifetime expires.
	//
	// Note, the remaining lifetime is calculated from when the PI was first
	// processed. Since we wait for some time before simulating a DAD conflict
	// and more time for the new address to resolve, the new address is only
	// expected to be valid for the remaining time. The DAD conflict should
	// not have reset the lifetimes.
	//
	// We expect either just the invalidation event or the deprecation event
	// followed by the invalidation event.
	clock.Advance(lifetimeSeconds*time.Second - failureTimer - dadTransmits*retransmitTimer)
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if e.eventType == deprecatedAddr {
			if diff := checkAutoGenAddrEvent(e, addr, deprecatedAddr); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}

			select {
			case e := <-ndpDisp.autoGenAddrC:
				if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
					t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("timed out waiting for invalidated auto gen addr event after deprecation")
			}
		} else {
			if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		}
	default:
		t.Fatal("timed out waiting for auto gen addr event")
	}
	if err := addrDisp.expectRemoved(stack.AddressRemovalInvalidated); err != nil {
		t.Error(err)
	}
}

// TestNDPRecursiveDNSServerDispatch tests that we properly dispatch an event
// to the integrator when an RA is received with the NDP Recursive DNS Server
// option with at least one valid address.
func TestNDPRecursiveDNSServerDispatch(t *testing.T) {
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
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				// We do not expect more than a single RDNSS
				// event at any time for this test.
				rdnssC: make(chan ndpRDNSSEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs: ipv6.HandlingRAsEnabledWhenForwardingDisabled,
					},
					NDPDisp: &ndpDisp,
				})},
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

// TestNDPDNSSearchListDispatch tests that the integrator is informed when an
// NDP DNS Search List option is received with at least one domain name in the
// search list.
func TestNDPDNSSearchListDispatch(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dnsslC: make(chan ndpDNSSLEvent, 3),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs: ipv6.HandlingRAsEnabledWhenForwardingDisabled,
			},
			NDPDisp: &ndpDisp,
		})},
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	optSer := header.NDPOptionsSerializer{
		header.NDPDNSSearchList([]byte{
			0, 0,
			0, 0, 0, 0,
			2, 'h', 'i',
			0,
		}),
		header.NDPDNSSearchList([]byte{
			0, 0,
			0, 0, 0, 1,
			1, 'i',
			0,
			2, 'a', 'm',
			2, 'm', 'e',
			0,
		}),
		header.NDPDNSSearchList([]byte{
			0, 0,
			0, 0, 1, 0,
			3, 'x', 'y', 'z',
			0,
			5, 'h', 'e', 'l', 'l', 'o',
			5, 'w', 'o', 'r', 'l', 'd',
			0,
			4, 't', 'h', 'i', 's',
			2, 'i', 's',
			1, 'a',
			4, 't', 'e', 's', 't',
			0,
		}),
	}
	expected := []struct {
		domainNames []string
		lifetime    time.Duration
	}{
		{
			domainNames: []string{
				"hi",
			},
			lifetime: 0,
		},
		{
			domainNames: []string{
				"i",
				"am.me",
			},
			lifetime: time.Second,
		},
		{
			domainNames: []string{
				"xyz",
				"hello.world",
				"this.is.a.test",
			},
			lifetime: 256 * time.Second,
		},
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))

	for i, expected := range expected {
		select {
		case dnssl := <-ndpDisp.dnsslC:
			if dnssl.nicID != nicID {
				t.Errorf("got %d-th dnssl nicID = %d, want = %d", i, dnssl.nicID, nicID)
			}
			if diff := cmp.Diff(dnssl.domainNames, expected.domainNames); diff != "" {
				t.Errorf("%d-th dnssl domain names mismatch (-want +got):\n%s", i, diff)
			}
			if dnssl.lifetime != expected.lifetime {
				t.Errorf("got %d-th dnssl lifetime = %s, want = %s", i, dnssl.lifetime, expected.lifetime)
			}
		default:
			t.Fatal("expected a DNSSL event")
		}
	}

	// Should have no more DNSSL options.
	select {
	case <-ndpDisp.dnsslC:
		t.Fatal("unexpectedly got a DNSSL event")
	default:
	}
}

func TestNoCleanupNDPStateWhenForwardingEnabled(t *testing.T) {
	const (
		lifetimeSeconds = 999
		nicID           = 1
	)

	const autoGenAddrCount = 1
	ndpDisp := ndpDispatcher{
		offLinkRouteC:   make(chan ndpOffLinkRouteEvent, 1),
		prefixC:         make(chan ndpPrefixEvent, 1),
		autoGenAddrC:    make(chan ndpAutoGenAddrEvent, autoGenAddrCount),
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, autoGenAddrCount),
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			AutoGenLinkLocal: true,
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
				DiscoverDefaultRouters: true,
				DiscoverOnLinkPrefixes: true,
				AutoGenGlobalAddresses: true,
			},
			NDPDisp: &ndpDisp,
		})},
	})

	e1 := channel.New(0, header.IPv6MinimumMTU, linkAddr1)
	if err := s.CreateNIC(nicID, e1); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	llAddr := tcpip.AddressWithPrefix{Address: llAddr1, PrefixLen: header.IPv6LinkLocalPrefix.PrefixLen}
	if _, err := expectAutoGenAddrNewEvent(&ndpDisp, llAddr); err != nil {
		t.Fatalf("error expecting link-local auto-gen address generated event: %s", err)
	}

	prefix, subnet, addr := prefixSubnetAddr(0, linkAddr1)
	e1.InjectInbound(
		header.IPv6ProtocolNumber,
		raBufWithPI(
			llAddr3,
			lifetimeSeconds,
			prefix,
			true, /* onLink */
			true, /* auto */
			lifetimeSeconds,
			lifetimeSeconds,
		),
	)
	select {
	case e := <-ndpDisp.offLinkRouteC:
		if diff := checkOffLinkRouteEvent(e, nicID, header.IPv6EmptySubnet, llAddr3, header.MediumRoutePreference, true /* discovered */); diff != "" {
			t.Errorf("off-link route event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Errorf("expected off-link route event for %s on NIC(%d)", llAddr3, nicID)
	}
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, true /* discovered */); diff != "" {
			t.Errorf("off-link route event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Errorf("expected prefix event for %s on NIC(%d)", prefix, nicID)
	}
	if _, err := expectAutoGenAddrNewEvent(&ndpDisp, addr); err != nil {
		t.Fatalf("error expecting stable auto-gen address generated event: %s", err)
	}

	// Enabling or disabling forwarding should not invalidate discovered prefixes
	// or routers, or auto-generated address.
	for _, forwarding := range [...]bool{true, false} {
		t.Run(fmt.Sprintf("Transition forwarding to %t", forwarding), func(t *testing.T) {
			if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, forwarding); err != nil {
				t.Fatalf("SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv6.ProtocolNumber, forwarding, err)
			}
			select {
			case e := <-ndpDisp.offLinkRouteC:
				t.Errorf("unexpected off-link route event = %#v", e)
			default:
			}
			select {
			case e := <-ndpDisp.prefixC:
				t.Errorf("unexpected prefix event = %#v", e)
			default:
			}
			select {
			case e := <-ndpDisp.autoGenAddrC:
				t.Errorf("unexpected auto-gen addr event = %#v", e)
			default:
			}
			select {
			case e := <-ndpDisp.autoGenAddrNewC:
				t.Errorf("unexpected new auto-gen addr event = %#v", e)
			default:
			}
		})
	}
}

func TestCleanupNDPState(t *testing.T) {
	const (
		lifetimeSeconds          = 5
		maxRouterAndPrefixEvents = 4
		nicID1                   = 1
		nicID2                   = 2
	)

	prefix1, subnet1, e1Addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, subnet2, e1Addr2 := prefixSubnetAddr(1, linkAddr1)
	e2Addr1 := addrForSubnet(subnet1, linkAddr2)
	e2Addr2 := addrForSubnet(subnet2, linkAddr2)
	llAddrWithPrefix1 := tcpip.AddressWithPrefix{
		Address:   llAddr1,
		PrefixLen: 64,
	}
	llAddrWithPrefix2 := tcpip.AddressWithPrefix{
		Address:   llAddr2,
		PrefixLen: 64,
	}

	tests := []struct {
		name                 string
		cleanupFn            func(t *testing.T, s *stack.Stack)
		keepAutoGenLinkLocal bool
		maxAutoGenAddrEvents int
		skipFinalAddrCheck   bool
	}{
		// A NIC should cleanup all NDP state when it is disabled.
		{
			name: "Disable NIC",
			cleanupFn: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				if err := s.DisableNIC(nicID1); err != nil {
					t.Fatalf("s.DisableNIC(%d): %s", nicID1, err)
				}
				if err := s.DisableNIC(nicID2); err != nil {
					t.Fatalf("s.DisableNIC(%d): %s", nicID2, err)
				}
			},
			keepAutoGenLinkLocal: false,
			maxAutoGenAddrEvents: 6,
		},

		// A NIC should cleanup all NDP state when it is removed.
		{
			name: "Remove NIC",
			cleanupFn: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				if err := s.RemoveNIC(nicID1); err != nil {
					t.Fatalf("s.RemoveNIC(%d): %s", nicID1, err)
				}
				if err := s.RemoveNIC(nicID2); err != nil {
					t.Fatalf("s.RemoveNIC(%d): %s", nicID2, err)
				}
			},
			keepAutoGenLinkLocal: false,
			maxAutoGenAddrEvents: 6,
			// The NICs are removed so we can't check their addresses after calling
			// stopFn.
			skipFinalAddrCheck: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				offLinkRouteC:   make(chan ndpOffLinkRouteEvent, maxRouterAndPrefixEvents),
				prefixC:         make(chan ndpPrefixEvent, maxRouterAndPrefixEvents),
				autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, test.maxAutoGenAddrEvents),
				autoGenAddrC:    make(chan ndpAutoGenAddrEvent, test.maxAutoGenAddrEvents),
			}
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					AutoGenLinkLocal: true,
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs:              ipv6.HandlingRAsEnabledWhenForwardingDisabled,
						DiscoverDefaultRouters: true,
						DiscoverOnLinkPrefixes: true,
						AutoGenGlobalAddresses: true,
					},
					NDPDisp: &ndpDisp,
				})},
				Clock: clock,
			})

			expectOffLinkRouteEvent := func() (bool, ndpOffLinkRouteEvent) {
				select {
				case e := <-ndpDisp.offLinkRouteC:
					return true, e
				default:
				}

				return false, ndpOffLinkRouteEvent{}
			}

			expectPrefixEvent := func() (bool, ndpPrefixEvent) {
				select {
				case e := <-ndpDisp.prefixC:
					return true, e
				default:
				}

				return false, ndpPrefixEvent{}
			}

			expectAutoGenAddrEvent := func() (bool, ndpAutoGenAddrEvent) {
				select {
				case e := <-ndpDisp.autoGenAddrC:
					return true, e
				default:
				}

				return false, ndpAutoGenAddrEvent{}
			}

			expectAutoGenAddrNewEvent := func() (bool, ndpAutoGenAddrNewEvent) {
				select {
				case e := <-ndpDisp.autoGenAddrNewC:
					return true, e
				default:
				}
				return false, ndpAutoGenAddrNewEvent{}
			}

			e1 := channel.New(0, 1280, linkAddr1)
			if err := s.CreateNIC(nicID1, e1); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID1, err)
			}
			// We have other tests that make sure we receive the *correct* events
			// on normal discovery of routers/prefixes, and auto-generated
			// addresses. Here we just make sure we get an event and let other tests
			// handle the correctness check.
			expectAutoGenAddrNewEvent()

			e2 := channel.New(0, 1280, linkAddr2)
			if err := s.CreateNIC(nicID2, e2); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID2, err)
			}
			expectAutoGenAddrNewEvent()

			// Receive RAs on NIC(1) and NIC(2) from default routers (llAddr3 and
			// llAddr4) w/ PI (for prefix1 in RA from llAddr3 and prefix2 in RA from
			// llAddr4) to discover multiple routers and prefixes, and auto-gen
			// multiple addresses.

			e1.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, lifetimeSeconds, prefix1, true, true, lifetimeSeconds, lifetimeSeconds))
			if ok, _ := expectOffLinkRouteEvent(); !ok {
				t.Errorf("expected off-link route event for %s on NIC(%d)", llAddr3, nicID1)
			}
			if ok, _ := expectPrefixEvent(); !ok {
				t.Errorf("expected prefix event for %s on NIC(%d)", prefix1, nicID1)
			}
			if ok, _ := expectAutoGenAddrNewEvent(); !ok {
				t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr1, nicID1)
			}

			e1.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, lifetimeSeconds, prefix2, true, true, lifetimeSeconds, lifetimeSeconds))
			if ok, _ := expectOffLinkRouteEvent(); !ok {
				t.Errorf("expected off-link route event for %s on NIC(%d)", llAddr4, nicID1)
			}
			if ok, _ := expectPrefixEvent(); !ok {
				t.Errorf("expected prefix event for %s on NIC(%d)", prefix2, nicID1)
			}
			if ok, _ := expectAutoGenAddrNewEvent(); !ok {
				t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr2, nicID1)
			}

			e2.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, lifetimeSeconds, prefix1, true, true, lifetimeSeconds, lifetimeSeconds))
			if ok, _ := expectOffLinkRouteEvent(); !ok {
				t.Errorf("expected off-link route event for %s on NIC(%d)", llAddr3, nicID2)
			}
			if ok, _ := expectPrefixEvent(); !ok {
				t.Errorf("expected prefix event for %s on NIC(%d)", prefix1, nicID2)
			}
			if ok, _ := expectAutoGenAddrNewEvent(); !ok {
				t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr2, nicID2)
			}

			e2.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, lifetimeSeconds, prefix2, true, true, lifetimeSeconds, lifetimeSeconds))
			if ok, _ := expectOffLinkRouteEvent(); !ok {
				t.Errorf("expected off-link route event for %s on NIC(%d)", llAddr4, nicID2)
			}
			if ok, _ := expectPrefixEvent(); !ok {
				t.Errorf("expected prefix event for %s on NIC(%d)", prefix2, nicID2)
			}
			if ok, _ := expectAutoGenAddrNewEvent(); !ok {
				t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e2Addr2, nicID2)
			}

			// We should have the auto-generated addresses added.
			nicinfo := s.NICInfo()
			nic1Addrs := nicinfo[nicID1].ProtocolAddresses
			nic2Addrs := nicinfo[nicID2].ProtocolAddresses
			if !containsV6Addr(nic1Addrs, llAddrWithPrefix1) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix1, nicID1, nic1Addrs)
			}
			if !containsV6Addr(nic1Addrs, e1Addr1) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e1Addr1, nicID1, nic1Addrs)
			}
			if !containsV6Addr(nic1Addrs, e1Addr2) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e1Addr2, nicID1, nic1Addrs)
			}
			if !containsV6Addr(nic2Addrs, llAddrWithPrefix2) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix2, nicID2, nic2Addrs)
			}
			if !containsV6Addr(nic2Addrs, e2Addr1) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e2Addr1, nicID2, nic2Addrs)
			}
			if !containsV6Addr(nic2Addrs, e2Addr2) {
				t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e2Addr2, nicID2, nic2Addrs)
			}

			// We can't proceed any further if we already failed the test (missing
			// some discovery/auto-generated address events or addresses).
			if t.Failed() {
				t.FailNow()
			}

			test.cleanupFn(t, s)

			// Collect invalidation events after having NDP state cleaned up.
			gotOffLinkRouteEvents := make(map[ndpOffLinkRouteEvent]int)
			for i := 0; i < maxRouterAndPrefixEvents; i++ {
				ok, e := expectOffLinkRouteEvent()
				if !ok {
					t.Errorf("expected %d off-link route events after becoming a router; got = %d", maxRouterAndPrefixEvents, i)
					break
				}
				gotOffLinkRouteEvents[e]++
			}
			gotPrefixEvents := make(map[ndpPrefixEvent]int)
			for i := 0; i < maxRouterAndPrefixEvents; i++ {
				ok, e := expectPrefixEvent()
				if !ok {
					t.Errorf("expected %d prefix events after becoming a router; got = %d", maxRouterAndPrefixEvents, i)
					break
				}
				gotPrefixEvents[e]++
			}
			gotAutoGenAddrEvents := make(map[ndpAutoGenAddrEvent]int)
			for i := 0; i < test.maxAutoGenAddrEvents; i++ {
				ok, e := expectAutoGenAddrEvent()
				if !ok {
					t.Errorf("expected %d auto-generated address events after becoming a router; got = %d", test.maxAutoGenAddrEvents, i)
					break
				}
				gotAutoGenAddrEvents[e]++
			}

			// No need to proceed any further if we already failed the test (missing
			// some invalidation events).
			if t.Failed() {
				t.FailNow()
			}

			expectedOffLinkRouteEvents := map[ndpOffLinkRouteEvent]int{
				{nicID: nicID1, subnet: header.IPv6EmptySubnet, router: llAddr3, updated: false}: 1,
				{nicID: nicID1, subnet: header.IPv6EmptySubnet, router: llAddr4, updated: false}: 1,
				{nicID: nicID2, subnet: header.IPv6EmptySubnet, router: llAddr3, updated: false}: 1,
				{nicID: nicID2, subnet: header.IPv6EmptySubnet, router: llAddr4, updated: false}: 1,
			}
			if diff := cmp.Diff(expectedOffLinkRouteEvents, gotOffLinkRouteEvents); diff != "" {
				t.Errorf("off-link route events mismatch (-want +got):\n%s", diff)
			}
			expectedPrefixEvents := map[ndpPrefixEvent]int{
				{nicID: nicID1, prefix: subnet1, discovered: false}: 1,
				{nicID: nicID1, prefix: subnet2, discovered: false}: 1,
				{nicID: nicID2, prefix: subnet1, discovered: false}: 1,
				{nicID: nicID2, prefix: subnet2, discovered: false}: 1,
			}
			if diff := cmp.Diff(expectedPrefixEvents, gotPrefixEvents); diff != "" {
				t.Errorf("prefix events mismatch (-want +got):\n%s", diff)
			}
			expectedAutoGenAddrEvents := map[ndpAutoGenAddrEvent]int{
				{nicID: nicID1, addr: e1Addr1, eventType: invalidatedAddr}: 1,
				{nicID: nicID1, addr: e1Addr2, eventType: invalidatedAddr}: 1,
				{nicID: nicID2, addr: e2Addr1, eventType: invalidatedAddr}: 1,
				{nicID: nicID2, addr: e2Addr2, eventType: invalidatedAddr}: 1,
			}

			if !test.keepAutoGenLinkLocal {
				expectedAutoGenAddrEvents[ndpAutoGenAddrEvent{nicID: nicID1, addr: llAddrWithPrefix1, eventType: invalidatedAddr}] = 1
				expectedAutoGenAddrEvents[ndpAutoGenAddrEvent{nicID: nicID2, addr: llAddrWithPrefix2, eventType: invalidatedAddr}] = 1
			}

			if diff := cmp.Diff(expectedAutoGenAddrEvents, gotAutoGenAddrEvents); diff != "" {
				t.Errorf("auto-generated address events mismatch (-want +got):\n%s", diff)
			}

			if !test.skipFinalAddrCheck {
				// Make sure the auto-generated addresses got removed.
				nicinfo = s.NICInfo()
				nic1Addrs = nicinfo[nicID1].ProtocolAddresses
				nic2Addrs = nicinfo[nicID2].ProtocolAddresses
				if containsV6Addr(nic1Addrs, llAddrWithPrefix1) != test.keepAutoGenLinkLocal {
					if test.keepAutoGenLinkLocal {
						t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix1, nicID1, nic1Addrs)
					} else {
						t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", llAddrWithPrefix1, nicID1, nic1Addrs)
					}
				}
				if containsV6Addr(nic1Addrs, e1Addr1) {
					t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e1Addr1, nicID1, nic1Addrs)
				}
				if containsV6Addr(nic1Addrs, e1Addr2) {
					t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e1Addr2, nicID1, nic1Addrs)
				}
				if containsV6Addr(nic2Addrs, llAddrWithPrefix2) != test.keepAutoGenLinkLocal {
					if test.keepAutoGenLinkLocal {
						t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix2, nicID2, nic2Addrs)
					} else {
						t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", llAddrWithPrefix2, nicID2, nic2Addrs)
					}
				}
				if containsV6Addr(nic2Addrs, e2Addr1) {
					t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e2Addr1, nicID2, nic2Addrs)
				}
				if containsV6Addr(nic2Addrs, e2Addr2) {
					t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e2Addr2, nicID2, nic2Addrs)
				}
			}

			// Should not get any more events (invalidation timers should have been
			// cancelled when the NDP state was cleaned up).
			clock.Advance(lifetimeSeconds * time.Second)
			select {
			case <-ndpDisp.offLinkRouteC:
				t.Error("unexpected off-link route event")
			default:
			}
			select {
			case <-ndpDisp.prefixC:
				t.Error("unexpected prefix event")
			default:
			}
			select {
			case <-ndpDisp.autoGenAddrC:
				t.Error("unexpected auto-generated address event")
			default:
			}
			select {
			case <-ndpDisp.autoGenAddrNewC:
				t.Error("unexpected auto-generated address event")
			default:
			}
		})
	}
}

// TestDHCPv6ConfigurationFromNDPDA tests that the NDPDispatcher is properly
// informed when new information about what configurations are available via
// DHCPv6 is learned.
func TestDHCPv6ConfigurationFromNDPDA(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dhcpv6ConfigurationC: make(chan ndpDHCPv6Event, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: ipv6.NDPConfigurations{
				HandleRAs: ipv6.HandlingRAsEnabledWhenForwardingDisabled,
			},
			NDPDisp: &ndpDisp,
		})},
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	expectDHCPv6Event := func(configuration ipv6.DHCPv6ConfigurationFromNDPRA) {
		t.Helper()
		select {
		case e := <-ndpDisp.dhcpv6ConfigurationC:
			if diff := cmp.Diff(ndpDHCPv6Event{nicID: nicID, configuration: configuration}, e, cmp.AllowUnexported(e)); diff != "" {
				t.Errorf("dhcpv6 event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected DHCPv6 configuration event")
		}
	}

	expectNoDHCPv6Event := func() {
		t.Helper()
		select {
		case <-ndpDisp.dhcpv6ConfigurationC:
			t.Fatal("unexpected DHCPv6 configuration event")
		default:
		}
	}

	// Even if the first RA reports no DHCPv6 configurations are available, the
	// dispatcher should get an event.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectDHCPv6Event(ipv6.DHCPv6NoConfiguration)
	// Receiving the same update again should not result in an event to the
	// dispatcher.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Other
	// Configurations.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectDHCPv6Event(ipv6.DHCPv6OtherConfigurations)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Managed Address.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectDHCPv6Event(ipv6.DHCPv6ManagedAddress)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to none.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectDHCPv6Event(ipv6.DHCPv6NoConfiguration)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Managed Address.
	//
	// Note, when the M flag is set, the O flag is redundant.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectDHCPv6Event(ipv6.DHCPv6ManagedAddress)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectNoDHCPv6Event()
	// Even though the DHCPv6 flags are different, the effective configuration is
	// the same so we should not receive a new event.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectNoDHCPv6Event()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Other
	// Configurations.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectDHCPv6Event(ipv6.DHCPv6OtherConfigurations)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectNoDHCPv6Event()

	// Cycling the NIC should cause the last DHCPv6 configuration to be cleared.
	if err := s.DisableNIC(nicID); err != nil {
		t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
	}
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}

	// Receive an RA that updates the DHCPv6 configuration to Other
	// Configurations.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectDHCPv6Event(ipv6.DHCPv6OtherConfigurations)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectNoDHCPv6Event()
}

var _ rand.Source = (*savingRandSource)(nil)

type savingRandSource struct {
	s rand.Source

	lastInt63 int64
}

func (d *savingRandSource) Int63() int64 {
	i := d.s.Int63()
	d.lastInt63 = i
	return i
}
func (d *savingRandSource) Seed(seed int64) {
	d.s.Seed(seed)
}

// TestRouterSolicitation tests the initial Router Solicitations that are sent
// when a NIC newly becomes enabled.
func TestRouterSolicitation(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name                        string
		linkHeaderLen               uint16
		linkAddr                    tcpip.LinkAddress
		nicAddr                     tcpip.Address
		expectedSrcAddr             tcpip.Address
		expectedNDPOpts             []header.NDPOption
		maxRtrSolicit               uint8
		rtrSolicitInt               time.Duration
		effectiveRtrSolicitInt      time.Duration
		maxRtrSolicitDelay          time.Duration
		effectiveMaxRtrSolicitDelay time.Duration
	}{
		{
			name:                        "Single RS with 2s delay and interval",
			expectedSrcAddr:             header.IPv6Any,
			maxRtrSolicit:               1,
			rtrSolicitInt:               2 * time.Second,
			effectiveRtrSolicitInt:      2 * time.Second,
			maxRtrSolicitDelay:          2 * time.Second,
			effectiveMaxRtrSolicitDelay: 2 * time.Second,
		},
		{
			name:                        "Single RS with 4s delay and interval",
			expectedSrcAddr:             header.IPv6Any,
			maxRtrSolicit:               1,
			rtrSolicitInt:               4 * time.Second,
			effectiveRtrSolicitInt:      4 * time.Second,
			maxRtrSolicitDelay:          4 * time.Second,
			effectiveMaxRtrSolicitDelay: 4 * time.Second,
		},
		{
			name:                        "Two RS with delay",
			linkHeaderLen:               1,
			nicAddr:                     llAddr1,
			expectedSrcAddr:             llAddr1,
			maxRtrSolicit:               2,
			rtrSolicitInt:               2 * time.Second,
			effectiveRtrSolicitInt:      2 * time.Second,
			maxRtrSolicitDelay:          500 * time.Millisecond,
			effectiveMaxRtrSolicitDelay: 500 * time.Millisecond,
		},
		{
			name:            "Single RS without delay",
			linkHeaderLen:   2,
			linkAddr:        linkAddr1,
			nicAddr:         llAddr1,
			expectedSrcAddr: llAddr1,
			expectedNDPOpts: []header.NDPOption{
				header.NDPSourceLinkLayerAddressOption(linkAddr1),
			},
			maxRtrSolicit:               1,
			rtrSolicitInt:               2 * time.Second,
			effectiveRtrSolicitInt:      2 * time.Second,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Two RS without delay and invalid zero interval",
			linkHeaderLen:               3,
			linkAddr:                    linkAddr1,
			expectedSrcAddr:             header.IPv6Any,
			maxRtrSolicit:               2,
			rtrSolicitInt:               0,
			effectiveRtrSolicitInt:      4 * time.Second,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Three RS without delay",
			linkAddr:                    linkAddr1,
			expectedSrcAddr:             header.IPv6Any,
			maxRtrSolicit:               3,
			rtrSolicitInt:               500 * time.Millisecond,
			effectiveRtrSolicitInt:      500 * time.Millisecond,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Two RS with invalid negative delay",
			linkAddr:                    linkAddr1,
			expectedSrcAddr:             header.IPv6Any,
			maxRtrSolicit:               2,
			rtrSolicitInt:               time.Second,
			effectiveRtrSolicitInt:      time.Second,
			maxRtrSolicitDelay:          -3 * time.Second,
			effectiveMaxRtrSolicitDelay: time.Second,
		},
	}

	subTests := []struct {
		name         string
		handleRAs    ipv6.HandleRAsConfiguration
		afterFirstRS func(*testing.T, *stack.Stack)
	}{
		{
			name:         "Handle RAs when forwarding disabled",
			handleRAs:    ipv6.HandlingRAsEnabledWhenForwardingDisabled,
			afterFirstRS: func(*testing.T, *stack.Stack) {},
		},

		// Enabling forwarding when RAs are always configured to be handled
		// should not stop router solicitations.
		{
			name:      "Handle RAs always",
			handleRAs: ipv6.HandlingRAsAlwaysEnabled,
			afterFirstRS: func(t *testing.T, s *stack.Stack) {
				if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", ipv6.ProtocolNumber, err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					clock := faketime.NewManualClock()
					e := channelLinkWithHeaderLength{
						Endpoint:     channel.New(int(test.maxRtrSolicit), 1280, test.linkAddr),
						headerLength: test.linkHeaderLen,
					}
					e.Endpoint.LinkEPCapabilities |= stack.CapabilityResolutionRequired
					waitForPkt := func(timeout time.Duration) {
						t.Helper()

						clock.Advance(timeout)
						p := e.Read()
						if p.IsNil() {
							t.Fatal("expected router solicitation packet")
						}
						defer p.DecRef()

						if p.NetworkProtocolNumber != header.IPv6ProtocolNumber {
							t.Fatalf("got Proto = %d, want = %d", p.NetworkProtocolNumber, header.IPv6ProtocolNumber)
						}

						// Make sure the right remote link address is used.
						if want := header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllRoutersLinkLocalMulticastAddress); p.EgressRoute.RemoteLinkAddress != want {
							t.Errorf("got remote link address = %s, want = %s", p.EgressRoute.RemoteLinkAddress, want)
						}

						checker.IPv6(t, stack.PayloadSince(p.NetworkHeader()),
							checker.SrcAddr(test.expectedSrcAddr),
							checker.DstAddr(header.IPv6AllRoutersLinkLocalMulticastAddress),
							checker.TTL(header.NDPHopLimit),
							checker.NDPRS(checker.NDPRSOptions(test.expectedNDPOpts)),
						)

						if l, want := p.AvailableHeaderBytes(), int(test.linkHeaderLen); l != want {
							t.Errorf("got p.AvailableHeaderBytes() = %d; want = %d", l, want)
						}
					}
					waitForNothing := func(timeout time.Duration) {
						t.Helper()

						clock.Advance(timeout)
						if p := e.Read(); !p.IsNil() {
							t.Fatalf("unexpectedly got a packet = %#v", p)
						}
					}
					randSource := savingRandSource{
						s: rand.NewSource(time.Now().UnixNano()),
					}
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
							NDPConfigs: ipv6.NDPConfigurations{
								HandleRAs:               subTest.handleRAs,
								MaxRtrSolicitations:     test.maxRtrSolicit,
								RtrSolicitationInterval: test.rtrSolicitInt,
								MaxRtrSolicitationDelay: test.maxRtrSolicitDelay,
							},
						})},
						Clock:      clock,
						RandSource: &randSource,
					})

					opts := stack.NICOptions{Disabled: true}
					if err := s.CreateNICWithOptions(nicID, &e, opts); err != nil {
						t.Fatalf("CreateNICWithOptions(%d, _, %#v) = %s", nicID, opts, err)
					}

					if addr := test.nicAddr; addr != "" {
						protocolAddr := tcpip.ProtocolAddress{
							Protocol:          header.IPv6ProtocolNumber,
							AddressWithPrefix: addr.WithPrefix(),
						}
						if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
							t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
						}
					}

					if err := s.EnableNIC(nicID); err != nil {
						t.Fatalf("EnableNIC(%d): %s", nicID, err)
					}

					// Make sure each RS is sent at the right time.
					remaining := test.maxRtrSolicit
					if remaining != 0 {
						maxRtrSolicitDelay := test.maxRtrSolicitDelay
						if maxRtrSolicitDelay < 0 {
							maxRtrSolicitDelay = ipv6.DefaultNDPConfigurations().MaxRtrSolicitationDelay
						}
						var actualRtrSolicitDelay time.Duration
						if maxRtrSolicitDelay != 0 {
							actualRtrSolicitDelay = time.Duration(randSource.lastInt63) % maxRtrSolicitDelay
						}
						waitForPkt(actualRtrSolicitDelay)
						remaining--
					}

					subTest.afterFirstRS(t, s)

					for ; remaining != 0; remaining-- {
						if test.effectiveRtrSolicitInt != 0 {
							waitForNothing(test.effectiveRtrSolicitInt - time.Nanosecond)
							waitForPkt(time.Nanosecond)
						} else {
							waitForPkt(0)
						}
					}

					// Make sure no more RS.
					if test.effectiveRtrSolicitInt > test.effectiveMaxRtrSolicitDelay {
						waitForNothing(test.effectiveRtrSolicitInt)
					} else {
						waitForNothing(test.effectiveMaxRtrSolicitDelay)
					}

					if got, want := s.Stats().ICMP.V6.PacketsSent.RouterSolicit.Value(), uint64(test.maxRtrSolicit); got != want {
						t.Fatalf("got sent RouterSolicit = %d, want = %d", got, want)
					}
				})
			}
		})
	}
}

func TestStopStartSolicitingRouters(t *testing.T) {
	const nicID = 1
	const delay = 0
	const interval = 500 * time.Millisecond
	const maxRtrSolicitations = 3

	tests := []struct {
		name    string
		startFn func(t *testing.T, s *stack.Stack)
		// first is used to tell stopFn that it is being called for the first time
		// after router solicitations were last enabled.
		stopFn func(t *testing.T, s *stack.Stack, first bool)
	}{
		// Tests that when forwarding is enabled or disabled, router solicitations
		// are stopped or started, respectively.
		{
			name: "Enable and disable forwarding",
			startFn: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, false); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, false): %s", ipv6.ProtocolNumber, err)
				}
			},
			stopFn: func(t *testing.T, s *stack.Stack, _ bool) {
				t.Helper()

				if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", ipv6.ProtocolNumber, err)
				}
			},
		},

		// Tests that when a NIC is enabled or disabled, router solicitations
		// are started or stopped, respectively.
		{
			name: "Enable and disable NIC",
			startFn: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				if err := s.EnableNIC(nicID); err != nil {
					t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
				}
			},
			stopFn: func(t *testing.T, s *stack.Stack, _ bool) {
				t.Helper()

				if err := s.DisableNIC(nicID); err != nil {
					t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
				}
			},
		},

		// Tests that when a NIC is removed, router solicitations are stopped. We
		// cannot start router solications on a removed NIC.
		{
			name: "Remove NIC",
			stopFn: func(t *testing.T, s *stack.Stack, first bool) {
				t.Helper()

				// Only try to remove the NIC the first time stopFn is called since it's
				// impossible to remove an already removed NIC.
				if !first {
					return
				}

				if err := s.RemoveNIC(nicID); err != nil {
					t.Fatalf("s.RemoveNIC(%d): %s", nicID, err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(maxRtrSolicitations, 1280, linkAddr1)
			waitForPkt := func(clock *faketime.ManualClock, timeout time.Duration) {
				t.Helper()

				clock.Advance(timeout)
				p := e.Read()
				if p.IsNil() {
					t.Fatal("timed out waiting for packet")
				}

				if p.NetworkProtocolNumber != header.IPv6ProtocolNumber {
					t.Fatalf("got Proto = %d, want = %d", p.NetworkProtocolNumber, header.IPv6ProtocolNumber)
				}
				checker.IPv6(t, stack.PayloadSince(p.NetworkHeader()),
					checker.SrcAddr(header.IPv6Any),
					checker.DstAddr(header.IPv6AllRoutersLinkLocalMulticastAddress),
					checker.TTL(header.NDPHopLimit),
					checker.NDPRS())
				p.DecRef()
			}
			clock := faketime.NewManualClock()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					NDPConfigs: ipv6.NDPConfigurations{
						HandleRAs:               ipv6.HandlingRAsEnabledWhenForwardingDisabled,
						MaxRtrSolicitations:     maxRtrSolicitations,
						RtrSolicitationInterval: interval,
						MaxRtrSolicitationDelay: delay,
					},
				})},
				Clock: clock,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			// Stop soliciting routers.
			test.stopFn(t, s, true /* first */)
			clock.Advance(delay)
			if p := e.Read(); !p.IsNil() {
				p.DecRef()
				// A single RS may have been sent before solicitations were stopped.
				clock.Advance(interval)
				if pb := e.Read(); !pb.IsNil() {
					t.Fatal("should not have sent more than one RS message")
				}
			}

			// Stopping router solicitations after it has already been stopped should
			// do nothing.
			test.stopFn(t, s, false /* first */)
			clock.Advance(delay)
			if pb := e.Read(); !pb.IsNil() {
				t.Fatal("unexpectedly got a packet after router solicitation has been stopepd")
			}

			// If test.startFn is nil, there is no way to restart router solications.
			if test.startFn == nil {
				return
			}

			// Start soliciting routers.
			test.startFn(t, s)
			waitForPkt(clock, delay)
			waitForPkt(clock, interval)
			waitForPkt(clock, interval)
			clock.Advance(interval)
			if pb := e.Read(); !pb.IsNil() {
				t.Fatal("unexpectedly got an extra packet after sending out the expected RSs")
			}

			// Starting router solicitations after it has already completed should do
			// nothing.
			test.startFn(t, s)
			clock.Advance(interval)
			if pb := e.Read(); !pb.IsNil() {
				t.Fatal("unexpectedly got a packet after finishing router solicitations")
			}
		})
	}
}
