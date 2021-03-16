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

package ipv6

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// setupStackAndEndpoint creates a stack with a single NIC with a link-local
// address llladdr and an IPv6 endpoint to a remote with link-local address
// rlladdr
func setupStackAndEndpoint(t *testing.T, llladdr, rlladdr tcpip.Address) (*stack.Stack, stack.NetworkEndpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
	})

	if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}
	{
		subnet, err := tcpip.NewSubnet(rlladdr, tcpip.AddressMask(strings.Repeat("\xff", len(rlladdr))))
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable(
			[]tcpip.Route{{
				Destination: subnet,
				NIC:         1,
			}},
		)
	}

	netProto := s.NetworkProtocolInstance(ProtocolNumber)
	if netProto == nil {
		t.Fatalf("cannot find protocol instance for network protocol %d", ProtocolNumber)
	}

	ep := netProto.NewEndpoint(&testInterface{}, &stubDispatcher{})
	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}
	t.Cleanup(ep.Close)

	addressableEndpoint, ok := ep.(stack.AddressableEndpoint)
	if !ok {
		t.Fatalf("expected network endpoint to implement stack.AddressableEndpoint")
	}
	addr := llladdr.WithPrefix()
	if addressEP, err := addressableEndpoint.AddAndAcquirePermanentAddress(addr, stack.CanBePrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */); err != nil {
		t.Fatalf("addressableEndpoint.AddAndAcquirePermanentAddress(%s, CanBePrimaryEndpoint, AddressConfigStatic, false): %s", addr, err)
	} else {
		addressEP.DecRef()
	}

	return s, ep
}

var _ NDPDispatcher = (*testNDPDispatcher)(nil)

// testNDPDispatcher is an NDPDispatcher only allows default router discovery.
type testNDPDispatcher struct {
	addr tcpip.Address
}

func (*testNDPDispatcher) OnDuplicateAddressDetectionResult(tcpip.NICID, tcpip.Address, stack.DADResult) {
}

func (t *testNDPDispatcher) OnDefaultRouterDiscovered(_ tcpip.NICID, addr tcpip.Address) bool {
	t.addr = addr
	return true
}

func (t *testNDPDispatcher) OnDefaultRouterInvalidated(_ tcpip.NICID, addr tcpip.Address) {
	t.addr = addr
}

func (*testNDPDispatcher) OnOnLinkPrefixDiscovered(tcpip.NICID, tcpip.Subnet) bool {
	return false
}

func (*testNDPDispatcher) OnOnLinkPrefixInvalidated(tcpip.NICID, tcpip.Subnet) {
}

func (*testNDPDispatcher) OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) bool {
	return false
}

func (*testNDPDispatcher) OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix) {
}

func (*testNDPDispatcher) OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix) {
}

func (*testNDPDispatcher) OnRecursiveDNSServerOption(tcpip.NICID, []tcpip.Address, time.Duration) {
}

func (*testNDPDispatcher) OnDNSSearchListOption(tcpip.NICID, []string, time.Duration) {
}

func (*testNDPDispatcher) OnDHCPv6Configuration(tcpip.NICID, DHCPv6ConfigurationFromNDPRA) {
}

func TestStackNDPEndpointInvalidateDefaultRouter(t *testing.T) {
	var ndpDisp testNDPDispatcher
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocolWithOptions(Options{
			NDPDisp: &ndpDisp,
		})},
	})

	if err := s.CreateNIC(nicID, &stubLinkEndpoint{}); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	ep, err := s.GetNetworkEndpoint(nicID, ProtocolNumber)
	if err != nil {
		t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, ProtocolNumber, err)
	}

	ipv6EP := ep.(*endpoint)
	ipv6EP.mu.Lock()
	ipv6EP.mu.ndp.rememberDefaultRouter(lladdr1, time.Hour)
	ipv6EP.mu.Unlock()

	if ndpDisp.addr != lladdr1 {
		t.Fatalf("got ndpDisp.addr = %s, want = %s", ndpDisp.addr, lladdr1)
	}

	ndpDisp.addr = ""
	ndpEP := ep.(stack.NDPEndpoint)
	ndpEP.InvalidateDefaultRouter(lladdr1)
	if ndpDisp.addr != lladdr1 {
		t.Fatalf("got ndpDisp.addr = %s, want = %s", ndpDisp.addr, lladdr1)
	}
}

type linkResolutionResult struct {
	linkAddr tcpip.LinkAddress
	ok       bool
}

// TestNeighborSolicitationWithSourceLinkLayerOption tests that receiving a
// valid NDP NS message with the Source Link Layer Address option results in a
// new entry in the link address cache for the sender of the message.
func TestNeighborSolicitationWithSourceLinkLayerOption(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name             string
		optsBuf          []byte
		expectedLinkAddr tcpip.LinkAddress
	}{
		{
			name:             "Valid",
			optsBuf:          []byte{1, 1, 2, 3, 4, 5, 6, 7},
			expectedLinkAddr: "\x02\x03\x04\x05\x06\x07",
		},
		{
			name:    "Too Small",
			optsBuf: []byte{1, 1, 2, 3, 4, 5, 6},
		},
		{
			name:    "Invalid Length",
			optsBuf: []byte{1, 2, 2, 3, 4, 5, 6, 7},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			e := channel.New(0, 1280, linkAddr0)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, lladdr0, err)
			}

			ndpNSSize := header.ICMPv6NeighborSolicitMinimumSize + len(test.optsBuf)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + ndpNSSize)
			pkt := header.ICMPv6(hdr.Prepend(ndpNSSize))
			pkt.SetType(header.ICMPv6NeighborSolicit)
			ns := header.NDPNeighborSolicit(pkt.MessageBody())
			ns.SetTargetAddress(lladdr0)
			opts := ns.Options()
			copy(opts, test.optsBuf)
			pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: pkt,
				Src:    lladdr1,
				Dst:    lladdr0,
			}))
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          255,
				SrcAddr:           lladdr1,
				DstAddr:           lladdr0,
			})

			invalid := s.Stats().ICMP.V6.PacketsReceived.Invalid

			// Invalid count should initially be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			neighbors, err := s.Neighbors(nicID, ProtocolNumber)
			if err != nil {
				t.Fatalf("s.Neighbors(%d, %d): %s", nicID, ProtocolNumber, err)
			}

			neighborByAddr := make(map[tcpip.Address]stack.NeighborEntry)
			for _, n := range neighbors {
				if existing, ok := neighborByAddr[n.Addr]; ok {
					if diff := cmp.Diff(existing, n); diff != "" {
						t.Fatalf("s.Neighbors(%d, %d) returned unexpected duplicate neighbor entry (-existing +got):\n%s", nicID, ProtocolNumber, diff)
					}
					t.Fatalf("s.Neighbors(%d, %d) returned unexpected duplicate neighbor entry: %#v", nicID, ProtocolNumber, existing)
				}
				neighborByAddr[n.Addr] = n
			}

			if neigh, ok := neighborByAddr[lladdr1]; len(test.expectedLinkAddr) != 0 {
				// Invalid count should not have increased.
				if got := invalid.Value(); got != 0 {
					t.Errorf("got invalid = %d, want = 0", got)
				}

				if !ok {
					t.Fatalf("expected a neighbor entry for %q", lladdr1)
				}
				if neigh.LinkAddr != test.expectedLinkAddr {
					t.Errorf("got link address = %s, want = %s", neigh.LinkAddr, test.expectedLinkAddr)
				}
				if neigh.State != stack.Stale {
					t.Errorf("got NUD state = %s, want = %s", neigh.State, stack.Stale)
				}
			} else {
				// Invalid count should have increased.
				if got := invalid.Value(); got != 1 {
					t.Errorf("got invalid = %d, want = 1", got)
				}

				if ok {
					t.Fatalf("unexpectedly got neighbor entry: %#v", neigh)
				}
			}
		})
	}
}

func TestNeighborSolicitationResponse(t *testing.T) {
	const nicID = 1
	nicAddr := lladdr0
	remoteAddr := lladdr1
	nicAddrSNMC := header.SolicitedNodeAddr(nicAddr)
	nicLinkAddr := linkAddr0
	remoteLinkAddr0 := linkAddr1
	remoteLinkAddr1 := linkAddr2

	tests := []struct {
		name                   string
		nsOpts                 header.NDPOptionsSerializer
		nsSrcLinkAddr          tcpip.LinkAddress
		nsSrc                  tcpip.Address
		nsDst                  tcpip.Address
		nsInvalid              bool
		naDstLinkAddr          tcpip.LinkAddress
		naSolicited            bool
		naSrc                  tcpip.Address
		naDst                  tcpip.Address
		performsLinkResolution bool
	}{
		{
			name:          "Unspecified source to solicited-node multicast destination",
			nsOpts:        nil,
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         header.IPv6Any,
			nsDst:         nicAddrSNMC,
			nsInvalid:     false,
			naDstLinkAddr: header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllNodesMulticastAddress),
			naSolicited:   false,
			naSrc:         nicAddr,
			naDst:         header.IPv6AllNodesMulticastAddress,
		},
		{
			name: "Unspecified source with source ll option to multicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         header.IPv6Any,
			nsDst:         nicAddrSNMC,
			nsInvalid:     true,
		},
		{
			name:          "Unspecified source to unicast destination",
			nsOpts:        nil,
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         header.IPv6Any,
			nsDst:         nicAddr,
			nsInvalid:     true,
		},
		{
			name: "Unspecified source with source ll option to unicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         header.IPv6Any,
			nsDst:         nicAddr,
			nsInvalid:     true,
		},
		{
			name: "Specified source with 1 source ll to multicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddrSNMC,
			nsInvalid:     false,
			naDstLinkAddr: remoteLinkAddr0,
			naSolicited:   true,
			naSrc:         nicAddr,
			naDst:         remoteAddr,
		},
		{
			name: "Specified source with 1 source ll different from route to multicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr1[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddrSNMC,
			nsInvalid:     false,
			naDstLinkAddr: remoteLinkAddr1,
			naSolicited:   true,
			naSrc:         nicAddr,
			naDst:         remoteAddr,
		},
		{
			name:          "Specified source to multicast destination",
			nsOpts:        nil,
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddrSNMC,
			nsInvalid:     true,
		},
		{
			name: "Specified source with 2 source ll to multicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr1[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddrSNMC,
			nsInvalid:     true,
		},

		{
			name:          "Specified source to unicast destination",
			nsOpts:        nil,
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddr,
			nsInvalid:     false,
			naDstLinkAddr: remoteLinkAddr0,
			naSolicited:   true,
			naSrc:         nicAddr,
			naDst:         remoteAddr,
			// Since we send a unicast solicitations to a node without an entry for
			// the remote, the node needs to perform neighbor discovery to get the
			// remote's link address to send the advertisement response.
			performsLinkResolution: true,
		},
		{
			name: "Specified source with 1 source ll to unicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddr,
			nsInvalid:     false,
			naDstLinkAddr: remoteLinkAddr0,
			naSolicited:   true,
			naSrc:         nicAddr,
			naDst:         remoteAddr,
		},
		{
			name: "Specified source with 1 source ll different from route to unicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr1[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddr,
			nsInvalid:     false,
			naDstLinkAddr: remoteLinkAddr1,
			naSolicited:   true,
			naSrc:         nicAddr,
			naDst:         remoteAddr,
		},
		{
			name: "Specified source with 2 source ll to unicast destination",
			nsOpts: header.NDPOptionsSerializer{
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr0[:]),
				header.NDPSourceLinkLayerAddressOption(remoteLinkAddr1[:]),
			},
			nsSrcLinkAddr: remoteLinkAddr0,
			nsSrc:         remoteAddr,
			nsDst:         nicAddr,
			nsInvalid:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			e := channel.New(1, 1280, nicLinkAddr)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, nicAddr); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, nicAddr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         1,
				},
			})

			ndpNSSize := header.ICMPv6NeighborSolicitMinimumSize + test.nsOpts.Length()
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + ndpNSSize)
			pkt := header.ICMPv6(hdr.Prepend(ndpNSSize))
			pkt.SetType(header.ICMPv6NeighborSolicit)
			ns := header.NDPNeighborSolicit(pkt.MessageBody())
			ns.SetTargetAddress(nicAddr)
			opts := ns.Options()
			opts.Serialize(test.nsOpts)
			pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: pkt,
				Src:    test.nsSrc,
				Dst:    test.nsDst,
			}))
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          255,
				SrcAddr:           test.nsSrc,
				DstAddr:           test.nsDst,
			})

			invalid := s.Stats().ICMP.V6.PacketsReceived.Invalid

			// Invalid count should initially be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			e.InjectLinkAddr(ProtocolNumber, test.nsSrcLinkAddr, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			if test.nsInvalid {
				if got := invalid.Value(); got != 1 {
					t.Fatalf("got invalid = %d, want = 1", got)
				}

				if p, got := e.Read(); got {
					t.Fatalf("unexpected response to an invalid NS = %+v", p.Pkt)
				}

				// If we expected the NS to be invalid, we have nothing else to check.
				return
			}

			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			if test.performsLinkResolution {
				p, got := e.ReadContext(context.Background())
				if !got {
					t.Fatal("expected an NDP NS response")
				}

				respNSDst := header.SolicitedNodeAddr(test.nsSrc)
				var want stack.RouteInfo
				want.NetProto = ProtocolNumber
				want.RemoteLinkAddress = header.EthernetAddressFromMulticastIPv6Address(respNSDst)
				if diff := cmp.Diff(want, p.Route, cmp.AllowUnexported(want)); diff != "" {
					t.Errorf("route info mismatch (-want +got):\n%s", diff)
				}

				checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(nicAddr),
					checker.DstAddr(respNSDst),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(test.nsSrc),
						checker.NDPNSOptions([]header.NDPOption{
							header.NDPSourceLinkLayerAddressOption(nicLinkAddr),
						}),
					))

				ser := header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(linkAddr1),
				}
				ndpNASize := header.ICMPv6NeighborAdvertMinimumSize + ser.Length()
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + ndpNASize)
				pkt := header.ICMPv6(hdr.Prepend(ndpNASize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.MessageBody())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(test.nsSrc)
				na.Options().Serialize(ser)
				pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: pkt,
					Src:    test.nsSrc,
					Dst:    nicAddr,
				}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength:     uint16(payloadLength),
					TransportProtocol: header.ICMPv6ProtocolNumber,
					HopLimit:          header.NDPHopLimit,
					SrcAddr:           test.nsSrc,
					DstAddr:           nicAddr,
				})
				e.InjectLinkAddr(ProtocolNumber, "", stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			}

			p, got := e.ReadContext(context.Background())
			if !got {
				t.Fatal("expected an NDP NA response")
			}

			if p.Route.LocalAddress != test.naSrc {
				t.Errorf("got p.Route.LocalAddress = %s, want = %s", p.Route.LocalAddress, test.naSrc)
			}
			if p.Route.LocalLinkAddress != nicLinkAddr {
				t.Errorf("p.Route.LocalLinkAddress = %s, want = %s", p.Route.LocalLinkAddress, nicLinkAddr)
			}
			if p.Route.RemoteAddress != test.naDst {
				t.Errorf("got p.Route.RemoteAddress = %s, want = %s", p.Route.RemoteAddress, test.naDst)
			}
			if p.Route.RemoteLinkAddress != test.naDstLinkAddr {
				t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, test.naDstLinkAddr)
			}

			checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
				checker.SrcAddr(test.naSrc),
				checker.DstAddr(test.naDst),
				checker.TTL(header.NDPHopLimit),
				checker.NDPNA(
					checker.NDPNASolicitedFlag(test.naSolicited),
					checker.NDPNATargetAddress(nicAddr),
					checker.NDPNAOptions([]header.NDPOption{
						header.NDPTargetLinkLayerAddressOption(nicLinkAddr[:]),
					}),
				))
		})
	}
}

// TestNeighborAdvertisementWithTargetLinkLayerOption tests that receiving a
// valid NDP NA message with the Target Link Layer Address option does not
// result in a new entry in the neighbor cache for the target of the message.
func TestNeighborAdvertisementWithTargetLinkLayerOption(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name    string
		optsBuf []byte
		isValid bool
	}{
		{
			name:    "Valid",
			optsBuf: []byte{2, 1, 2, 3, 4, 5, 6, 7},
			isValid: true,
		},
		{
			name:    "Too Small",
			optsBuf: []byte{2, 1, 2, 3, 4, 5, 6},
		},
		{
			name:    "Invalid Length",
			optsBuf: []byte{2, 2, 2, 3, 4, 5, 6, 7},
		},
		{
			name: "Multiple",
			optsBuf: []byte{
				2, 1, 2, 3, 4, 5, 6, 7,
				2, 1, 2, 3, 4, 5, 6, 8,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			e := channel.New(0, 1280, linkAddr0)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, lladdr0, err)
			}

			ndpNASize := header.ICMPv6NeighborAdvertMinimumSize + len(test.optsBuf)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + ndpNASize)
			pkt := header.ICMPv6(hdr.Prepend(ndpNASize))
			pkt.SetType(header.ICMPv6NeighborAdvert)
			ns := header.NDPNeighborAdvert(pkt.MessageBody())
			ns.SetTargetAddress(lladdr1)
			opts := ns.Options()
			copy(opts, test.optsBuf)
			pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: pkt,
				Src:    lladdr1,
				Dst:    lladdr0,
			}))
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          255,
				SrcAddr:           lladdr1,
				DstAddr:           lladdr0,
			})

			invalid := s.Stats().ICMP.V6.PacketsReceived.Invalid

			// Invalid count should initially be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			neighbors, err := s.Neighbors(nicID, ProtocolNumber)
			if err != nil {
				t.Fatalf("s.Neighbors(%d, %d): %s", nicID, ProtocolNumber, err)
			}

			neighborByAddr := make(map[tcpip.Address]stack.NeighborEntry)
			for _, n := range neighbors {
				if existing, ok := neighborByAddr[n.Addr]; ok {
					if diff := cmp.Diff(existing, n); diff != "" {
						t.Fatalf("s.Neighbors(%d, %d) returned unexpected duplicate neighbor entry (-existing +got):\n%s", nicID, ProtocolNumber, diff)
					}
					t.Fatalf("s.Neighbors(%d, %d) returned unexpected duplicate neighbor entry: %#v", nicID, ProtocolNumber, existing)
				}
				neighborByAddr[n.Addr] = n
			}

			if neigh, ok := neighborByAddr[lladdr1]; ok {
				t.Fatalf("unexpectedly got neighbor entry: %#v", neigh)
			}

			if test.isValid {
				// Invalid count should not have increased.
				if got := invalid.Value(); got != 0 {
					t.Errorf("got invalid = %d, want = 0", got)
				}
			} else {
				// Invalid count should have increased.
				if got := invalid.Value(); got != 1 {
					t.Errorf("got invalid = %d, want = 1", got)
				}
			}
		})
	}
}

func TestNDPValidation(t *testing.T) {
	setup := func(t *testing.T) (*stack.Stack, stack.NetworkEndpoint) {
		t.Helper()

		// Create a stack with the assigned link-local address lladdr0
		// and an endpoint to lladdr1.
		s, ep := setupStackAndEndpoint(t, lladdr0, lladdr1)

		return s, ep
	}

	handleIPv6Payload := func(payload buffer.View, hopLimit uint8, atomicFragment bool, ep stack.NetworkEndpoint) {
		var extHdrs header.IPv6ExtHdrSerializer
		if atomicFragment {
			extHdrs = append(extHdrs, &header.IPv6SerializableFragmentExtHdr{})
		}
		extHdrsLen := extHdrs.Length()

		ip := buffer.NewView(header.IPv6MinimumSize + extHdrsLen)
		header.IPv6(ip).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(payload) + extHdrsLen),
			TransportProtocol: header.ICMPv6ProtocolNumber,
			HopLimit:          hopLimit,
			SrcAddr:           lladdr1,
			DstAddr:           lladdr0,
			ExtensionHeaders:  extHdrs,
		})
		vv := ip.ToVectorisedView()
		vv.AppendView(payload)
		ep.HandlePacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: vv,
		}))
	}

	var tllData [header.NDPLinkLayerAddressSize]byte
	header.NDPOptions(tllData[:]).Serialize(header.NDPOptionsSerializer{
		header.NDPTargetLinkLayerAddressOption(linkAddr1),
	})

	var sllData [header.NDPLinkLayerAddressSize]byte
	header.NDPOptions(sllData[:]).Serialize(header.NDPOptionsSerializer{
		header.NDPSourceLinkLayerAddressOption(linkAddr1),
	})

	types := []struct {
		name        string
		typ         header.ICMPv6Type
		size        int
		extraData   []byte
		statCounter func(tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
		routerOnly  bool
	}{
		{
			name: "RouterSolicit",
			typ:  header.ICMPv6RouterSolicit,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RouterSolicit
			},
			routerOnly: true,
		},
		{
			name: "RouterAdvert",
			typ:  header.ICMPv6RouterAdvert,
			size: header.ICMPv6HeaderSize + header.NDPRAMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RouterAdvert
			},
		},
		{
			name:      "NeighborSolicit",
			typ:       header.ICMPv6NeighborSolicit,
			size:      header.ICMPv6NeighborSolicitMinimumSize,
			extraData: sllData[:],
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.NeighborSolicit
			},
		},
		{
			name:      "NeighborAdvert",
			typ:       header.ICMPv6NeighborAdvert,
			size:      header.ICMPv6NeighborAdvertMinimumSize,
			extraData: tllData[:],
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.NeighborAdvert
			},
		},
		{
			name: "RedirectMsg",
			typ:  header.ICMPv6RedirectMsg,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RedirectMsg
			},
		},
	}

	subTests := []struct {
		name           string
		atomicFragment bool
		hopLimit       uint8
		code           header.ICMPv6Code
		valid          bool
	}{
		{
			name:           "Valid",
			atomicFragment: false,
			hopLimit:       header.NDPHopLimit,
			code:           0,
			valid:          true,
		},
		{
			name:           "Fragmented",
			atomicFragment: true,
			hopLimit:       header.NDPHopLimit,
			code:           0,
			valid:          false,
		},
		{
			name:           "Invalid hop limit",
			atomicFragment: false,
			hopLimit:       header.NDPHopLimit - 1,
			code:           0,
			valid:          false,
		},
		{
			name:           "Invalid ICMPv6 code",
			atomicFragment: false,
			hopLimit:       header.NDPHopLimit,
			code:           1,
			valid:          false,
		},
	}

	for _, typ := range types {
		for _, isRouter := range []bool{false, true} {
			name := typ.name
			if isRouter {
				name += " (Router)"
			}

			t.Run(name, func(t *testing.T) {
				for _, test := range subTests {
					t.Run(test.name, func(t *testing.T) {
						s, ep := setup(t)

						if isRouter {
							// Enabling forwarding makes the stack act as a router.
							s.SetForwarding(ProtocolNumber, true)
						}

						stats := s.Stats().ICMP.V6.PacketsReceived
						invalid := stats.Invalid
						routerOnly := stats.RouterOnlyPacketsDroppedByHost
						typStat := typ.statCounter(stats)

						icmp := header.ICMPv6(buffer.NewView(typ.size + len(typ.extraData)))
						copy(icmp[typ.size:], typ.extraData)
						icmp.SetType(typ.typ)
						icmp.SetCode(test.code)
						icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
							Header:      icmp[:typ.size],
							Src:         lladdr0,
							Dst:         lladdr1,
							PayloadCsum: header.Checksum(typ.extraData /* initial */, 0),
							PayloadLen:  len(typ.extraData),
						}))

						// Rx count of the NDP message should initially be 0.
						if got := typStat.Value(); got != 0 {
							t.Errorf("got %s = %d, want = 0", typ.name, got)
						}

						// Invalid count should initially be 0.
						if got := invalid.Value(); got != 0 {
							t.Errorf("got invalid = %d, want = 0", got)
						}

						// RouterOnlyPacketsReceivedByHost count should initially be 0.
						if got := routerOnly.Value(); got != 0 {
							t.Errorf("got RouterOnlyPacketsReceivedByHost = %d, want = 0", got)
						}

						if t.Failed() {
							t.FailNow()
						}

						handleIPv6Payload(buffer.View(icmp), test.hopLimit, test.atomicFragment, ep)

						// Rx count of the NDP packet should have increased.
						if got := typStat.Value(); got != 1 {
							t.Errorf("got %s = %d, want = 1", typ.name, got)
						}

						want := uint64(0)
						if !test.valid {
							// Invalid count should have increased.
							want = 1
						}
						if got := invalid.Value(); got != want {
							t.Errorf("got invalid = %d, want = %d", got, want)
						}

						want = 0
						if test.valid && !isRouter && typ.routerOnly {
							// RouterOnlyPacketsReceivedByHost count should have increased.
							want = 1
						}
						if got := routerOnly.Value(); got != want {
							t.Errorf("got RouterOnlyPacketsReceivedByHost = %d, want = %d", got, want)
						}

					})
				}
			})
		}
	}
}

// TestNeighborAdvertisementValidation tests that the NIC validates received
// Neighbor Advertisements.
//
// In particular, if the IP Destination Address is a multicast address, and the
// Solicited flag is not zero, the Neighbor Advertisement is invalid and should
// be discarded.
func TestNeighborAdvertisementValidation(t *testing.T) {
	tests := []struct {
		name          string
		ipDstAddr     tcpip.Address
		solicitedFlag bool
		valid         bool
	}{
		{
			name:          "Multicast IP destination address with Solicited flag set",
			ipDstAddr:     header.IPv6AllNodesMulticastAddress,
			solicitedFlag: true,
			valid:         false,
		},
		{
			name:          "Multicast IP destination address with Solicited flag unset",
			ipDstAddr:     header.IPv6AllNodesMulticastAddress,
			solicitedFlag: false,
			valid:         true,
		},
		{
			name:          "Unicast IP destination address with Solicited flag set",
			ipDstAddr:     lladdr0,
			solicitedFlag: true,
			valid:         true,
		},
		{
			name:          "Unicast IP destination address with Solicited flag unset",
			ipDstAddr:     lladdr0,
			solicitedFlag: false,
			valid:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			e := channel.New(0, header.IPv6MinimumMTU, linkAddr0)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, lladdr0, err)
			}

			ndpNASize := header.ICMPv6NeighborAdvertMinimumSize
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + ndpNASize)
			pkt := header.ICMPv6(hdr.Prepend(ndpNASize))
			pkt.SetType(header.ICMPv6NeighborAdvert)
			na := header.NDPNeighborAdvert(pkt.MessageBody())
			na.SetTargetAddress(lladdr1)
			na.SetSolicitedFlag(test.solicitedFlag)
			pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: pkt,
				Src:    lladdr1,
				Dst:    test.ipDstAddr,
			}))
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          255,
				SrcAddr:           lladdr1,
				DstAddr:           test.ipDstAddr,
			})

			stats := s.Stats().ICMP.V6.PacketsReceived
			invalid := stats.Invalid
			rxNA := stats.NeighborAdvert

			if got := rxNA.Value(); got != 0 {
				t.Fatalf("got rxNA = %d, want = 0", got)
			}
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			if got := rxNA.Value(); got != 1 {
				t.Fatalf("got rxNA = %d, want = 1", got)
			}
			var wantInvalid uint64 = 1
			if test.valid {
				wantInvalid = 0
			}
			if got := invalid.Value(); got != wantInvalid {
				t.Fatalf("got invalid = %d, want = %d", got, wantInvalid)
			}
			// As per RFC 4861 section 7.2.5:
			//   When a valid Neighbor Advertisement is received ...
			//   If no entry exists, the advertisement SHOULD be silently discarded.
			//   There is no need to create an entry if none exists, since the
			//   recipient has apparently not initiated any communication with the
			//   target.
			if neighbors, err := s.Neighbors(nicID, ProtocolNumber); err != nil {
				t.Fatalf("s.Neighbors(%d, %d): %s", nicID, ProtocolNumber, err)
			} else if len(neighbors) != 0 {
				t.Fatalf("got len(neighbors) = %d, want = 0; neighbors = %#v", len(neighbors), neighbors)
			}
		})
	}
}

// TestRouterAdvertValidation tests that when the NIC is configured to handle
// NDP Router Advertisement packets, it validates the Router Advertisement
// properly before handling them.
func TestRouterAdvertValidation(t *testing.T) {
	tests := []struct {
		name            string
		src             tcpip.Address
		hopLimit        uint8
		code            header.ICMPv6Code
		ndpPayload      []byte
		expectedSuccess bool
	}{
		{
			"OK",
			lladdr0,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			true,
		},
		{
			"NonLinkLocalSourceAddr",
			addr1,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"HopLimitNot255",
			lladdr0,
			254,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"NonZeroCode",
			lladdr0,
			255,
			1,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"NDPPayloadTooSmall",
			lladdr0,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0,
			},
			false,
		},
		{
			"OKWithOptions",
			lladdr0,
			255,
			0,
			[]byte{
				// RA payload
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,

				// Option #1 (TargetLinkLayerAddress)
				2, 1, 0, 0, 0, 0, 0, 0,

				// Option #2 (unrecognized)
				255, 1, 0, 0, 0, 0, 0, 0,

				// Option #3 (PrefixInformation)
				3, 4, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			true,
		},
		{
			"OptionWithZeroLength",
			lladdr0,
			255,
			0,
			[]byte{
				// RA payload
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,

				// Option #1 (TargetLinkLayerAddress)
				// Invalid as it has 0 length.
				2, 0, 0, 0, 0, 0, 0, 0,

				// Option #2 (unrecognized)
				255, 1, 0, 0, 0, 0, 0, 0,

				// Option #3 (PrefixInformation)
				3, 4, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(10, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			icmpSize := header.ICMPv6HeaderSize + len(test.ndpPayload)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
			pkt := header.ICMPv6(hdr.Prepend(icmpSize))
			pkt.SetType(header.ICMPv6RouterAdvert)
			pkt.SetCode(test.code)
			copy(pkt.MessageBody(), test.ndpPayload)
			payloadLength := hdr.UsedLength()
			pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: pkt,
				Src:    test.src,
				Dst:    header.IPv6AllNodesMulticastAddress,
			}))
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: icmp.ProtocolNumber6,
				HopLimit:          test.hopLimit,
				SrcAddr:           test.src,
				DstAddr:           header.IPv6AllNodesMulticastAddress,
			})

			stats := s.Stats().ICMP.V6.PacketsReceived
			invalid := stats.Invalid
			rxRA := stats.RouterAdvert

			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}
			if got := rxRA.Value(); got != 0 {
				t.Fatalf("got rxRA = %d, want = 0", got)
			}

			e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			if got := rxRA.Value(); got != 1 {
				t.Fatalf("got rxRA = %d, want = 1", got)
			}

			if test.expectedSuccess {
				if got := invalid.Value(); got != 0 {
					t.Fatalf("got invalid = %d, want = 0", got)
				}
			} else {
				if got := invalid.Value(); got != 1 {
					t.Fatalf("got invalid = %d, want = 1", got)
				}
			}
		})
	}
}

// TestCheckDuplicateAddress checks that calls to CheckDuplicateAddress and DAD
// performed when adding new addresses do not interfere with each other.
func TestCheckDuplicateAddress(t *testing.T) {
	const nicID = 1

	clock := faketime.NewManualClock()
	dadConfigs := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}

	nonces := [...][]byte{
		{1, 2, 3, 4, 5, 6},
		{7, 8, 9, 10, 11, 12},
	}

	var secureRNGBytes []byte
	for _, n := range nonces {
		secureRNGBytes = append(secureRNGBytes, n...)
	}
	var secureRNG bytes.Reader
	secureRNG.Reset(secureRNGBytes[:])
	s := stack.New(stack.Options{
		SecureRNG: &secureRNG,
		Clock:     clock,
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocolWithOptions(Options{
			DADConfigs: dadConfigs,
		})},
	})
	// This test is expected to send at max 2 DAD messages. We allow an extra
	// packet to be stored to catch unexpected packets.
	e := channel.New(3, header.IPv6MinimumMTU, linkAddr0)
	e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	dadPacketsSent := 0
	snmc := header.SolicitedNodeAddr(lladdr0)
	remoteLinkAddr := header.EthernetAddressFromMulticastIPv6Address(snmc)
	checkDADMsg := func() {
		p, ok := e.ReadContext(context.Background())
		if !ok {
			t.Fatalf("expected %d-th DAD message", dadPacketsSent)
		}

		if p.Proto != header.IPv6ProtocolNumber {
			t.Errorf("(i=%d) got p.Proto = %d, want = %d", dadPacketsSent, p.Proto, header.IPv6ProtocolNumber)
		}

		if p.Route.RemoteLinkAddress != remoteLinkAddr {
			t.Errorf("(i=%d) got p.Route.RemoteLinkAddress = %s, want = %s", dadPacketsSent, p.Route.RemoteLinkAddress, remoteLinkAddr)
		}

		checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
			checker.SrcAddr(header.IPv6Any),
			checker.DstAddr(snmc),
			checker.TTL(header.NDPHopLimit),
			checker.NDPNS(
				checker.NDPNSTargetAddress(lladdr0),
				checker.NDPNSOptions([]header.NDPOption{header.NDPNonceOption(nonces[dadPacketsSent])}),
			))
	}
	if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, lladdr0, err)
	}
	checkDADMsg()

	// Start DAD for the address we just added.
	//
	// Even though the stack will perform DAD before the added address transitions
	// from tentative to assigned, this DAD request should be independent of that.
	ch := make(chan stack.DADResult, 3)
	dadRequestsMade := 1
	dadPacketsSent++
	if res, err := s.CheckDuplicateAddress(nicID, ProtocolNumber, lladdr0, func(r stack.DADResult) {
		ch <- r
	}); err != nil {
		t.Fatalf("s.CheckDuplicateAddress(%d, %d, %s, _): %s", nicID, ProtocolNumber, lladdr0, err)
	} else if res != stack.DADStarting {
		t.Fatalf("got s.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", nicID, ProtocolNumber, lladdr0, res, stack.DADStarting)
	}
	checkDADMsg()

	// Remove the address and make sure our DAD request was not stopped.
	if err := s.RemoveAddress(nicID, lladdr0); err != nil {
		t.Fatalf("RemoveAddress(%d, %s): %s", nicID, lladdr0, err)
	}
	// Should not restart DAD since we already requested DAD above - the handler
	// should be called when the original request compeletes so we should not send
	// an extra DAD message here.
	dadRequestsMade++
	if res, err := s.CheckDuplicateAddress(nicID, ProtocolNumber, lladdr0, func(r stack.DADResult) {
		ch <- r
	}); err != nil {
		t.Fatalf("s.CheckDuplicateAddress(%d, %d, %s, _): %s", nicID, ProtocolNumber, lladdr0, err)
	} else if res != stack.DADAlreadyRunning {
		t.Fatalf("got s.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", nicID, ProtocolNumber, lladdr0, res, stack.DADAlreadyRunning)
	}

	// Wait for DAD to complete.
	clock.Advance(time.Duration(dadConfigs.DupAddrDetectTransmits) * dadConfigs.RetransmitTimer)
	for i := 0; i < dadRequestsMade; i++ {
		if diff := cmp.Diff(&stack.DADSucceeded{}, <-ch); diff != "" {
			t.Errorf("(i=%d) DAD result mismatch (-want +got):\n%s", i, diff)
		}
	}
	// Should have no more results.
	select {
	case r := <-ch:
		t.Errorf("unexpectedly got an extra DAD result; r = %#v", r)
	default:
	}

	// Should have no more packets.
	if p, ok := e.Read(); ok {
		t.Errorf("got unexpected packet = %#v", p)
	}
}
