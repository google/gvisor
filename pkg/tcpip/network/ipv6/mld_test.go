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

package ipv6_test

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

var (
	linkLocalAddr       = testutil.MustParse6("fe80::1")
	globalAddr          = testutil.MustParse6("a80::1")
	globalMulticastAddr = testutil.MustParse6("ff05:100::2")

	linkLocalAddrSNMC = header.SolicitedNodeAddr(linkLocalAddr)
	globalAddrSNMC    = header.SolicitedNodeAddr(globalAddr)
)

func validateMLDPacket(t *testing.T, p buffer.View, localAddress, remoteAddress tcpip.Address, mldType header.ICMPv6Type, groupAddress tcpip.Address) {
	t.Helper()

	checker.IPv6WithExtHdr(t, p,
		checker.IPv6ExtHdr(
			checker.IPv6HopByHopExtensionHeader(checker.IPv6RouterAlert(header.IPv6RouterAlertMLD)),
		),
		checker.SrcAddr(localAddress),
		checker.DstAddr(remoteAddress),
		checker.TTL(header.MLDHopLimit),
		checker.MLD(mldType, header.MLDMinimumSize,
			checker.MLDMaxRespDelay(0),
			checker.MLDMulticastAddress(groupAddress),
		),
	)
}

func TestIPv6JoinLeaveSolicitedNodeAddressPerformsMLD(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			MLD: ipv6.MLDOptions{
				Enabled: true,
			},
		})},
	})
	e := channel.New(1, header.IPv6MinimumMTU, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}

	// The stack will join an address's solicited node multicast address when
	// an address is added. An MLD report message should be sent for the
	// solicited-node group.
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: linkLocalAddr.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}
	if p, ok := e.Read(); !ok {
		t.Fatal("expected a report message to be sent")
	} else {
		validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), linkLocalAddr, linkLocalAddrSNMC, header.ICMPv6MulticastListenerReport, linkLocalAddrSNMC)
	}

	// The stack will leave an address's solicited node multicast address when
	// an address is removed. An MLD done message should be sent for the
	// solicited-node group.
	if err := s.RemoveAddress(nicID, linkLocalAddr); err != nil {
		t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, linkLocalAddr, err)
	}
	if p, ok := e.Read(); !ok {
		t.Fatal("expected a done message to be sent")
	} else {
		validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), header.IPv6Any, header.IPv6AllRoutersLinkLocalMulticastAddress, header.ICMPv6MulticastListenerDone, linkLocalAddrSNMC)
	}
}

func TestSendQueuedMLDReports(t *testing.T) {
	const (
		nicID      = 1
		maxReports = 2
	)

	tests := []struct {
		name            string
		dadTransmits    uint8
		retransmitTimer time.Duration
	}{
		{
			name:            "DAD Disabled",
			dadTransmits:    0,
			retransmitTimer: 0,
		},
		{
			name:            "DAD Enabled",
			dadTransmits:    1,
			retransmitTimer: time.Second,
		},
	}

	nonce := [...]byte{
		1, 2, 3, 4, 5, 6,
	}

	const maxNSMessages = 2
	secureRNGBytes := make([]byte, len(nonce)*maxNSMessages)
	for b := secureRNGBytes[:]; len(b) > 0; b = b[len(nonce):] {
		if n := copy(b, nonce[:]); n != len(nonce) {
			t.Fatalf("got copy(...) = %d, want = %d", n, len(nonce))
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dadResolutionTime := test.retransmitTimer * time.Duration(test.dadTransmits)
			clock := faketime.NewManualClock()
			var secureRNG bytes.Reader
			secureRNG.Reset(secureRNGBytes[:])
			s := stack.New(stack.Options{
				SecureRNG:  &secureRNG,
				RandSource: rand.NewSource(time.Now().UnixNano()),
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					DADConfigs: stack.DADConfigurations{
						DupAddrDetectTransmits: test.dadTransmits,
						RetransmitTimer:        test.retransmitTimer,
					},
					MLD: ipv6.MLDOptions{
						Enabled: true,
					},
				})},
				Clock: clock,
			})

			// Allow space for an extra packet so we can observe packets that were
			// unexpectedly sent.
			e := channel.New(maxReports+int(test.dadTransmits)+1 /* extra */, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}

			resolveDAD := func(addr, snmc tcpip.Address) {
				clock.Advance(dadResolutionTime)
				if p, ok := e.Read(); !ok {
					t.Fatal("expected DAD packet")
				} else {
					checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
						checker.SrcAddr(header.IPv6Any),
						checker.DstAddr(snmc),
						checker.TTL(header.NDPHopLimit),
						checker.NDPNS(
							checker.NDPNSTargetAddress(addr),
							checker.NDPNSOptions([]header.NDPOption{header.NDPNonceOption(nonce[:])}),
						))
				}
			}

			var reportCounter uint64
			reportStat := s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			if got := reportStat.Value(); got != reportCounter {
				t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
			}
			var doneCounter uint64
			doneStat := s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone
			if got := doneStat.Value(); got != doneCounter {
				t.Errorf("got doneStat.Value() = %d, want = %d", got, doneCounter)
			}

			// Joining a group without an assigned address should send an MLD report
			// with the unspecified address.
			if err := s.JoinGroup(ipv6.ProtocolNumber, nicID, globalMulticastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, globalMulticastAddr, err)
			}
			reportCounter++
			if got := reportStat.Value(); got != reportCounter {
				t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
			}
			if p, ok := e.Read(); !ok {
				t.Errorf("expected MLD report for %s", globalMulticastAddr)
			} else {
				validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), header.IPv6Any, globalMulticastAddr, header.ICMPv6MulticastListenerReport, globalMulticastAddr)
			}
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Errorf("got unexpected packet = %#v", p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Adding a global address should not send reports for the already joined
			// group since we should only send queued reports when a link-local
			// address is assigned.
			//
			// Note, we will still expect to send a report for the global address's
			// solicited node address from the unspecified address as per  RFC 3590
			// section 4.
			properties := stack.AddressProperties{PEB: stack.FirstPrimaryEndpoint}
			globalProtocolAddr := tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: globalAddr.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, globalProtocolAddr, properties); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, %+v): %s", nicID, globalProtocolAddr, properties, err)
			}
			reportCounter++
			if got := reportStat.Value(); got != reportCounter {
				t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
			}
			if p, ok := e.Read(); !ok {
				t.Errorf("expected MLD report for %s", globalAddrSNMC)
			} else {
				validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), header.IPv6Any, globalAddrSNMC, header.ICMPv6MulticastListenerReport, globalAddrSNMC)
			}
			if dadResolutionTime != 0 {
				// Reports should not be sent when the address resolves.
				resolveDAD(globalAddr, globalAddrSNMC)
				if got := reportStat.Value(); got != reportCounter {
					t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
				}
			}
			// Leave the group since we don't care about the global address's
			// solicited node multicast group membership.
			if err := s.LeaveGroup(ipv6.ProtocolNumber, nicID, globalAddrSNMC); err != nil {
				t.Fatalf("LeaveGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, globalAddrSNMC, err)
			}
			if got := doneStat.Value(); got != doneCounter {
				t.Errorf("got doneStat.Value() = %d, want = %d", got, doneCounter)
			}
			if p, ok := e.Read(); ok {
				t.Errorf("got unexpected packet = %#v", p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Adding a link-local address should send a report for its solicited node
			// address and globalMulticastAddr.
			linkLocalProtocolAddr := tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: linkLocalAddr.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, linkLocalProtocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, linkLocalProtocolAddr, err)
			}
			if dadResolutionTime != 0 {
				reportCounter++
				if got := reportStat.Value(); got != reportCounter {
					t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
				}
				if p, ok := e.Read(); !ok {
					t.Errorf("expected MLD report for %s", linkLocalAddrSNMC)
				} else {
					validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), header.IPv6Any, linkLocalAddrSNMC, header.ICMPv6MulticastListenerReport, linkLocalAddrSNMC)
				}
				resolveDAD(linkLocalAddr, linkLocalAddrSNMC)
			}

			// We expect two batches of reports to be sent (1 batch when the
			// link-local address is assigned, and another after the maximum
			// unsolicited report interval.
			for i := 0; i < 2; i++ {
				// We expect reports to be sent (one for globalMulticastAddr and another
				// for linkLocalAddrSNMC).
				reportCounter += maxReports
				if got := reportStat.Value(); got != reportCounter {
					t.Errorf("got reportStat.Value() = %d, want = %d", got, reportCounter)
				}

				addrs := map[tcpip.Address]bool{
					globalMulticastAddr: false,
					linkLocalAddrSNMC:   false,
				}
				for range addrs {
					p, ok := e.Read()
					if !ok {
						t.Fatalf("expected MLD report for %s and %s; addrs = %#v", globalMulticastAddr, linkLocalAddrSNMC, addrs)
					}

					addr := header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader())).DestinationAddress()
					if seen, ok := addrs[addr]; !ok {
						t.Fatalf("got unexpected packet destined to %s", addr)
					} else if seen {
						t.Fatalf("got another packet destined to %s", addr)
					}

					addrs[addr] = true
					validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), linkLocalAddr, addr, header.ICMPv6MulticastListenerReport, addr)

					clock.Advance(ipv6.UnsolicitedReportIntervalMax)
				}
			}

			// Should not send any more reports.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Errorf("got unexpected packet = %#v", p)
			}
		})
	}
}

// createAndInjectMLDPacket creates and injects an MLD packet with the
// specified fields.
func createAndInjectMLDPacket(e *channel.Endpoint, mldType header.ICMPv6Type, hopLimit uint8, srcAddress tcpip.Address, withRouterAlertOption bool, routerAlertValue header.IPv6RouterAlertValue) {
	var extensionHeaders header.IPv6ExtHdrSerializer
	if withRouterAlertOption {
		extensionHeaders = header.IPv6ExtHdrSerializer{
			header.IPv6SerializableHopByHopExtHdr{
				&header.IPv6RouterAlertOption{Value: routerAlertValue},
			},
		}
	}

	extensionHeadersLength := extensionHeaders.Length()
	payloadLength := extensionHeadersLength + header.ICMPv6HeaderSize + header.MLDMinimumSize
	buf := buffer.NewView(header.IPv6MinimumSize + payloadLength)

	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		HopLimit:          hopLimit,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		SrcAddr:           srcAddress,
		DstAddr:           header.IPv6AllNodesMulticastAddress,
		ExtensionHeaders:  extensionHeaders,
	})

	icmp := header.ICMPv6(ip.Payload()[extensionHeadersLength:])
	icmp.SetType(mldType)
	mld := header.MLD(icmp.MessageBody())
	mld.SetMaximumResponseDelay(0)
	mld.SetMulticastAddress(header.IPv6Any)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    srcAddress,
		Dst:    header.IPv6AllNodesMulticastAddress,
	}))

	e.InjectInbound(ipv6.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
}

func TestMLDPacketValidation(t *testing.T) {
	const nicID = 1
	linkLocalAddr2 := testutil.MustParse6("fe80::2")

	tests := []struct {
		name                     string
		messageType              header.ICMPv6Type
		srcAddr                  tcpip.Address
		includeRouterAlertOption bool
		routerAlertValue         header.IPv6RouterAlertValue
		hopLimit                 uint8
		expectValidMLD           bool
		getMessageTypeStatValue  func(tcpip.Stats) uint64
	}{
		{
			name:                     "valid",
			messageType:              header.ICMPv6MulticastListenerQuery,
			includeRouterAlertOption: true,
			routerAlertValue:         header.IPv6RouterAlertMLD,
			srcAddr:                  linkLocalAddr2,
			hopLimit:                 header.MLDHopLimit,
			expectValidMLD:           true,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.ICMP.V6.PacketsReceived.MulticastListenerQuery.Value() },
		},
		{
			name:                     "bad hop limit",
			messageType:              header.ICMPv6MulticastListenerReport,
			includeRouterAlertOption: true,
			routerAlertValue:         header.IPv6RouterAlertMLD,
			srcAddr:                  linkLocalAddr2,
			hopLimit:                 header.MLDHopLimit + 1,
			expectValidMLD:           false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.ICMP.V6.PacketsReceived.MulticastListenerReport.Value() },
		},
		{
			name:                     "src ip not link local",
			messageType:              header.ICMPv6MulticastListenerReport,
			includeRouterAlertOption: true,
			routerAlertValue:         header.IPv6RouterAlertMLD,
			srcAddr:                  globalAddr,
			hopLimit:                 header.MLDHopLimit,
			expectValidMLD:           false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.ICMP.V6.PacketsReceived.MulticastListenerReport.Value() },
		},
		{
			name:                     "missing router alert ip option",
			messageType:              header.ICMPv6MulticastListenerDone,
			includeRouterAlertOption: false,
			srcAddr:                  linkLocalAddr2,
			hopLimit:                 header.MLDHopLimit,
			expectValidMLD:           false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.ICMP.V6.PacketsReceived.MulticastListenerDone.Value() },
		},
		{
			name:                     "incorrect router alert value",
			messageType:              header.ICMPv6MulticastListenerDone,
			includeRouterAlertOption: true,
			routerAlertValue:         header.IPv6RouterAlertRSVP,
			srcAddr:                  linkLocalAddr2,
			hopLimit:                 header.MLDHopLimit,
			expectValidMLD:           false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.ICMP.V6.PacketsReceived.MulticastListenerDone.Value() },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					MLD: ipv6.MLDOptions{
						Enabled: true,
					},
				})},
			})
			e := channel.New(nicID, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			stats := s.Stats()
			// Verify that every relevant stats is zero'd before we send a packet.
			if got := test.getMessageTypeStatValue(s.Stats()); got != 0 {
				t.Errorf("got test.getMessageTypeStatValue(s.Stats()) = %d, want = 0", got)
			}
			if got := stats.ICMP.V6.PacketsReceived.Invalid.Value(); got != 0 {
				t.Errorf("got stats.ICMP.V6.PacketsReceived.Invalid.Value() = %d, want = 0", got)
			}
			if got := stats.IP.PacketsDelivered.Value(); got != 0 {
				t.Fatalf("got stats.IP.PacketsDelivered.Value() = %d, want = 0", got)
			}
			createAndInjectMLDPacket(e, test.messageType, test.hopLimit, test.srcAddr, test.includeRouterAlertOption, test.routerAlertValue)
			// We always expect the packet to pass IP validation.
			if got := stats.IP.PacketsDelivered.Value(); got != 1 {
				t.Fatalf("got stats.IP.PacketsDelivered.Value() = %d, want = 1", got)
			}
			// Even when the MLD-specific validation checks fail, we expect the
			// corresponding MLD counter to be incremented.
			if got := test.getMessageTypeStatValue(s.Stats()); got != 1 {
				t.Errorf("got test.getMessageTypeStatValue(s.Stats()) = %d, want = 1", got)
			}
			var expectedInvalidCount uint64
			if !test.expectValidMLD {
				expectedInvalidCount = 1
			}
			if got := stats.ICMP.V6.PacketsReceived.Invalid.Value(); got != expectedInvalidCount {
				t.Errorf("got stats.ICMP.V6.PacketsReceived.Invalid.Value() = %d, want = %d", got, expectedInvalidCount)
			}
		})
	}
}

func TestMLDSkipProtocol(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name         string
		group        tcpip.Address
		expectReport bool
	}{
		{
			name:         "Reserverd0",
			group:        "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: false,
		},
		{
			name:         "Interface Local",
			group:        "\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: false,
		},
		{
			name:         "Link Local",
			group:        "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Realm Local",
			group:        "\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Admin Local",
			group:        "\xff\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Site Local",
			group:        "\xff\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(6)",
			group:        "\xff\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(7)",
			group:        "\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Organization Local",
			group:        "\xff\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(9)",
			group:        "\xff\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(A)",
			group:        "\xff\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(B)",
			group:        "\xff\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(C)",
			group:        "\xff\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Unassigned(D)",
			group:        "\xff\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "Global",
			group:        "\xff\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
		{
			name:         "ReservedF",
			group:        "\xff\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11",
			expectReport: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
					MLD: ipv6.MLDOptions{
						Enabled: true,
					},
				})},
			})
			e := channel.New(1, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: linkLocalAddr.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), linkLocalAddr, linkLocalAddrSNMC, header.ICMPv6MulticastListenerReport, linkLocalAddrSNMC)
			}

			if err := s.JoinGroup(ipv6.ProtocolNumber, nicID, test.group); err != nil {
				t.Fatalf("s.JoinGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, test.group, err)
			}
			if isInGroup, err := s.IsInGroup(nicID, test.group); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.group, err)
			} else if !isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = false, want = true", nicID, test.group)
			}

			if !test.expectReport {
				if p, ok := e.Read(); ok {
					t.Fatalf("got e.Read() = (%#v, true), want = (_, false)", p)
				}

				return
			}

			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				validateMLDPacket(t, stack.PayloadSince(p.Pkt.NetworkHeader()), linkLocalAddr, test.group, header.ICMPv6MulticastListenerReport, test.group)
			}
		})
	}
}
