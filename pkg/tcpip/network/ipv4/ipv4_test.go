// Copyright 2021 The gVisor Authors.
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

package ipv4_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	iptestutil "gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	extraHeaderReserve = 50
	defaultMTU         = 65536
)

type testContext struct {
	s     *stack.Stack
	clock *faketime.ManualClock
}

var _ stack.MulticastForwardingEventDispatcher = (*fakeMulticastEventDispatcher)(nil)

type fakeMulticastEventDispatcher struct{}

func (m *fakeMulticastEventDispatcher) OnMissingRoute(context stack.MulticastPacketContext) {}

func (m *fakeMulticastEventDispatcher) OnUnexpectedInputInterface(context stack.MulticastPacketContext, expectedInputInterface tcpip.NICID) {
}

func newTestContext() testContext {
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              clock,
		RawFactory:         raw.EndpointFactory{},
	})
	return testContext{s: s, clock: clock}
}

func (ctx testContext) cleanup() {
	ctx.s.Close()
	ctx.s.Wait()
	refs.DoRepeatedLeakCheck()
}

func TestExcludeBroadcast(t *testing.T) {
	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	ch := channel.New(256, defaultMTU, "")
	defer ch.Close()
	ep := stack.LinkEndpoint(ch)
	if testing.Verbose() {
		ep = sniffer.New(ep)
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}})

	randomAddr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x01")), Port: 53}

	var wq waiter.Queue
	t.Run("WithoutPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Cannot connect using a broadcast address as the source.
		{
			err := ep.Connect(randomAddr)
			if _, ok := err.(*tcpip.ErrHostUnreachable); !ok {
				t.Errorf("got ep.Connect(...) = %v, want = %v", err, &tcpip.ErrHostUnreachable{})
			}
		}

		// However, we can bind to a broadcast address to listen.
		if err := ep.Bind(tcpip.FullAddress{Addr: header.IPv4Broadcast, Port: 53, NIC: 1}); err != nil {
			t.Errorf("Bind failed: %v", err)
		}
	})

	t.Run("WithPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Add a valid primary endpoint address, now we can connect.
		protocolAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x02")).WithPrefix(),
		}
		if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr, err)
		}
		if err := ep.Connect(randomAddr); err != nil {
			t.Errorf("Connect failed: %v", err)
		}
	})
}

const (
	incomingNICID = 1
	outgoingNICID = 2
)

var (
	incomingIPv4Addr = tcpip.AddressWithPrefix{
		Address:   testutil.MustParse4("10.0.0.1"),
		PrefixLen: 8,
	}
	outgoingIPv4Addr = tcpip.AddressWithPrefix{
		Address:   testutil.MustParse4("11.0.0.1"),
		PrefixLen: 8,
	}
	defaultEndpointConfigs = map[tcpip.NICID]tcpip.AddressWithPrefix{
		incomingNICID: incomingIPv4Addr,
		outgoingNICID: outgoingIPv4Addr,
	}
	multicastIPv4Addr = testutil.MustParse4("225.0.0.0")
	remoteIPv4Addr1   = testutil.MustParse4("10.0.0.2")
	remoteIPv4Addr2   = testutil.MustParse4("11.0.0.2")
)

func TestAddMulticastRouteIPv4Errors(t *testing.T) {
	incomingEpSubnet := incomingIPv4Addr.Subnet()
	wantErr := &tcpip.ErrBadAddress{}

	tests := []struct {
		name    string
		srcAddr tcpip.Address
	}{
		{
			name:    "subnet-local broadcast source",
			srcAddr: incomingEpSubnet.Broadcast().To4(),
		},
		{
			name:    "broadcast source",
			srcAddr: header.IPv4Broadcast,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			for nicID, addr := range defaultEndpointConfigs {
				ep := channel.New(1, ipv4.MaxTotalSize, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{
					Protocol:          header.IPv4ProtocolNumber,
					AddressWithPrefix: addr,
				}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
			}

			if _, err := s.EnableMulticastForwardingForProtocol(ipv4.ProtocolNumber, &fakeMulticastEventDispatcher{}); err != nil {
				t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", ipv4.ProtocolNumber, err)
			}

			outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{{ID: outgoingNICID, MinTTL: 1}}

			addresses := stack.UnicastSourceAndMulticastDestination{
				Source:      test.srcAddr,
				Destination: multicastIPv4Addr,
			}

			route := stack.MulticastRoute{
				ExpectedInputInterface: outgoingNICID,
				OutgoingInterfaces:     outgoingInterfaces,
			}

			err := s.AddMulticastRoute(ipv4.ProtocolNumber, addresses, route)

			if !cmp.Equal(err, wantErr, cmpopts.EquateErrors()) {
				t.Errorf("got s.AddMulticastRoute(%d, %#v, %#v) = %s, want %s", ipv4.ProtocolNumber, addresses, route, err, wantErr)
			}
		})
	}
}

type icmpError struct {
	icmpType header.ICMPv4Type
	icmpCode header.ICMPv4Code
}

type packetOptions struct {
	ipFlags       uint8
	payloadLength int
	options       header.IPv4Options
}

func newICMPEchoPacket(t *testing.T, srcAddr, dstAddr tcpip.Address, ttl uint8, options packetOptions) (stack.PacketBufferPtr, []byte) {
	const (
		arbitraryICMPHeaderSequence = 123
		randomIdent                 = 42
	)

	t.Helper()
	ipHeaderLength := header.IPv4MinimumSize + len(options.options)
	if ipHeaderLength > header.IPv4MaximumHeaderSize {
		t.Fatalf("ipHeaderLength = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
	}
	totalLength := ipHeaderLength + header.ICMPv4MinimumSize + options.payloadLength
	hdr := prependable.New(totalLength)
	hdr.Prepend(options.payloadLength)
	icmpH := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	icmpH.SetIdent(randomIdent)
	icmpH.SetSequence(arbitraryICMPHeaderSequence)
	icmpH.SetType(header.ICMPv4Echo)
	icmpH.SetCode(header.ICMPv4UnusedCode)
	icmpH.SetChecksum(0)
	icmpH.SetChecksum(^checksum.Checksum(icmpH, 0))
	ip := header.IPv4(hdr.Prepend(ipHeaderLength))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLength),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		TTL:         ttl,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Flags:       options.ipFlags,
	})
	if len(options.options) != 0 {
		ip.SetHeaderLength(uint8(ipHeaderLength))
		// Copy options manually. We do not use Encode for options so we can
		// verify malformed options with handcrafted payloads.
		if want, got := copy(ip.Options(), options.options), len(options.options); want != got {
			t.Fatalf("got copy(ip.Options(), test.options) = %d, want = %d", got, want)
		}
	}
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	expectedICMPPayloadLength := func() int {
		maxICMPPacketLength := header.IPv4MinimumProcessableDatagramSize
		maxICMPPayloadLength := maxICMPPacketLength - header.ICMPv4MinimumSize - header.IPv4MinimumSize
		if len(hdr.View()) > maxICMPPayloadLength {
			return maxICMPPayloadLength
		}
		return len(hdr.View())
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(hdr.View()),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber

	return pkt, hdr.View()[:expectedICMPPayloadLength()]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func checkFragements(t *testing.T, ep *channel.Endpoint, expectedFragments []fragmentInfo, requestPkt stack.PacketBufferPtr) {
	t.Helper()
	var fragmentedPackets []stack.PacketBufferPtr
	for i := 0; i < len(expectedFragments); i++ {
		reply := ep.Read()
		if reply.IsNil() {
			t.Fatal("Expected ICMP Echo fragment through outgoing NIC")
		}
		fragmentedPackets = append(fragmentedPackets, reply)
	}

	// The forwarded packet's TTL will have been decremented.
	ipHeader := header.IPv4(requestPkt.NetworkHeader().Slice())
	ipHeader.SetTTL(ipHeader.TTL() - 1)

	// Forwarded packets have available header bytes equalling the sum of the
	// maximum IP header size and the maximum size allocated for link layer
	// headers. In this case, no size is allocated for link layer headers.
	expectedAvailableHeaderBytes := header.IPv4MaximumHeaderSize
	if err := compareFragments(fragmentedPackets, requestPkt, defaultMTU, expectedFragments, header.ICMPv4ProtocolNumber, true /* withIPHeader */, expectedAvailableHeaderBytes); err != nil {
		t.Error(err)
	}
	for _, pkt := range fragmentedPackets {
		pkt.DecRef()
	}
}

func TestForwarding(t *testing.T) {
	const randomTimeOffset = 0x10203040

	unreachableIPv4Addr := testutil.MustParse4("12.0.0.2")
	linkLocalIPv4Addr := testutil.MustParse4("169.254.0.0")

	tests := []struct {
		name                             string
		TTL                              uint8
		srcAddr                          tcpip.Address
		dstAddr                          tcpip.Address
		options                          header.IPv4Options
		forwardedOptions                 header.IPv4Options
		icmpError                        *icmpError
		expectedPacketUnrouteableErrors  uint64
		expectedInitializingSourceErrors uint64
		expectedLinkLocalSourceErrors    uint64
		expectedLinkLocalDestErrors      uint64
		expectedMalformedPacketErrors    uint64
		expectedExhaustedTTLErrors       uint64
		expectPacketForwarded            bool
	}{
		{
			name:    "TTL of zero",
			TTL:     0,
			srcAddr: remoteIPv4Addr1,
			dstAddr: remoteIPv4Addr2,
			icmpError: &icmpError{
				icmpType: header.ICMPv4TimeExceeded,
				icmpCode: header.ICMPv4TTLExceeded,
			},
			expectedExhaustedTTLErrors: 1,
			expectPacketForwarded:      false,
		},
		{
			name:                  "TTL of one",
			TTL:                   1,
			srcAddr:               remoteIPv4Addr1,
			dstAddr:               remoteIPv4Addr2,
			expectPacketForwarded: true,
		},
		{
			name:                  "TTL of two",
			TTL:                   2,
			srcAddr:               remoteIPv4Addr1,
			dstAddr:               remoteIPv4Addr2,
			expectPacketForwarded: true,
		},
		{
			name:                  "Max TTL",
			TTL:                   math.MaxUint8,
			srcAddr:               remoteIPv4Addr1,
			dstAddr:               remoteIPv4Addr2,
			expectPacketForwarded: true,
		},
		{
			name:                  "four EOL options",
			TTL:                   2,
			srcAddr:               remoteIPv4Addr1,
			dstAddr:               remoteIPv4Addr2,
			options:               header.IPv4Options{0, 0, 0, 0},
			forwardedOptions:      header.IPv4Options{0, 0, 0, 0},
			expectPacketForwarded: true,
		},
		{
			name:    "TS type 1 full",
			TTL:     2,
			srcAddr: remoteIPv4Addr1,
			dstAddr: remoteIPv4Addr2,
			options: header.IPv4Options{
				68, 12, 13, 0xF1,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			icmpError: &icmpError{
				icmpType: header.ICMPv4ParamProblem,
				icmpCode: header.ICMPv4UnusedCode,
			},
			expectedMalformedPacketErrors: 1,
		},
		{
			name:    "TS type 0",
			TTL:     2,
			srcAddr: remoteIPv4Addr1,
			dstAddr: remoteIPv4Addr2,
			options: header.IPv4Options{
				68, 24, 21, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
			},
			forwardedOptions: header.IPv4Options{
				68, 24, 25, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
			expectPacketForwarded: true,
		},
		{
			name:    "end of options list",
			TTL:     2,
			srcAddr: remoteIPv4Addr1,
			dstAddr: remoteIPv4Addr2,
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 10, 3, 99, // EOL followed by junk
				1, 2, 3, 4,
			},
			forwardedOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0,       // End of Options hides following bytes.
				0, 0, 0, // 7 bytes unknown option removed.
				0, 0, 0, 0,
			},
			expectPacketForwarded: true,
		},
		{
			name:    "Network unreachable",
			TTL:     2,
			srcAddr: remoteIPv4Addr1,
			dstAddr: unreachableIPv4Addr,
			icmpError: &icmpError{
				icmpType: header.ICMPv4DstUnreachable,
				icmpCode: header.ICMPv4NetUnreachable,
			},
			expectedPacketUnrouteableErrors: 1,
			expectPacketForwarded:           false,
		},
		{
			name:                        "Link local destination",
			TTL:                         2,
			srcAddr:                     remoteIPv4Addr1,
			dstAddr:                     linkLocalIPv4Addr,
			expectedLinkLocalDestErrors: 1,
			expectPacketForwarded:       false,
		},
		{
			name:                          "Link local source",
			TTL:                           2,
			srcAddr:                       linkLocalIPv4Addr,
			dstAddr:                       remoteIPv4Addr2,
			expectedLinkLocalSourceErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:                             "unspecified source",
			TTL:                              2,
			srcAddr:                          header.IPv4Any,
			dstAddr:                          remoteIPv4Addr2,
			expectedInitializingSourceErrors: 1,
			expectPacketForwarded:            false,
		},
		{
			name:                             "initializing source",
			TTL:                              2,
			srcAddr:                          tcpip.AddrFromSlice(net.ParseIP("0.0.0.255").To4()),
			dstAddr:                          remoteIPv4Addr2,
			expectedInitializingSourceErrors: 1,
			expectPacketForwarded:            false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s
			clock := ctx.clock

			// Advance the clock by some unimportant amount to make
			// it give a more recognisable signature than 00,00,00,00.
			clock.Advance(time.Millisecond * randomTimeOffset)

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				ep := channel.New(1, ipv4.MaxTotalSize, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				endpoints[nicID] = ep
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: incomingIPv4Addr.Subnet(),
					NIC:         incomingNICID,
				},
				{
					Destination: outgoingIPv4Addr.Subnet(),
					NIC:         outgoingNICID,
				},
			})

			if err := s.SetForwardingDefaultAndAllNICs(header.IPv4ProtocolNumber, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", header.IPv4ProtocolNumber, err)
			}

			requestPkt, expectedICMPErrorPayload := newICMPEchoPacket(t, test.srcAddr, test.dstAddr, test.TTL, packetOptions{options: test.options})
			defer requestPkt.DecRef()

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}
			incomingEndpoint.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply := incomingEndpoint.Read()

			if test.icmpError != nil {
				if reply.IsNil() {
					t.Fatalf("Expected ICMP packet type %d through incoming NIC", test.icmpError.icmpType)
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(incomingIPv4Addr.Address),
					checker.DstAddr(test.srcAddr),
					checker.TTL(ipv4.DefaultTTL),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(test.icmpError.icmpType),
						checker.ICMPv4Code(test.icmpError.icmpCode),
						checker.ICMPv4Payload(expectedICMPErrorPayload),
					),
				)
				reply.DecRef()
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if test.expectPacketForwarded {
				reply := outgoingEndpoint.Read()
				if reply.IsNil() {
					t.Fatal("Expected ICMP Echo packet through outgoing NIC")
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(test.srcAddr),
					checker.DstAddr(test.dstAddr),
					checker.TTL(test.TTL-1),
					checker.IPv4Options(test.forwardedOptions),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(header.ICMPv4Echo),
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Payload(nil),
					),
				)
				reply.DecRef()
			} else {
				if reply := outgoingEndpoint.Read(); !reply.IsNil() {
					t.Fatalf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
				}
			}

			if got, want := s.Stats().IP.Forwarding.InitializingSource.Value(), test.expectedInitializingSourceErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.InitializingSource.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.LinkLocalSource.Value(), test.expectedLinkLocalSourceErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.LinkLocalSource.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.LinkLocalDestination.Value(), test.expectedLinkLocalDestErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.LinkLocalDestination.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.expectedMalformedPacketErrors; got != want {
				t.Errorf("s.Stats().IP.MalformedPacketsReceived.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.ExhaustedTTL.Value(), test.expectedExhaustedTTLErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.ExhaustedTTL.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.Unrouteable.Value(), test.expectedPacketUnrouteableErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Unrouteable.Value() = %d, want = %d", got, want)
			}

			expectedTotalErrors := test.expectedLinkLocalSourceErrors + test.expectedLinkLocalDestErrors + test.expectedMalformedPacketErrors + test.expectedExhaustedTTLErrors + test.expectedPacketUnrouteableErrors + test.expectedInitializingSourceErrors
			if got, want := s.Stats().IP.Forwarding.Errors.Value(), expectedTotalErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

func TestFragmentForwarding(t *testing.T) {
	const (
		defaultMTU           = 1000
		defaultPayloadLength = defaultMTU + 4
		packetTTL            = 2
	)

	tests := []struct {
		name                       string
		ipFlags                    uint8
		icmpError                  *icmpError
		expectedPacketTooBigErrors uint64
		expectedFragmentsForwarded []fragmentInfo
	}{
		{
			name:    "Fragmentation needed and DF set",
			ipFlags: header.IPv4FlagDontFragment,
			// We've picked this MTU because it is:
			//
			// 1) Greater than the minimum MTU that IPv4 hosts are required to process
			// (576 bytes). As per RFC 1812, Section 4.3.2.3:
			//
			//   The ICMP datagram SHOULD contain as much of the original datagram as
			//   possible without the length of the ICMP datagram exceeding 576 bytes.
			//
			// Therefore, setting an MTU greater than 576 bytes ensures that we can fit a
			// complete ICMP packet on the incoming endpoint (and make assertions about
			// it).
			//
			// 2) Less than `ipv4.MaxTotalSize`, which lets us build an IPv4 packet whose
			// size exceeds the MTU.
			icmpError: &icmpError{
				icmpType: header.ICMPv4DstUnreachable,
				icmpCode: header.ICMPv4FragmentationNeeded,
			},
			expectedFragmentsForwarded: []fragmentInfo{},
			expectedPacketTooBigErrors: 1,
		},
		{
			name: "Fragmentation needed and DF not set",
			expectedFragmentsForwarded: []fragmentInfo{
				// The first fragment has a length of the greatest multiple of 8 which is
				// less than or equal to to `mtu - header.IPv4MinimumSize`.
				{offset: 0, payloadSize: uint16(976), more: true},
				// The next fragment holds the rest of the packet.
				{offset: uint16(976), payloadSize: 36, more: false},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				// For the input interface, we expect at most a single packet in
				// response to our ICMP Echo Request.
				expectedEmittedPacketCount := 1

				if nicID == outgoingNICID {
					expectedEmittedPacketCount = max(1, len(test.expectedFragmentsForwarded))
				}

				ep := channel.New(expectedEmittedPacketCount, defaultMTU, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				endpoints[nicID] = ep
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: incomingIPv4Addr.Subnet(),
					NIC:         incomingNICID,
				},
				{
					Destination: outgoingIPv4Addr.Subnet(),
					NIC:         outgoingNICID,
				},
			})

			if err := s.SetForwardingDefaultAndAllNICs(header.IPv4ProtocolNumber, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", header.IPv4ProtocolNumber, err)
			}

			requestPkt, expectedICMPErrorPayload := newICMPEchoPacket(t, remoteIPv4Addr1, remoteIPv4Addr2, packetTTL, packetOptions{ipFlags: test.ipFlags, payloadLength: defaultPayloadLength})
			defer requestPkt.DecRef()

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}
			incomingEndpoint.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply := incomingEndpoint.Read()

			if test.icmpError != nil {
				if reply.IsNil() {
					t.Fatalf("Expected ICMP packet type %d through incoming NIC", test.icmpError.icmpType)
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(incomingIPv4Addr.Address),
					checker.DstAddr(remoteIPv4Addr1),
					checker.TTL(ipv4.DefaultTTL),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(test.icmpError.icmpType),
						checker.ICMPv4Code(test.icmpError.icmpCode),
						checker.ICMPv4Payload(expectedICMPErrorPayload),
					),
				)
				reply.DecRef()
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if len(test.expectedFragmentsForwarded) > 0 {
				checkFragements(t, outgoingEndpoint, test.expectedFragmentsForwarded, requestPkt)
			} else {
				if reply := outgoingEndpoint.Read(); !reply.IsNil() {
					t.Errorf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
				}
			}

			if got, want := s.Stats().IP.Forwarding.PacketTooBig.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.PacketTooBig.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.Errors.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

func TestMulticastFragmentForwarding(t *testing.T) {
	const (
		defaultMTU           = 1000
		defaultPayloadLength = defaultMTU + 4
		packetTTL            = 2
		multicastRouteMinTTL = 2
	)

	tests := []struct {
		name                       string
		ipFlags                    uint8
		icmpError                  *icmpError
		expectedPacketTooBigErrors uint64
		expectedFragmentsForwarded []fragmentInfo
	}{
		{
			name:    "Fragmentation needed and DF set",
			ipFlags: header.IPv4FlagDontFragment,
			// We've picked this MTU because it is:
			//
			// 1) Greater than the minimum MTU that IPv4 hosts are required to process
			// (576 bytes). As per RFC 1812, Section 4.3.2.3:
			//
			//   The ICMP datagram SHOULD contain as much of the original datagram as
			//   possible without the length of the ICMP datagram exceeding 576 bytes.
			//
			// Therefore, setting an MTU greater than 576 bytes ensures that we can fit a
			// complete ICMP packet on the incoming endpoint (and make assertions about
			// it).
			//
			// 2) Less than `ipv4.MaxTotalSize`, which lets us build an IPv4 packet whose
			// size exceeds the MTU.
			icmpError: &icmpError{
				icmpType: header.ICMPv4DstUnreachable,
				icmpCode: header.ICMPv4FragmentationNeeded,
			},
			expectedFragmentsForwarded: []fragmentInfo{},
			expectedPacketTooBigErrors: 1,
		},
		{
			name: "Fragmentation needed and DF not set",
			expectedFragmentsForwarded: []fragmentInfo{
				// The first fragment has a length of the greatest multiple of 8 which is
				// less than or equal to to `mtu - header.IPv4MinimumSize`.
				{offset: 0, payloadSize: uint16(976), more: true},
				// The next fragment holds the rest of the packet.
				{offset: uint16(976), payloadSize: 36, more: false},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			if _, err := s.EnableMulticastForwardingForProtocol(ipv4.ProtocolNumber, &fakeMulticastEventDispatcher{}); err != nil {
				t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", ipv4.ProtocolNumber, err)
			}

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				// For the input interface, we expect at most a single packet in
				// response to our ICMP Echo Request.
				expectedEmittedPacketCount := 1

				if nicID == outgoingNICID {
					expectedEmittedPacketCount = max(1, len(test.expectedFragmentsForwarded))
				}

				ep := channel.New(expectedEmittedPacketCount, defaultMTU, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				s.SetNICMulticastForwarding(nicID, ipv4.ProtocolNumber, true /* enabled */)
				endpoints[nicID] = ep
			}

			// Add a route that could theoretically be used to send an ICMP error.
			// Note that such an error should never be sent for multicast.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         outgoingNICID,
				},
			})

			outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
				{ID: outgoingNICID, MinTTL: multicastRouteMinTTL},
			}
			addresses := stack.UnicastSourceAndMulticastDestination{
				Source:      remoteIPv4Addr1,
				Destination: multicastIPv4Addr,
			}

			route := stack.MulticastRoute{
				ExpectedInputInterface: incomingNICID,
				OutgoingInterfaces:     outgoingInterfaces,
			}

			if err := s.AddMulticastRoute(ipv4.ProtocolNumber, addresses, route); err != nil {
				t.Fatalf("s.AddMulticastRoute(%d, %#v, %#v): %s", ipv4.ProtocolNumber, addresses, route, err)
			}

			requestPkt, _ := newICMPEchoPacket(t, remoteIPv4Addr1, multicastIPv4Addr, packetTTL, packetOptions{ipFlags: test.ipFlags, payloadLength: defaultPayloadLength})
			defer requestPkt.DecRef()

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}
			incomingEndpoint.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply := incomingEndpoint.Read()

			if !reply.IsNil() {
				// An ICMP error should never be sent in response to a multicast packet.
				t.Errorf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if len(test.expectedFragmentsForwarded) > 0 {
				checkFragements(t, outgoingEndpoint, test.expectedFragmentsForwarded, requestPkt)
			} else {
				if reply := outgoingEndpoint.Read(); !reply.IsNil() {
					t.Errorf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
				}
			}

			if got, want := s.Stats().IP.Forwarding.PacketTooBig.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.PacketTooBig.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.Errors.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

func TestMulticastForwardingOptions(t *testing.T) {
	const (
		randomTimeOffset     = 0x10203040
		packetTTL            = 2
		multicastRouteMinTTL = 2
	)

	tests := []struct {
		name                          string
		options                       header.IPv4Options
		forwardedOptions              header.IPv4Options
		expectedMalformedPacketErrors uint64
		expectPacketForwarded         bool
	}{
		{
			name:                  "four EOL options",
			options:               header.IPv4Options{0, 0, 0, 0},
			forwardedOptions:      header.IPv4Options{0, 0, 0, 0},
			expectPacketForwarded: true,
		},
		{
			name: "TS type 1 full",
			options: header.IPv4Options{
				68, 12, 13, 0xF1,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			expectedMalformedPacketErrors: 1,
		},
		{
			name: "TS type 0",
			options: header.IPv4Options{
				68, 24, 21, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
			},
			forwardedOptions: header.IPv4Options{
				68, 24, 25, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
			expectPacketForwarded: true,
		},
		{
			name: "end of options list",
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 10, 3, 99, // EOL followed by junk
				1, 2, 3, 4,
			},
			forwardedOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0,       // End of Options hides following bytes.
				0, 0, 0, // 7 bytes unknown option removed.
				0, 0, 0, 0,
			},
			expectPacketForwarded: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s
			clock := ctx.clock

			// Advance the clock by some unimportant amount to make
			// it give a more recognisable signature than 00,00,00,00.
			clock.Advance(time.Millisecond * randomTimeOffset)

			if _, err := s.EnableMulticastForwardingForProtocol(ipv4.ProtocolNumber, &fakeMulticastEventDispatcher{}); err != nil {
				t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", ipv4.ProtocolNumber, err)
			}

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				ep := channel.New(1, ipv4.MaxTotalSize, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				s.SetNICMulticastForwarding(nicID, ipv4.ProtocolNumber, true /* enabled */)
				endpoints[nicID] = ep
			}

			// Add a route that could theoretically be used to send an ICMP error.
			// Note that such an error should never be sent for multicast.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         outgoingNICID,
				},
			})

			outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
				{ID: outgoingNICID, MinTTL: multicastRouteMinTTL},
			}
			addresses := stack.UnicastSourceAndMulticastDestination{
				Source:      remoteIPv4Addr1,
				Destination: multicastIPv4Addr,
			}

			route := stack.MulticastRoute{
				ExpectedInputInterface: incomingNICID,
				OutgoingInterfaces:     outgoingInterfaces,
			}

			if err := s.AddMulticastRoute(ipv4.ProtocolNumber, addresses, route); err != nil {
				t.Fatalf("s.AddMulticastRoute(%d, %#v, %#v): %s", ipv4.ProtocolNumber, addresses, route, err)
			}

			requestPkt, _ := newICMPEchoPacket(t, remoteIPv4Addr1, multicastIPv4Addr, packetTTL, packetOptions{options: test.options})
			defer requestPkt.DecRef()

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}
			incomingEndpoint.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply := incomingEndpoint.Read()

			if !reply.IsNil() {
				// An ICMP error should never be sent in response to a multicast packet.
				t.Errorf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if test.expectPacketForwarded {
				reply := outgoingEndpoint.Read()
				if reply.IsNil() {
					t.Fatal("Expected ICMP Echo packet through outgoing NIC")
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(remoteIPv4Addr1),
					checker.DstAddr(multicastIPv4Addr),
					checker.TTL(packetTTL-1),
					checker.IPv4Options(test.forwardedOptions),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Type(header.ICMPv4Echo),
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Payload(nil),
					),
				)
				reply.DecRef()
			} else {
				if reply := outgoingEndpoint.Read(); !reply.IsNil() {
					t.Fatalf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
				}
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.expectedMalformedPacketErrors; got != want {
				t.Errorf("s.Stats().IP.MalformedPacketsReceived.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.Errors.Value(), test.expectedMalformedPacketErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

// TestIPv4Sanity sends IP/ICMP packets with various problems to the stack and
// checks the response.
func TestIPv4Sanity(t *testing.T) {
	const (
		ttl            = 255
		nicID          = 1
		randomSequence = 123
		randomIdent    = 42
		// In some cases Linux sets the error pointer to the start of the option
		// (offset 0) instead of the actual wrong value, which is the length byte
		// (offset 1). For compatibility we must do the same. Use this constant
		// to indicate where this happens.
		pointerOffsetForInvalidLength = 0
		randomTimeOffset              = 0x10203040
	)
	var (
		ipv4Addr = tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP("192.168.1.58").To4()),
			PrefixLen: 24,
		}
		remoteIPv4Addr = tcpip.AddrFromSlice(net.ParseIP("10.0.0.1").To4())
	)

	tests := []struct {
		name                string
		headerLength        uint8 // value of 0 means "use correct size"
		badHeaderChecksum   bool
		maxTotalLength      uint16
		transportProtocol   uint8
		TTL                 uint8
		options             header.IPv4Options
		replyOptions        header.IPv4Options // reply should look like this
		shouldFail          bool
		expectErrorICMP     bool
		ICMPType            header.ICMPv4Type
		ICMPCode            header.ICMPv4Code
		paramProblemPointer uint8
	}{
		{
			name:              "valid no options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
		},
		{
			name:              "bad header checksum",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			badHeaderChecksum: true,
			shouldFail:        true,
		},
		// The TTL tests check that we are not rejecting an incoming packet
		// with a zero or one TTL, which has been a point of confusion in the
		// past as RFC 791 says: "If this field contains the value zero, then the
		// datagram must be destroyed". However RFC 1122 section 3.2.1.7 clarifies
		// for the case of the destination host, stating as follows.
		//
		//      A host MUST NOT send a datagram with a Time-to-Live (TTL)
		//      value of zero.
		//
		//      A host MUST NOT discard a datagram just because it was
		//      received with TTL less than 2.
		{
			name:              "zero TTL",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               0,
		},
		{
			name:              "one TTL",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               1,
		},
		{
			name:              "End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{0, 0, 0, 0},
			replyOptions:      header.IPv4Options{0, 0, 0, 0},
		},
		{
			name:              "NOP options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{1, 1, 1, 1},
			replyOptions:      header.IPv4Options{1, 1, 1, 1},
		},
		{
			name:              "NOP and End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{1, 1, 0, 0},
			replyOptions:      header.IPv4Options{1, 1, 0, 0},
		},
		{
			name:              "bad header length",
			headerLength:      header.IPv4MinimumSize - 1,
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (0)",
			maxTotalLength:    0,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (ip - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad total length (ip + icmp - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize + header.ICMPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
		},
		{
			name:              "bad protocol",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: 99,
			TTL:               ttl,
			shouldFail:        true,
			expectErrorICMP:   true,
			ICMPType:          header.ICMPv4DstUnreachable,
			ICMPCode:          header.ICMPv4ProtoUnreachable,
		},
		{
			name:              "timestamp option overflow",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			replyOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
		},
		{
			name:              "timestamp option overflow full",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 12, 13, 0xF1,
				//            ^   Counter full (15/0xF)
				192, 168, 1, 12,
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 3,
			replyOptions:        header.IPv4Options{},
		},
		{
			name:              "unknown option",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           header.IPv4Options{10, 4, 9, 0},
			//                        ^^
			// The unknown option should be stripped out of the reply.
			replyOptions: header.IPv4Options{},
		},
		{
			name:              "bad option - no length",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				1, 1, 1, 68,
				//        ^-start of timestamp.. but no length..
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 3,
		},
		{
			name:              "bad option - length 0",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 0, 9, 0,
				//  ^
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "bad option - length 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 1, 9, 0,
				//  ^
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "bad option - length big",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 9, 9, 0,
				//  ^
				// There are only 8 bytes allocated to options so 9 bytes of timestamp
				// space is not possible. (Second byte)
				1, 2, 3, 4,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			// This tests for some linux compatible behaviour.
			// The ICMP pointer returned is 22 for Linux but the
			// error is actually in spot 21.
			name:              "bad option - length bad",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			// Timestamps are in multiples of 4 or 8 but never 7.
			// The option space should be padded out.
			options: header.IPv4Options{
				68, 7, 5, 0,
				//  ^  ^ Linux points here which is wrong.
				//  | Not a multiple of 4
				1, 2, 3, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		{
			name:              "multiple type 0 with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 24, 21, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
				68, 24, 25, 0x00,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// The timestamp area is full so add to the overflow count.
			name:              "multiple type 1 timestamps",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 20, 21, 0x11,
				//            ^
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
			},
			// Overflow count is the top nibble of the 4th byte.
			replyOptions: header.IPv4Options{
				68, 20, 21, 0x21,
				//            ^
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
			},
		},
		{
			name:              "multiple type 1 timestamps with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 28, 21, 0x01,
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
				68, 28, 29, 0x01,
				192, 168, 1, 12,
				1, 2, 3, 4,
				192, 168, 1, 13,
				5, 6, 7, 8,
				192, 168, 1, 58, // New IP Address.
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// Timestamp pointer uses one based counting so 0 is invalid.
			name:              "timestamp pointer invalid",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, 0, 0x00,
				//      ^ 0 instead of 5 or more.
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 2,
		},
		{
			// Timestamp pointer cannot be less than 5. It must point past the header
			// which is 4 bytes. (1 based counting)
			name:              "timestamp pointer too small by 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, header.IPv4OptionTimestampHdrLength, 0x00,
				//          ^ header is 4 bytes, so 4 should fail.
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		{
			name:              "valid timestamp pointer",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 8, header.IPv4OptionTimestampHdrLength + 1, 0x00,
				//          ^ header is 4 bytes, so 5 should succeed.
				0, 0, 0, 0,
			},
			replyOptions: header.IPv4Options{
				68, 8, 9, 0x00,
				0x00, 0xad, 0x1c, 0x40, // time we expect from fakeclock
			},
		},
		{
			// Needs 8 bytes for a type 1 timestamp but there are only 4 free.
			name:              "bad timer element alignment",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 20, 17, 0x01,
				//  ^^  ^^   20 byte area, next free spot at 17.
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptTSPointerOffset,
		},
		// End of option list with illegal option after it, which should be ignored.
		{
			name:              "end of options list",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 12, 13, 0x11,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0, 10, 3, 99, // EOL followed by junk
			},
			replyOptions: header.IPv4Options{
				68, 12, 13, 0x21,
				192, 168, 1, 12,
				1, 2, 3, 4,
				0,       // End of Options hides following bytes.
				0, 0, 0, // 3 bytes unknown option removed.
			},
		},
		{
			// Timestamp with a size much too small.
			name:              "timestamp truncated",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				68, 1, 0, 0,
				//  ^ Smallest possible is 8. Linux points at the 68.
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + pointerOffsetForInvalidLength,
		},
		{
			name:              "single record route with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, 4, //  3 byte header
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			name:              "multiple record route with room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 23, 20, //  3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 23, 24,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			name:              "single record route with no room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Unlike timestamp, this should just succeed.
			name:              "multiple record route with no room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 23, 24, // 3 byte header
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 23, 24,
				1, 2, 3, 4,
				5, 6, 7, 8,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Pointer uses one based counting so 0 is invalid.
			name:              "record route pointer zero",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, 0, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			// Pointer must be 4 or more as it must point past the 3 byte header
			// using 1 based counting. 3 should fail.
			name:              "record route pointer too small by 1",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, header.IPv4OptionRecordRouteHdrLength, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			// Pointer must be 4 or more as it must point past the 3 byte header
			// using 1 based counting. Check 4 passes. (Duplicates "single
			// record route with room")
			name:              "valid record route pointer",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, header.IPv4OptionRecordRouteHdrLength + 1, // 3 byte header
				0, 0, 0, 0,
				0,
			},
			replyOptions: header.IPv4Options{
				7, 7, 8, // 3 byte header
				192, 168, 1, 58, // New IP Address.
				0, // padding to multiple of 4 bytes.
			},
		},
		{
			// Confirm Linux bug for bug compatibility.
			// Linux returns slot 22 but the error is in slot 21.
			name:              "multiple record route with not enough room",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 8, 8, // 3 byte header
				// ^  ^ Linux points here. We must too.
				// | Not enough room. 1 byte free, need 4.
				1, 2, 3, 4,
				0,
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + header.IPv4OptRRPointerOffset,
		},
		{
			name:              "duplicate record route",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options: header.IPv4Options{
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				7, 7, 8, // 3 byte header
				1, 2, 3, 4,
				0, 0, // pad
			},
			shouldFail:          true,
			expectErrorICMP:     true,
			ICMPType:            header.ICMPv4ParamProblem,
			ICMPCode:            header.ICMPv4UnusedCode,
			paramProblemPointer: header.IPv4MinimumSize + 7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s
			clock := ctx.clock

			// Advance the clock by some unimportant amount to make
			// it give a more recognisable signature than 00,00,00,00.
			clock.Advance(time.Millisecond * randomTimeOffset)

			// We expect at most a single packet in response to our ICMP Echo Request.
			e := channel.New(1, ipv4.MaxTotalSize, "")
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, ipv4ProtoAddr, err)
			}

			// Default routes for IPv4 so ICMP can find a route to the remote
			// node when attempting to send the ICMP Echo Reply.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			if len(test.options)%4 != 0 {
				t.Fatalf("options must be aligned to 32 bits, invalid test options: %x (len=%d)", test.options, len(test.options))
			}
			ipHeaderLength := header.IPv4MinimumSize + len(test.options)
			if ipHeaderLength > header.IPv4MaximumHeaderSize {
				t.Fatalf("IP header length too large: got = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
			}
			totalLen := uint16(ipHeaderLength + header.ICMPv4MinimumSize)
			hdr := prependable.New(int(totalLen))
			icmpH := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))

			// Specify ident/seq to make sure we get the same in the response.
			icmpH.SetIdent(randomIdent)
			icmpH.SetSequence(randomSequence)
			icmpH.SetType(header.ICMPv4Echo)
			icmpH.SetCode(header.ICMPv4UnusedCode)
			icmpH.SetChecksum(0)
			icmpH.SetChecksum(^checksum.Checksum(icmpH, 0))
			ip := header.IPv4(hdr.Prepend(ipHeaderLength))
			if test.maxTotalLength < totalLen {
				totalLen = test.maxTotalLength
			}
			ip.Encode(&header.IPv4Fields{
				TotalLength: totalLen,
				Protocol:    test.transportProtocol,
				TTL:         test.TTL,
				SrcAddr:     remoteIPv4Addr,
				DstAddr:     ipv4Addr.Address,
			})
			if test.headerLength != 0 {
				ip.SetHeaderLength(test.headerLength)
			} else {
				// Set the calculated header length, since we may manually add options.
				ip.SetHeaderLength(uint8(ipHeaderLength))
			}
			if len(test.options) != 0 {
				// Copy options manually. We do not use Encode for options so we can
				// verify malformed options with handcrafted payloads.
				if want, got := copy(ip.Options(), test.options), len(test.options); want != got {
					t.Fatalf("got copy(ip.Options(), test.options) = %d, want = %d", got, want)
				}
			}
			ip.SetChecksum(0)
			ipHeaderChecksum := ip.CalculateChecksum()
			if test.badHeaderChecksum {
				ipHeaderChecksum += 42
			}
			ip.SetChecksum(^ipHeaderChecksum)
			requestPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(hdr.View()),
			})
			defer requestPkt.DecRef()
			e.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply := e.Read()
			if reply.IsNil() {
				if test.shouldFail {
					if test.expectErrorICMP {
						t.Fatalf("ICMP error response (type %d, code %d) missing", test.ICMPType, test.ICMPCode)
					}
					return // Expected silent failure.
				}
				t.Fatal("expected ICMP echo reply missing")
			}
			defer reply.DecRef()

			// We didn't expect a packet. Register our surprise but carry on to
			// provide more information about what we got.
			if test.shouldFail && !test.expectErrorICMP {
				t.Error("unexpected packet response")
			}

			// Check the route that brought the packet to us.
			if reply.EgressRoute.LocalAddress != ipv4Addr.Address {
				t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", reply.EgressRoute.LocalAddress, ipv4Addr.Address)
			}
			if reply.EgressRoute.RemoteAddress != remoteIPv4Addr {
				t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", reply.EgressRoute.RemoteAddress, remoteIPv4Addr)
			}

			// Make sure it's all in one buffer for checker.
			replyIPHeader := stack.PayloadSince(reply.NetworkHeader())
			defer replyIPHeader.Release()

			// At this stage we only know it's probably an IP+ICMP header so verify
			// that much.
			checker.IPv4(t, replyIPHeader,
				checker.SrcAddr(ipv4Addr.Address),
				checker.DstAddr(remoteIPv4Addr),
				checker.ICMPv4(
					checker.ICMPv4Checksum(),
				),
			)

			// Don't proceed any further if the checker found problems.
			if t.Failed() {
				t.FailNow()
			}

			// OK it's ICMP. We can safely look at the type now.
			replyICMPHeader := header.ICMPv4(header.IPv4(replyIPHeader.AsSlice()).Payload())
			switch replyICMPHeader.Type() {
			case header.ICMPv4ParamProblem:
				if !test.shouldFail {
					t.Fatalf("got Parameter Problem with pointer %d, wanted Echo Reply", replyICMPHeader.Pointer())
				}
				if !test.expectErrorICMP {
					t.Fatalf("got Parameter Problem with pointer %d, wanted no response", replyICMPHeader.Pointer())
				}
				checker.IPv4(t, replyIPHeader,
					checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+requestPkt.Size())),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.ICMPv4(
						checker.ICMPv4Type(test.ICMPType),
						checker.ICMPv4Code(test.ICMPCode),
						checker.ICMPv4Pointer(test.paramProblemPointer),
						checker.ICMPv4Payload(hdr.View()),
					),
				)
				return
			case header.ICMPv4DstUnreachable:
				if !test.shouldFail {
					t.Fatalf("got ICMP error packet type %d, code %d, wanted Echo Reply",
						header.ICMPv4DstUnreachable, replyICMPHeader.Code())
				}
				if !test.expectErrorICMP {
					t.Fatalf("got ICMP error packet type %d, code %d, wanted no response",
						header.ICMPv4DstUnreachable, replyICMPHeader.Code())
				}
				checker.IPv4(t, replyIPHeader,
					checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+requestPkt.Size())),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.ICMPv4(
						checker.ICMPv4Type(test.ICMPType),
						checker.ICMPv4Code(test.ICMPCode),
						checker.ICMPv4Payload(hdr.View()),
					),
				)
				return
			case header.ICMPv4EchoReply:
				if test.shouldFail {
					if !test.expectErrorICMP {
						t.Error("got Echo Reply packet, want no response")
					} else {
						t.Errorf("got Echo Reply, want ICMP error type %d, code %d", test.ICMPType, test.ICMPCode)
					}
				}
				// If the IP options change size then the packet will change size, so
				// some IP header fields will need to be adjusted for the checks.
				sizeChange := len(test.replyOptions) - len(test.options)

				checker.IPv4(t, replyIPHeader,
					checker.IPv4HeaderLength(ipHeaderLength+sizeChange),
					checker.IPv4Options(test.replyOptions),
					checker.IPFullLength(uint16(requestPkt.Size()+sizeChange)),
					checker.ICMPv4(
						checker.ICMPv4Checksum(),
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Seq(randomSequence),
						checker.ICMPv4Ident(randomIdent),
					),
				)
			default:
				t.Fatalf("unexpected ICMP response, got type %d, want = %d, %d or %d",
					replyICMPHeader.Type(), header.ICMPv4EchoReply, header.ICMPv4DstUnreachable, header.ICMPv4ParamProblem)
			}
		})
	}
}

// compareFragments compares the contents of a set of fragmented packets against
// the contents of a source packet.
//
// If withIPHeader is set to true, we will validate the fragmented packets' IP
// headers against the source packet's IP header. If set to false, we validate
// the fragmented packets' IP headers against each other.
func compareFragments(packets []stack.PacketBufferPtr, sourcePacket stack.PacketBufferPtr, mtu uint32, wantFragments []fragmentInfo, proto tcpip.TransportProtocolNumber, withIPHeader bool, expectedAvailableHeaderBytes int) error {
	// Make a complete array of the sourcePacket packet.
	var source header.IPv4
	buf := sourcePacket.ToBuffer()
	defer buf.Release()

	// If the packet to be fragmented contains an IPv4 header, use that header for
	// validating fragment headers. Else, use the header of the first fragment.
	if withIPHeader {
		source = header.IPv4(buf.Flatten())
	} else {
		source = header.IPv4(packets[0].NetworkHeader().Slice())
		source = append(source, buf.Flatten()...)
	}

	// Make a copy of the IP header, which will be modified in some fields to make
	// an expected header.
	sourceCopy := header.IPv4(append([]byte{}, source[:source.HeaderLength()]...))
	sourceCopy.SetChecksum(0)
	sourceCopy.SetFlagsFragmentOffset(0, 0)
	sourceCopy.SetTotalLength(0)
	// Build up an array of the bytes sent.
	var reassembledPayload bufferv2.Buffer
	defer reassembledPayload.Release()
	for i, packet := range packets {
		// Confirm that the packet is valid.
		allBytes := packet.ToBuffer()
		defer allBytes.Release()
		fragmentIPHeader := header.IPv4(allBytes.Flatten())
		if !fragmentIPHeader.IsValid(len(fragmentIPHeader)) {
			return fmt.Errorf("fragment #%d: IP packet is invalid:\n%s", i, hex.Dump(fragmentIPHeader))
		}
		if got := len(fragmentIPHeader); got > int(mtu) {
			return fmt.Errorf("fragment #%d: got len(fragmentIPHeader) = %d, want <= %d", i, got, mtu)
		}
		if got := fragmentIPHeader.TransportProtocol(); got != proto {
			return fmt.Errorf("fragment #%d: got fragmentIPHeader.TransportProtocol() = %d, want = %d", i, got, uint8(proto))
		}
		if got, want := packet.NetworkProtocolNumber, sourcePacket.NetworkProtocolNumber; got != want {
			return fmt.Errorf("fragment #%d: got fragment.NetworkProtocolNumber = %d, want = %d", i, got, want)
		}
		if got := packet.AvailableHeaderBytes(); got != expectedAvailableHeaderBytes {
			return fmt.Errorf("fragment #%d: got packet.AvailableHeaderBytes() = %d, want = %d", i, got, expectedAvailableHeaderBytes)
		}
		if got, want := fragmentIPHeader.CalculateChecksum(), uint16(0xffff); got != want {
			return fmt.Errorf("fragment #%d: got ip.CalculateChecksum() = %#x, want = %#x", i, got, want)
		}
		if wantFragments[i].more {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()|header.IPv4FlagMoreFragments, wantFragments[i].offset)
		} else {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()&^header.IPv4FlagMoreFragments, wantFragments[i].offset)
		}
		reassembledPayload.Append(packet.TransportHeader().View())
		reassembledPayload.Append(packet.Data().AsRange().ToView())
		// Clear out the checksum and length from the ip because we can't compare
		// it.
		sourceCopy.SetTotalLength(wantFragments[i].payloadSize + header.IPv4MinimumSize)
		sourceCopy.SetChecksum(0)
		sourceCopy.SetChecksum(^sourceCopy.CalculateChecksum())

		// If we are validating against the original IP header, we should exclude the
		// ID field, which will only be set fo fragmented packets.
		if withIPHeader {
			fragmentIPHeader.SetID(0)
			fragmentIPHeader.SetChecksum(0)
			fragmentIPHeader.SetChecksum(^fragmentIPHeader.CalculateChecksum())
		}
		if diff := cmp.Diff(fragmentIPHeader[:fragmentIPHeader.HeaderLength()], sourceCopy[:sourceCopy.HeaderLength()]); diff != "" {
			return fmt.Errorf("fragment #%d: fragmentIPHeader mismatch (-want +got):\n%s", i, diff)
		}
	}

	expected := []byte(source[source.HeaderLength():])
	if diff := cmp.Diff(expected, reassembledPayload.Flatten()); diff != "" {
		return fmt.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
	}

	return nil
}

type fragmentInfo struct {
	offset      uint16
	more        bool
	payloadSize uint16
}

var fragmentationTests = []struct {
	description           string
	mtu                   uint32
	transportHeaderLength int
	payloadSize           int
	wantFragments         []fragmentInfo
}{
	{
		description:           "No fragmentation",
		mtu:                   1280,
		transportHeaderLength: 0,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1000, more: false},
		},
	},
	{
		description:           "Fragmented",
		mtu:                   1280,
		transportHeaderLength: 0,
		payloadSize:           2000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 744, more: false},
		},
	},
	{
		description:           "Fragmented with the minimum mtu",
		mtu:                   header.IPv4MinimumMTU,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "Fragmented with mtu not a multiple of 8",
		mtu:                   header.IPv4MinimumMTU + 1,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "No fragmentation with big header",
		mtu:                   2000,
		transportHeaderLength: 100,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1100, more: false},
		},
	},
	{
		description:           "Fragmented with big header",
		mtu:                   1280,
		transportHeaderLength: 100,
		payloadSize:           1200,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 44, more: false},
		},
	},
	{
		description:           "Fragmented with MTU smaller than header",
		mtu:                   300,
		transportHeaderLength: 1000,
		payloadSize:           500,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 280, more: true},
			{offset: 280, payloadSize: 280, more: true},
			{offset: 560, payloadSize: 280, more: true},
			{offset: 840, payloadSize: 280, more: true},
			{offset: 1120, payloadSize: 280, more: true},
			{offset: 1400, payloadSize: 100, more: false},
		},
	},
}

func TestFragmentationWritePacket(t *testing.T) {
	const ttl = 42

	for _, ft := range fragmentationTests {
		t.Run(ft.description, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()

			ep := iptestutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			defer ep.Close()
			r := buildRoute(t, ctx, ep)
			defer r.Release()
			pkt := iptestutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			defer pkt.DecRef()
			source := pkt.Clone()
			defer source.DecRef()
			err := r.WritePacket(stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Fatalf("r.WritePacket(...): %s", err)
			}
			if got := len(ep.WrittenPackets); got != len(ft.wantFragments) {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != len(ft.wantFragments) {
				t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := r.Stats().IP.OutgoingPacketErrors.Value(); got != 0 {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = 0", got)
			}
			if err := compareFragments(ep.WrittenPackets, source, ft.mtu, ft.wantFragments, tcp.ProtocolNumber, false /* withIPHeader */, extraHeaderReserve); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestFragmentationErrors checks that errors are returned from WritePacket
// correctly.
func TestFragmentationErrors(t *testing.T) {
	const ttl = 42

	tests := []struct {
		description           string
		mtu                   uint32
		transportHeaderLength int
		payloadSize           int
		allowPackets          int
		outgoingErrors        int
		mockError             tcpip.Error
		wantError             tcpip.Error
	}{
		{
			description:           "No frag",
			mtu:                   2000,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             &tcpip.ErrAborted{},
			wantError:             &tcpip.ErrAborted{},
		},
		{
			description:           "Error on first frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        3,
			mockError:             &tcpip.ErrAborted{},
			wantError:             &tcpip.ErrAborted{},
		},
		{
			description:           "Error on second frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          1,
			outgoingErrors:        2,
			mockError:             &tcpip.ErrAborted{},
			wantError:             &tcpip.ErrAborted{},
		},
		{
			description:           "Error on first frag MTU smaller than header",
			mtu:                   500,
			transportHeaderLength: 1000,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        4,
			mockError:             &tcpip.ErrAborted{},
			wantError:             &tcpip.ErrAborted{},
		},
		{
			description:           "Error when MTU is smaller than IPv4 minimum MTU",
			mtu:                   header.IPv4MinimumMTU - 1,
			transportHeaderLength: 0,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             nil,
			wantError:             &tcpip.ErrInvalidEndpointState{},
		},
	}

	for _, ft := range tests {
		t.Run(ft.description, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()

			ep := iptestutil.NewMockLinkEndpoint(ft.mtu, ft.mockError, ft.allowPackets)
			defer ep.Close()
			r := buildRoute(t, ctx, ep)
			defer r.Release()
			pkt := iptestutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			defer pkt.DecRef()
			err := r.WritePacket(stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if diff := cmp.Diff(ft.wantError, err); diff != "" {
				t.Fatalf("unexpected error from r.WritePacket(_, _, _), (-want, +got):\n%s", diff)
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != ft.allowPackets {
				t.Errorf("got r.Stats().IP.PacketsSent.Value() = %d, want = %d", got, ft.allowPackets)
			}
			if got := int(r.Stats().IP.OutgoingPacketErrors.Value()); got != ft.outgoingErrors {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = %d", got, ft.outgoingErrors)
			}
		})
	}
}

func TestInvalidFragments(t *testing.T) {
	const (
		nicID    = 1
		linkAddr = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		tos      = 0
		ident    = 1
		ttl      = 48
		protocol = 6
	)

	var (
		addr1 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x01"))
		addr2 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x02"))
	)

	payloadGen := func(payloadLen int) []byte {
		payload := make([]byte, payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = 0x30
		}
		return payload
	}

	type fragmentData struct {
		ipv4fields header.IPv4Fields
		// 0 means insert the correct IHL. Non 0 means override the correct IHL.
		overrideIHL  int // For 0 use 1 as it is an int and will be divided by 4.
		payload      []byte
		autoChecksum bool // If true, the Checksum field will be overwritten.
	}

	tests := []struct {
		name                   string
		fragments              []fragmentData
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
	}{
		{
			name: "IHL and TotalLength zero, FragmentOffset non-zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagDontFragment | header.IPv4FlagMoreFragments,
						FragmentOffset: 59776,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					overrideIHL:  1, // See note above.
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL and TotalLength zero, FragmentOffset zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					overrideIHL:  1, // See note above.
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			// Payload 17 octets and Fragment offset 65520
			// Leading to the fragment end to be past 65536.
			name: "fragment ends past 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 17,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(17),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			// Payload 16 octets and fragment offset 65520
			// Leading to the fragment end to be exactly 65536.
			name: "fragment ends exactly at 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(16),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 0,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL less than IPv4 minimum size",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 1944,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize - 12,
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize - 12,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize - 12,
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 2,
			wantMalformedFragments: 0,
		},
		{
			name: "fragment with short TotalLength and extra payload",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 28816,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize + 4,
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 4,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					overrideIHL:  header.IPv4MinimumSize + 4,
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			name: "multiple fragments with More Fragments flag set to false",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 128,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 8,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			e := channel.New(0, 1500, linkAddr)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			for _, f := range test.fragments {
				pktSize := header.IPv4MinimumSize + len(f.payload)
				hdr := prependable.New(pktSize)

				ip := header.IPv4(hdr.Prepend(pktSize))
				ip.Encode(&f.ipv4fields)
				if want, got := len(f.payload), copy(ip[header.IPv4MinimumSize:], f.payload); want != got {
					t.Fatalf("copied %d bytes, expected %d bytes.", got, want)
				}
				// Encode sets this up correctly. If we want a different value for
				// testing then we need to overwrite the good value.
				if f.overrideIHL != 0 {
					ip.SetHeaderLength(uint8(f.overrideIHL))
					// If we are asked to add options (type not specified) then pad
					// with 0 (EOL). RFC 791 page 23 says "The padding is zero".
					for i := header.IPv4MinimumSize; i < f.overrideIHL; i++ {
						ip[i] = byte(header.IPv4OptionListEndType)
					}
				}

				if f.autoChecksum {
					ip.SetChecksum(0)
					ip.SetChecksum(^ip.CalculateChecksum())
				}

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(hdr.View()),
				})
				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.wantMalformedIPPackets; got != want {
				t.Errorf("incorrect Stats.IP.MalformedPacketsReceived, got: %d, want: %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), test.wantMalformedFragments; got != want {
				t.Errorf("incorrect Stats.IP.MalformedFragmentsReceived, got: %d, want: %d", got, want)
			}
		})
	}
}

func TestFragmentReassemblyTimeout(t *testing.T) {
	const (
		nicID    = 1
		linkAddr = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		tos      = 0
		ident    = 1
		ttl      = 48
		protocol = 99
		data     = "TEST_FRAGMENT_REASSEMBLY_TIMEOUT"
	)

	var (
		addr1 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x01"))
		addr2 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x02"))
	)

	type fragmentData struct {
		ipv4fields header.IPv4Fields
		payload    []byte
	}

	tests := []struct {
		name       string
		fragments  []fragmentData
		expectICMP bool
	}{
		{
			name: "first fragment only",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "two first fragments",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "second fragment only",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 8,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: false,
		},
		{
			name: "two fragments with a gap",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:8],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 16,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: true,
		},
		{
			name: "two fragments with a gap in reverse order",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    uint16(header.IPv4MinimumSize + len(data) - 16),
						ID:             ident,
						Flags:          0,
						FragmentOffset: 16,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[16:],
				},
				{
					ipv4fields: header.IPv4Fields{
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload: []byte(data)[:8],
				},
			},
			expectICMP: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s
			clock := ctx.clock

			e := channel.New(1, 1500, linkAddr)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv4EmptySubnet,
				NIC:         nicID,
			}})

			var firstFragmentSent bufferv2.Buffer
			for _, f := range test.fragments {
				pktSize := header.IPv4MinimumSize
				hdr := prependable.New(pktSize)

				ip := header.IPv4(hdr.Prepend(pktSize))
				ip.Encode(&f.ipv4fields)

				ip.SetChecksum(0)
				ip.SetChecksum(^ip.CalculateChecksum())

				buf := bufferv2.MakeWithData(hdr.View())
				buf.Append(bufferv2.NewViewWithData(f.payload))

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buf,
				})

				if firstFragmentSent.Size() == 0 && ip.FragmentOffset() == 0 {
					firstFragmentSent = bufferv2.MakeWithView(stack.PayloadSince(pkt.NetworkHeader()))
					defer firstFragmentSent.Release()
				}

				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}

			clock.Advance(ipv4.ReassembleTimeout)

			reply := e.Read()
			if !test.expectICMP {
				if !reply.IsNil() {
					t.Fatalf("unexpected ICMP error message received: %#v", reply)
				}
				return
			}
			if reply.IsNil() {
				t.Fatal("expected ICMP error message missing")
			}
			if firstFragmentSent.Size() == 0 {
				t.Fatalf("unexpected ICMP error message received: %#v", reply)
			}

			payload := stack.PayloadSince(reply.NetworkHeader())
			defer payload.Release()
			checker.IPv4(t, payload,
				checker.SrcAddr(addr2),
				checker.DstAddr(addr1),
				checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+firstFragmentSent.Size())),
				checker.IPv4HeaderLength(header.IPv4MinimumSize),
				checker.ICMPv4(
					checker.ICMPv4Type(header.ICMPv4TimeExceeded),
					checker.ICMPv4Code(header.ICMPv4ReassemblyTimeout),
					checker.ICMPv4Checksum(),
					checker.ICMPv4Payload(firstFragmentSent.Flatten()),
				),
			)
			reply.DecRef()
		})
	}
}

// TestReceiveFragments feeds fragments in through the incoming packet path to
// test reassembly
func TestReceiveFragments(t *testing.T) {
	const (
		nicID = 1
	)

	var (
		addr1 = tcpip.AddrFromSlice([]byte("\x0c\xa8\x00\x01")) // 192.168.0.1
		addr2 = tcpip.AddrFromSlice([]byte("\x0c\xa8\x00\x02")) // 192.168.0.2
		addr3 = tcpip.AddrFromSlice([]byte("\x0c\xa8\x00\x03")) // 192.168.0.3
	)

	// Build and return a UDP header containing payload.
	udpGen := func(payloadLen int, multiplier uint8, src, dst tcpip.Address) []byte {
		payload := make([]byte, payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = uint8(i) * multiplier
		}

		udpLength := header.UDPMinimumSize + len(payload)

		hdr := prependable.New(udpLength)
		u := header.UDP(hdr.Prepend(udpLength))
		u.Encode(&header.UDPFields{
			SrcPort: 5555,
			DstPort: 80,
			Length:  uint16(udpLength),
		})
		copy(u.Payload(), payload)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLength))
		sum = checksum.Checksum(payload, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
		return hdr.View()
	}

	// UDP header plus a payload of 0..256
	ipv4Payload1Addr1ToAddr2 := udpGen(256, 1, addr1, addr2)
	udpPayload1Addr1ToAddr2 := ipv4Payload1Addr1ToAddr2[header.UDPMinimumSize:]
	ipv4Payload1Addr3ToAddr2 := udpGen(256, 1, addr3, addr2)
	udpPayload1Addr3ToAddr2 := ipv4Payload1Addr3ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 2.
	ipv4Payload2Addr1ToAddr2 := udpGen(128, 2, addr1, addr2)
	udpPayload2Addr1ToAddr2 := ipv4Payload2Addr1ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 3.
	// Used to test cases where the fragment blocks are not a multiple of
	// the fragment block size of 8 (RFC 791 section 3.1 page 14).
	ipv4Payload3Addr1ToAddr2 := udpGen(127, 3, addr1, addr2)
	udpPayload3Addr1ToAddr2 := ipv4Payload3Addr1ToAddr2[header.UDPMinimumSize:]
	// Used to test the max reassembled IPv4 payload length.
	ipv4Payload4Addr1ToAddr2 := udpGen(header.UDPMaximumSize-header.UDPMinimumSize, 4, addr1, addr2)
	udpPayload4Addr1ToAddr2 := ipv4Payload4Addr1ToAddr2[header.UDPMinimumSize:]

	type fragmentData struct {
		srcAddr        tcpip.Address
		dstAddr        tcpip.Address
		id             uint16
		flags          uint8
		fragmentOffset uint16
		payload        []byte
	}

	tests := []struct {
		name             string
		fragments        []fragmentData
		expectedPayloads [][]byte
	}{
		{
			name: "No fragmentation",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "No fragmentation with size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "More fragments without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Non-zero fragment offset without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 8,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments out of order",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with last fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload3Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments with first fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:63],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 63,
					payload:        ipv4Payload3Addr1ToAddr2[63:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Second fragment has MoreFlags set",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload2Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload2Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload2Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets from different sources but with same ID",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr3ToAddr2[:32],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 32,
					payload:        ipv4Payload1Addr3ToAddr2[32:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload1Addr3ToAddr2},
		},
		{
			name: "Fragment without followup",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload4Addr1ToAddr2[:65512],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 65512,
					payload:        ipv4Payload4Addr1ToAddr2[65512:],
				},
			},
			expectedPayloads: [][]byte{udpPayload4Addr1ToAddr2},
		},
		{
			name: "Two fragments with MF flag reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload4Addr1ToAddr2[:65512],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 65512,
					payload:        ipv4Payload4Addr1ToAddr2[65512:],
				},
			},
			expectedPayloads: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s

			e := channel.New(0, 1280, "\xf0\x00")
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, header.IPv4ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			// Bring up a raw endpoint so we can examine network headers.
			epRaw, err := s.NewRawEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq, true /* associated */)
			if err != nil {
				t.Fatalf("NewRawEndpoint(%d, %d, _, true): %s", udp.ProtocolNumber, header.IPv4ProtocolNumber, err)
			}
			defer epRaw.Close()

			// Prepare and send the fragments.
			for _, frag := range test.fragments {
				hdr := prependable.New(header.IPv4MinimumSize)

				// Serialize IPv4 fixed header.
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength:    header.IPv4MinimumSize + uint16(len(frag.payload)),
					ID:             frag.id,
					Flags:          frag.flags,
					FragmentOffset: frag.fragmentOffset,
					TTL:            64,
					Protocol:       uint8(header.UDPProtocolNumber),
					SrcAddr:        frag.srcAddr,
					DstAddr:        frag.dstAddr,
				})
				ip.SetChecksum(^ip.CalculateChecksum())

				buf := bufferv2.MakeWithData(hdr.View())
				buf.Append(bufferv2.NewViewWithData(frag.payload))
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buf,
				})
				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, expectedPayload := range test.expectedPayloads {
				// Check UDP payload delivered by UDP endpoint.
				var buf bytes.Buffer
				result, err := ep.Read(&buf, tcpip.ReadOptions{})
				if err != nil {
					t.Fatalf("(i=%d) ep.Read: %s", i, err)
				}
				if diff := cmp.Diff(tcpip.ReadResult{
					Count: len(expectedPayload),
					Total: len(expectedPayload),
				}, result, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
					t.Errorf("(i=%d) ep.Read: unexpected result (-want +got):\n%s", i, diff)
				}
				if diff := cmp.Diff(expectedPayload, buf.Bytes()); diff != "" {
					t.Errorf("(i=%d) ep.Read: UDP payload mismatch (-want +got):\n%s", i, diff)
				}

				// Check IPv4 header in packet delivered by raw endpoint.
				buf.Reset()
				_, err = epRaw.Read(&buf, tcpip.ReadOptions{})
				if err != nil {
					t.Fatalf("(i=%d) epRaw.Read: %s", i, err)
				}
				// Reassambly does not take care of checksum. Here we write our own
				// check routine instead of using checker.IPv4.
				ip := header.IPv4(buf.Bytes())
				for _, check := range []checker.NetworkChecker{
					checker.FragmentFlags(0),
					checker.FragmentOffset(0),
					checker.IPFullLength(uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(expectedPayload))),
				} {
					check(t, []header.Network{ip})
				}
			}

			res, err := ep.Read(ioutil.Discard, tcpip.ReadOptions{})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("(last) got Read = (%#v, %v), want = (_, %s)", res, err, &tcpip.ErrWouldBlock{})
			}
		})
	}
}

func TestWriteStats(t *testing.T) {
	const nPackets = 3

	tests := []struct {
		name                     string
		setup                    func(*testing.T, *stack.Stack)
		allowPackets             int
		expectSent               int
		expectOutputDropped      int
		expectPostroutingDropped int
		expectWritten            int
	}{
		{
			name: "Accept all",
			// No setup needed, tables accept everything by default.
			setup:                    func(*testing.T, *stack.Stack) {},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets,
			expectOutputDropped:      0,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Accept all with error",
			// No setup needed, tables accept everything by default.
			setup:                    func(*testing.T, *stack.Stack) {},
			allowPackets:             nPackets - 1,
			expectSent:               nPackets - 1,
			expectOutputDropped:      0,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets - 1,
		}, {
			name: "Drop all with Output chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               0,
			expectOutputDropped:      nPackets,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Drop all with Postrouting chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.NATID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Postrouting]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				ipt.ReplaceTable(stack.NATID, filter, false /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               0,
			expectOutputDropped:      0,
			expectPostroutingDropped: nPackets,
			expectWritten:            nPackets,
		}, {
			name: "Drop some with Output chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule that matches only 1
				// of the 3 packets.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets - 1,
			expectOutputDropped:      1,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Drop some with Postrouting chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Postrouting DROP rule that matches only 1
				// of the 3 packets.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.NATID, false /* ipv6 */)
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Postrouting]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				ipt.ReplaceTable(stack.NATID, filter, false /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets - 1,
			expectOutputDropped:      0,
			expectPostroutingDropped: 1,
			expectWritten:            nPackets,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()

			ep := iptestutil.NewMockLinkEndpoint(header.IPv4MinimumMTU, &tcpip.ErrInvalidEndpointState{}, test.allowPackets)
			defer ep.Close()
			rt := buildRoute(t, ctx, ep)
			defer rt.Release()

			test.setup(t, rt.Stack())
			nWritten := 0
			for i := 0; i < nPackets; i++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.UDPMinimumSize + int(rt.MaxHeaderLength()),
					Payload:            bufferv2.Buffer{},
				})
				defer pkt.DecRef()
				pkt.TransportHeader().Push(header.UDPMinimumSize)
				if err := rt.WritePacket(stack.NetworkHeaderParams{}, pkt); err != nil {
					break
				}
				nWritten++
			}

			if got := int(rt.Stats().IP.PacketsSent.Value()); got != test.expectSent {
				t.Errorf("got rt.Stats().IP.PacketsSent.Value() = %d, want = %d", got, test.expectSent)
			}
			if got := int(rt.Stats().IP.IPTablesOutputDropped.Value()); got != test.expectOutputDropped {
				t.Errorf("got rt.Stats().IP.IPTablesOutputDropped.Value() = %d, want = %d", got, test.expectOutputDropped)
			}
			if got := int(rt.Stats().IP.IPTablesPostroutingDropped.Value()); got != test.expectPostroutingDropped {
				t.Errorf("got rt.Stats().IP.IPTablesPostroutingDropped.Value() = %d, want = %d", got, test.expectPostroutingDropped)
			}
			if nWritten != test.expectWritten {
				t.Errorf("got nWritten = %d, want = %d", nWritten, test.expectWritten)
			}
		})
	}
}

func buildRoute(t *testing.T, c testContext, ep stack.LinkEndpoint) *stack.Route {
	s := c.s
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1, _) failed: %s", err)
	}
	var (
		src = tcpip.AddrFromSlice([]byte("\x10\x00\x00\x01"))
		dst = tcpip.AddrFromSlice([]byte("\x10\x00\x00\x02"))
	)
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: src.WithPrefix(),
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr, err)
	}
	{
		mask := tcpip.MaskFromBytes(header.IPv4Broadcast.AsSlice())
		subnet, err := tcpip.NewSubnet(dst, mask)
		if err != nil {
			t.Fatalf("NewSubnet(%s, %s) failed: %v", dst, mask, err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d, false) = %s", src, dst, ipv4.ProtocolNumber, err)
	}
	return rt
}

// limitedMatcher is an iptables matcher that matches after a certain number of
// packets are checked against it.
type limitedMatcher struct {
	limit int
}

// Name implements Matcher.Name.
func (*limitedMatcher) Name() string {
	return "limitedMatcher"
}

// Match implements Matcher.Match.
func (lm *limitedMatcher) Match(stack.Hook, stack.PacketBufferPtr, string, string) (bool, bool) {
	if lm.limit == 0 {
		return true, false
	}
	lm.limit--
	return false, false
}

func TestPacketQueuing(t *testing.T) {
	const nicID = 1

	var (
		host1NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
		host2NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

		host1IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("192.168.0.1").To4()),
				PrefixLen: 24,
			},
		}
		host2IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("192.168.0.2").To4()),
				PrefixLen: 8,
			},
		}
	)

	tests := []struct {
		name      string
		rxPkt     func(*channel.Endpoint)
		checkResp func(*testing.T, *channel.Endpoint)
	}{
		{
			name: "ICMP Error",
			rxPkt: func(e *channel.Endpoint) {
				hdr := prependable.New(header.IPv4MinimumSize + header.UDPMinimumSize)
				u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				u.Encode(&header.UDPFields{
					SrcPort: 5555,
					DstPort: 80,
					Length:  header.UDPMinimumSize,
				})
				sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, host2IPv4Addr.AddressWithPrefix.Address, host1IPv4Addr.AddressWithPrefix.Address, header.UDPMinimumSize)
				sum = checksum.Checksum(nil, sum)
				u.SetChecksum(^u.CalculateChecksum(sum))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
					TTL:         ipv4.DefaultTTL,
					Protocol:    uint8(udp.ProtocolNumber),
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(hdr.View()),
				})
				defer pkt.DecRef()
				e.InjectInbound(ipv4.ProtocolNumber, pkt)
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("timed out waiting for packet")
				}
				defer p.DecRef()
				if p.NetworkProtocolNumber != header.IPv4ProtocolNumber {
					t.Errorf("got p.NetworkProtocolNumber = %d, want = %d", p.NetworkProtocolNumber, header.IPv4ProtocolNumber)
				}
				if p.EgressRoute.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.EgressRoute.RemoteLinkAddress = %s, want = %s", p.EgressRoute.RemoteLinkAddress, host2NICLinkAddr)
				}
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4DstUnreachable),
						checker.ICMPv4Code(header.ICMPv4PortUnreachable)))
			},
		},

		{
			name: "Ping",
			rxPkt: func(e *channel.Endpoint) {
				totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
				hdr := prependable.New(totalLen)
				pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
				pkt.SetType(header.ICMPv4Echo)
				pkt.SetCode(0)
				pkt.SetChecksum(0)
				pkt.SetChecksum(^checksum.Checksum(pkt, 0))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: uint16(totalLen),
					Protocol:    uint8(icmp.ProtocolNumber4),
					TTL:         ipv4.DefaultTTL,
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				echoPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(hdr.View()),
				})
				defer echoPkt.DecRef()
				e.InjectInbound(header.IPv4ProtocolNumber, echoPkt)
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("timed out waiting for packet")
				}
				defer p.DecRef()
				if p.NetworkProtocolNumber != header.IPv4ProtocolNumber {
					t.Errorf("got p.NetworkProtocolNumber = %d, want = %d", p.NetworkProtocolNumber, header.IPv4ProtocolNumber)
				}
				if p.EgressRoute.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.EgressRoute.RemoteLinkAddress = %s, want = %s", p.EgressRoute.RemoteLinkAddress, host2NICLinkAddr)
				}
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4EchoReply),
						checker.ICMPv4Code(header.ICMPv4UnusedCode)))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestContext()
			defer ctx.cleanup()
			s := ctx.s
			clock := ctx.clock

			e := channel.New(1, defaultMTU, host1NICLinkAddr)
			defer e.Close()
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, host1IPv4Addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, host1IPv4Addr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         nicID,
				},
			})

			// Receive a packet to trigger link resolution before a response is sent.
			test.rxPkt(e)

			// Wait for a ARP request since link address resolution should be
			// performed.
			{
				clock.RunImmediatelyScheduledJobs()
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("timed out waiting for packet")
				}
				if p.NetworkProtocolNumber != arp.ProtocolNumber {
					t.Errorf("got p.NetworkProtocolNumber = %d, want = %d", p.NetworkProtocolNumber, arp.ProtocolNumber)
				}
				if p.EgressRoute.RemoteLinkAddress != header.EthernetBroadcastAddress {
					t.Errorf("got p.EgressRoute.RemoteLinkAddress = %s, want = %s", p.EgressRoute.RemoteLinkAddress, header.EthernetBroadcastAddress)
				}
				rep := header.ARP(p.NetworkHeader().Slice())
				p.DecRef()
				if got := rep.Op(); got != header.ARPRequest {
					t.Errorf("got Op() = %d, want = %d", got, header.ARPRequest)
				}
				if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != host1NICLinkAddr {
					t.Errorf("got HardwareAddressSender = %s, want = %s", got, host1NICLinkAddr)
				}
				if got := tcpip.AddrFromSlice(rep.ProtocolAddressSender()); got != host1IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressSender = %s, want = %s", got, host1IPv4Addr.AddressWithPrefix.Address)
				}
				if got := tcpip.AddrFromSlice(rep.ProtocolAddressTarget()); got != host2IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, host2IPv4Addr.AddressWithPrefix.Address)
				}
			}

			// Send an ARP reply to complete link address resolution.
			{
				hdr := make([]byte, header.ARPSize)
				packet := header.ARP(hdr)
				packet.SetIPv4OverEthernet()
				packet.SetOp(header.ARPReply)
				copy(packet.HardwareAddressSender(), host2NICLinkAddr)
				copy(packet.ProtocolAddressSender(), host2IPv4Addr.AddressWithPrefix.Address.AsSlice())
				copy(packet.HardwareAddressTarget(), host1NICLinkAddr)
				copy(packet.ProtocolAddressTarget(), host1IPv4Addr.AddressWithPrefix.Address.AsSlice())
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(hdr),
				})
				e.InjectInbound(arp.ProtocolNumber, pkt)
				pkt.DecRef()
			}

			// Expect the response now that the link address has resolved.
			clock.RunImmediatelyScheduledJobs()
			test.checkResp(t, e)

			// Since link resolution was already performed, it shouldn't be performed
			// again.
			test.rxPkt(e)
			test.checkResp(t, e)
		})
	}
}

// TestCloseLocking test that lock ordering is followed when closing an
// endpoint.
func TestCloseLocking(t *testing.T) {
	const (
		nicID1 = 1
		nicID2 = 2

		iterations = 1000
	)

	var (
		src = testutil.MustParse4("16.0.0.1")
		dst = testutil.MustParse4("16.0.0.2")
	)

	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	// Perform NAT so that the endpoint tries to search for a sibling endpoint
	// which ends up taking the protocol and endpoint lock (in that order).
	table := stack.Table{
		Rules: []stack.Rule{
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.RedirectTarget{Port: 5, NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: 3,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: 3,
		},
	}
	s.IPTables().ReplaceTable(stack.NATID, table, false /* ipv6 */)

	e := channel.New(0, defaultMTU, "")
	defer e.Close()
	if err := s.CreateNIC(nicID1, e); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: src.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID1, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID1, protocolAddr, err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID1,
	}})

	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()

	addr := tcpip.FullAddress{NIC: nicID1, Addr: dst, Port: 53}
	if err := ep.Connect(addr); err != nil {
		t.Errorf("ep.Connect(%#v): %s", addr, err)
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	// Writing packets should trigger NAT which requires the stack to search the
	// protocol for network endpoints with the destination address.
	//
	// Creating and removing interfaces should modify the protocol and endpoint
	// which requires taking the locks of each.
	//
	// We expect the protocol > endpoint lock ordering to be followed here.
	wg.Add(2)
	go func() {
		defer wg.Done()

		data := []byte{1, 2, 3, 4}

		for i := 0; i < iterations; i++ {
			var r bytes.Reader
			r.Reset(data)
			if n, err := ep.Write(&r, tcpip.WriteOptions{}); err != nil {
				t.Errorf("ep.Write(_, _): %s", err)
				return
			} else if want := int64(len(data)); n != want {
				t.Errorf("got ep.Write(_, _) = (%d, _), want = (%d, _)", n, want)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()

		for i := 0; i < iterations; i++ {
			ch := channel.New(0, defaultMTU, "")
			defer ch.Close()
			if err := s.CreateNIC(nicID2, ch); err != nil {
				t.Errorf("CreateNIC(%d, _): %s", nicID2, err)
				return
			}
			if err := s.RemoveNIC(nicID2); err != nil {
				t.Errorf("RemoveNIC(%d): %s", nicID2, err)
				return
			}
		}
	}()
}

func TestIcmpRateLimit(t *testing.T) {
	var (
		host1IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("192.168.0.1").To4()),
				PrefixLen: 24,
			},
		}
		host2IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("192.168.0.2").To4()),
				PrefixLen: 24,
			},
		}
	)
	ctx := newTestContext()
	defer ctx.cleanup()
	s := ctx.s

	const icmpBurst = 5
	s.SetICMPBurst(icmpBurst)

	e := channel.New(1, defaultMTU, tcpip.LinkAddress(""))
	defer e.Close()
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.AddProtocolAddress(nicID, host1IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, host1IPv4Addr, err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
			NIC:         nicID,
		},
	})
	tests := []struct {
		name         string
		createPacket func() []byte
		check        func(*testing.T, *channel.Endpoint, int)
	}{
		{
			name: "echo",
			createPacket: func() []byte {
				totalLength := header.IPv4MinimumSize + header.ICMPv4MinimumSize
				hdr := prependable.New(totalLength)
				icmpH := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
				icmpH.SetIdent(1)
				icmpH.SetSequence(1)
				icmpH.SetType(header.ICMPv4Echo)
				icmpH.SetCode(header.ICMPv4UnusedCode)
				icmpH.SetChecksum(0)
				icmpH.SetChecksum(^checksum.Checksum(icmpH, 0))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: uint16(totalLength),
					Protocol:    uint8(header.ICMPv4ProtocolNumber),
					TTL:         1,
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				return hdr.View()
			},
			check: func(t *testing.T, e *channel.Endpoint, round int) {
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("expected echo response, no packet read in endpoint in round %d", round)
				}
				defer p.DecRef()
				if got, want := p.NetworkProtocolNumber, header.IPv4ProtocolNumber; got != want {
					t.Errorf("got p.NetworkProtocolNumber = %d, want = %d", got, want)
				}
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4EchoReply),
					))
			},
		},
		{
			name: "dst unreachable",
			createPacket: func() []byte {
				totalLength := header.IPv4MinimumSize + header.UDPMinimumSize
				hdr := prependable.New(totalLength)
				udpH := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				udpH.Encode(&header.UDPFields{
					SrcPort: 100,
					DstPort: 101,
					Length:  header.UDPMinimumSize,
				})
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					TotalLength: uint16(totalLength),
					Protocol:    uint8(header.UDPProtocolNumber),
					TTL:         1,
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				return hdr.View()
			},
			check: func(t *testing.T, e *channel.Endpoint, round int) {
				p := e.Read()
				if round >= icmpBurst {
					if !p.IsNil() {
						t.Errorf("got packet %x in round %d, expected ICMP rate limit to stop it", p.Data().AsRange().ToSlice(), round)
						p.DecRef()
					}
					return
				}
				if p.IsNil() {
					t.Fatalf("expected unreachable in round %d, no packet read in endpoint", round)
				}
				defer p.DecRef()
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv4(t, payload,
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4DstUnreachable),
					))
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			for round := 0; round < icmpBurst+1; round++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(testCase.createPacket()),
				})
				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
				testCase.check(t, e, round)
			}
		})
	}
}
