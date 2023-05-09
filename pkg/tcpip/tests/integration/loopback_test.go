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

package loopback_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ ipv6.NDPDispatcher = (*ndpDispatcher)(nil)

type ndpDispatcher struct{}

func (*ndpDispatcher) OnDuplicateAddressDetectionResult(tcpip.NICID, tcpip.Address, stack.DADResult) {
}

func (*ndpDispatcher) OnOffLinkRouteUpdated(tcpip.NICID, tcpip.Subnet, tcpip.Address, header.NDPRoutePreference) {
}

func (*ndpDispatcher) OnOffLinkRouteInvalidated(tcpip.NICID, tcpip.Subnet, tcpip.Address) {}

func (*ndpDispatcher) OnOnLinkPrefixDiscovered(tcpip.NICID, tcpip.Subnet) {
}

func (*ndpDispatcher) OnOnLinkPrefixInvalidated(tcpip.NICID, tcpip.Subnet) {}

func (*ndpDispatcher) OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) stack.AddressDispatcher {
	return nil
}

func (*ndpDispatcher) OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix) {}

func (*ndpDispatcher) OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix) {}

func (*ndpDispatcher) OnRecursiveDNSServerOption(tcpip.NICID, []tcpip.Address, time.Duration) {}

func (*ndpDispatcher) OnDNSSearchListOption(tcpip.NICID, []string, time.Duration) {}

func (*ndpDispatcher) OnDHCPv6Configuration(tcpip.NICID, ipv6.DHCPv6ConfigurationFromNDPRA) {}

// TestInitialLoopbackAddresses tests that the loopback interface does not
// auto-generate a link-local address when it is brought up.
func TestInitialLoopbackAddresses(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPDisp:          &ndpDispatcher{},
			AutoGenLinkLocal: true,
			OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: func(nicID tcpip.NICID, nicName string) string {
					t.Fatalf("should not attempt to get name for NIC with ID = %d; nicName = %s", nicID, nicName)
					return ""
				},
			},
		})},
	})
	defer s.Destroy()

	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}

	nicsInfo := s.NICInfo()
	if nicInfo, ok := nicsInfo[nicID]; !ok {
		t.Fatalf("did not find NIC with ID = %d in s.NICInfo() = %#v", nicID, nicsInfo)
	} else if got := len(nicInfo.ProtocolAddresses); got != 0 {
		t.Fatalf("got len(nicInfo.ProtocolAddresses) = %d, want = 0; nicInfo.ProtocolAddresses = %#v", got, nicInfo.ProtocolAddresses)
	}
}

// TestLoopbackAcceptAllInSubnetUDP tests that a loopback interface considers
// itself bound to all addresses in the subnet of an assigned address and UDP
// traffic is sent/received correctly.
func TestLoopbackAcceptAllInSubnetUDP(t *testing.T) {
	const (
		nicID     = 1
		localPort = 80
	)

	data := []byte{1, 2, 3, 4}

	ipv4ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: utils.Ipv4Addr,
	}
	ipv4Bytes := []byte(ipv4ProtocolAddress.AddressWithPrefix.Address)
	ipv4Bytes[len(ipv4Bytes)-1]++
	otherIPv4Address := tcpip.Address(ipv4Bytes)

	ipv6ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: utils.Ipv6Addr,
	}
	ipv6Bytes := []byte(utils.Ipv6Addr.Address)
	ipv6Bytes[len(ipv6Bytes)-1]++
	otherIPv6Address := tcpip.Address(ipv6Bytes)

	tests := []struct {
		name       string
		addAddress tcpip.ProtocolAddress
		bindAddr   tcpip.Address
		dstAddr    tcpip.Address
		expectRx   bool
	}{
		{
			name:       "IPv4 bind to wildcard and send to assigned address",
			addAddress: ipv4ProtocolAddress,
			dstAddr:    ipv4ProtocolAddress.AddressWithPrefix.Address,
			expectRx:   true,
		},
		{
			name:       "IPv4 bind to wildcard and send to other subnet-local address",
			addAddress: ipv4ProtocolAddress,
			dstAddr:    otherIPv4Address,
			expectRx:   true,
		},
		{
			name:       "IPv4 bind to wildcard send to other address",
			addAddress: ipv4ProtocolAddress,
			dstAddr:    utils.RemoteIPv4Addr,
			expectRx:   false,
		},
		{
			name:       "IPv4 bind to other subnet-local address and send to assigned address",
			addAddress: ipv4ProtocolAddress,
			bindAddr:   otherIPv4Address,
			dstAddr:    ipv4ProtocolAddress.AddressWithPrefix.Address,
			expectRx:   false,
		},
		{
			name:       "IPv4 bind and send to other subnet-local address",
			addAddress: ipv4ProtocolAddress,
			bindAddr:   otherIPv4Address,
			dstAddr:    otherIPv4Address,
			expectRx:   true,
		},
		{
			name:       "IPv4 bind to assigned address and send to other subnet-local address",
			addAddress: ipv4ProtocolAddress,
			bindAddr:   ipv4ProtocolAddress.AddressWithPrefix.Address,
			dstAddr:    otherIPv4Address,
			expectRx:   false,
		},

		{
			name:       "IPv6 bind and send to assigned address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   utils.Ipv6Addr.Address,
			dstAddr:    utils.Ipv6Addr.Address,
			expectRx:   true,
		},
		{
			name:       "IPv6 bind to wildcard and send to other subnet-local address",
			addAddress: ipv6ProtocolAddress,
			dstAddr:    otherIPv6Address,
			expectRx:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			defer s.Destroy()
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, test.addAddress, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, test.addAddress, err)
			}
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			var wq waiter.Queue
			rep, err := s.NewEndpoint(udp.ProtocolNumber, test.addAddress.Protocol, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.addAddress.Protocol, err)
			}
			defer rep.Close()

			bindAddr := tcpip.FullAddress{Addr: test.bindAddr, Port: localPort}
			if err := rep.Bind(bindAddr); err != nil {
				t.Fatalf("rep.Bind(%+v): %s", bindAddr, err)
			}

			sep, err := s.NewEndpoint(udp.ProtocolNumber, test.addAddress.Protocol, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.addAddress.Protocol, err)
			}
			defer sep.Close()

			wopts := tcpip.WriteOptions{
				To: &tcpip.FullAddress{
					Addr: test.dstAddr,
					Port: localPort,
				},
			}
			var r bytes.Reader
			r.Reset(data)
			n, err := sep.Write(&r, wopts)
			if err != nil {
				t.Fatalf("sep.Write(_, _): %s", err)
			}
			if want := int64(len(data)); n != want {
				t.Fatalf("got sep.Write(_, _) = (%d, nil), want = (%d, nil)", n, want)
			}

			var buf bytes.Buffer
			opts := tcpip.ReadOptions{NeedRemoteAddr: true}
			if res, err := rep.Read(&buf, opts); test.expectRx {
				if err != nil {
					t.Fatalf("rep.Read(_, %#v): %s", opts, err)
				}
				if diff := cmp.Diff(tcpip.ReadResult{
					Count: buf.Len(),
					Total: buf.Len(),
					RemoteAddr: tcpip.FullAddress{
						Addr: test.addAddress.AddressWithPrefix.Address,
					},
				}, res,
					checker.IgnoreCmpPath("ControlMessages", "RemoteAddr.NIC", "RemoteAddr.Port"),
				); diff != "" {
					t.Errorf("rep.Read: unexpected result (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(data, buf.Bytes()); diff != "" {
					t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
				}
			} else if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("got rep.Read = (%v, %s) [with data %x], want = (_, %s)", res, err, buf.Bytes(), &tcpip.ErrWouldBlock{})
			}
		})
	}
}

// TestLoopbackSubnetLifetimeBoundToAddr tests that the lifetime of an address
// in a loopback interface's associated subnet is bound to the permanently bound
// address.
func TestLoopbackSubnetLifetimeBoundToAddr(t *testing.T) {
	const nicID = 1

	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: utils.Ipv4Addr,
	}
	addrBytes := []byte(utils.Ipv4Addr.Address)
	addrBytes[len(addrBytes)-1]++
	otherAddr := tcpip.Address(addrBytes)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	defer s.Destroy()
	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, protoAddr, err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	r, err := s.FindRoute(nicID, otherAddr, utils.RemoteIPv4Addr, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("s.FindRoute(%d, %s, %s, %d, false): %s", nicID, otherAddr, utils.RemoteIPv4Addr, ipv4.ProtocolNumber, err)
	}
	defer r.Release()

	params := stack.NetworkHeaderParams{
		Protocol: 111,
		TTL:      64,
		TOS:      stack.DefaultTOS,
	}
	data := []byte{1, 2, 3, 4}
	if err := r.WritePacket(params, stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            bufferv2.MakeWithData(data),
	})); err != nil {
		t.Fatalf("r.WritePacket(%#v, _): %s", params, err)
	}

	// Removing the address should make the endpoint invalid.
	if err := s.RemoveAddress(nicID, protoAddr.AddressWithPrefix.Address); err != nil {
		t.Fatalf("s.RemoveAddress(%d, %s): %s", nicID, protoAddr.AddressWithPrefix.Address, err)
	}
	{
		err := r.WritePacket(params, stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Payload:            bufferv2.MakeWithData(data),
		}))
		if _, ok := err.(*tcpip.ErrInvalidEndpointState); !ok {
			t.Fatalf("got r.WritePacket(%#v, _) = %s, want = %s", params, err, &tcpip.ErrInvalidEndpointState{})
		}
	}
}

// TestLoopbackAcceptAllInSubnetTCP tests that a loopback interface considers
// itself bound to all addresses in the subnet of an assigned address and TCP
// traffic is sent/received correctly.
func TestLoopbackAcceptAllInSubnetTCP(t *testing.T) {
	const (
		nicID     = 1
		localPort = 80
	)

	ipv4ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: utils.Ipv4Addr,
	}
	ipv4ProtocolAddress.AddressWithPrefix.PrefixLen = 8
	ipv4Bytes := []byte(ipv4ProtocolAddress.AddressWithPrefix.Address)
	ipv4Bytes[len(ipv4Bytes)-1]++
	otherIPv4Address := tcpip.Address(ipv4Bytes)

	ipv6ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: utils.Ipv6Addr,
	}
	ipv6Bytes := []byte(utils.Ipv6Addr.Address)
	ipv6Bytes[len(ipv6Bytes)-1]++
	otherIPv6Address := tcpip.Address(ipv6Bytes)

	tests := []struct {
		name         string
		addAddress   tcpip.ProtocolAddress
		bindAddr     tcpip.Address
		dstAddr      tcpip.Address
		expectAccept bool
	}{
		{
			name:         "IPv4 bind to wildcard and send to assigned address",
			addAddress:   ipv4ProtocolAddress,
			dstAddr:      ipv4ProtocolAddress.AddressWithPrefix.Address,
			expectAccept: true,
		},
		{
			name:         "IPv4 bind to wildcard and send to other subnet-local address",
			addAddress:   ipv4ProtocolAddress,
			dstAddr:      otherIPv4Address,
			expectAccept: true,
		},
		{
			name:         "IPv4 bind to wildcard send to other address",
			addAddress:   ipv4ProtocolAddress,
			dstAddr:      utils.RemoteIPv4Addr,
			expectAccept: false,
		},
		{
			name:         "IPv4 bind to other subnet-local address and send to assigned address",
			addAddress:   ipv4ProtocolAddress,
			bindAddr:     otherIPv4Address,
			dstAddr:      ipv4ProtocolAddress.AddressWithPrefix.Address,
			expectAccept: false,
		},
		{
			name:         "IPv4 bind and send to other subnet-local address",
			addAddress:   ipv4ProtocolAddress,
			bindAddr:     otherIPv4Address,
			dstAddr:      otherIPv4Address,
			expectAccept: true,
		},
		{
			name:         "IPv4 bind to assigned address and send to other subnet-local address",
			addAddress:   ipv4ProtocolAddress,
			bindAddr:     ipv4ProtocolAddress.AddressWithPrefix.Address,
			dstAddr:      otherIPv4Address,
			expectAccept: false,
		},

		{
			name:         "IPv6 bind and send to assigned address",
			addAddress:   ipv6ProtocolAddress,
			bindAddr:     utils.Ipv6Addr.Address,
			dstAddr:      utils.Ipv6Addr.Address,
			expectAccept: true,
		},
		{
			name:         "IPv6 bind to wildcard and send to other subnet-local address",
			addAddress:   ipv6ProtocolAddress,
			dstAddr:      otherIPv6Address,
			expectAccept: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			})
			defer s.Destroy()
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, test.addAddress, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, test.addAddress, err)
			}
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			var wq waiter.Queue
			we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)
			listeningEndpoint, err := s.NewEndpoint(tcp.ProtocolNumber, test.addAddress.Protocol, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, test.addAddress.Protocol, err)
			}
			defer listeningEndpoint.Close()

			bindAddr := tcpip.FullAddress{Addr: test.bindAddr, Port: localPort}
			if err := listeningEndpoint.Bind(bindAddr); err != nil {
				t.Fatalf("listeningEndpoint.Bind(%#v): %s", bindAddr, err)
			}

			if err := listeningEndpoint.Listen(1); err != nil {
				t.Fatalf("listeningEndpoint.Listen(1): %s", err)
			}

			connectingEndpoint, err := s.NewEndpoint(tcp.ProtocolNumber, test.addAddress.Protocol, &wq)
			if err != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, test.addAddress.Protocol, err)
			}
			defer connectingEndpoint.Close()

			connectAddr := tcpip.FullAddress{
				Addr: test.dstAddr,
				Port: localPort,
			}
			{
				err := connectingEndpoint.Connect(connectAddr)
				if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
					t.Fatalf("connectingEndpoint.Connect(%#v): %s", connectAddr, err)
				}
			}

			if !test.expectAccept {
				_, _, err := listeningEndpoint.Accept(nil)
				if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
					t.Fatalf("got listeningEndpoint.Accept(nil) = %s, want = %s", err, &tcpip.ErrWouldBlock{})
				}
				return
			}

			// Wait for the listening endpoint to be "readable". That is, wait for a
			// new connection.
			<-ch
			var addr tcpip.FullAddress
			if _, _, err := listeningEndpoint.Accept(&addr); err != nil {
				t.Fatalf("listeningEndpoint.Accept(nil): %s", err)
			}
			if addr.Addr != test.addAddress.AddressWithPrefix.Address {
				t.Errorf("got addr.Addr = %s, want = %s", addr.Addr, test.addAddress.AddressWithPrefix.Address)
			}
		})
	}
}

func TestExternalLoopbackTraffic(t *testing.T) {
	const (
		nicID1 = 1
		nicID2 = 2

		numPackets = 1
		ttl        = 64
	)
	ipv4Loopback := testutil.MustParse4("127.0.0.1")

	loopbackSourcedICMPv4 := func(e *channel.Endpoint) {
		utils.RxICMPv4EchoRequest(e, ipv4Loopback, utils.Ipv4Addr.Address, ttl)
	}

	loopbackSourcedICMPv6 := func(e *channel.Endpoint) {
		utils.RxICMPv6EchoRequest(e, header.IPv6Loopback, utils.Ipv6Addr.Address, ttl)
	}

	loopbackDestinedICMPv4 := func(e *channel.Endpoint) {
		utils.RxICMPv4EchoRequest(e, utils.RemoteIPv4Addr, ipv4Loopback, ttl)
	}

	loopbackDestinedICMPv6 := func(e *channel.Endpoint) {
		utils.RxICMPv6EchoRequest(e, utils.RemoteIPv6Addr, header.IPv6Loopback, ttl)
	}

	invalidSrcAddrStat := func(s tcpip.IPStats) *tcpip.StatCounter {
		return s.InvalidSourceAddressesReceived
	}

	invalidDestAddrStat := func(s tcpip.IPStats) *tcpip.StatCounter {
		return s.InvalidDestinationAddressesReceived
	}

	tests := []struct {
		name                  string
		allowExternalLoopback bool
		forwarding            bool
		rxICMP                func(*channel.Endpoint)
		invalidAddressStat    func(tcpip.IPStats) *tcpip.StatCounter
		shouldAccept          bool
	}{
		{
			name:                  "IPv4 external loopback sourced traffic without forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            false,
			rxICMP:                loopbackSourcedICMPv4,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv4 external loopback sourced traffic without forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            false,
			rxICMP:                loopbackSourcedICMPv4,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv4 external loopback sourced traffic with forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            true,
			rxICMP:                loopbackSourcedICMPv4,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv4 external loopback sourced traffic with forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            true,
			rxICMP:                loopbackSourcedICMPv4,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv4 external loopback destined traffic without forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            false,
			rxICMP:                loopbackDestinedICMPv4,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv4 external loopback destined traffic without forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            false,
			rxICMP:                loopbackDestinedICMPv4,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv4 external loopback destined traffic with forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            true,
			rxICMP:                loopbackDestinedICMPv4,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv4 external loopback destined traffic with forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            true,
			rxICMP:                loopbackDestinedICMPv4,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},

		{
			name:                  "IPv6 external loopback sourced traffic without forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            false,
			rxICMP:                loopbackSourcedICMPv6,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv6 external loopback sourced traffic without forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            false,
			rxICMP:                loopbackSourcedICMPv6,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv6 external loopback sourced traffic with forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            true,
			rxICMP:                loopbackSourcedICMPv6,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv6 external loopback sourced traffic with forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            true,
			rxICMP:                loopbackSourcedICMPv6,
			invalidAddressStat:    invalidSrcAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv6 external loopback destined traffic without forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            false,
			rxICMP:                loopbackDestinedICMPv6,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv6 external loopback destined traffic without forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            false,
			rxICMP:                loopbackDestinedICMPv6,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},
		{
			name:                  "IPv6 external loopback destined traffic with forwarding and drop external loopback disabled",
			allowExternalLoopback: true,
			forwarding:            true,
			rxICMP:                loopbackDestinedICMPv6,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          true,
		},
		{
			name:                  "IPv6 external loopback destined traffic with forwarding and drop external loopback enabled",
			allowExternalLoopback: false,
			forwarding:            true,
			rxICMP:                loopbackDestinedICMPv6,
			invalidAddressStat:    invalidDestAddrStat,
			shouldAccept:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{
					ipv4.NewProtocolWithOptions(ipv4.Options{
						AllowExternalLoopbackTraffic: test.allowExternalLoopback,
					}),
					ipv6.NewProtocolWithOptions(ipv6.Options{
						AllowExternalLoopbackTraffic: test.allowExternalLoopback,
					}),
				},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
			})
			defer s.Destroy()
			e := channel.New(1, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID1, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
			}
			v4Addr := tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: utils.Ipv4Addr,
			}
			if err := s.AddProtocolAddress(nicID1, v4Addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID1, v4Addr, err)
			}
			v6Addr := tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: utils.Ipv6Addr,
			}
			if err := s.AddProtocolAddress(nicID1, v6Addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID1, v6Addr, err)
			}

			if err := s.CreateNIC(nicID2, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID2, err)
			}
			protocolAddrV4 := tcpip.ProtocolAddress{
				Protocol: ipv4.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   ipv4Loopback,
					PrefixLen: 8,
				},
			}
			if err := s.AddProtocolAddress(nicID2, protocolAddrV4, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID2, protocolAddrV4, err)
			}
			protocolAddrV6 := tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: header.IPv6Loopback.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID2, protocolAddrV6, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID2, protocolAddrV6, err)
			}

			if test.forwarding {
				if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
				}
				if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", ipv6.ProtocolNumber, err)
				}
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID1,
				},
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID1,
				},
				{
					Destination: ipv4Loopback.WithPrefix().Subnet(),
					NIC:         nicID2,
				},
				{
					Destination: header.IPv6Loopback.WithPrefix().Subnet(),
					NIC:         nicID2,
				},
			})

			stats := s.Stats().IP
			invalidAddressStat := test.invalidAddressStat(stats)
			deliveredPacketsStat := stats.PacketsDelivered
			if got := invalidAddressStat.Value(); got != 0 {
				t.Fatalf("got invalidAddressStat.Value() = %d, want = 0", got)
			}
			if got := deliveredPacketsStat.Value(); got != 0 {
				t.Fatalf("got deliveredPacketsStat.Value() = %d, want = 0", got)
			}
			test.rxICMP(e)
			var expectedInvalidPackets uint64
			if !test.shouldAccept {
				expectedInvalidPackets = numPackets
			}
			if got := invalidAddressStat.Value(); got != expectedInvalidPackets {
				t.Fatalf("got invalidAddressStat.Value() = %d, want = %d", got, expectedInvalidPackets)
			}
			if got, want := deliveredPacketsStat.Value(), numPackets-expectedInvalidPackets; got != want {
				t.Fatalf("got deliveredPacketsStat.Value() = %d, want = %d", got, want)
			}
		})
	}
}
