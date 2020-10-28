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

package integration_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ ipv6.NDPDispatcher = (*ndpDispatcher)(nil)

type ndpDispatcher struct{}

func (*ndpDispatcher) OnDuplicateAddressDetectionStatus(tcpip.NICID, tcpip.Address, bool, *tcpip.Error) {
}

func (*ndpDispatcher) OnDefaultRouterDiscovered(tcpip.NICID, tcpip.Address) bool {
	return false
}

func (*ndpDispatcher) OnDefaultRouterInvalidated(tcpip.NICID, tcpip.Address) {}

func (*ndpDispatcher) OnOnLinkPrefixDiscovered(tcpip.NICID, tcpip.Subnet) bool {
	return false
}

func (*ndpDispatcher) OnOnLinkPrefixInvalidated(tcpip.NICID, tcpip.Subnet) {}

func (*ndpDispatcher) OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) bool {
	return true
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
			NDPDisp:              &ndpDispatcher{},
			AutoGenIPv6LinkLocal: true,
			OpaqueIIDOpts: ipv6.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: func(nicID tcpip.NICID, nicName string) string {
					t.Fatalf("should not attempt to get name for NIC with ID = %d; nicName = %s", nicID, nicName)
					return ""
				},
			},
		})},
	})

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

// TestLoopbackAcceptAllInSubnet tests that a loopback interface considers
// itself bound to all addresses in the subnet of an assigned address.
func TestLoopbackAcceptAllInSubnet(t *testing.T) {
	const (
		nicID     = 1
		localPort = 80
	)

	data := []byte{1, 2, 3, 4}

	ipv4ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: ipv4Addr,
	}
	ipv4Bytes := []byte(ipv4Addr.Address)
	ipv4Bytes[len(ipv4Bytes)-1]++
	otherIPv4Address := tcpip.Address(ipv4Bytes)

	ipv6ProtocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: ipv6Addr,
	}
	ipv6Bytes := []byte(ipv6Addr.Address)
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
			dstAddr:    ipv4Addr.Address,
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
			dstAddr:    remoteIPv4Addr,
			expectRx:   false,
		},
		{
			name:       "IPv4 bind to other subnet-local address and send to assigned address",
			addAddress: ipv4ProtocolAddress,
			bindAddr:   otherIPv4Address,
			dstAddr:    ipv4Addr.Address,
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
			bindAddr:   ipv4Addr.Address,
			dstAddr:    otherIPv4Address,
			expectRx:   false,
		},

		{
			name:       "IPv6 bind and send to assigned address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   ipv6Addr.Address,
			dstAddr:    ipv6Addr.Address,
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
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, test.addAddress); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, test.addAddress, err)
			}
			s.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
				tcpip.Route{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			wq := waiter.Queue{}
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
			n, _, err := sep.Write(tcpip.SlicePayload(data), wopts)
			if err != nil {
				t.Fatalf("sep.Write(_, _): %s", err)
			}
			if want := int64(len(data)); n != want {
				t.Fatalf("got sep.Write(_, _) = (%d, _, nil), want = (%d, _, nil)", n, want)
			}

			if gotPayload, _, err := rep.Read(nil); test.expectRx {
				if err != nil {
					t.Fatalf("reep.Read(nil): %s", err)
				}
				if diff := cmp.Diff(buffer.View(data), gotPayload); diff != "" {
					t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
				}
			} else {
				if err != tcpip.ErrWouldBlock {
					t.Fatalf("got rep.Read(nil) = (%x, _, %s), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
				}
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
		AddressWithPrefix: ipv4Addr,
	}
	addrBytes := []byte(ipv4Addr.Address)
	addrBytes[len(addrBytes)-1]++
	otherAddr := tcpip.Address(addrBytes)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.AddProtocolAddress(nicID, protoAddr); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID, protoAddr, err)
	}
	s.SetRouteTable([]tcpip.Route{
		tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	r, err := s.FindRoute(nicID, otherAddr, remoteIPv4Addr, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("s.FindRoute(%d, %s, %s, %d, false): %s", nicID, otherAddr, remoteIPv4Addr, ipv4.ProtocolNumber, err)
	}
	defer r.Release()

	params := stack.NetworkHeaderParams{
		Protocol: 111,
		TTL:      64,
		TOS:      stack.DefaultTOS,
	}
	data := buffer.View([]byte{1, 2, 3, 4})
	if err := r.WritePacket(nil /* gso */, params, stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Data:               data.ToVectorisedView(),
	})); err != nil {
		t.Fatalf("r.WritePacket(nil, %#v, _): %s", params, err)
	}

	// Removing the address should make the endpoint invalid.
	if err := s.RemoveAddress(nicID, protoAddr.AddressWithPrefix.Address); err != nil {
		t.Fatalf("s.RemoveAddress(%d, %s): %s", nicID, protoAddr.AddressWithPrefix.Address, err)
	}
	if err := r.WritePacket(nil /* gso */, params, stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Data:               data.ToVectorisedView(),
	})); err != tcpip.ErrInvalidEndpointState {
		t.Fatalf("got r.WritePacket(nil, %#v, _) = %s, want = %s", params, err, tcpip.ErrInvalidEndpointState)
	}
}

func TestLoopbackPing(t *testing.T) {
	const (
		nicID        = 1
		ipv4Loopback = tcpip.Address("\x7f\x00\x00\x01")

		// icmpDataOffset is the offset to the data in both ICMPv4 and ICMPv6 echo
		// request/reply packets.
		icmpDataOffset = 8
	)

	tests := []struct {
		name       string
		transProto tcpip.TransportProtocolNumber
		netProto   tcpip.NetworkProtocolNumber
		addr       tcpip.Address
		icmpBuf    func(*testing.T) buffer.View
	}{
		{
			name:       "IPv4 Ping",
			transProto: icmp.ProtocolNumber4,
			netProto:   ipv4.ProtocolNumber,
			addr:       ipv4Loopback,
			icmpBuf: func(t *testing.T) buffer.View {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
				hdr.SetType(header.ICMPv4Echo)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return buffer.View(hdr)
			},
		},
		{
			name:       "IPv6 Ping",
			transProto: icmp.ProtocolNumber6,
			netProto:   ipv6.ProtocolNumber,
			addr:       header.IPv6Loopback,
			icmpBuf: func(t *testing.T) buffer.View {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
				hdr.SetType(header.ICMPv6EchoRequest)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return buffer.View(hdr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
				HandleLocal:        true,
			})
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddAddress(nicID, test.netProto, test.addr); err != nil {
				t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, test.netProto, test.addr, err)
			}

			var wq waiter.Queue
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			ep, err := s.NewEndpoint(test.transProto, test.netProto, &wq)
			if err != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", test.transProto, test.netProto, err)
			}
			defer ep.Close()

			connAddr := tcpip.FullAddress{Addr: test.addr}
			if err := ep.Connect(connAddr); err != nil {
				t.Fatalf("ep.Connect(%#v): %s", connAddr, err)
			}

			payload := tcpip.SlicePayload(test.icmpBuf(t))
			var wOpts tcpip.WriteOptions
			if n, _, err := ep.Write(payload, wOpts); err != nil {
				t.Fatalf("ep.Write(%#v, %#v): %s", payload, wOpts, err)
			} else if n != int64(len(payload)) {
				t.Fatalf("got ep.Write(%#v, %#v) = (%d, _, nil), want = (%d, _, nil)", payload, wOpts, n, len(payload))
			}

			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out")
			}
			var addr tcpip.FullAddress
			v, _, err := ep.Read(&addr)
			if err != nil {
				t.Fatalf("ep.Read(_): %s", err)
			}
			if diff := cmp.Diff(v[icmpDataOffset:], buffer.View(payload[icmpDataOffset:])); diff != "" {
				t.Errorf("received data mismatch (-want +got):\n%s", diff)
			}
			if addr.Addr != test.addr {
				t.Errorf("got addr.Addr = %s, want = %s", addr.Addr, test.addr)
			}
		})
	}
}
