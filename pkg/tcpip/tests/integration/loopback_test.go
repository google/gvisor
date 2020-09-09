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

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

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
			name:       "IPv6 bind to wildcard and send to assigned address",
			addAddress: ipv6ProtocolAddress,
			dstAddr:    ipv6Addr.Address,
			expectRx:   true,
		},
		{
			name:       "IPv6 bind to wildcard and send to other subnet-local address",
			addAddress: ipv6ProtocolAddress,
			dstAddr:    otherIPv6Address,
			expectRx:   true,
		},
		{
			name:       "IPv6 bind to wildcard send to other address",
			addAddress: ipv6ProtocolAddress,
			dstAddr:    remoteIPv6Addr,
			expectRx:   false,
		},
		{
			name:       "IPv6 bind to other subnet-local address and send to assigned address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   otherIPv6Address,
			dstAddr:    ipv6Addr.Address,
			expectRx:   false,
		},
		{
			name:       "IPv6 bind and send to other subnet-local address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   otherIPv6Address,
			dstAddr:    otherIPv6Address,
			expectRx:   true,
		},
		{
			name:       "IPv6 bind to assigned address and send to other subnet-local address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   ipv6Addr.Address,
			dstAddr:    otherIPv6Address,
			expectRx:   false,
		},
		{
			name:       "IPv6 bind and send to assigned address",
			addAddress: ipv6ProtocolAddress,
			bindAddr:   ipv6Addr.Address,
			dstAddr:    ipv6Addr.Address,
			expectRx:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
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
