// Copyright 2022 The gVisor Authors.
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

// Package datagram_test has tests shared by datagram-based transport endpoints.
package datagram_test

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestStateUpdates(t *testing.T) {
	const nicID = 1

	for _, test := range []struct {
		name           string
		createEndpoint func(*stack.Stack) (tcpip.Endpoint, error)
	}{
		{
			name: "UDP",
			createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
				ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
				if err != nil {
					return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", udp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				return ep, nil
			},
		},
		{
			name: "ICMP",
			createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
				ep, err := s.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &waiter.Queue{})
				if err != nil {
					return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", icmp.ProtocolNumber4, ipv4.ProtocolNumber, err)
				}
				return ep, nil
			},
		},
		{
			name: "RAW",
			createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
				ep, err := s.NewRawEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{}, true /* associated */)
				if err != nil {
					return nil, fmt.Errorf("s.NewRawEndpoint(%d, %d, _, true) failed: %s", udp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				return ep, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol4},
				RawFactory:         &raw.EndpointFactory{},
			})
			if err := s.CreateNIC(nicID, loopback.New()); err != nil {
				t.Fatalf("s.CreateNIC(%d, loopback.New()) failed: %s", nicID, err)
			}
			ep, err := test.createEndpoint(s)
			if err != nil {
				t.Fatalf("test.createEndpoint(_) failed: %s", err)
			}
			// The endpoint may be closed during the test, but closing twice is
			// expected to be a no-op.
			defer ep.Close()

			if got, want := transport.DatagramEndpointState(ep.State()), transport.DatagramEndpointStateInitial; got != want {
				t.Errorf("got ep.State() = %s, want = %s", got, want)
			}

			addr := tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: testutil.MustParse4("1.2.3.4").WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
			}
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			if err := ep.Bind(tcpip.FullAddress{}); err != nil {
				t.Fatalf("ep.Bind(...) failed: %s", err)
			}
			if got, want := transport.DatagramEndpointState(ep.State()), transport.DatagramEndpointStateBound; got != want {
				t.Errorf("got ep.State() = %s, want = %s", got, want)
			}

			if err := ep.Connect(tcpip.FullAddress{NIC: nicID, Addr: testutil.MustParse4("1.0.0.1"), Port: 12345}); err != nil {
				t.Fatalf("ep.Connect(...) failed: %s", err)
			}
			if got, want := transport.DatagramEndpointState(ep.State()), transport.DatagramEndpointStateConnected; got != want {
				t.Errorf("got ep.State() = %s, want = %s", got, want)
			}

			ep.Close()
			if got, want := transport.DatagramEndpointState(ep.State()), transport.DatagramEndpointStateClosed; got != want {
				t.Errorf("got ep.State() = %s, want = %s", got, want)
			}
		})
	}
}
