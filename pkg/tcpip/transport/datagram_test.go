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
	"bytes"
	"fmt"
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
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

type mockEndpoint struct {
	disp stack.NetworkDispatcher
	pkts stack.PacketBufferList
}

func (*mockEndpoint) MTU() uint32 {
	return math.MaxUint32
}
func (*mockEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}
func (*mockEndpoint) MaxHeaderLength() uint16 {
	return 0
}
func (*mockEndpoint) LinkAddress() tcpip.LinkAddress {
	var l tcpip.LinkAddress
	return l
}
func (e *mockEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	pkts.IncRef()
	e.pkts = pkts
	return pkts.Len(), nil
}
func (e *mockEndpoint) Attach(d stack.NetworkDispatcher)      { e.disp = d }
func (e *mockEndpoint) IsAttached() bool                      { return e.disp != nil }
func (*mockEndpoint) Wait()                                   {}
func (*mockEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*mockEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *mockEndpoint) releasePackets() {
	e.pkts.DecRef()
	e.pkts = stack.PacketBufferList{}
}

func TestSndBuf(t *testing.T) {
	const nicID = 1

	buf := buffer.NewView(header.ICMPv4MinimumSize)
	header.ICMPv4(buf).SetType(header.ICMPv4Echo)

	for _, test := range []struct {
		name           string
		createEndpoint func(*stack.Stack, *waiter.Queue) (tcpip.Endpoint, error)
	}{
		{
			name: "UDP",
			createEndpoint: func(s *stack.Stack, wq *waiter.Queue) (tcpip.Endpoint, error) {
				ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, wq)
				if err != nil {
					return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", udp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				return ep, nil
			},
		},
		{
			name: "ICMP",
			createEndpoint: func(s *stack.Stack, wq *waiter.Queue) (tcpip.Endpoint, error) {
				ep, err := s.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, wq)
				if err != nil {
					return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", icmp.ProtocolNumber4, ipv4.ProtocolNumber, err)
				}
				return ep, nil
			},
		},
		{
			name: "RAW",
			createEndpoint: func(s *stack.Stack, wq *waiter.Queue) (tcpip.Endpoint, error) {
				ep, err := s.NewRawEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, wq, true /* associated */)
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
			var e mockEndpoint
			defer e.releasePackets()
			if err := s.CreateNIC(nicID, &e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _) failed: %s", nicID, err)
			}
			var wq waiter.Queue
			ep, err := test.createEndpoint(s, &wq)
			if err != nil {
				t.Fatalf("test.createEndpoint(_) failed: %s", err)
			}
			defer ep.Close()

			ep.SocketOptions().SetSendBufferSize(1, false)

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

			to := tcpip.FullAddress{NIC: nicID, Addr: testutil.MustParse4("1.0.0.1"), Port: 12345}
			if err := ep.Connect(to); err != nil {
				t.Fatalf("ep.Connect(%#v): %s", to, err)
			}

			checkWrites := func() {
				t.Helper()

				if got := ep.Readiness(waiter.WritableEvents); got != waiter.WritableEvents {
					t.Fatalf("got ep.Readiness(0x%x) = 0x%x, want = 0x%x", waiter.WritableEvents, got, waiter.WritableEvents)
				}

				var r bytes.Reader
				r.Reset(buf[:])
				if n, err := ep.Write(&r, tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write(...): %s", err)
				} else if want := int64(len(buf)); n != want {
					t.Fatalf("got Write(...) = %d, want = %d", n, want)
				}

				if got := ep.Readiness(waiter.WritableEvents); got != 0 {
					t.Fatalf("got ep.Readiness(0x%x) = 0x%x, want = 0x0", waiter.WritableEvents, got)
				}

				// The next write should block since the packet we sent before
				// is still held.
				r.Reset(buf[:])
				wantErr := &tcpip.ErrWouldBlock{}
				if n, err := ep.Write(&r, tcpip.WriteOptions{}); err != wantErr {
					t.Fatalf("got Write(...) = (%d, %s), want = (_, %s)", n, err, wantErr)
				}
			}

			checkWrites()

			// Releasing the packets should open up the send buffer for the next
			// write.
			we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)
			e.releasePackets()
			<-ch
			checkWrites()
		})
	}
}
