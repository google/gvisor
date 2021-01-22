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
	"bytes"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ stack.NetworkDispatcher = (*endpointWithDestinationCheck)(nil)
var _ stack.LinkEndpoint = (*endpointWithDestinationCheck)(nil)

// newEthernetEndpoint returns an ethernet link endpoint that wraps an inner
// link endpoint and checks the destination link address before delivering
// network packets to the network dispatcher.
//
// See ethernet.Endpoint for more details.
func newEthernetEndpoint(ep stack.LinkEndpoint) *endpointWithDestinationCheck {
	var e endpointWithDestinationCheck
	e.Endpoint.Init(ethernet.New(ep), &e)
	return &e
}

// endpointWithDestinationCheck is a link endpoint that checks the destination
// link address before delivering network packets to the network dispatcher.
type endpointWithDestinationCheck struct {
	nested.Endpoint
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *endpointWithDestinationCheck) DeliverNetworkPacket(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if dst == e.Endpoint.LinkAddress() || dst == header.EthernetBroadcastAddress || header.IsMulticastEthernetAddress(dst) {
		e.Endpoint.DeliverNetworkPacket(src, dst, proto, pkt)
	}
}

func TestForwarding(t *testing.T) {
	const (
		host1NICID   = 1
		routerNICID1 = 2
		routerNICID2 = 3
		host2NICID   = 4

		listenPort = 8080
	)

	host1IPv4Addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 24,
		},
	}
	routerNIC1IPv4Addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	routerNIC2IPv4Addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("10.0.0.1").To4()),
			PrefixLen: 8,
		},
	}
	host2IPv4Addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("10.0.0.2").To4()),
			PrefixLen: 8,
		},
	}
	host1IPv6Addr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::2").To16()),
			PrefixLen: 64,
		},
	}
	routerNIC1IPv6Addr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	routerNIC2IPv6Addr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("b::1").To16()),
			PrefixLen: 64,
		},
	}
	host2IPv6Addr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("b::2").To16()),
			PrefixLen: 64,
		},
	}

	type endpointAndAddresses struct {
		serverEP         tcpip.Endpoint
		serverAddr       tcpip.Address
		serverReadableCH chan struct{}

		clientEP         tcpip.Endpoint
		clientAddr       tcpip.Address
		clientReadableCH chan struct{}
	}

	newEP := func(t *testing.T, s *stack.Stack, transProto tcpip.TransportProtocolNumber, netProto tcpip.NetworkProtocolNumber) (tcpip.Endpoint, chan struct{}) {
		t.Helper()
		var wq waiter.Queue
		we, ch := waiter.NewChannelEntry(nil)
		wq.EventRegister(&we, waiter.EventIn)
		ep, err := s.NewEndpoint(transProto, netProto, &wq)
		if err != nil {
			t.Fatalf("s.NewEndpoint(%d, %d, _): %s", transProto, netProto, err)
		}

		t.Cleanup(func() {
			wq.EventUnregister(&we)
		})

		return ep, ch
	}

	tests := []struct {
		name       string
		epAndAddrs func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses
	}{
		{
			name: "IPv4 host1 server with host2 client",
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host1Stack, proto, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv4.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:         ep1,
					serverAddr:       host1IPv4Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       host2IPv4Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
				}
			},
		},
		{
			name: "IPv6 host2 server with host1 client",
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host2Stack, proto, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host1Stack, proto, ipv6.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:         ep1,
					serverAddr:       host2IPv6Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       host1IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
				}
			},
		},
		{
			name: "IPv4 host2 server with routerNIC1 client",
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host2Stack, proto, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, routerStack, proto, ipv4.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:         ep1,
					serverAddr:       host2IPv4Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       routerNIC1IPv4Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
				}
			},
		},
		{
			name: "IPv6 routerNIC2 server with host1 client",
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, routerStack, proto, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host1Stack, proto, ipv6.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:         ep1,
					serverAddr:       routerNIC2IPv6Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       host1IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
				}
			},
		},
	}

	subTests := []struct {
		name               string
		proto              tcpip.TransportProtocolNumber
		expectedConnectErr *tcpip.Error
		setupServerSide    func(t *testing.T, ep tcpip.Endpoint, ch <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{})
		needRemoteAddr     bool
	}{
		{
			name:               "UDP",
			proto:              udp.ProtocolNumber,
			expectedConnectErr: nil,
			setupServerSide: func(t *testing.T, ep tcpip.Endpoint, _ <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{}) {
				t.Helper()

				if err := ep.Connect(clientAddr); err != nil {
					t.Fatalf("ep.Connect(%#v): %s", clientAddr, err)
				}
				return nil, nil
			},
			needRemoteAddr: true,
		},
		{
			name:               "TCP",
			proto:              tcp.ProtocolNumber,
			expectedConnectErr: tcpip.ErrConnectStarted,
			setupServerSide: func(t *testing.T, ep tcpip.Endpoint, ch <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{}) {
				t.Helper()

				if err := ep.Listen(1); err != nil {
					t.Fatalf("ep.Listen(1): %s", err)
				}
				var addr tcpip.FullAddress
				for {
					newEP, wq, err := ep.Accept(&addr)
					if err == tcpip.ErrWouldBlock {
						<-ch
						continue
					}
					if err != nil {
						t.Fatalf("ep.Accept(_): %s", err)
					}
					if diff := cmp.Diff(clientAddr, addr, checker.IgnoreCmpPath(
						"NIC",
					)); diff != "" {
						t.Errorf("accepted address mismatch (-want +got):\n%s", diff)
					}

					we, newCH := waiter.NewChannelEntry(nil)
					wq.EventRegister(&we, waiter.EventIn)
					return newEP, newCH
				}
			},
			needRemoteAddr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					stackOpts := stack.Options{
						NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
						TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
					}

					host1Stack := stack.New(stackOpts)
					routerStack := stack.New(stackOpts)
					host2Stack := stack.New(stackOpts)

					host1NIC, routerNIC1 := pipe.New(linkAddr1, linkAddr2)
					routerNIC2, host2NIC := pipe.New(linkAddr3, linkAddr4)

					if err := host1Stack.CreateNIC(host1NICID, newEthernetEndpoint(host1NIC)); err != nil {
						t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
					}
					if err := routerStack.CreateNIC(routerNICID1, newEthernetEndpoint(routerNIC1)); err != nil {
						t.Fatalf("routerStack.CreateNIC(%d, _): %s", routerNICID1, err)
					}
					if err := routerStack.CreateNIC(routerNICID2, newEthernetEndpoint(routerNIC2)); err != nil {
						t.Fatalf("routerStack.CreateNIC(%d, _): %s", routerNICID2, err)
					}
					if err := host2Stack.CreateNIC(host2NICID, newEthernetEndpoint(host2NIC)); err != nil {
						t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
					}

					if err := routerStack.SetForwarding(ipv4.ProtocolNumber, true); err != nil {
						t.Fatalf("routerStack.SetForwarding(%d): %s", ipv4.ProtocolNumber, err)
					}
					if err := routerStack.SetForwarding(ipv6.ProtocolNumber, true); err != nil {
						t.Fatalf("routerStack.SetForwarding(%d): %s", ipv6.ProtocolNumber, err)
					}

					if err := host1Stack.AddProtocolAddress(host1NICID, host1IPv4Addr); err != nil {
						t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, host1IPv4Addr, err)
					}
					if err := routerStack.AddProtocolAddress(routerNICID1, routerNIC1IPv4Addr); err != nil {
						t.Fatalf("routerStack.AddProtocolAddress(%d, %#v): %s", routerNICID1, routerNIC1IPv4Addr, err)
					}
					if err := routerStack.AddProtocolAddress(routerNICID2, routerNIC2IPv4Addr); err != nil {
						t.Fatalf("routerStack.AddProtocolAddress(%d, %#v): %s", routerNICID2, routerNIC2IPv4Addr, err)
					}
					if err := host2Stack.AddProtocolAddress(host2NICID, host2IPv4Addr); err != nil {
						t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, host2IPv4Addr, err)
					}
					if err := host1Stack.AddProtocolAddress(host1NICID, host1IPv6Addr); err != nil {
						t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, host1IPv6Addr, err)
					}
					if err := routerStack.AddProtocolAddress(routerNICID1, routerNIC1IPv6Addr); err != nil {
						t.Fatalf("routerStack.AddProtocolAddress(%d, %#v): %s", routerNICID1, routerNIC1IPv6Addr, err)
					}
					if err := routerStack.AddProtocolAddress(routerNICID2, routerNIC2IPv6Addr); err != nil {
						t.Fatalf("routerStack.AddProtocolAddress(%d, %#v): %s", routerNICID2, routerNIC2IPv6Addr, err)
					}
					if err := host2Stack.AddProtocolAddress(host2NICID, host2IPv6Addr); err != nil {
						t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, host2IPv6Addr, err)
					}

					host1Stack.SetRouteTable([]tcpip.Route{
						{
							Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
							NIC:         host1NICID,
						},
						{
							Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
							NIC:         host1NICID,
						},
						{
							Destination: host2IPv4Addr.AddressWithPrefix.Subnet(),
							Gateway:     routerNIC1IPv4Addr.AddressWithPrefix.Address,
							NIC:         host1NICID,
						},
						{
							Destination: host2IPv6Addr.AddressWithPrefix.Subnet(),
							Gateway:     routerNIC1IPv6Addr.AddressWithPrefix.Address,
							NIC:         host1NICID,
						},
					})
					routerStack.SetRouteTable([]tcpip.Route{
						{
							Destination: routerNIC1IPv4Addr.AddressWithPrefix.Subnet(),
							NIC:         routerNICID1,
						},
						{
							Destination: routerNIC1IPv6Addr.AddressWithPrefix.Subnet(),
							NIC:         routerNICID1,
						},
						{
							Destination: routerNIC2IPv4Addr.AddressWithPrefix.Subnet(),
							NIC:         routerNICID2,
						},
						{
							Destination: routerNIC2IPv6Addr.AddressWithPrefix.Subnet(),
							NIC:         routerNICID2,
						},
					})
					host2Stack.SetRouteTable([]tcpip.Route{
						{
							Destination: host2IPv4Addr.AddressWithPrefix.Subnet(),
							NIC:         host2NICID,
						},
						{
							Destination: host2IPv6Addr.AddressWithPrefix.Subnet(),
							NIC:         host2NICID,
						},
						{
							Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
							Gateway:     routerNIC2IPv4Addr.AddressWithPrefix.Address,
							NIC:         host2NICID,
						},
						{
							Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
							Gateway:     routerNIC2IPv6Addr.AddressWithPrefix.Address,
							NIC:         host2NICID,
						},
					})

					epsAndAddrs := test.epAndAddrs(t, host1Stack, routerStack, host2Stack, subTest.proto)
					defer epsAndAddrs.serverEP.Close()
					defer epsAndAddrs.clientEP.Close()

					serverAddr := tcpip.FullAddress{Addr: epsAndAddrs.serverAddr, Port: listenPort}
					if err := epsAndAddrs.serverEP.Bind(serverAddr); err != nil {
						t.Fatalf("epsAndAddrs.serverEP.Bind(%#v): %s", serverAddr, err)
					}
					clientAddr := tcpip.FullAddress{Addr: epsAndAddrs.clientAddr}
					if err := epsAndAddrs.clientEP.Bind(clientAddr); err != nil {
						t.Fatalf("epsAndAddrs.clientEP.Bind(%#v): %s", clientAddr, err)
					}

					if err := epsAndAddrs.clientEP.Connect(serverAddr); err != subTest.expectedConnectErr {
						t.Fatalf("got epsAndAddrs.clientEP.Connect(%#v) = %s, want = %s", serverAddr, err, subTest.expectedConnectErr)
					}
					if addr, err := epsAndAddrs.clientEP.GetLocalAddress(); err != nil {
						t.Fatalf("epsAndAddrs.clientEP.GetLocalAddress(): %s", err)
					} else {
						clientAddr = addr
						clientAddr.NIC = 0
					}

					serverEP := epsAndAddrs.serverEP
					serverCH := epsAndAddrs.serverReadableCH
					if ep, ch := subTest.setupServerSide(t, serverEP, serverCH, clientAddr); ep != nil {
						defer ep.Close()
						serverEP = ep
						serverCH = ch
					}

					write := func(ep tcpip.Endpoint, data []byte) {
						t.Helper()

						var r bytes.Reader
						r.Reset(data)
						var wOpts tcpip.WriteOptions
						n, err := ep.Write(&r, wOpts)
						if err != nil {
							t.Fatalf("ep.Write(_, %#v): %s", wOpts, err)
						}
						if want := int64(len(data)); n != want {
							t.Fatalf("got ep.Write(_, %#v) = (%d, _), want = (%d, _)", wOpts, n, want)
						}
					}

					data := []byte{1, 2, 3, 4}
					write(epsAndAddrs.clientEP, data)

					read := func(ch chan struct{}, ep tcpip.Endpoint, data []byte, expectedFrom tcpip.FullAddress) {
						t.Helper()

						// Wait for the endpoint to be readable.
						<-ch
						var buf bytes.Buffer
						opts := tcpip.ReadOptions{NeedRemoteAddr: subTest.needRemoteAddr}
						res, err := ep.Read(&buf, opts)
						if err != nil {
							t.Fatalf("ep.Read(_, %d, %#v): %s", len(data), opts, err)
						}

						readResult := tcpip.ReadResult{
							Count: len(data),
							Total: len(data),
						}
						if subTest.needRemoteAddr {
							readResult.RemoteAddr = expectedFrom
						}
						if diff := cmp.Diff(readResult, res, checker.IgnoreCmpPath(
							"ControlMessages",
							"RemoteAddr.NIC",
						)); diff != "" {
							t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
						}
						if diff := cmp.Diff(buf.Bytes(), data); diff != "" {
							t.Errorf("received data mismatch (-want +got):\n%s", diff)
						}

						if t.Failed() {
							t.FailNow()
						}
					}

					read(serverCH, serverEP, data, clientAddr)

					data = []byte{5, 6, 7, 8, 9, 10, 11, 12}
					write(serverEP, data)
					read(epsAndAddrs.clientReadableCH, epsAndAddrs.clientEP, data, serverAddr)
				})
			}
		})
	}
}
