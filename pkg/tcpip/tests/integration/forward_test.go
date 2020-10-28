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
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestForwarding(t *testing.T) {
	const (
		host1NICLinkAddr   = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
		routerNIC1LinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x07")
		routerNIC2LinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x08")
		host2NICLinkAddr   = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

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
		epAndAddrs func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) endpointAndAddresses
	}{
		{
			name: "IPv4 host1 server with host2 client",
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host1Stack, udp.ProtocolNumber, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, udp.ProtocolNumber, ipv4.ProtocolNumber)
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
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host2Stack, udp.ProtocolNumber, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host1Stack, udp.ProtocolNumber, ipv6.ProtocolNumber)
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
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, host2Stack, udp.ProtocolNumber, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, routerStack, udp.ProtocolNumber, ipv4.ProtocolNumber)
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
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) endpointAndAddresses {
				ep1, ep1WECH := newEP(t, routerStack, udp.ProtocolNumber, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host1Stack, udp.ProtocolNumber, ipv6.ProtocolNumber)
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			}

			host1Stack := stack.New(stackOpts)
			routerStack := stack.New(stackOpts)
			host2Stack := stack.New(stackOpts)

			host1NIC, routerNIC1 := pipe.New(host1NICLinkAddr, routerNIC1LinkAddr)
			routerNIC2, host2NIC := pipe.New(routerNIC2LinkAddr, host2NICLinkAddr)

			if err := host1Stack.CreateNIC(host1NICID, ethernet.New(host1NIC)); err != nil {
				t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
			}
			if err := routerStack.CreateNIC(routerNICID1, ethernet.New(routerNIC1)); err != nil {
				t.Fatalf("routerStack.CreateNIC(%d, _): %s", routerNICID1, err)
			}
			if err := routerStack.CreateNIC(routerNICID2, ethernet.New(routerNIC2)); err != nil {
				t.Fatalf("routerStack.CreateNIC(%d, _): %s", routerNICID2, err)
			}
			if err := host2Stack.CreateNIC(host2NICID, ethernet.New(host2NIC)); err != nil {
				t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
			}

			if err := routerStack.SetForwarding(ipv4.ProtocolNumber, true); err != nil {
				t.Fatalf("routerStack.SetForwarding(%d): %s", ipv4.ProtocolNumber, err)
			}
			if err := routerStack.SetForwarding(ipv6.ProtocolNumber, true); err != nil {
				t.Fatalf("routerStack.SetForwarding(%d): %s", ipv6.ProtocolNumber, err)
			}

			if err := host1Stack.AddAddress(host1NICID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("host1Stack.AddAddress(%d, %d, %s): %s", host1NICID, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}
			if err := routerStack.AddAddress(routerNICID1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("routerStack.AddAddress(%d, %d, %s): %s", routerNICID1, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}
			if err := routerStack.AddAddress(routerNICID2, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("routerStack.AddAddress(%d, %d, %s): %s", routerNICID2, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}
			if err := host2Stack.AddAddress(host2NICID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("host2Stack.AddAddress(%d, %d, %s): %s", host2NICID, arp.ProtocolNumber, arp.ProtocolAddress, err)
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
				tcpip.Route{
					Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         host1NICID,
				},
				tcpip.Route{
					Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
					NIC:         host1NICID,
				},
				tcpip.Route{
					Destination: host2IPv4Addr.AddressWithPrefix.Subnet(),
					Gateway:     routerNIC1IPv4Addr.AddressWithPrefix.Address,
					NIC:         host1NICID,
				},
				tcpip.Route{
					Destination: host2IPv6Addr.AddressWithPrefix.Subnet(),
					Gateway:     routerNIC1IPv6Addr.AddressWithPrefix.Address,
					NIC:         host1NICID,
				},
			})
			routerStack.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: routerNIC1IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         routerNICID1,
				},
				tcpip.Route{
					Destination: routerNIC1IPv6Addr.AddressWithPrefix.Subnet(),
					NIC:         routerNICID1,
				},
				tcpip.Route{
					Destination: routerNIC2IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         routerNICID2,
				},
				tcpip.Route{
					Destination: routerNIC2IPv6Addr.AddressWithPrefix.Subnet(),
					NIC:         routerNICID2,
				},
			})
			host2Stack.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: host2IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         host2NICID,
				},
				tcpip.Route{
					Destination: host2IPv6Addr.AddressWithPrefix.Subnet(),
					NIC:         host2NICID,
				},
				tcpip.Route{
					Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
					Gateway:     routerNIC2IPv4Addr.AddressWithPrefix.Address,
					NIC:         host2NICID,
				},
				tcpip.Route{
					Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
					Gateway:     routerNIC2IPv6Addr.AddressWithPrefix.Address,
					NIC:         host2NICID,
				},
			})

			epsAndAddrs := test.epAndAddrs(t, host1Stack, routerStack, host2Stack)
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

			write := func(ep tcpip.Endpoint, data []byte, to *tcpip.FullAddress) {
				t.Helper()

				dataPayload := tcpip.SlicePayload(data)
				wOpts := tcpip.WriteOptions{To: to}
				n, ch, err := ep.Write(dataPayload, wOpts)
				if err == tcpip.ErrNoLinkAddress {
					// Wait for link resolution to complete.
					<-ch
					n, _, err = ep.Write(dataPayload, wOpts)
				}
				if err != nil {
					t.Fatalf("ep.Write(_, _): %s", err)
				}
				if want := int64(len(data)); n != want {
					t.Fatalf("got ep.Write(_, _) = (%d, _, _), want = (%d, _, _)", n, want)
				}
			}

			data := []byte{1, 2, 3, 4}
			write(epsAndAddrs.clientEP, data, &serverAddr)

			read := func(ch chan struct{}, ep tcpip.Endpoint, data []byte, expectedFrom tcpip.Address) tcpip.FullAddress {
				t.Helper()

				// Wait for the endpoint to be readable.
				<-ch
				var addr tcpip.FullAddress
				v, _, err := ep.Read(&addr)
				if err != nil {
					t.Fatalf("ep.Read(_): %s", err)
				}

				if diff := cmp.Diff(v, buffer.View(data)); diff != "" {
					t.Errorf("received data mismatch (-want +got):\n%s", diff)
				}
				if addr.Addr != expectedFrom {
					t.Errorf("got addr.Addr = %s, want = %s", addr.Addr, expectedFrom)
				}

				if t.Failed() {
					t.FailNow()
				}

				return addr
			}

			addr := read(epsAndAddrs.serverReadableCH, epsAndAddrs.serverEP, data, epsAndAddrs.clientAddr)
			// Unspecify the NIC since NIC IDs are meaningless across stacks.
			addr.NIC = 0

			data = tcpip.SlicePayload([]byte{5, 6, 7, 8, 9, 10, 11, 12})
			write(epsAndAddrs.serverEP, data, &addr)
			addr = read(epsAndAddrs.clientReadableCH, epsAndAddrs.clientEP, data, epsAndAddrs.serverAddr)
			if addr.Port != listenPort {
				t.Errorf("got addr.Port = %d, want = %d", addr.Port, listenPort)
			}
		})
	}
}
