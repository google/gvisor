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

package forward_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestForwarding(t *testing.T) {
	const listenPort = 8080

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
					serverAddr:       utils.Host1IPv4Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv4Addr.AddressWithPrefix.Address,
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
					serverAddr:       utils.Host2IPv6Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       utils.Host1IPv6Addr.AddressWithPrefix.Address,
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
					serverAddr:       utils.Host2IPv4Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
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
					serverAddr:       utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
					serverReadableCH: ep1WECH,

					clientEP:         ep2,
					clientAddr:       utils.Host1IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
				}
			},
		},
	}

	subTests := []struct {
		name               string
		proto              tcpip.TransportProtocolNumber
		expectedConnectErr tcpip.Error
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
			expectedConnectErr: &tcpip.ErrConnectStarted{},
			setupServerSide: func(t *testing.T, ep tcpip.Endpoint, ch <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{}) {
				t.Helper()

				if err := ep.Listen(1); err != nil {
					t.Fatalf("ep.Listen(1): %s", err)
				}
				var addr tcpip.FullAddress
				for {
					newEP, wq, err := ep.Accept(&addr)
					if _, ok := err.(*tcpip.ErrWouldBlock); ok {
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
					utils.SetupRoutedStacks(t, host1Stack, routerStack, host2Stack)

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

					{
						err := epsAndAddrs.clientEP.Connect(serverAddr)
						if diff := cmp.Diff(subTest.expectedConnectErr, err); diff != "" {
							t.Fatalf("unexpected error from epsAndAddrs.clientEP.Connect(%#v), (-want, +got):\n%s", serverAddr, diff)
						}
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
