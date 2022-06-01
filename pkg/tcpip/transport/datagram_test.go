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

// Package transport_test has tests shared by datagram-based transport endpoints.
package transport_test

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
	disp     stack.NetworkDispatcher
	pkts     stack.PacketBufferList
	writeErr tcpip.Error
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
	if e.writeErr != nil {
		return 0, e.writeErr
	}

	len := pkts.Len()
	for _, pkt := range pkts.AsSlice() {
		e.pkts.PushBack(pkt.IncRef())
	}

	return len, nil
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

func (e *mockEndpoint) pktsSize() int {
	s := 0
	for _, pkt := range e.pkts.AsSlice() {
		s += pkt.Size() + pkt.AvailableHeaderBytes()
	}
	return s
}

func TestSndBuf(t *testing.T) {
	const nicID = 1

	buf := make([]byte, header.ICMPv4MinimumSize)
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

			checkWriteFail := func() {
				t.Helper()

				if got := ep.Readiness(waiter.WritableEvents); got != 0 {
					t.Fatalf("got ep.Readiness(0x%x) = 0x%x, want = 0x0", waiter.WritableEvents, got)
				}

				var r bytes.Reader
				r.Reset(buf[:])
				wantErr := &tcpip.ErrWouldBlock{}
				if n, err := ep.Write(&r, tcpip.WriteOptions{}); err != wantErr {
					t.Fatalf("got Write(...) = (%d, %s), want = (_, %s)", n, err, wantErr)
				}

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

				// The next write should fail since the packet we sent before
				// is still held.
				checkWriteFail()
			}

			we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)

			checkNoWritableEvent := func() {
				t.Helper()

				select {
				case <-ch:
					t.Fatal("unexpected writable event")
				default:
				}
			}

			checkWritableEvent := func() {
				t.Helper()

				select {
				case <-ch:
				default:
					t.Fatal("expected writable event")
				}
			}

			// As long as there is space in the send buffer, writes should succeed
			// so a send buffer of 1 allows at max 1 in-flight packet.
			ep.SocketOptions().SetSendBufferSize(1, true)
			checkWritableEvent()
			checkWrites()
			checkNoWritableEvent()

			// Increase the size of the send buffer but still be full.
			inUseSize := int64(e.pktsSize())
			checkNoWritableEvent()
			ep.SocketOptions().SetSendBufferSize(inUseSize, true /* notify */)
			checkNoWritableEvent()
			checkWriteFail()

			// Open up the send buffer by 1 byte.
			checkNoWritableEvent()
			ep.SocketOptions().SetSendBufferSize(inUseSize+1, true /* notify */)
			checkWritableEvent()
			checkWrites()

			// We can resize the send buffer to a smaller size but it is still
			// full so we can't write.
			checkNoWritableEvent()
			ep.SocketOptions().SetSendBufferSize(1, true /* notify */)
			checkNoWritableEvent()
			checkWriteFail()

			// Releasing the packets should open up the send buffer for the next
			// write.
			e.releasePackets()
			checkWritableEvent()
			checkWrites()
		})
	}
}

func TestDeviceReturnErrNoBufferSpace(t *testing.T) {
	const nicID = 1

	for _, networkTest := range []struct {
		name       string
		netProto   tcpip.NetworkProtocolNumber
		localAddr  tcpip.Address
		remoteAddr tcpip.Address
		buf        []byte
	}{
		{
			name:       "IPv4",
			netProto:   ipv4.ProtocolNumber,
			localAddr:  testutil.MustParse4("1.2.3.4"),
			remoteAddr: testutil.MustParse4("1.0.0.1"),
			buf: func() []byte {
				buf := make([]byte, header.ICMPv4MinimumSize)
				header.ICMPv4(buf).SetType(header.ICMPv4Echo)
				return buf
			}(),
		},
		{
			name:       "IPv6",
			netProto:   ipv6.ProtocolNumber,
			localAddr:  testutil.MustParse6("a::1"),
			remoteAddr: testutil.MustParse6("a::2"),
			buf: func() []byte {
				buf := make([]byte, header.ICMPv6MinimumSize)
				header.ICMPv6(buf).SetType(header.ICMPv6EchoRequest)
				return buf
			}(),
		},
	} {
		t.Run(networkTest.name, func(t *testing.T) {
			for _, test := range []struct {
				name           string
				createEndpoint func(*stack.Stack) (tcpip.Endpoint, error)
			}{
				// TODO(https://gvisor.dev/issues/7656): Also test ping sockets.
				{
					name: "UDP",
					createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
						ep, err := s.NewEndpoint(udp.ProtocolNumber, networkTest.netProto, &waiter.Queue{})
						if err != nil {
							return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", udp.ProtocolNumber, networkTest.netProto, err)
						}
						return ep, nil
					},
				},
				{
					name: "ICMP",
					createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
						proto := icmp.ProtocolNumber4
						if networkTest.netProto == ipv6.ProtocolNumber {
							proto = icmp.ProtocolNumber6
						}
						ep, err := s.NewEndpoint(proto, networkTest.netProto, &waiter.Queue{})
						if err != nil {
							return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", proto, networkTest.netProto, err)
						}
						return ep, nil
					},
				},
				{
					name: "RAW",
					createEndpoint: func(s *stack.Stack) (tcpip.Endpoint, error) {
						ep, err := s.NewRawEndpoint(udp.ProtocolNumber, networkTest.netProto, &waiter.Queue{}, true /* associated */)
						if err != nil {
							return nil, fmt.Errorf("s.NewRawEndpoint(%d, %d, _, true) failed: %s", udp.ProtocolNumber, networkTest.netProto, err)
						}
						return ep, nil
					},
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
						TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
						RawFactory:         &raw.EndpointFactory{},
					})
					e := mockEndpoint{writeErr: &tcpip.ErrNoBufferSpace{}}
					defer e.releasePackets()
					if err := s.CreateNIC(nicID, &e); err != nil {
						t.Fatalf("s.CreateNIC(%d, _) failed: %s", nicID, err)
					}
					ep, err := test.createEndpoint(s)
					if err != nil {
						t.Fatalf("test.createEndpoint(_) failed: %s", err)
					}
					defer ep.Close()

					addr := tcpip.ProtocolAddress{
						Protocol:          networkTest.netProto,
						AddressWithPrefix: networkTest.localAddr.WithPrefix(),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
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

					to := tcpip.FullAddress{NIC: nicID, Addr: networkTest.remoteAddr, Port: 12345}
					if err := ep.Connect(to); err != nil {
						t.Fatalf("ep.Connect(%#v): %s", to, err)
					}

					stackTxPacketsDroppedNoBufferSpace := s.Stats().NICs.TxPacketsDroppedNoBufferSpace

					nicsInfo := s.NICInfo()
					nicInfo, ok := nicsInfo[nicID]
					if !ok {
						t.Fatalf("expected NICInfo for nicID=%d; got s.NICInfo() = %#v", nicID, nicsInfo)
					}
					nicTxPacketsDroppedNoBufferSpace := nicInfo.Stats.TxPacketsDroppedNoBufferSpace

					checkStats := func(want uint64) {
						t.Helper()

						if got := stackTxPacketsDroppedNoBufferSpace.Value(); got != want {
							t.Errorf("got stackTxPacketsDroppedNoBufferSpace.Value() = %d, want = %d", got, want)
						}
						if got := nicTxPacketsDroppedNoBufferSpace.Value(); got != want {
							t.Errorf("got nicTxPacketsDroppedNoBufferSpace.Value() = %d, want = %d", got, want)
						}
					}

					droppedPkts := uint64(0)
					checkStats(droppedPkts)

					checkWrite := func(netProto tcpip.NetworkProtocolNumber) {
						t.Helper()

						var r bytes.Reader
						r.Reset(networkTest.buf)
						var wantErr tcpip.Error
						if netProto == networkTest.netProto {
							wantErr = &tcpip.ErrNoBufferSpace{}
						}
						if n, err := ep.Write(&r, tcpip.WriteOptions{}); err != wantErr {
							t.Fatalf("got Write(...) = (%d, %s), want = (_, %s)", n, err, wantErr)
						}

						droppedPkts++
						checkStats(droppedPkts)
					}

					ops := ep.SocketOptions()
					ops.SetIPv4RecvError(true)
					checkWrite(ipv4.ProtocolNumber)

					ops.SetIPv4RecvError(false)
					ops.SetIPv6RecvError(true)
					checkWrite(ipv6.ProtocolNumber)
				})
			}
		})
	}
}

func TestMulticastLoop(t *testing.T) {
	const (
		nicID = 1
		port  = 12345
	)

	for _, netProto := range []struct {
		name            string
		num             tcpip.NetworkProtocolNumber
		localAddr       tcpip.AddressWithPrefix
		destAddr        tcpip.Address
		rawSocketHdrLen int
	}{
		{
			name:            "IPv4",
			num:             header.IPv4ProtocolNumber,
			localAddr:       testutil.MustParse4("1.2.3.4").WithPrefix(),
			destAddr:        header.IPv4AllSystems,
			rawSocketHdrLen: header.IPv4MinimumSize,
		},
		{
			name:            "IPv6",
			num:             header.IPv6ProtocolNumber,
			localAddr:       testutil.MustParse6("a::1").WithPrefix(),
			destAddr:        header.IPv6AllNodesMulticastAddress,
			rawSocketHdrLen: 0,
		},
	} {
		t.Run(netProto.name, func(t *testing.T) {
			for _, test := range []struct {
				name             string
				createEndpoint   func(*stack.Stack, *waiter.Queue) (tcpip.Endpoint, error)
				includedHdrBytes int
			}{
				{
					name: "UDP",
					createEndpoint: func(s *stack.Stack, wq *waiter.Queue) (tcpip.Endpoint, error) {
						ep, err := s.NewEndpoint(udp.ProtocolNumber, netProto.num, wq)
						if err != nil {
							return nil, fmt.Errorf("s.NewEndpoint(%d, %d, _) failed: %s", udp.ProtocolNumber, netProto.num, err)
						}
						return ep, nil
					},
					includedHdrBytes: 0,
				},
				{
					name: "RAW",
					createEndpoint: func(s *stack.Stack, wq *waiter.Queue) (tcpip.Endpoint, error) {
						ep, err := s.NewRawEndpoint(udp.ProtocolNumber, netProto.num, wq, true /* associated */)
						if err != nil {
							return nil, fmt.Errorf("s.NewRawEndpoint(%d, %d, _, true) failed: %s", udp.ProtocolNumber, netProto.num, err)
						}
						return ep, nil
					},
					includedHdrBytes: netProto.rawSocketHdrLen,
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
						TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
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

					addr := tcpip.ProtocolAddress{
						Protocol:          netProto.num,
						AddressWithPrefix: netProto.localAddr,
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
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

					bind := tcpip.FullAddress{Port: port}
					if err := ep.Bind(bind); err != nil {
						t.Fatalf("ep.Bind(%#v): %s", bind, err)
					}

					to := tcpip.FullAddress{NIC: nicID, Addr: netProto.destAddr, Port: port}
					checkWrite := func(buf []byte, withRead bool) {
						t.Helper()

						{
							var r bytes.Reader
							r.Reset(buf[:])
							if n, err := ep.Write(&r, tcpip.WriteOptions{To: &to}); err != nil {
								t.Fatalf("Write(...): %s", err)
							} else if want := int64(len(buf)); n != want {
								t.Fatalf("got Write(...) = %d, want = %d", n, want)
							}
						}

						var wantErr tcpip.Error
						if !withRead {
							wantErr = &tcpip.ErrWouldBlock{}
						}

						var r bytes.Buffer
						if _, err := ep.Read(&r, tcpip.ReadOptions{}); err != wantErr {
							t.Fatalf("got Read(...) = %s, want = %s", err, wantErr)
						}
						if wantErr != nil {
							return
						}

						if diff := cmp.Diff(buf, r.Bytes()[test.includedHdrBytes:]); diff != "" {
							t.Errorf("read data bytes mismatch (-want +got):\n%s", diff)
						}
					}

					checkWrite([]byte{1, 2, 3, 4}, true /* withRead */)

					ops := ep.SocketOptions()
					ops.SetMulticastLoop(false)
					checkWrite([]byte{5, 6, 7, 8}, false /* withRead */)

					ops.SetMulticastLoop(true)
					checkWrite([]byte{9, 10, 11, 12}, true /* withRead */)
				})
			}
		})
	}
}
