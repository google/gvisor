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

package route_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestLocalPing tests pinging a remote that is local the stack.
//
// This tests that a local route is created and packets do not leave the stack.
func TestLocalPing(t *testing.T) {
	const (
		nicID = 1

		// icmpDataOffset is the offset to the data in both ICMPv4 and ICMPv6 echo
		// request/reply packets.
		icmpDataOffset = 8
	)
	ipv4Loopback := tcpip.AddressWithPrefix{
		Address:   testutil.MustParse4("127.0.0.1"),
		PrefixLen: 8,
	}

	channelEP := func() stack.LinkEndpoint { return channel.New(1, header.IPv6MinimumMTU, "") }
	channelEPCheck := func(t *testing.T, e stack.LinkEndpoint) {
		channelEP := e.(*channel.Endpoint)
		if n := channelEP.Drain(); n != 0 {
			t.Fatalf("got channelEP.Drain() = %d, want = 0", n)
		}
	}

	ipv4ICMPBuf := func(t *testing.T) []byte {
		data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
		hdr.SetType(header.ICMPv4Echo)
		if n := copy(hdr.Payload(), data[:]); n != len(data) {
			t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
		}
		return hdr
	}

	ipv6ICMPBuf := func(t *testing.T) []byte {
		data := [8]byte{1, 2, 3, 4, 5, 6, 7, 9}
		hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
		hdr.SetType(header.ICMPv6EchoRequest)
		if n := copy(hdr.Payload(), data[:]); n != len(data) {
			t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
		}
		return hdr
	}

	tests := []struct {
		name               string
		transProto         tcpip.TransportProtocolNumber
		netProto           tcpip.NetworkProtocolNumber
		linkEndpoint       func() stack.LinkEndpoint
		localAddr          tcpip.AddressWithPrefix
		icmpBuf            func(*testing.T) []byte
		expectedConnectErr tcpip.Error
		checkLinkEndpoint  func(t *testing.T, e stack.LinkEndpoint)
	}{
		{
			name:              "IPv4 loopback",
			transProto:        icmp.ProtocolNumber4,
			netProto:          ipv4.ProtocolNumber,
			linkEndpoint:      loopback.New,
			localAddr:         ipv4Loopback,
			icmpBuf:           ipv4ICMPBuf,
			checkLinkEndpoint: func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:              "IPv6 loopback",
			transProto:        icmp.ProtocolNumber6,
			netProto:          ipv6.ProtocolNumber,
			linkEndpoint:      loopback.New,
			localAddr:         header.IPv6Loopback.WithPrefix(),
			icmpBuf:           ipv6ICMPBuf,
			checkLinkEndpoint: func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:              "IPv4 non-loopback",
			transProto:        icmp.ProtocolNumber4,
			netProto:          ipv4.ProtocolNumber,
			linkEndpoint:      channelEP,
			localAddr:         utils.Ipv4Addr,
			icmpBuf:           ipv4ICMPBuf,
			checkLinkEndpoint: channelEPCheck,
		},
		{
			name:              "IPv6 non-loopback",
			transProto:        icmp.ProtocolNumber6,
			netProto:          ipv6.ProtocolNumber,
			linkEndpoint:      channelEP,
			localAddr:         utils.Ipv6Addr,
			icmpBuf:           ipv6ICMPBuf,
			checkLinkEndpoint: channelEPCheck,
		},
		{
			name:               "IPv4 loopback without local address",
			transProto:         icmp.ProtocolNumber4,
			netProto:           ipv4.ProtocolNumber,
			linkEndpoint:       loopback.New,
			icmpBuf:            ipv4ICMPBuf,
			expectedConnectErr: &tcpip.ErrHostUnreachable{},
			checkLinkEndpoint:  func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:               "IPv6 loopback without local address",
			transProto:         icmp.ProtocolNumber6,
			netProto:           ipv6.ProtocolNumber,
			linkEndpoint:       loopback.New,
			icmpBuf:            ipv6ICMPBuf,
			expectedConnectErr: &tcpip.ErrHostUnreachable{},
			checkLinkEndpoint:  func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:               "IPv4 non-loopback without local address",
			transProto:         icmp.ProtocolNumber4,
			netProto:           ipv4.ProtocolNumber,
			linkEndpoint:       channelEP,
			icmpBuf:            ipv4ICMPBuf,
			expectedConnectErr: &tcpip.ErrHostUnreachable{},
			checkLinkEndpoint:  channelEPCheck,
		},
		{
			name:               "IPv6 non-loopback without local address",
			transProto:         icmp.ProtocolNumber6,
			netProto:           ipv6.ProtocolNumber,
			linkEndpoint:       channelEP,
			icmpBuf:            ipv6ICMPBuf,
			expectedConnectErr: &tcpip.ErrHostUnreachable{},
			checkLinkEndpoint:  channelEPCheck,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, allowExternalLoopback := range []bool{true, false} {
				t.Run(fmt.Sprintf("AllowExternalLoopback=%t", allowExternalLoopback), func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{
							ipv4.NewProtocolWithOptions(ipv4.Options{
								AllowExternalLoopbackTraffic: allowExternalLoopback,
							}),
							ipv6.NewProtocolWithOptions(ipv6.Options{
								AllowExternalLoopbackTraffic: allowExternalLoopback,
							}),
						},
						TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
						HandleLocal:        true,
					})
					defer s.Destroy()
					e := test.linkEndpoint()
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}

					if len(test.localAddr.Address) != 0 {
						protocolAddr := tcpip.ProtocolAddress{
							Protocol:          test.netProto,
							AddressWithPrefix: test.localAddr,
						}
						if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
							t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
						}
					}

					var wq waiter.Queue
					we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
					wq.EventRegister(&we)
					ep, err := s.NewEndpoint(test.transProto, test.netProto, &wq)
					if err != nil {
						t.Fatalf("s.NewEndpoint(%d, %d, _): %s", test.transProto, test.netProto, err)
					}
					defer ep.Close()

					connAddr := tcpip.FullAddress{Addr: test.localAddr.Address}
					if err := ep.Connect(connAddr); err != test.expectedConnectErr {
						t.Fatalf("got ep.Connect(%#v) = %s, want = %s", connAddr, err, test.expectedConnectErr)
					}

					if test.expectedConnectErr != nil {
						return
					}

					var r bytes.Reader
					payload := test.icmpBuf(t)
					r.Reset(payload)
					var wOpts tcpip.WriteOptions
					if n, err := ep.Write(&r, wOpts); err != nil {
						t.Fatalf("ep.Write(%#v, %#v): %s", payload, wOpts, err)
					} else if n != int64(len(payload)) {
						t.Fatalf("got ep.Write(%#v, %#v) = (%d, _, nil), want = (%d, _, nil)", payload, wOpts, n, len(payload))
					}

					// Wait for the endpoint to become readable.
					<-ch

					var w bytes.Buffer
					rr, err := ep.Read(&w, tcpip.ReadOptions{
						NeedRemoteAddr: true,
					})
					if err != nil {
						t.Fatalf("ep.Read(...): %s", err)
					}
					if diff := cmp.Diff(w.Bytes()[icmpDataOffset:], payload[icmpDataOffset:]); diff != "" {
						t.Errorf("received data mismatch (-want +got):\n%s", diff)
					}
					if rr.RemoteAddr.Addr != test.localAddr.Address {
						t.Errorf("got addr.Addr = %s, want = %s", rr.RemoteAddr.Addr, test.localAddr.Address)
					}

					test.checkLinkEndpoint(t, e)
				})
			}
		})
	}
}

// TestLocalUDP tests sending UDP packets between two endpoints that are local
// to the stack.
//
// This tests that that packets never leave the stack and the addresses
// used when sending a packet.
func TestLocalUDP(t *testing.T) {
	const (
		nicID = 1
	)

	tests := []struct {
		name             string
		canBePrimaryAddr tcpip.ProtocolAddress
		firstPrimaryAddr tcpip.ProtocolAddress
	}{
		{
			name:             "IPv4",
			canBePrimaryAddr: utils.Ipv4Addr1,
			firstPrimaryAddr: utils.Ipv4Addr2,
		},
		{
			name:             "IPv6",
			canBePrimaryAddr: utils.Ipv6Addr1,
			firstPrimaryAddr: utils.Ipv6Addr2,
		},
	}

	subTests := []struct {
		name             string
		addAddress       bool
		expectedWriteErr tcpip.Error
	}{
		{
			name:             "Unassigned local address",
			addAddress:       false,
			expectedWriteErr: &tcpip.ErrHostUnreachable{},
		},
		{
			name:             "Assigned local address",
			addAddress:       true,
			expectedWriteErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					stackOpts := stack.Options{
						NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
						TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
						HandleLocal:        true,
					}

					s := stack.New(stackOpts)
					defer s.Destroy()
					ep := channel.New(1, header.IPv6MinimumMTU, "")

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}

					if subTest.addAddress {
						if err := s.AddProtocolAddress(nicID, test.canBePrimaryAddr, stack.AddressProperties{}); err != nil {
							t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, test.canBePrimaryAddr, err)
						}
						properties := stack.AddressProperties{PEB: stack.FirstPrimaryEndpoint}
						if err := s.AddProtocolAddress(nicID, test.firstPrimaryAddr, properties); err != nil {
							t.Fatalf("s.AddProtocolAddress(%d, %+v, %+v): %s", nicID, test.firstPrimaryAddr, properties, err)
						}
					}

					var serverWQ waiter.Queue
					serverWE, serverCH := waiter.NewChannelEntry(waiter.ReadableEvents)
					serverWQ.EventRegister(&serverWE)
					server, err := s.NewEndpoint(udp.ProtocolNumber, test.firstPrimaryAddr.Protocol, &serverWQ)
					if err != nil {
						t.Fatalf("s.NewEndpoint(%d, %d): %s", udp.ProtocolNumber, test.firstPrimaryAddr.Protocol, err)
					}
					defer server.Close()

					bindAddr := tcpip.FullAddress{Port: 80}
					if err := server.Bind(bindAddr); err != nil {
						t.Fatalf("server.Bind(%#v): %s", bindAddr, err)
					}

					var clientWQ waiter.Queue
					clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents)
					clientWQ.EventRegister(&clientWE)
					client, err := s.NewEndpoint(udp.ProtocolNumber, test.firstPrimaryAddr.Protocol, &clientWQ)
					if err != nil {
						t.Fatalf("s.NewEndpoint(%d, %d): %s", udp.ProtocolNumber, test.firstPrimaryAddr.Protocol, err)
					}
					defer client.Close()

					serverAddr := tcpip.FullAddress{
						Addr: test.canBePrimaryAddr.AddressWithPrefix.Address,
						Port: 80,
					}

					clientPayload := []byte{1, 2, 3, 4}
					{
						var r bytes.Reader
						r.Reset(clientPayload)
						wOpts := tcpip.WriteOptions{
							To: &serverAddr,
						}
						if n, err := client.Write(&r, wOpts); err != subTest.expectedWriteErr {
							t.Fatalf("got client.Write(%#v, %#v) = (%d, %s), want = (_, %s)", clientPayload, wOpts, n, err, subTest.expectedWriteErr)
						} else if subTest.expectedWriteErr != nil {
							// Nothing else to test if we expected not to be able to send the
							// UDP packet.
							return
						} else if n != int64(len(clientPayload)) {
							t.Fatalf("got client.Write(%#v, %#v) = (%d, nil), want = (%d, nil)", clientPayload, wOpts, n, len(clientPayload))
						}
					}

					// Wait for the server endpoint to become readable.
					<-serverCH

					var clientAddr tcpip.FullAddress
					var readBuf bytes.Buffer
					if read, err := server.Read(&readBuf, tcpip.ReadOptions{NeedRemoteAddr: true}); err != nil {
						t.Fatalf("server.Read(_): %s", err)
					} else {
						clientAddr = read.RemoteAddr

						if diff := cmp.Diff(tcpip.ReadResult{
							Count: readBuf.Len(),
							Total: readBuf.Len(),
							RemoteAddr: tcpip.FullAddress{
								Addr: test.canBePrimaryAddr.AddressWithPrefix.Address,
							},
						}, read, checker.IgnoreCmpPath(
							"ControlMessages",
							"RemoteAddr.NIC",
							"RemoteAddr.Port",
						)); diff != "" {
							t.Errorf("server.Read: unexpected result (-want +got):\n%s", diff)
						}
						if diff := cmp.Diff(clientPayload, readBuf.Bytes()); diff != "" {
							t.Errorf("server read clientPayload mismatch (-want +got):\n%s", diff)
						}
						if t.Failed() {
							t.FailNow()
						}
					}

					serverPayload := []byte{1, 2, 3, 4}
					{
						var r bytes.Reader
						r.Reset(serverPayload)
						wOpts := tcpip.WriteOptions{
							To: &clientAddr,
						}
						if n, err := server.Write(&r, wOpts); err != nil {
							t.Fatalf("server.Write(%#v, %#v): %s", serverPayload, wOpts, err)
						} else if n != int64(len(serverPayload)) {
							t.Fatalf("got server.Write(%#v, %#v) = (%d, nil), want = (%d, nil)", serverPayload, wOpts, n, len(serverPayload))
						}
					}

					// Wait for the client endpoint to become readable.
					<-clientCH

					readBuf.Reset()
					if read, err := client.Read(&readBuf, tcpip.ReadOptions{NeedRemoteAddr: true}); err != nil {
						t.Fatalf("client.Read(_): %s", err)
					} else {
						if diff := cmp.Diff(tcpip.ReadResult{
							Count:      readBuf.Len(),
							Total:      readBuf.Len(),
							RemoteAddr: tcpip.FullAddress{Addr: serverAddr.Addr},
						}, read, checker.IgnoreCmpPath(
							"ControlMessages",
							"RemoteAddr.NIC",
							"RemoteAddr.Port",
						)); diff != "" {
							t.Errorf("client.Read: unexpected result (-want +got):\n%s", diff)
						}
						if diff := cmp.Diff(serverPayload, readBuf.Bytes()); diff != "" {
							t.Errorf("client read serverPayload mismatch (-want +got):\n%s", diff)
						}
						if t.Failed() {
							t.FailNow()
						}
					}
				})
			}
		})
	}
}
