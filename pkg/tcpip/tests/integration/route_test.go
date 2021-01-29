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
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestLocalPing tests pinging a remote that is local the stack.
//
// This tests that a local route is created and packets do not leave the stack.
func TestLocalPing(t *testing.T) {
	const (
		nicID        = 1
		ipv4Loopback = tcpip.Address("\x7f\x00\x00\x01")

		// icmpDataOffset is the offset to the data in both ICMPv4 and ICMPv6 echo
		// request/reply packets.
		icmpDataOffset = 8
	)

	channelEP := func() stack.LinkEndpoint { return channel.New(1, header.IPv6MinimumMTU, "") }
	channelEPCheck := func(t *testing.T, e stack.LinkEndpoint) {
		channelEP := e.(*channel.Endpoint)
		if n := channelEP.Drain(); n != 0 {
			t.Fatalf("got channelEP.Drain() = %d, want = 0", n)
		}
	}

	ipv4ICMPBuf := func(t *testing.T) buffer.View {
		data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
		hdr.SetType(header.ICMPv4Echo)
		if n := copy(hdr.Payload(), data[:]); n != len(data) {
			t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
		}
		return buffer.View(hdr)
	}

	ipv6ICMPBuf := func(t *testing.T) buffer.View {
		data := [8]byte{1, 2, 3, 4, 5, 6, 7, 9}
		hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
		hdr.SetType(header.ICMPv6EchoRequest)
		if n := copy(hdr.Payload(), data[:]); n != len(data) {
			t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
		}
		return buffer.View(hdr)
	}

	tests := []struct {
		name               string
		transProto         tcpip.TransportProtocolNumber
		netProto           tcpip.NetworkProtocolNumber
		linkEndpoint       func() stack.LinkEndpoint
		localAddr          tcpip.Address
		icmpBuf            func(*testing.T) buffer.View
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
			localAddr:         header.IPv6Loopback,
			icmpBuf:           ipv6ICMPBuf,
			checkLinkEndpoint: func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:              "IPv4 non-loopback",
			transProto:        icmp.ProtocolNumber4,
			netProto:          ipv4.ProtocolNumber,
			linkEndpoint:      channelEP,
			localAddr:         ipv4Addr.Address,
			icmpBuf:           ipv4ICMPBuf,
			checkLinkEndpoint: channelEPCheck,
		},
		{
			name:              "IPv6 non-loopback",
			transProto:        icmp.ProtocolNumber6,
			netProto:          ipv6.ProtocolNumber,
			linkEndpoint:      channelEP,
			localAddr:         ipv6Addr.Address,
			icmpBuf:           ipv6ICMPBuf,
			checkLinkEndpoint: channelEPCheck,
		},
		{
			name:               "IPv4 loopback without local address",
			transProto:         icmp.ProtocolNumber4,
			netProto:           ipv4.ProtocolNumber,
			linkEndpoint:       loopback.New,
			icmpBuf:            ipv4ICMPBuf,
			expectedConnectErr: &tcpip.ErrNoRoute{},
			checkLinkEndpoint:  func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:               "IPv6 loopback without local address",
			transProto:         icmp.ProtocolNumber6,
			netProto:           ipv6.ProtocolNumber,
			linkEndpoint:       loopback.New,
			icmpBuf:            ipv6ICMPBuf,
			expectedConnectErr: &tcpip.ErrNoRoute{},
			checkLinkEndpoint:  func(*testing.T, stack.LinkEndpoint) {},
		},
		{
			name:               "IPv4 non-loopback without local address",
			transProto:         icmp.ProtocolNumber4,
			netProto:           ipv4.ProtocolNumber,
			linkEndpoint:       channelEP,
			icmpBuf:            ipv4ICMPBuf,
			expectedConnectErr: &tcpip.ErrNoRoute{},
			checkLinkEndpoint:  channelEPCheck,
		},
		{
			name:               "IPv6 non-loopback without local address",
			transProto:         icmp.ProtocolNumber6,
			netProto:           ipv6.ProtocolNumber,
			linkEndpoint:       channelEP,
			icmpBuf:            ipv6ICMPBuf,
			expectedConnectErr: &tcpip.ErrNoRoute{},
			checkLinkEndpoint:  channelEPCheck,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
				HandleLocal:        true,
			})
			e := test.linkEndpoint()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}

			if len(test.localAddr) != 0 {
				if err := s.AddAddress(nicID, test.netProto, test.localAddr); err != nil {
					t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, test.netProto, test.localAddr, err)
				}
			}

			var wq waiter.Queue
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			ep, err := s.NewEndpoint(test.transProto, test.netProto, &wq)
			if err != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", test.transProto, test.netProto, err)
			}
			defer ep.Close()

			connAddr := tcpip.FullAddress{Addr: test.localAddr}
			{
				err := ep.Connect(connAddr)
				if diff := cmp.Diff(test.expectedConnectErr, err); diff != "" {
					t.Fatalf("unexpected error from ep.Connect(%#v), (-want, +got):\n%s", connAddr, diff)
				}
			}

			if test.expectedConnectErr != nil {
				return
			}

			payload := test.icmpBuf(t)
			var r bytes.Reader
			r.Reset(payload)
			var wOpts tcpip.WriteOptions
			if n, err := ep.Write(&r, wOpts); err != nil {
				t.Fatalf("ep.Write(%#v, %#v): %s", payload, wOpts, err)
			} else if n != int64(len(payload)) {
				t.Fatalf("got ep.Write(%#v, %#v) = (%d, nil), want = (%d, nil)", payload, wOpts, n, len(payload))
			}

			// Wait for the endpoint to become readable.
			<-ch

			var buf bytes.Buffer
			opts := tcpip.ReadOptions{NeedRemoteAddr: true}
			res, err := ep.Read(&buf, opts)
			if err != nil {
				t.Fatalf("ep.Read(_, %#v): %s", opts, err)
			}
			if diff := cmp.Diff(tcpip.ReadResult{
				Count:      buf.Len(),
				Total:      buf.Len(),
				RemoteAddr: tcpip.FullAddress{Addr: test.localAddr},
			}, res, checker.IgnoreCmpPath(
				"ControlMessages",
				"RemoteAddr.NIC",
				"RemoteAddr.Port",
			)); diff != "" {
				t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(buf.Bytes()[icmpDataOffset:], []byte(payload[icmpDataOffset:])); diff != "" {
				t.Errorf("received data mismatch (-want +got):\n%s", diff)
			}

			test.checkLinkEndpoint(t, e)
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
			canBePrimaryAddr: ipv4Addr1,
			firstPrimaryAddr: ipv4Addr2,
		},
		{
			name:             "IPv6",
			canBePrimaryAddr: ipv6Addr1,
			firstPrimaryAddr: ipv6Addr2,
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
			expectedWriteErr: &tcpip.ErrNoRoute{},
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
					ep := channel.New(1, header.IPv6MinimumMTU, "")

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}

					if subTest.addAddress {
						if err := s.AddProtocolAddressWithOptions(nicID, test.canBePrimaryAddr, stack.CanBePrimaryEndpoint); err != nil {
							t.Fatalf("s.AddProtocolAddressWithOptions(%d, %#v, %d): %s", nicID, test.canBePrimaryAddr, stack.FirstPrimaryEndpoint, err)
						}
						if err := s.AddProtocolAddressWithOptions(nicID, test.firstPrimaryAddr, stack.FirstPrimaryEndpoint); err != nil {
							t.Fatalf("s.AddProtocolAddressWithOptions(%d, %#v, %d): %s", nicID, test.firstPrimaryAddr, stack.FirstPrimaryEndpoint, err)
						}
					}

					var serverWQ waiter.Queue
					serverWE, serverCH := waiter.NewChannelEntry(nil)
					serverWQ.EventRegister(&serverWE, waiter.EventIn)
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
					clientWE, clientCH := waiter.NewChannelEntry(nil)
					clientWQ.EventRegister(&clientWE, waiter.EventIn)
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
						if diff := cmp.Diff(buffer.View(clientPayload), buffer.View(readBuf.Bytes())); diff != "" {
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
						if diff := cmp.Diff(buffer.View(serverPayload), buffer.View(readBuf.Bytes())); diff != "" {
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
