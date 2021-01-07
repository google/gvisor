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
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	linkAddr1 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
	linkAddr2 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x07")
	linkAddr3 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x08")
	linkAddr4 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")
)

var (
	ipv4Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	ipv4Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 8,
		},
	}
	ipv6Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	ipv6Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::2").To16()),
			PrefixLen: 64,
		},
	}
)

// TestPing tests that two hosts can ping eachother when link resolution is
// enabled.
func TestPing(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4

		// icmpDataOffset is the offset to the data in both ICMPv4 and ICMPv6 echo
		// request/reply packets.
		icmpDataOffset = 8
	)

	tests := []struct {
		name       string
		transProto tcpip.TransportProtocolNumber
		netProto   tcpip.NetworkProtocolNumber
		remoteAddr tcpip.Address
		icmpBuf    func(*testing.T) []byte
	}{
		{
			name:       "IPv4 Ping",
			transProto: icmp.ProtocolNumber4,
			netProto:   ipv4.ProtocolNumber,
			remoteAddr: ipv4Addr2.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) []byte {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
				hdr.SetType(header.ICMPv4Echo)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return hdr
			},
		},
		{
			name:       "IPv6 Ping",
			transProto: icmp.ProtocolNumber6,
			netProto:   ipv6.ProtocolNumber,
			remoteAddr: ipv6Addr2.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) []byte {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
				hdr.SetType(header.ICMPv6EchoRequest)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return hdr
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
			}

			host1Stack := stack.New(stackOpts)
			host2Stack := stack.New(stackOpts)

			host1NIC, host2NIC := pipe.New(linkAddr1, linkAddr2)

			if err := host1Stack.CreateNIC(host1NICID, newEthernetEndpoint(host1NIC)); err != nil {
				t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
			}
			if err := host2Stack.CreateNIC(host2NICID, newEthernetEndpoint(host2NIC)); err != nil {
				t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
			}

			if err := host1Stack.AddProtocolAddress(host1NICID, ipv4Addr1); err != nil {
				t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, ipv4Addr1, err)
			}
			if err := host2Stack.AddProtocolAddress(host2NICID, ipv4Addr2); err != nil {
				t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, ipv4Addr2, err)
			}
			if err := host1Stack.AddProtocolAddress(host1NICID, ipv6Addr1); err != nil {
				t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, ipv6Addr1, err)
			}
			if err := host2Stack.AddProtocolAddress(host2NICID, ipv6Addr2); err != nil {
				t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, ipv6Addr2, err)
			}

			host1Stack.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: ipv4Addr1.AddressWithPrefix.Subnet(),
					NIC:         host1NICID,
				},
				tcpip.Route{
					Destination: ipv6Addr1.AddressWithPrefix.Subnet(),
					NIC:         host1NICID,
				},
			})
			host2Stack.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: ipv4Addr2.AddressWithPrefix.Subnet(),
					NIC:         host2NICID,
				},
				tcpip.Route{
					Destination: ipv6Addr2.AddressWithPrefix.Subnet(),
					NIC:         host2NICID,
				},
			})

			var wq waiter.Queue
			we, waiterCH := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			ep, err := host1Stack.NewEndpoint(test.transProto, test.netProto, &wq)
			if err != nil {
				t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", test.transProto, test.netProto, err)
			}
			defer ep.Close()

			// The first write should trigger link resolution.
			icmpBuf := test.icmpBuf(t)
			wOpts := tcpip.WriteOptions{To: &tcpip.FullAddress{Addr: test.remoteAddr}}
			if _, ch, err := ep.Write(tcpip.SlicePayload(icmpBuf), wOpts); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("got ep.Write(_, _) = %s, want = %s", err, tcpip.ErrNoLinkAddress)
			} else {
				// Wait for link resolution to complete.
				<-ch
			}
			if n, _, err := ep.Write(tcpip.SlicePayload(icmpBuf), wOpts); err != nil {
				t.Fatalf("ep.Write(_, _): %s", err)
			} else if want := int64(len(icmpBuf)); n != want {
				t.Fatalf("got ep.Write(_, _) = (%d, _, _), want = (%d, _, _)", n, want)
			}

			// Wait for the endpoint to be readable.
			<-waiterCH

			var buf bytes.Buffer
			opts := tcpip.ReadOptions{NeedRemoteAddr: true}
			res, err := ep.Read(&buf, len(icmpBuf), opts)
			if err != nil {
				t.Fatalf("ep.Read(_, %d, %#v): %s", len(icmpBuf), opts, err)
			}
			if diff := cmp.Diff(tcpip.ReadResult{
				Count:      buf.Len(),
				Total:      buf.Len(),
				RemoteAddr: tcpip.FullAddress{Addr: test.remoteAddr},
			}, res, checker.IgnoreCmpPath(
				"ControlMessages",
				"RemoteAddr.NIC",
				"RemoteAddr.Port",
			)); diff != "" {
				t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(buf.Bytes()[icmpDataOffset:], icmpBuf[icmpDataOffset:]); diff != "" {
				t.Errorf("received data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
