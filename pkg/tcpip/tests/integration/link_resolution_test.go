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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	host1NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
	host2NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

	host1IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	host2IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 8,
		},
	}
	host1IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	host2IPv6Addr = tcpip.ProtocolAddress{
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
		icmpBuf    func(*testing.T) buffer.View
	}{
		{
			name:       "IPv4 Ping",
			transProto: icmp.ProtocolNumber4,
			netProto:   ipv4.ProtocolNumber,
			remoteAddr: host2IPv4Addr.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) buffer.View {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
				hdr.SetType(header.ICMPv4Echo)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return buffer.View(hdr)
			},
		},
		{
			name:       "IPv6 Ping",
			transProto: icmp.ProtocolNumber6,
			netProto:   ipv6.ProtocolNumber,
			remoteAddr: host2IPv6Addr.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) buffer.View {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
				hdr.SetType(header.ICMPv6EchoRequest)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return buffer.View(hdr)
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

			host1NIC, host2NIC := pipe.New(host1NICLinkAddr, host2NICLinkAddr, stack.CapabilityResolutionRequired)

			if err := host1Stack.CreateNIC(host1NICID, host1NIC); err != nil {
				t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
			}
			if err := host2Stack.CreateNIC(host2NICID, host2NIC); err != nil {
				t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
			}

			if err := host1Stack.AddAddress(host1NICID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("host1Stack.AddAddress(%d, %d, %s): %s", host1NICID, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}
			if err := host2Stack.AddAddress(host2NICID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("host2Stack.AddAddress(%d, %d, %s): %s", host2NICID, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}

			if err := host1Stack.AddProtocolAddress(host1NICID, host1IPv4Addr); err != nil {
				t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, host1IPv4Addr, err)
			}
			if err := host2Stack.AddProtocolAddress(host2NICID, host2IPv4Addr); err != nil {
				t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, host2IPv4Addr, err)
			}
			if err := host1Stack.AddProtocolAddress(host1NICID, host1IPv6Addr); err != nil {
				t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, host1IPv6Addr, err)
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

			var addr tcpip.FullAddress
			v, _, err := ep.Read(&addr)
			if err != nil {
				t.Fatalf("ep.Read(_): %s", err)
			}
			if diff := cmp.Diff(v[icmpDataOffset:], icmpBuf[icmpDataOffset:]); diff != "" {
				t.Errorf("received data mismatch (-want +got):\n%s", diff)
			}
			if addr.Addr != test.remoteAddr {
				t.Errorf("got addr.Addr = %s, want = %s", addr.Addr, test.remoteAddr)
			}
		})
	}
}
