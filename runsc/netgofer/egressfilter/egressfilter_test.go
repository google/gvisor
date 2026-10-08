// Copyright 2026 The gVisor Authors.
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

package egressfilter

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestEgressFilter(t *testing.T) {
	localIPv4 := net.ParseIP("192.168.1.100")
	localIPv6 := net.ParseIP("fd00::100")

	for _, allowLoopback := range []bool{false, true} {
		filter, err := New(Options{
			AllowLoopback: allowLoopback,
			LocalAddrs:    []net.IP{localIPv4, localIPv6},
		})
		if err != nil {
			t.Fatalf("New(allowLoopback=%v) failed: %v", allowLoopback, err)
		}

		tests := []struct {
			name string
			addr tcpip.Address
			port uint16
			want bool
		}{
			{
				name: "public_ipv4",
				addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
				port: 53,
				want: true,
			},
			{
				name: "public_ipv6",
				addr: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}),
				port: 53,
				want: true,
			},
			{
				name: "port_zero",
				addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
				port: 0,
				want: false,
			},
			{
				name: "local_ipv4_interface",
				addr: tcpip.AddrFrom4Slice(localIPv4.To4()),
				port: 80,
				want: false,
			},
			{
				name: "local_ipv6_interface",
				addr: tcpip.AddrFrom16Slice(localIPv6.To16()),
				port: 80,
				want: false,
			},
			{
				name: "ipv4_loopback_127_0_0_1",
				addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
				port: 8080,
				want: allowLoopback,
			},
			{
				name: "ipv4_loopback_127_0_0_11_dns",
				addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 11}),
				port: 53,
				want: allowLoopback,
			},
			{
				name: "ipv6_loopback",
				addr: header.IPv6Loopback,
				port: 8080,
				want: allowLoopback,
			},
			{
				name: "ipv4_unspecified",
				addr: header.IPv4Any,
				port: 80,
				want: false,
			},
			{
				name: "ipv6_unspecified",
				addr: header.IPv6Any,
				port: 80,
				want: false,
			},
			{
				name: "ipv4_broadcast",
				addr: header.IPv4Broadcast,
				port: 80,
				want: false,
			},
			{
				name: "ipv4_current_network_0_0_0_1",
				addr: tcpip.AddrFrom4([4]byte{0, 0, 0, 1}),
				port: 80,
				want: false,
			},
			{
				name: "ipv4_cloud_metadata_link_local",
				addr: tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
				port: 80,
				want: false,
			},
			{
				name: "ipv4_multicast",
				addr: tcpip.AddrFrom4([4]byte{224, 0, 0, 1}),
				port: 80,
				want: false,
			},
			{
				name: "ipv6_link_local_unicast",
				addr: tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
				port: 80,
				want: false,
			},
			{
				name: "ipv6_multicast",
				addr: tcpip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
				port: 80,
				want: false,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := filter.Allows(tc.addr, tc.port); got != tc.want {
					t.Errorf("Allows(%s, %d) = %v, want %v (allowLoopback=%v)", tc.addr, tc.port, got, tc.want, allowLoopback)
				}
			})
		}
	}
}

func TestNilFilterRejectsAll(t *testing.T) {
	var f *Filter
	if f.Allows(tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), 80) {
		t.Errorf("nil Filter.Allows() = true, want false")
	}
	if f.AllowsLoopback() {
		t.Errorf("nil Filter.AllowsLoopback() = true, want false")
	}
}
