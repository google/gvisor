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

package netfilter

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	addrTypeLocalV4  = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	addrTypeRemoteV4 = tcpip.AddrFrom4([4]byte{198, 51, 100, 1})
	addrTypeLocalV6  = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	addrTypeRemoteV6 = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 2})
)

func ipv4Packet(src, dst tcpip.Address) *stack.PacketBuffer {
	b := make([]byte, header.IPv4MinimumSize)
	header.IPv4(b).Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	return networkPacket(b, header.IPv4ProtocolNumber)
}

func ipv6Packet(src, dst tcpip.Address) *stack.PacketBuffer {
	b := make([]byte, header.IPv6MinimumSize)
	header.IPv6(b).Encode(&header.IPv6Fields{
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	return networkPacket(b, header.IPv6ProtocolNumber)
}

func networkPacket(b []byte, netProto tcpip.NetworkProtocolNumber) *stack.PacketBuffer {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(b),
	})
	if _, ok := pkt.NetworkHeader().Consume(len(b)); !ok {
		panic("NetworkHeader.Consume failed")
	}
	pkt.NetworkProtocolNumber = netProto
	return pkt
}

// addrTypeStack returns a stack with addrTypeLocalV4 and addrTypeLocalV6
// assigned.
func addrTypeStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            &faketime.NullClock{},
	})
	t.Cleanup(s.Destroy)
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	for _, pa := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addrTypeLocalV4.WithPrefix()},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: addrTypeLocalV6.WithPrefix()},
	} {
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%s): %s", pa.AddressWithPrefix, err)
		}
	}
	return s
}

// newAddrTypeMatcher parses info as iptables would send it.
func newAddrTypeMatcher(t *testing.T, netProto tcpip.NetworkProtocolNumber, info linux.XTAddrtypeInfoV1, s *stack.Stack) *addrTypeMatcher {
	t.Helper()
	filter := emptyIPv4Filter
	if netProto == header.IPv6ProtocolNumber {
		filter = emptyIPv6Filter
	}
	m, err := (addrTypeMarshaler{}).unmarshal(nil, marshal.Marshal(&info), filter)
	if err != nil {
		t.Fatalf("unmarshal(%+v): %v", info, err)
	}
	am := m.(*addrTypeMatcher)
	am.setStack(s)
	return am
}

func TestAddrTypeIPv4(t *testing.T) {
	s := addrTypeStack(t)
	for _, test := range []struct {
		name string
		dst  tcpip.Address
		mask uint16
		want bool
	}{
		{name: "assigned is LOCAL", dst: addrTypeLocalV4, mask: linux.XT_ADDRTYPE_LOCAL, want: true},
		{name: "assigned is not UNICAST", dst: addrTypeLocalV4, mask: linux.XT_ADDRTYPE_UNICAST, want: false},
		{name: "remote is UNICAST", dst: addrTypeRemoteV4, mask: linux.XT_ADDRTYPE_UNICAST, want: true},
		{name: "remote is not LOCAL", dst: addrTypeRemoteV4, mask: linux.XT_ADDRTYPE_LOCAL, want: false},
		{name: "loopback is LOCAL", dst: tcpip.AddrFrom4([4]byte{127, 1, 2, 3}), mask: linux.XT_ADDRTYPE_LOCAL, want: true},
		{name: "multicast is MULTICAST", dst: tcpip.AddrFrom4([4]byte{224, 0, 0, 1}), mask: linux.XT_ADDRTYPE_MULTICAST, want: true},
		{name: "multicast is not LOCAL", dst: tcpip.AddrFrom4([4]byte{224, 0, 0, 1}), mask: linux.XT_ADDRTYPE_LOCAL, want: false},
		{name: "limited broadcast is BROADCAST", dst: header.IPv4Broadcast, mask: linux.XT_ADDRTYPE_BROADCAST, want: true},
		{name: "0.0.0.0 is BROADCAST", dst: header.IPv4Any, mask: linux.XT_ADDRTYPE_BROADCAST, want: true},
		{name: "0.1.2.3 is BROADCAST", dst: tcpip.AddrFrom4([4]byte{0, 1, 2, 3}), mask: linux.XT_ADDRTYPE_BROADCAST, want: true},
		{name: "0.0.0.0 is not UNICAST", dst: header.IPv4Any, mask: linux.XT_ADDRTYPE_UNICAST, want: false},
		{name: "any of LOCAL or UNICAST", dst: addrTypeRemoteV4, mask: linux.XT_ADDRTYPE_LOCAL | linux.XT_ADDRTYPE_UNICAST, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := newAddrTypeMatcher(t, header.IPv4ProtocolNumber, linux.XTAddrtypeInfoV1{Dest: test.mask}, s)
			pkt := ipv4Packet(addrTypeRemoteV4, test.dst)
			defer pkt.DecRef()
			if got, hotdrop := m.Match(stack.Input, pkt, "", ""); got != test.want || hotdrop {
				t.Errorf("Match() = (%t, %t), want (%t, false)", got, hotdrop, test.want)
			}
		})
	}
}

func TestAddrTypeIPv6(t *testing.T) {
	s := addrTypeStack(t)
	mcast := tcpip.AddrFrom16([16]byte{0xff, 0x02, 15: 1})
	mapped := tcpip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 1})
	for _, test := range []struct {
		name string
		dst  tcpip.Address
		mask uint16
		want bool
	}{
		{name: "assigned is LOCAL", dst: addrTypeLocalV6, mask: linux.XT_ADDRTYPE_LOCAL, want: true},
		{name: "assigned is also UNICAST", dst: addrTypeLocalV6, mask: linux.XT_ADDRTYPE_UNICAST, want: true},
		{name: "assigned is UNICAST and LOCAL", dst: addrTypeLocalV6, mask: linux.XT_ADDRTYPE_UNICAST | linux.XT_ADDRTYPE_LOCAL, want: true},
		{name: "loopback is LOCAL", dst: header.IPv6Loopback, mask: linux.XT_ADDRTYPE_LOCAL, want: true},
		{name: "loopback is UNICAST", dst: header.IPv6Loopback, mask: linux.XT_ADDRTYPE_UNICAST, want: true},
		{name: "remote is UNICAST", dst: addrTypeRemoteV6, mask: linux.XT_ADDRTYPE_UNICAST, want: true},
		{name: "remote is not LOCAL", dst: addrTypeRemoteV6, mask: linux.XT_ADDRTYPE_LOCAL, want: false},
		{name: "remote is not UNICAST and LOCAL", dst: addrTypeRemoteV6, mask: linux.XT_ADDRTYPE_UNICAST | linux.XT_ADDRTYPE_LOCAL, want: false},
		{name: "multicast is MULTICAST", dst: mcast, mask: linux.XT_ADDRTYPE_MULTICAST, want: true},
		{name: "multicast is not UNICAST", dst: mcast, mask: linux.XT_ADDRTYPE_UNICAST, want: false},
		{name: "nothing is UNICAST and MULTICAST", dst: mcast, mask: linux.XT_ADDRTYPE_UNICAST | linux.XT_ADDRTYPE_MULTICAST, want: false},
		{name: "unspecified is UNSPEC", dst: header.IPv6Any, mask: linux.XT_ADDRTYPE_UNSPEC, want: true},
		{name: "unspecified is not UNICAST", dst: header.IPv6Any, mask: linux.XT_ADDRTYPE_UNICAST, want: false},
		{name: "remote is not UNSPEC", dst: addrTypeRemoteV6, mask: linux.XT_ADDRTYPE_UNSPEC, want: false},
		{name: "v4-mapped is not UNICAST", dst: mapped, mask: linux.XT_ADDRTYPE_UNICAST, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := newAddrTypeMatcher(t, header.IPv6ProtocolNumber, linux.XTAddrtypeInfoV1{Dest: test.mask}, s)
			pkt := ipv6Packet(addrTypeRemoteV6, test.dst)
			defer pkt.DecRef()
			if got, hotdrop := m.Match(stack.Input, pkt, "", ""); got != test.want || hotdrop {
				t.Errorf("Match() = (%t, %t), want (%t, false)", got, hotdrop, test.want)
			}
		})
	}
}

func TestAddrTypeSourceAndInvert(t *testing.T) {
	s := addrTypeStack(t)
	pkt := ipv4Packet(addrTypeLocalV4, addrTypeRemoteV4)
	defer pkt.DecRef()
	for _, test := range []struct {
		name string
		info linux.XTAddrtypeInfoV1
		want bool
	}{
		{name: "src LOCAL", info: linux.XTAddrtypeInfoV1{Source: linux.XT_ADDRTYPE_LOCAL}, want: true},
		{name: "! src LOCAL", info: linux.XTAddrtypeInfoV1{Source: linux.XT_ADDRTYPE_LOCAL, Flags: linux.XT_ADDRTYPE_INVERT_SOURCE}, want: false},
		{name: "! dst LOCAL", info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_LOCAL, Flags: linux.XT_ADDRTYPE_INVERT_DEST}, want: true},
		{name: "src LOCAL and dst LOCAL", info: linux.XTAddrtypeInfoV1{Source: linux.XT_ADDRTYPE_LOCAL, Dest: linux.XT_ADDRTYPE_LOCAL}, want: false},
		{name: "no masks", info: linux.XTAddrtypeInfoV1{}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := newAddrTypeMatcher(t, header.IPv4ProtocolNumber, test.info, s)
			if got, _ := m.Match(stack.Input, pkt, "", ""); got != test.want {
				t.Errorf("Match() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAddrTypeUnmarshal(t *testing.T) {
	for _, test := range []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		info     linux.XTAddrtypeInfoV1
		size     int
		wantErr  bool
	}{
		{name: "ipv4 LOCAL", netProto: header.IPv4ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_LOCAL}},
		{name: "ipv6 LOCAL", netProto: header.IPv6ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_LOCAL}},
		{name: "ipv4 BROADCAST", netProto: header.IPv4ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_BROADCAST}},
		{name: "ipv6 BROADCAST", netProto: header.IPv6ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_BROADCAST}, wantErr: true},
		{name: "ipv4 BLACKHOLE", netProto: header.IPv4ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_BLACKHOLE}, wantErr: true},
		{name: "ipv6 BLACKHOLE", netProto: header.IPv6ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_BLACKHOLE}, wantErr: true},
		{name: "ipv6 ANYCAST", netProto: header.IPv6ProtocolNumber, info: linux.XTAddrtypeInfoV1{Source: linux.XT_ADDRTYPE_ANYCAST}, wantErr: true},
		{name: "limit iface in", netProto: header.IPv4ProtocolNumber, info: linux.XTAddrtypeInfoV1{Dest: linux.XT_ADDRTYPE_LOCAL, Flags: linux.XT_ADDRTYPE_LIMIT_IFACE_IN}, wantErr: true},
		{name: "short", netProto: header.IPv4ProtocolNumber, size: linux.SizeOfXTAddrtypeInfoV1 - 1, wantErr: true},
		{name: "long", netProto: header.IPv4ProtocolNumber, size: linux.SizeOfXTAddrtypeInfoV1 + 8, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := marshal.Marshal(&test.info)
			if test.size != 0 {
				buf = make([]byte, test.size)
			}
			filter := emptyIPv4Filter
			if test.netProto == header.IPv6ProtocolNumber {
				filter = emptyIPv6Filter
			}
			m, err := (addrTypeMarshaler{}).unmarshal(nil, buf, filter)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("unmarshal() error = %v, want error %t", err, test.wantErr)
			}
			if err == nil {
				if got := (addrTypeMarshaler{}).marshal(m.(matcher)); len(got) != linux.SizeOfXTEntryMatch+linux.SizeOfXTAddrtypeInfoV1 {
					t.Errorf("marshal() size = %d, want %d", len(got), linux.SizeOfXTEntryMatch+linux.SizeOfXTAddrtypeInfoV1)
				}
			}
		})
	}
}
