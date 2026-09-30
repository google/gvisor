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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherNameAddrType = "addrtype"
	addrTypeRevision    = 1
)

// supportedIPv4AddrTypes are the IPv4 types that can be classified without a
// routing table lookup. Linux also accepts the FIB route types (ANYCAST,
// BLACKHOLE, UNREACHABLE, PROHIBIT, THROW, NAT, XRESOLVE); they are rejected
// because they are not implemented.
const supportedIPv4AddrTypes = linux.XT_ADDRTYPE_UNSPEC |
	linux.XT_ADDRTYPE_UNICAST |
	linux.XT_ADDRTYPE_LOCAL |
	linux.XT_ADDRTYPE_BROADCAST |
	linux.XT_ADDRTYPE_MULTICAST

// supportedIPv6AddrTypes are the IPv6 types that are implemented. Linux
// rejects BROADCAST, BLACKHOLE and PROHIBIT and above for IPv6
// (addrtype_mt_checkentry_v1). It accepts ANYCAST and UNREACHABLE, which need
// a route lookup and are rejected because they are not implemented.
const supportedIPv6AddrTypes = linux.XT_ADDRTYPE_UNSPEC |
	linux.XT_ADDRTYPE_UNICAST |
	linux.XT_ADDRTYPE_LOCAL |
	linux.XT_ADDRTYPE_MULTICAST

const supportedAddrTypeFlags = linux.XT_ADDRTYPE_INVERT_SOURCE | linux.XT_ADDRTYPE_INVERT_DEST

func init() {
	registerMatchMaker(addrTypeMarshaler{})
}

// addrTypeMarshaler implements matchMaker for the "addrtype" match (revision 1).
type addrTypeMarshaler struct{}

func (addrTypeMarshaler) name() string {
	return matcherNameAddrType
}

func (addrTypeMarshaler) revision() uint8 {
	return addrTypeRevision
}

func (addrTypeMarshaler) marshal(mr matcher) []byte {
	m := mr.(*addrTypeMatcher)
	return marshalEntryMatch(matcherNameAddrType, marshal.Marshal(&m.info))
}

// unmarshal implements matchMaker.unmarshal, following
// addrtype_mt_checkentry_v1 in net/netfilter/xt_addrtype.c.
func (addrTypeMarshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	// Linux xt_check_match requires the exact match size.
	if len(buf) != linux.SizeOfXTAddrtypeInfoV1 {
		return nil, fmt.Errorf("addrtype: match size %d, want %d", len(buf), linux.SizeOfXTAddrtypeInfoV1)
	}
	var info linux.XTAddrtypeInfoV1
	info.UnmarshalUnsafe(buf)

	if info.Flags&^supportedAddrTypeFlags != 0 {
		return nil, fmt.Errorf("addrtype: unsupported flags 0x%x; interface limits are not implemented", info.Flags)
	}
	netProto := filter.NetworkProtocol()
	supported := uint16(supportedIPv4AddrTypes)
	if netProto == header.IPv6ProtocolNumber {
		supported = supportedIPv6AddrTypes
	}
	if (info.Source|info.Dest)&^supported != 0 {
		return nil, fmt.Errorf("addrtype: unsupported address types for network protocol %d (source=0x%x, dest=0x%x)", netProto, info.Source, info.Dest)
	}
	return &addrTypeMatcher{info: info, netProto: netProto}, nil
}

// addrTypeMatcher matches on the address type of the packet's source and
// destination addresses.
type addrTypeMatcher struct {
	info     linux.XTAddrtypeInfoV1
	netProto tcpip.NetworkProtocolNumber
	stack    *stack.Stack
}

func (m *addrTypeMatcher) setStack(stk *stack.Stack) {
	m.stack = stk
}

func (*addrTypeMatcher) name() string {
	return matcherNameAddrType
}

func (*addrTypeMatcher) revision() uint8 {
	return addrTypeRevision
}

// Match implements stack.Matcher.Match, following addrtype_mt_v1. A side whose
// type mask is 0 is not checked.
func (m *addrTypeMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	src, dst, ok := addrsFromPacket(pkt)
	if !ok {
		return false, false
	}
	if m.info.Source != 0 && m.matchType(src, m.info.Source) == (m.info.Flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0) {
		return false, false
	}
	if m.info.Dest != 0 && m.matchType(dst, m.info.Dest) == (m.info.Flags&linux.XT_ADDRTYPE_INVERT_DEST != 0) {
		return false, false
	}
	return true, false
}

func (m *addrTypeMatcher) matchType(addr tcpip.Address, mask uint16) bool {
	if m.netProto == header.IPv6ProtocolNumber {
		return m.matchTypeIPv6(addr, mask)
	}
	return mask&m.ipv4AddrType(addr) != 0
}

// ipv4AddrType classifies addr like Linux inet_dev_addr_type, which looks addr
// up in the local routing table.
func (m *addrTypeMatcher) ipv4AddrType(addr tcpip.Address) uint16 {
	if addr.Len() != header.IPv4AddressSize {
		return linux.XT_ADDRTYPE_UNICAST
	}
	// ipv4_is_zeronet and ipv4_is_lbcast.
	if addr.As4()[0] == 0 || addr == header.IPv4Broadcast {
		return linux.XT_ADDRTYPE_BROADCAST
	}
	if header.IsV4MulticastAddress(addr) {
		return linux.XT_ADDRTYPE_MULTICAST
	}
	// The local table routes 127.0.0.0/8 as local.
	if header.IsV4LoopbackAddress(addr) {
		return linux.XT_ADDRTYPE_LOCAL
	}
	if m.stack != nil {
		if m.stack.IsSubnetBroadcast(0, header.IPv4ProtocolNumber, addr) {
			return linux.XT_ADDRTYPE_BROADCAST
		}
		if m.isLocal(header.IPv4ProtocolNumber, addr) {
			return linux.XT_ADDRTYPE_LOCAL
		}
	}
	return linux.XT_ADDRTYPE_UNICAST
}

// matchTypeIPv6 implements Linux match_type6. Each of MULTICAST, UNICAST and
// UNSPEC in mask is a separate requirement on addr; LOCAL then requires addr
// to be local.
func (m *addrTypeMatcher) matchTypeIPv6(addr tcpip.Address, mask uint16) bool {
	if addr.Len() != header.IPv6AddressSize {
		return false
	}
	multicast := header.IsV6MulticastAddress(addr)
	unspecified := addr == header.IPv6Any
	// ipv6_addr_type reports every address except multicast, unspecified and
	// IPv4-mapped as unicast.
	unicast := !multicast && !unspecified && !header.IsV4MappedAddress(addr)

	if mask&linux.XT_ADDRTYPE_MULTICAST != 0 && !multicast {
		return false
	}
	if mask&linux.XT_ADDRTYPE_UNICAST != 0 && !unicast {
		return false
	}
	if mask&linux.XT_ADDRTYPE_UNSPEC != 0 && !unspecified {
		return false
	}
	if mask&linux.XT_ADDRTYPE_LOCAL != 0 {
		return addr == header.IPv6Loopback || (m.stack != nil && m.isLocal(header.IPv6ProtocolNumber, addr))
	}
	return true
}

// isLocal returns whether addr is assigned to a NIC.
func (m *addrTypeMatcher) isLocal(proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return m.stack.CheckLocalAddress(0, proto, addr) != 0
}

func addrsFromPacket(pkt *stack.PacketBuffer) (src, dst tcpip.Address, ok bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(pkt.NetworkHeader().Slice())
		if len(hdr) < header.IPv4MinimumSize {
			return tcpip.Address{}, tcpip.Address{}, false
		}
		return hdr.SourceAddress(), hdr.DestinationAddress(), true
	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(pkt.NetworkHeader().Slice())
		if len(hdr) < header.IPv6MinimumSize {
			return tcpip.Address{}, tcpip.Address{}, false
		}
		return hdr.SourceAddress(), hdr.DestinationAddress(), true
	default:
		return tcpip.Address{}, tcpip.Address{}, false
	}
}
