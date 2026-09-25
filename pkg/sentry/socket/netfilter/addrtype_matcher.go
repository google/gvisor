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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherNameAddrType = "addrtype"
	addrTypeRevision    = 1

	offAddrTypeSource = 0
	offAddrTypeDest   = 2
	offAddrTypeFlags  = 4
)

// supportedAddrTypes contains address types that can be classified without full
// FIB routing tables. Other types (ANYCAST, BLACKHOLE, UNREACHABLE, PROHIBIT)
// are explicitly rejected during unmarshal.
const supportedAddrTypes = linux.XT_ADDRTYPE_UNSPEC |
	linux.XT_ADDRTYPE_UNICAST |
	linux.XT_ADDRTYPE_LOCAL |
	linux.XT_ADDRTYPE_BROADCAST |
	linux.XT_ADDRTYPE_MULTICAST

const supportedAddrTypeFlags = linux.XT_ADDRTYPE_INVERT_SOURCE | linux.XT_ADDRTYPE_INVERT_DEST

func init() {
	registerMatchMaker(addrTypeMarshaler{})
}

// addrTypeMarshaler implements matchMaker for the "addrtype" match (revision 1).
// kube-proxy uses `-m addrtype --dst-type LOCAL -j KUBE-NODEPORTS`.
type addrTypeMarshaler struct{}

func (addrTypeMarshaler) name() string {
	return matcherNameAddrType
}

func (addrTypeMarshaler) revision() uint8 {
	return addrTypeRevision
}

func (addrTypeMarshaler) marshal(mr matcher) []byte {
	m := mr.(*addrTypeMatcher)
	return marshalEntryMatch(matcherNameAddrType, m.raw)
}

func (addrTypeMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfXTAddrtypeInfoV1 {
		return nil, fmt.Errorf("buf has insufficient size for addrtype match: %d", len(buf))
	}
	raw := make([]byte, linux.SizeOfXTAddrtypeInfoV1)
	copy(raw, buf[:linux.SizeOfXTAddrtypeInfoV1])

	source := hostarch.ByteOrder.Uint16(buf[offAddrTypeSource:])
	dest := hostarch.ByteOrder.Uint16(buf[offAddrTypeDest:])
	flags := hostarch.ByteOrder.Uint32(buf[offAddrTypeFlags:])

	if (source|dest)&^supportedAddrTypes != 0 {
		return nil, fmt.Errorf("addrtype: unsupported address type mask (source=0x%x, dest=0x%x); FIB routing types are not supported", source, dest)
	}
	if flags&^supportedAddrTypeFlags != 0 {
		return nil, fmt.Errorf("addrtype: unsupported flags 0x%x; interface limits are not supported", flags)
	}

	return &addrTypeMatcher{
		source: source,
		dest:   dest,
		flags:  flags,
		raw:    raw,
	}, nil
}

// addrTypeMatcher matches on the address type of the packet's source/dest.
type addrTypeMatcher struct {
	source uint16
	dest   uint16
	flags  uint32
	raw    []byte
	stack  *stack.Stack
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

// Match implements stack.Matcher.Match.
//
// Address types follow Linux xt_addrtype: multicast and limited broadcast are
// classified from the address value; LOCAL is RTN_LOCAL via a stack address
// lookup (inet_dev_addr_type); remaining addresses are UNICAST.
func (m *addrTypeMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	src, dst, ok := m.addrsFromPacket(pkt)
	if !ok {
		return false, false
	}
	// A zero mask means "do not check this side". XT_ADDRTYPE_UNSPEC is
	// 1<<0, a real type bit, not the empty-mask sentinel Linux uses
	// (`if (info->source)` in xt_addrtype.c).
	if m.dest != 0 {
		matched := m.addrTypeOf(dst)&m.dest != 0
		if m.flags&linux.XT_ADDRTYPE_INVERT_DEST != 0 {
			matched = !matched
		}
		if !matched {
			return false, false
		}
	}
	if m.source != 0 {
		matched := m.addrTypeOf(src)&m.source != 0
		if m.flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0 {
			matched = !matched
		}
		if !matched {
			return false, false
		}
	}
	return true, false
}

func (*addrTypeMatcher) addrsFromPacket(pkt *stack.PacketBuffer) (src, dst tcpip.Address, ok bool) {
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

func (m *addrTypeMatcher) addrTypeOf(addr tcpip.Address) uint16 {
	switch addr.Len() {
	case header.IPv4AddressSize:
		if header.IsV4MulticastAddress(addr) {
			return linux.XT_ADDRTYPE_MULTICAST
		}
		if addr == header.IPv4Broadcast {
			return linux.XT_ADDRTYPE_BROADCAST
		}
		// 127.0.0.0/8 is RTN_LOCAL via the local FIB (inet_dev_addr_type).
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
	case header.IPv6AddressSize:
		if header.IsV6MulticastAddress(addr) {
			return linux.XT_ADDRTYPE_MULTICAST
		}
		if addr == header.IPv6Loopback {
			return linux.XT_ADDRTYPE_LOCAL
		}
		if m.stack != nil && m.isLocal(header.IPv6ProtocolNumber, addr) {
			return linux.XT_ADDRTYPE_LOCAL
		}
	}
	return linux.XT_ADDRTYPE_UNICAST
}

// isLocal reports whether addr is assigned to any NIC, matching Linux
// RT_TABLE_LOCAL / nf_ipv6_chk_addr used by xt_addrtype --dst-type LOCAL.
func (m *addrTypeMatcher) isLocal(proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	if m.stack.CheckLocalAddress(0, proto, addr) != 0 {
		return true
	}
	for _, addrs := range m.stack.AllAddresses() {
		for _, a := range addrs {
			if a.Protocol == proto && a.AddressWithPrefix.Address == addr {
				return true
			}
		}
	}
	return false
}
