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
}

func (*addrTypeMatcher) name() string {
	return matcherNameAddrType
}

func (*addrTypeMatcher) revision() uint8 {
	return addrTypeRevision
}

// Match implements stack.Matcher.Match. Address types are derived from the
// packet address itself (multicast/broadcast/unicast).
func (m *addrTypeMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	netHdr := pkt.Network()
	if netHdr == nil {
		return false, false
	}
	if m.dest != linux.XT_ADDRTYPE_UNSPEC {
		matched := addrTypeOf(netHdr.DestinationAddress())&m.dest != 0
		if m.flags&linux.XT_ADDRTYPE_INVERT_DEST != 0 {
			matched = !matched
		}
		if !matched {
			return false, false
		}
	}
	if m.source != linux.XT_ADDRTYPE_UNSPEC {
		matched := addrTypeOf(netHdr.SourceAddress())&m.source != 0
		if m.flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0 {
			matched = !matched
		}
		if !matched {
			return false, false
		}
	}
	return true, false
}

// addrTypeOf classifies an address into XT_ADDRTYPE_* bits using only the
// address value (no routing-table lookup).
func addrTypeOf(addr tcpip.Address) uint16 {
	switch addr.Len() {
	case header.IPv4AddressSize:
		if header.IsV4MulticastAddress(addr) {
			return linux.XT_ADDRTYPE_MULTICAST
		}
		if addr == header.IPv4Broadcast {
			return linux.XT_ADDRTYPE_BROADCAST
		}
	case header.IPv6AddressSize:
		if header.IsV6MulticastAddress(addr) {
			return linux.XT_ADDRTYPE_MULTICAST
		}
	}
	return linux.XT_ADDRTYPE_UNICAST
}
