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

package linux

import (
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// This file contains structures required to support IPv6 netfilter and
// ip6tables. Some constants and structs are equal to their IPv4 analogues, and
// are only distinguished by context (e.g. whether used on an IPv4 of IPv6
// socket).

// Socket options for SOL_SOCLET. These correspond to values in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
const (
	IP6T_BASE_CTL            = 64
	IP6T_SO_SET_REPLACE      = IPT_BASE_CTL
	IP6T_SO_SET_ADD_COUNTERS = IPT_BASE_CTL + 1
	IP6T_SO_SET_MAX          = IPT_SO_SET_ADD_COUNTERS

	IP6T_SO_GET_INFO            = IPT_BASE_CTL
	IP6T_SO_GET_ENTRIES         = IPT_BASE_CTL + 1
	IP6T_SO_GET_REVISION_MATCH  = IPT_BASE_CTL + 4
	IP6T_SO_GET_REVISION_TARGET = IPT_BASE_CTL + 5
	IP6T_SO_GET_MAX             = IP6T_SO_GET_REVISION_TARGET
)

// IP6T_ORIGINAL_DST is the ip6tables SOL_IPV6 socket option. Corresponds to
// the value in include/uapi/linux/netfilter_ipv6/ip6_tables.h.
const IP6T_ORIGINAL_DST = 80

// IP6TReplace is the argument for the IP6T_SO_SET_REPLACE sockopt. It
// corresponds to struct ip6t_replace in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
//
// +marshal
type IP6TReplace struct {
	Name        TableName
	ValidHooks  uint32
	NumEntries  uint32
	Size        uint32
	HookEntry   [NF_INET_NUMHOOKS]uint32
	Underflow   [NF_INET_NUMHOOKS]uint32
	NumCounters uint32
	Counters    uint64 // This is really a *XTCounters.
	// Entries is omitted here because it would cause IP6TReplace to be an
	// extra byte longer (see http://www.catb.org/esr/structure-packing/).
	// Entries [0]IP6TEntry
}

// SizeOfIP6TReplace is the size of an IP6TReplace.
const SizeOfIP6TReplace = 96

// KernelIP6TGetEntries is identical to IP6TGetEntries, but includes the
// Entrytable field.
//
// +marshal dynamic
type KernelIP6TGetEntries struct {
	IPTGetEntries
	Entrytable []KernelIP6TEntry
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (ke *KernelIP6TGetEntries) SizeBytes() int {
	res := ke.IPTGetEntries.SizeBytes()
	for _, entry := range ke.Entrytable {
		res += entry.SizeBytes()
	}
	return res
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ke *KernelIP6TGetEntries) MarshalBytes(dst []byte) {
	ke.IPTGetEntries.MarshalUnsafe(dst)
	marshalledUntil := ke.IPTGetEntries.SizeBytes()
	for i := range ke.Entrytable {
		ke.Entrytable[i].MarshalBytes(dst[marshalledUntil:])
		marshalledUntil += ke.Entrytable[i].SizeBytes()
	}
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ke *KernelIP6TGetEntries) UnmarshalBytes(src []byte) {
	ke.IPTGetEntries.UnmarshalUnsafe(src)
	unmarshalledUntil := ke.IPTGetEntries.SizeBytes()
	for i := range ke.Entrytable {
		ke.Entrytable[i].UnmarshalBytes(src[unmarshalledUntil:])
		unmarshalledUntil += ke.Entrytable[i].SizeBytes()
	}
}

var _ marshal.Marshallable = (*KernelIP6TGetEntries)(nil)

// IP6TEntry is an iptables rule. It corresponds to struct ip6t_entry in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
//
// +marshal
type IP6TEntry struct {
	// IPv6 is used to filter packets based on the IPv6 header.
	IPv6 IP6TIP

	// NFCache relates to kernel-internal caching and isn't used by
	// userspace.
	NFCache uint32

	// TargetOffset is the byte offset from the beginning of this IPTEntry
	// to the start of the entry's target.
	TargetOffset uint16

	// NextOffset is the byte offset from the beginning of this IPTEntry to
	// the start of the next entry. It is thus also the size of the entry.
	NextOffset uint16

	// Comeback is a return pointer. It is not used by userspace.
	Comeback uint32

	_ [4]byte

	// Counters holds the packet and byte counts for this rule.
	Counters XTCounters

	// Elems holds the data for all this rule's matches followed by the
	// target. It is variable length -- users have to iterate over any
	// matches and use TargetOffset and NextOffset to make sense of the
	// data.
	//
	// Elems is omitted here because it would cause IPTEntry to be an extra
	// byte larger (see http://www.catb.org/esr/structure-packing/).
	//
	// Elems [0]byte
}

// SizeOfIP6TEntry is the size of an IP6TEntry.
const SizeOfIP6TEntry = 168

// KernelIP6TEntry is identical to IP6TEntry, but includes the Elems field.
//
// +marshal dynamic
type KernelIP6TEntry struct {
	Entry IP6TEntry

	// Elems holds the data for all this rule's matches followed by the
	// target. It is variable length -- users have to iterate over any
	// matches and use TargetOffset and NextOffset to make sense of the
	// data.
	Elems primitive.ByteSlice
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (ke *KernelIP6TEntry) SizeBytes() int {
	return ke.Entry.SizeBytes() + ke.Elems.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ke *KernelIP6TEntry) MarshalBytes(dst []byte) {
	ke.Entry.MarshalUnsafe(dst)
	ke.Elems.MarshalBytes(dst[ke.Entry.SizeBytes():])
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ke *KernelIP6TEntry) UnmarshalBytes(src []byte) {
	ke.Entry.UnmarshalUnsafe(src)
	ke.Elems.UnmarshalBytes(src[ke.Entry.SizeBytes():])
}

// IP6TIP contains information for matching a packet's IP header.
// It corresponds to struct ip6t_ip6 in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
//
// +marshal
type IP6TIP struct {
	// Src is the source IP address.
	Src Inet6Addr

	// Dst is the destination IP address.
	Dst Inet6Addr

	// SrcMask is the source IP mask.
	SrcMask Inet6Addr

	// DstMask is the destination IP mask.
	DstMask Inet6Addr

	// InputInterface is the input network interface.
	InputInterface [IFNAMSIZ]byte

	// OutputInterface is the output network interface.
	OutputInterface [IFNAMSIZ]byte

	// InputInterfaceMask is the input interface mask.
	InputInterfaceMask [IFNAMSIZ]byte

	// OuputInterfaceMask is the output interface mask.
	OutputInterfaceMask [IFNAMSIZ]byte

	// Protocol is the transport protocol.
	Protocol uint16

	// TOS matches TOS flags when Flags indicates filtering by TOS.
	TOS uint8

	// Flags define matching behavior for the IP header.
	Flags uint8

	// InverseFlags invert the meaning of fields in struct IPTIP. See the
	// IP6T_INV_* flags.
	InverseFlags uint8

	// Linux defines in6_addr (Inet6Addr for us) as the union of a
	// 16-element byte array and a 4-element 32-bit integer array, so the
	// whole struct is 4-byte aligned.
	_ [3]byte
}

// SizeOfIP6TIP is the size of an IP6 header.
const SizeOfIP6TIP = 136

// Flags in IP6TIP.Flags. Corresponding constants are in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
const (
	// Whether to check the Protocol field.
	IP6T_F_PROTO = 0x01
	// Whether to match the TOS field.
	IP6T_F_TOS = 0x02
	// Indicates that the jump target is an aboslute GOTO, not an offset.
	IP6T_F_GOTO = 0x04
	// Enables all flags.
	IP6T_F_MASK = 0x07
)

// Flags in IP6TIP.InverseFlags. Corresponding constants are in
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
const (
	// Invert the meaning of InputInterface.
	IP6T_INV_VIA_IN = 0x01
	// Invert the meaning of OutputInterface.
	IP6T_INV_VIA_OUT = 0x02
	// Invert the meaning of TOS.
	IP6T_INV_TOS = 0x04
	// Invert the meaning of Src.
	IP6T_INV_SRCIP = 0x08
	// Invert the meaning of Dst.
	IP6T_INV_DSTIP = 0x10
	// Invert the meaning of the IPT_F_FRAG flag.
	IP6T_INV_FRAG = 0x20
	// Enable all flags.
	IP6T_INV_MASK = 0x7F
)

// NFNATRange corresponds to struct nf_nat_range in
// include/uapi/linux/netfilter/nf_nat.h.
//
// +marshal
type NFNATRange struct {
	Flags    uint32
	MinAddr  Inet6Addr
	MaxAddr  Inet6Addr
	MinProto uint16 // Network byte order.
	MaxProto uint16 // Network byte order.
}

// SizeOfNFNATRange is the size of NFNATRange.
const SizeOfNFNATRange = 40
