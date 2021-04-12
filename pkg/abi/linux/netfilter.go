// Copyright 2019 The gVisor Authors.
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

// This file contains structures required to support netfilter, specifically
// the iptables tool.

// Hooks into the network stack. These correspond to values in
// include/uapi/linux/netfilter.h.
const (
	NF_INET_PRE_ROUTING  = 0
	NF_INET_LOCAL_IN     = 1
	NF_INET_FORWARD      = 2
	NF_INET_LOCAL_OUT    = 3
	NF_INET_POST_ROUTING = 4
	NF_INET_NUMHOOKS     = 5
)

// Verdicts that can be returned by targets. These correspond to values in
// include/uapi/linux/netfilter.h
const (
	NF_DROP        = 0
	NF_ACCEPT      = 1
	NF_STOLEN      = 2
	NF_QUEUE       = 3
	NF_REPEAT      = 4
	NF_STOP        = 5
	NF_MAX_VERDICT = NF_STOP
	// NF_RETURN is defined in include/uapi/linux/netfilter/x_tables.h.
	NF_RETURN = -NF_REPEAT - 1
)

// VerdictStrings maps int verdicts to the strings they represent. It is used
// for debugging.
var VerdictStrings = map[int32]string{
	-NF_DROP - 1:   "DROP",
	-NF_ACCEPT - 1: "ACCEPT",
	-NF_QUEUE - 1:  "QUEUE",
	NF_RETURN:      "RETURN",
}

// Socket options for SOL_SOCKET. These correspond to values in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
const (
	IPT_BASE_CTL            = 64
	IPT_SO_SET_REPLACE      = IPT_BASE_CTL
	IPT_SO_SET_ADD_COUNTERS = IPT_BASE_CTL + 1
	IPT_SO_SET_MAX          = IPT_SO_SET_ADD_COUNTERS

	IPT_SO_GET_INFO            = IPT_BASE_CTL
	IPT_SO_GET_ENTRIES         = IPT_BASE_CTL + 1
	IPT_SO_GET_REVISION_MATCH  = IPT_BASE_CTL + 2
	IPT_SO_GET_REVISION_TARGET = IPT_BASE_CTL + 3
	IPT_SO_GET_MAX             = IPT_SO_GET_REVISION_TARGET
)

// Socket option for SOL_IP. This corresponds to the value in
// include/uapi/linux/netfilter_ipv4.h.
const (
	SO_ORIGINAL_DST = 80
)

// Name lengths. These correspond to values in
// include/uapi/linux/netfilter/x_tables.h.
const (
	XT_FUNCTION_MAXNAMELEN  = 30
	XT_EXTENSION_MAXNAMELEN = 29
	XT_TABLE_MAXNAMELEN     = 32
)

// IPTEntry is an iptable rule. It corresponds to struct ipt_entry in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
//
// +marshal
type IPTEntry struct {
	// IP is used to filter packets based on the IP header.
	IP IPTIP

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

// SizeOfIPTEntry is the size of an IPTEntry.
const SizeOfIPTEntry = 112

// KernelIPTEntry is identical to IPTEntry, but includes the Elems field.
//
// +marshal dynamic
type KernelIPTEntry struct {
	Entry IPTEntry

	// Elems holds the data for all this rule's matches followed by the
	// target. It is variable length -- users have to iterate over any
	// matches and use TargetOffset and NextOffset to make sense of the
	// data.
	Elems primitive.ByteSlice
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (ke *KernelIPTEntry) SizeBytes() int {
	return ke.Entry.SizeBytes() + ke.Elems.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ke *KernelIPTEntry) MarshalBytes(dst []byte) {
	ke.Entry.MarshalUnsafe(dst)
	ke.Elems.MarshalBytes(dst[ke.Entry.SizeBytes():])
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ke *KernelIPTEntry) UnmarshalBytes(src []byte) {
	ke.Entry.UnmarshalUnsafe(src)
	ke.Elems.UnmarshalBytes(src[ke.Entry.SizeBytes():])
}

var _ marshal.Marshallable = (*KernelIPTEntry)(nil)

// IPTIP contains information for matching a packet's IP header.
// It corresponds to struct ipt_ip in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
//
// +marshal
type IPTIP struct {
	// Src is the source IP address.
	Src InetAddr

	// Dst is the destination IP address.
	Dst InetAddr

	// SrcMask is the source IP mask.
	SrcMask InetAddr

	// DstMask is the destination IP mask.
	DstMask InetAddr

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

	// Flags define matching behavior for the IP header.
	Flags uint8

	// InverseFlags invert the meaning of fields in struct IPTIP. See the
	// IPT_INV_* flags.
	InverseFlags uint8
}

// Flags in IPTIP.InverseFlags. Corresponding constants are in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
const (
	// Invert the meaning of InputInterface.
	IPT_INV_VIA_IN = 0x01
	// Invert the meaning of OutputInterface.
	IPT_INV_VIA_OUT = 0x02
	// Unclear what this is, as no references to it exist in the kernel.
	IPT_INV_TOS = 0x04
	// Invert the meaning of Src.
	IPT_INV_SRCIP = 0x08
	// Invert the meaning of Dst.
	IPT_INV_DSTIP = 0x10
	// Invert the meaning of the IPT_F_FRAG flag.
	IPT_INV_FRAG = 0x20
	// Invert the meaning of the Protocol field.
	IPT_INV_PROTO = 0x40
	// Enable all flags.
	IPT_INV_MASK = 0x7F
)

// SizeOfIPTIP is the size of an IPTIP.
const SizeOfIPTIP = 84

// XTCounters holds packet and byte counts for a rule. It corresponds to struct
// xt_counters in include/uapi/linux/netfilter/x_tables.h.
//
// +marshal
type XTCounters struct {
	// Pcnt is the packet count.
	Pcnt uint64

	// Bcnt is the byte count.
	Bcnt uint64
}

// SizeOfXTCounters is the size of an XTCounters.
const SizeOfXTCounters = 16

// XTEntryMatch holds a match for a rule. For example, a user using the
// addrtype iptables match extension would put the data for that match into an
// XTEntryMatch. iptables-extensions(8) has a list of possible matches.
//
// XTEntryMatch corresponds to struct xt_entry_match in
// include/uapi/linux/netfilter/x_tables.h. That struct contains a union
// exposing different data to the user and kernel, but this struct holds only
// the user data.
type XTEntryMatch struct {
	MatchSize uint16
	Name      ExtensionName
	Revision  uint8
	// Data is omitted here because it would cause XTEntryMatch to be an
	// extra byte larger (see http://www.catb.org/esr/structure-packing/).
	// Data [0]byte
}

// SizeOfXTEntryMatch is the size of an XTEntryMatch.
const SizeOfXTEntryMatch = 32

// KernelXTEntryMatch is identical to XTEntryMatch, but contains
// variable-length Data field.
type KernelXTEntryMatch struct {
	XTEntryMatch
	Data []byte
}

// XTGetRevision corresponds to xt_get_revision in
// include/uapi/linux/netfilter/x_tables.h
//
// +marshal
type XTGetRevision struct {
	Name     ExtensionName
	Revision uint8
}

// SizeOfXTGetRevision is the size of an XTGetRevision.
const SizeOfXTGetRevision = 30

// XTEntryTarget holds a target for a rule. For example, it can specify that
// packets matching the rule should DROP, ACCEPT, or use an extension target.
// iptables-extension(8) has a list of possible targets.
//
// XTEntryTarget corresponds to struct xt_entry_target in
// include/uapi/linux/netfilter/x_tables.h. That struct contains a union
// exposing different data to the user and kernel, but this struct holds only
// the user data.
type XTEntryTarget struct {
	TargetSize uint16
	Name       ExtensionName
	Revision   uint8
	// Data is omitted here because it would cause XTEntryTarget to be an
	// extra byte larger (see http://www.catb.org/esr/structure-packing/).
	// Data [0]byte
}

// SizeOfXTEntryTarget is the size of an XTEntryTarget.
const SizeOfXTEntryTarget = 32

// KernelXTEntryTarget is identical to XTEntryTarget, but contains a
// variable-length Data field.
type KernelXTEntryTarget struct {
	XTEntryTarget
	Data []byte
}

// XTStandardTarget is a built-in target, one of ACCEPT, DROP, JUMP, QUEUE,
// RETURN, or jump. It corresponds to struct xt_standard_target in
// include/uapi/linux/netfilter/x_tables.h.
type XTStandardTarget struct {
	Target XTEntryTarget
	// A positive verdict indicates a jump, and is the offset from the
	// start of the table to jump to. A negative value means one of the
	// other built-in targets.
	Verdict int32
	_       [4]byte
}

// SizeOfXTStandardTarget is the size of an XTStandardTarget.
const SizeOfXTStandardTarget = 40

// XTErrorTarget triggers an error when reached. It is also used to mark the
// beginning of user-defined chains by putting the name of the chain in
// ErrorName. It corresponds to struct xt_error_target in
// include/uapi/linux/netfilter/x_tables.h.
type XTErrorTarget struct {
	Target XTEntryTarget
	Name   ErrorName
	_      [2]byte
}

// SizeOfXTErrorTarget is the size of an XTErrorTarget.
const SizeOfXTErrorTarget = 64

// Flag values for NfNATIPV4Range. The values indicate whether to map
// protocol specific part(ports) or IPs. It corresponds to values in
// include/uapi/linux/netfilter/nf_nat.h.
const (
	NF_NAT_RANGE_MAP_IPS            = 1 << 0
	NF_NAT_RANGE_PROTO_SPECIFIED    = 1 << 1
	NF_NAT_RANGE_PROTO_RANDOM       = 1 << 2
	NF_NAT_RANGE_PERSISTENT         = 1 << 3
	NF_NAT_RANGE_PROTO_RANDOM_FULLY = 1 << 4
	NF_NAT_RANGE_PROTO_RANDOM_ALL   = (NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY)
	NF_NAT_RANGE_MASK               = (NF_NAT_RANGE_MAP_IPS |
		NF_NAT_RANGE_PROTO_SPECIFIED | NF_NAT_RANGE_PROTO_RANDOM |
		NF_NAT_RANGE_PERSISTENT | NF_NAT_RANGE_PROTO_RANDOM_FULLY)
)

// NfNATIPV4Range corresponds to struct nf_nat_ipv4_range
// in include/uapi/linux/netfilter/nf_nat.h. The fields are in
// network byte order.
type NfNATIPV4Range struct {
	Flags   uint32
	MinIP   [4]byte
	MaxIP   [4]byte
	MinPort uint16
	MaxPort uint16
}

// NfNATIPV4MultiRangeCompat corresponds to struct
// nf_nat_ipv4_multi_range_compat in include/uapi/linux/netfilter/nf_nat.h.
type NfNATIPV4MultiRangeCompat struct {
	RangeSize uint32
	RangeIPV4 NfNATIPV4Range
}

// XTRedirectTarget triggers a redirect when reached.
// Adding 4 bytes of padding to make the struct 8 byte aligned.
type XTRedirectTarget struct {
	Target  XTEntryTarget
	NfRange NfNATIPV4MultiRangeCompat
	_       [4]byte
}

// SizeOfXTRedirectTarget is the size of an XTRedirectTarget.
const SizeOfXTRedirectTarget = 56

// XTSNATTarget triggers Source NAT when reached.
// Adding 4 bytes of padding to make the struct 8 byte aligned.
type XTSNATTarget struct {
	Target  XTEntryTarget
	NfRange NfNATIPV4MultiRangeCompat
	_       [4]byte
}

// SizeOfXTSNATTarget is the size of an XTSNATTarget.
const SizeOfXTSNATTarget = 56

// IPTGetinfo is the argument for the IPT_SO_GET_INFO sockopt. It corresponds
// to struct ipt_getinfo in include/uapi/linux/netfilter_ipv4/ip_tables.h.
//
// +marshal
type IPTGetinfo struct {
	Name       TableName
	ValidHooks uint32
	HookEntry  [NF_INET_NUMHOOKS]uint32
	Underflow  [NF_INET_NUMHOOKS]uint32
	NumEntries uint32
	Size       uint32
}

// SizeOfIPTGetinfo is the size of an IPTGetinfo.
const SizeOfIPTGetinfo = 84

// IPTGetEntries is the argument for the IPT_SO_GET_ENTRIES sockopt. It
// corresponds to struct ipt_get_entries in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
//
// +marshal
type IPTGetEntries struct {
	Name TableName
	Size uint32
	_    [4]byte
	// Entrytable is omitted here because it would cause IPTGetEntries to
	// be an extra byte longer (see
	// http://www.catb.org/esr/structure-packing/).
	// Entrytable [0]IPTEntry
}

// SizeOfIPTGetEntries is the size of an IPTGetEntries.
const SizeOfIPTGetEntries = 40

// KernelIPTGetEntries is identical to IPTGetEntries, but includes the
// Entrytable field.
//
// +marshal dynamic
type KernelIPTGetEntries struct {
	IPTGetEntries
	Entrytable []KernelIPTEntry
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (ke *KernelIPTGetEntries) SizeBytes() int {
	res := ke.IPTGetEntries.SizeBytes()
	for _, entry := range ke.Entrytable {
		res += entry.SizeBytes()
	}
	return res
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ke *KernelIPTGetEntries) MarshalBytes(dst []byte) {
	ke.IPTGetEntries.MarshalUnsafe(dst)
	marshalledUntil := ke.IPTGetEntries.SizeBytes()
	for i := range ke.Entrytable {
		ke.Entrytable[i].MarshalBytes(dst[marshalledUntil:])
		marshalledUntil += ke.Entrytable[i].SizeBytes()
	}
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ke *KernelIPTGetEntries) UnmarshalBytes(src []byte) {
	ke.IPTGetEntries.UnmarshalUnsafe(src)
	unmarshalledUntil := ke.IPTGetEntries.SizeBytes()
	for i := range ke.Entrytable {
		ke.Entrytable[i].UnmarshalBytes(src[unmarshalledUntil:])
		unmarshalledUntil += ke.Entrytable[i].SizeBytes()
	}
}

var _ marshal.Marshallable = (*KernelIPTGetEntries)(nil)

// IPTReplace is the argument for the IPT_SO_SET_REPLACE sockopt. It
// corresponds to struct ipt_replace in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
type IPTReplace struct {
	Name        TableName
	ValidHooks  uint32
	NumEntries  uint32
	Size        uint32
	HookEntry   [NF_INET_NUMHOOKS]uint32
	Underflow   [NF_INET_NUMHOOKS]uint32
	NumCounters uint32
	Counters    uint64 // This is really a *XTCounters.
	// Entries is omitted here because it would cause IPTReplace to be an
	// extra byte longer (see http://www.catb.org/esr/structure-packing/).
	// Entries [0]IPTEntry
}

// SizeOfIPTReplace is the size of an IPTReplace.
const SizeOfIPTReplace = 96

// ExtensionName holds the name of a netfilter extension.
//
// +marshal
type ExtensionName [XT_EXTENSION_MAXNAMELEN]byte

// String implements fmt.Stringer.
func (en ExtensionName) String() string {
	return goString(en[:])
}

// TableName holds the name of a netfilter table.
//
// +marshal
type TableName [XT_TABLE_MAXNAMELEN]byte

// String implements fmt.Stringer.
func (tn TableName) String() string {
	return goString(tn[:])
}

// ErrorName holds the name of a netfilter error. These can also hold
// user-defined chains.
type ErrorName [XT_FUNCTION_MAXNAMELEN]byte

// String implements fmt.Stringer.
func (en ErrorName) String() string {
	return goString(en[:])
}

func goString(cstring []byte) string {
	for i, c := range cstring {
		if c == 0 {
			return string(cstring[:i])
		}
	}
	return string(cstring)
}

// XTTCP holds data for matching TCP packets. It corresponds to struct xt_tcp
// in include/uapi/linux/netfilter/xt_tcpudp.h.
type XTTCP struct {
	// SourcePortStart specifies the inclusive start of the range of source
	// ports to which the matcher applies.
	SourcePortStart uint16

	// SourcePortEnd specifies the inclusive end of the range of source ports
	// to which the matcher applies.
	SourcePortEnd uint16

	// DestinationPortStart specifies the start of the destination port
	// range to which the matcher applies.
	DestinationPortStart uint16

	// DestinationPortEnd specifies the end of the destination port
	// range to which the matcher applies.
	DestinationPortEnd uint16

	// Option specifies that a particular TCP option must be set.
	Option uint8

	// FlagMask masks TCP flags when comparing to the FlagCompare byte. It allows
	// for specification of which flags are important to the matcher.
	FlagMask uint8

	// FlagCompare, in combination with FlagMask, is used to match only packets
	// that have certain flags set.
	FlagCompare uint8

	// InverseFlags flips the meaning of certain fields. See the
	// TX_TCP_INV_* flags.
	InverseFlags uint8
}

// SizeOfXTTCP is the size of an XTTCP.
const SizeOfXTTCP = 12

// Flags in XTTCP.InverseFlags. Corresponding constants are in
// include/uapi/linux/netfilter/xt_tcpudp.h.
const (
	// Invert the meaning of SourcePortStart/End.
	XT_TCP_INV_SRCPT = 0x01
	// Invert the meaning of DestinationPortStart/End.
	XT_TCP_INV_DSTPT = 0x02
	// Invert the meaning of FlagCompare.
	XT_TCP_INV_FLAGS = 0x04
	// Invert the meaning of Option.
	XT_TCP_INV_OPTION = 0x08
	// Enable all flags.
	XT_TCP_INV_MASK = 0x0F
)

// XTUDP holds data for matching UDP packets. It corresponds to struct xt_udp
// in include/uapi/linux/netfilter/xt_tcpudp.h.
type XTUDP struct {
	// SourcePortStart is the inclusive start of the range of source ports
	// to which the matcher applies.
	SourcePortStart uint16

	// SourcePortEnd is the inclusive end of the range of source ports to
	// which the matcher applies.
	SourcePortEnd uint16

	// DestinationPortStart is the inclusive start of the destination port
	// range to which the matcher applies.
	DestinationPortStart uint16

	// DestinationPortEnd is the inclusive end of the destination port
	// range to which the matcher applies.
	DestinationPortEnd uint16

	// InverseFlags flips the meaning of certain fields. See the
	// TX_UDP_INV_* flags.
	InverseFlags uint8

	_ uint8
}

// SizeOfXTUDP is the size of an XTUDP.
const SizeOfXTUDP = 10

// Flags in XTUDP.InverseFlags. Corresponding constants are in
// include/uapi/linux/netfilter/xt_tcpudp.h.
const (
	// Invert the meaning of SourcePortStart/End.
	XT_UDP_INV_SRCPT = 0x01
	// Invert the meaning of DestinationPortStart/End.
	XT_UDP_INV_DSTPT = 0x02
	// Enable all flags.
	XT_UDP_INV_MASK = 0x03
)

// IPTOwnerInfo holds data for matching packets with owner. It corresponds
// to struct ipt_owner_info in libxt_owner.c of iptables binary.
type IPTOwnerInfo struct {
	// UID is user id which created the packet.
	UID uint32

	// GID is group id which created the packet.
	GID uint32

	// PID is process id of the process which created the packet.
	PID uint32

	// SID is session id which created the packet.
	SID uint32

	// Comm is the command name which created the packet.
	Comm [16]byte

	// Match is used to match UID/GID of the socket. See the
	// XT_OWNER_* flags below.
	Match uint8

	// Invert flips the meaning of Match field.
	Invert uint8
}

// SizeOfIPTOwnerInfo is the size of an XTOwnerMatchInfo.
const SizeOfIPTOwnerInfo = 34

// Flags in IPTOwnerInfo.Match. Corresponding constants are in
// include/uapi/linux/netfilter/xt_owner.h.
const (
	// Match the UID of the packet.
	XT_OWNER_UID = 1 << 0
	// Match the GID of the packet.
	XT_OWNER_GID = 1 << 1
	// Match if the socket exists for the packet. Forwarded
	// packets do not have an associated socket.
	XT_OWNER_SOCKET = 1 << 2
)
