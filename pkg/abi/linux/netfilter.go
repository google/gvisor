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

// Socket options. These correspond to values in
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

// Name lengths. These correspond to values in
// include/uapi/linux/netfilter/x_tables.h.
const (
	XT_FUNCTION_MAXNAMELEN  = 30
	XT_EXTENSION_MAXNAMELEN = 29
	XT_TABLE_MAXNAMELEN     = 32
)

// IPTEntry is an iptable rule. It corresponds to struct ipt_entry in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
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

// KernelIPTEntry is identical to IPTEntry, but includes the Elems field. This
// struct marshaled via the binary package to write an IPTEntry to userspace.
type KernelIPTEntry struct {
	IPTEntry

	// Elems holds the data for all this rule's matches followed by the
	// target. It is variable length -- users have to iterate over any
	// matches and use TargetOffset and NextOffset to make sense of the
	// data.
	Elems []byte
}

// IPTIP contains information for matching a packet's IP header.
// It corresponds to struct ipt_ip in
// include/uapi/linux/netfilter_ipv4/ip_tables.h.
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

	// InputInterfaceMask is the intput interface mask.
	InputInterfaceMask [IFNAMSIZ]byte

	// OuputInterfaceMask is the output interface mask.
	OutputInterfaceMask [IFNAMSIZ]byte

	// Protocol is the transport protocol.
	Protocol uint16

	// Flags define matching behavior for the IP header.
	Flags uint8

	// InverseFlags invert the meaning of fields in struct IPTIP.
	InverseFlags uint8
}

// SizeOfIPTIP is the size of an IPTIP.
const SizeOfIPTIP = 84

// XTCounters holds packet and byte counts for a rule. It corresponds to struct
// xt_counters in include/uapi/linux/netfilter/x_tables.h.
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

// XTStandardTarget is a builtin target, one of ACCEPT, DROP, JUMP, QUEUE, or
// RETURN. It corresponds to struct xt_standard_target in
// include/uapi/linux/netfilter/x_tables.h.
type XTStandardTarget struct {
	Target  XTEntryTarget
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

// IPTGetinfo is the argument for the IPT_SO_GET_INFO sockopt. It corresponds
// to struct ipt_getinfo in include/uapi/linux/netfilter_ipv4/ip_tables.h.
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
// Entrytable field. This struct marshaled via the binary package to write an
// KernelIPTGetEntries to userspace.
type KernelIPTGetEntries struct {
	IPTGetEntries
	Entrytable []KernelIPTEntry
}

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

// KernelIPTEntry is identical to IPTReplace, but includes the Entries field.
type KernelIPTReplace struct {
	IPTReplace
	Entries [0]IPTEntry
}

// SizeOfIPTReplace is the size of an IPTReplace.
const SizeOfIPTReplace = 96

// ExtensionName holds the name of a netfilter extension.
type ExtensionName [XT_EXTENSION_MAXNAMELEN]byte

// String implements fmt.Stringer.
func (en ExtensionName) String() string {
	return goString(en[:])
}

// ExtensionName holds the name of a netfilter table.
type TableName [XT_TABLE_MAXNAMELEN]byte

// String implements fmt.Stringer.
func (tn TableName) String() string {
	return goString(tn[:])
}

// ExtensionName holds the name of a netfilter error. These can also hold
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
