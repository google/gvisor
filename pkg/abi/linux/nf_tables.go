// Copyright 2024 The gVisor Authors.
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

// This file contains constants required to support nf_tables.

const NFT_MAX_HOOKS = NF_INET_NUMHOOKS + 1

// Name length constants for nf_table structures. These correspond to values in
// include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_NAME_MAXLEN      = 256
	NFT_TABLE_MAXNAMELEN = NFT_NAME_MAXLEN
	NFT_CHAIN_MAXNAMELEN = NFT_NAME_MAXLEN
	NFT_SET_MAXNAMELEN   = NFT_NAME_MAXLEN
	NFT_OBJ_MAXNAMELEN   = NFT_NAME_MAXLEN
	NFT_USERDATA_MAXLEN  = 256
	NFT_OSF_MAXGENRELEN  = 16
)

// 16-byte Registers that can be used to maintain state for rules.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_REG_VERDICT = iota
	NFT_REG_1
	NFT_REG_2
	NFT_REG_3
	NFT_REG_4
	__NFT_REG_MAX
)

// 4-byte Registers that can be used to maintain state for rules.
// Note that these overlap with the 16-byte registers in memory.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_REG32_00 = 8 + iota
	NFT_REG32_01
	NFT_REG32_02
	NFT_REG32_03
	NFT_REG32_04
	NFT_REG32_05
	NFT_REG32_06
	NFT_REG32_07
	NFT_REG32_08
	NFT_REG32_09
	NFT_REG32_10
	NFT_REG32_11
	NFT_REG32_12
	NFT_REG32_13
	NFT_REG32_14
	NFT_REG32_15
)

// Other register constants, corresponding to values in
// include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_REG_MAX     = __NFT_REG_MAX - 1               // Maximum register value
	NFT_REG_SIZE    = 16                              // Size of NFT_REG
	NFT_REG32_SIZE  = 4                               // Size of NFT_REG32
	NFT_REG32_COUNT = NFT_REG32_15 - NFT_REG32_00 + 1 // Count of 4-byte registers
)

// Internal nf table verdicts. These are used for ruleset evaluation and
// are not returned to userspace.
//
// These also share their numeric name space with the netfilter verdicts. When
// used these values are converted to uint32 (purposefully overflowing the int).
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	// Continue evaluation of the current rule.
	NFT_CONTINUE int32 = -1

	// Terminate evaluation of the current rule.
	NFT_BREAK int32 = -2

	// Push the current chain on the jump stack and jump to a chain.
	NFT_JUMP int32 = -3

	// Jump to a chain without pushing the current chain on the jump stack.
	NFT_GOTO int32 = -4

	// Return to the topmost chain on the jump stack.
	NFT_RETURN int32 = -5
)

// NfTableMsgType values map to operations within the nftables api.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
type NfTableMsgType uint16

// Netlink Netfilter table message types.
const (
	NFT_MSG_NEWTABLE NfTableMsgType = iota
	NFT_MSG_GETTABLE
	NFT_MSG_DELTABLE
	NFT_MSG_NEWCHAIN
	NFT_MSG_GETCHAIN
	NFT_MSG_DELCHAIN
	NFT_MSG_NEWRULE
	NFT_MSG_GETRULE
	NFT_MSG_DELRULE
	NFT_MSG_NEWSET
	NFT_MSG_GETSET
	NFT_MSG_DELSET
	NFT_MSG_NEWSETELEM
	NFT_MSG_GETSETELEM
	NFT_MSG_DELSETELEM
	NFT_MSG_NEWGEN
	NFT_MSG_GETGEN
	NFT_MSG_TRACE
	NFT_MSG_NEWOBJ
	NFT_MSG_GETOBJ
	NFT_MSG_DELOBJ
	NFT_MSG_GETOBJ_RESET
	NFT_MSG_NEWFLOWTABLE
	NFT_MSG_GETFLOWTABLE
	NFT_MSG_DELFLOWTABLE
	NFT_MSG_GETRULE_RESET
	NFT_MSG_DESTROYTABLE
	NFT_MSG_DESTROYCHAIN
	NFT_MSG_DESTROYRULE
	NFT_MSG_DESTROYSET
	NFT_MSG_DESTROYSETELEM
	NFT_MSG_DESTROYOBJ
	NFT_MSG_DESTROYFLOWTABLE
	NFT_MSG_GETSETELEM_RESET
	NFT_MSG_MAX
)

var nfTableMsgTypeStrings = [...]string{
	NFT_MSG_NEWTABLE:         "NFT_MSG_NEWTABLE",
	NFT_MSG_GETTABLE:         "NFT_MSG_GETTABLE",
	NFT_MSG_DELTABLE:         "NFT_MSG_DELTABLE",
	NFT_MSG_NEWCHAIN:         "NFT_MSG_NEWCHAIN",
	NFT_MSG_GETCHAIN:         "NFT_MSG_GETCHAIN",
	NFT_MSG_DELCHAIN:         "NFT_MSG_DELCHAIN",
	NFT_MSG_NEWRULE:          "NFT_MSG_NEWRULE",
	NFT_MSG_GETRULE:          "NFT_MSG_GETRULE",
	NFT_MSG_DELRULE:          "NFT_MSG_DELRULE",
	NFT_MSG_NEWSET:           "NFT_MSG_NEWSET",
	NFT_MSG_GETSET:           "NFT_MSG_GETSET",
	NFT_MSG_DELSET:           "NFT_MSG_DELSET",
	NFT_MSG_NEWSETELEM:       "NFT_MSG_NEWSETELEM",
	NFT_MSG_GETSETELEM:       "NFT_MSG_GETSETELEM",
	NFT_MSG_DELSETELEM:       "NFT_MSG_DELSETELEM",
	NFT_MSG_NEWGEN:           "NFT_MSG_NEWGEN",
	NFT_MSG_GETGEN:           "NFT_MSG_GETGEN",
	NFT_MSG_TRACE:            "NFT_MSG_TRACE",
	NFT_MSG_NEWOBJ:           "NFT_MSG_NEWOBJ",
	NFT_MSG_GETOBJ:           "NFT_MSG_GETOBJ",
	NFT_MSG_DELOBJ:           "NFT_MSG_DELOBJ",
	NFT_MSG_GETOBJ_RESET:     "NFT_MSG_GETOBJ_RESET",
	NFT_MSG_NEWFLOWTABLE:     "NFT_MSG_NEWFLOWTABLE",
	NFT_MSG_GETFLOWTABLE:     "NFT_MSG_GETFLOWTABLE",
	NFT_MSG_DELFLOWTABLE:     "NFT_MSG_DELFLOWTABLE",
	NFT_MSG_GETRULE_RESET:    "NFT_MSG_GETRULE_RESET",
	NFT_MSG_DESTROYTABLE:     "NFT_MSG_DESTROYTABLE",
	NFT_MSG_DESTROYCHAIN:     "NFT_MSG_DESTROYCHAIN",
	NFT_MSG_DESTROYRULE:      "NFT_MSG_DESTROYRULE",
	NFT_MSG_DESTROYSET:       "NFT_MSG_DESTROYSET",
	NFT_MSG_DESTROYSETELEM:   "NFT_MSG_DESTROYSETELEM",
	NFT_MSG_DESTROYOBJ:       "NFT_MSG_DESTROYOBJ",
	NFT_MSG_DESTROYFLOWTABLE: "NFT_MSG_DESTROYFLOWTABLE",
	NFT_MSG_GETSETELEM_RESET: "NFT_MSG_GETSETELEM_RESET",
	NFT_MSG_MAX:              "NFT_MSG_MAX",
}

// String returns the string representation of the NfTableMsgType.
func (msg NfTableMsgType) String() string {
	if int(msg) < len(nfTableMsgTypeStrings) {
		return nfTableMsgTypeStrings[msg]
	}
	return "UNKNOWN"
}

// NfTableListAttributes represents the netfilter attributes for lists of data.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_LIST_UNSPEC uint16 = iota
	NFTA_LIST_ELEM
	__NFTA_LIST_MAX
	NFTA_LIST_MAX = __NFTA_LIST_MAX - 1
)

// NfTableHookAttributes represents the netfilter hook attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_HOOK_UNSPEC uint16 = iota
	NFTA_HOOK_HOOKNUM
	NFTA_HOOK_PRIORITY
	NFTA_HOOK_DEV
	NFTA_HOOK_DEVS
	__NFTA_HOOK_MAX
	NFTA_HOOK_MAX = __NFTA_HOOK_MAX - 1
)

// NfTableFlags represents table flags that can be set for a table, namely dormant.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_TABLE_F_DORMANT uint32 = 0x1
	NFT_TABLE_F_OWNER          = 0x2
	NFT_TABLE_F_PERSIST        = 0x4
	NFT_TABLE_F_MASK           = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER | NFT_TABLE_F_PERSIST
)

// NfTableAttributes represents the netfilter table attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_TABLE_UNSPEC uint16 = iota
	NFTA_TABLE_NAME
	NFTA_TABLE_FLAGS
	NFTA_TABLE_USE
	NFTA_TABLE_HANDLE
	NFTA_TABLE_PAD
	NFTA_TABLE_USERDATA
	NFTA_TABLE_OWNER
	__NFTA_TABLE_MAX
)

// NFTA_TABLE_MAX is the maximum netfilter table attribute.
const NFTA_TABLE_MAX = __NFTA_TABLE_MAX - 1

// NfTableChainFlags represents chain flags that can be set for a chain.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_CHAIN_BASE       uint32 = (1 << 0)
	NFT_CHAIN_HW_OFFLOAD        = (1 << 1)
	NFT_CHAIN_BINDING           = (1 << 2)
	NFT_CHAIN_FLAGS             = (NFT_CHAIN_BASE | NFT_CHAIN_HW_OFFLOAD | NFT_CHAIN_BINDING)
)

// NfTableChainAttributes represents the netfilter chain attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_CHAIN_UNSPEC uint16 = iota
	NFTA_CHAIN_TABLE
	NFTA_CHAIN_HANDLE
	NFTA_CHAIN_NAME
	NFTA_CHAIN_HOOK
	NFTA_CHAIN_POLICY
	NFTA_CHAIN_USE
	NFTA_CHAIN_TYPE
	NFTA_CHAIN_COUNTERS
	NFTA_CHAIN_PAD
	NFTA_CHAIN_FLAGS
	NFTA_CHAIN_ID
	NFTA_CHAIN_USERDATA
	__NFTA_CHAIN_MAX
	NFTA_CHAIN_MAX = __NFTA_CHAIN_MAX - 1
)

// NfTableRuleAttributes represents the netfilter rule attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_RULE_UNSPEC uint16 = iota
	NFTA_RULE_TABLE
	NFTA_RULE_CHAIN
	NFTA_RULE_HANDLE
	NFTA_RULE_EXPRESSIONS
	NFTA_RULE_COMPAT
	NFTA_RULE_POSITION
	NFTA_RULE_USERDATA
	NFTA_RULE_PAD
	NFTA_RULE_ID
	NFTA_RULE_POSITION_ID
	NFTA_RULE_CHAIN_ID
	__NFTA_RULE_MAX
	NFTA_RULE_MAX = __NFTA_RULE_MAX - 1
)

// NfTableDataTypes represents the netfilter data types.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_DATA_VALUE   = iota
	NFT_DATA_VERDICT = 0xffffff00
)

// NfTableDataReservedMask represents the netfilter data reserved mask for internally used types.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_DATA_RESERVED_MASK = 0xffffff00
)

// NfTableDataAttributes represents the netfilter data attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_DATA_UNSPEC uint16 = iota
	NFTA_DATA_VALUE
	NFTA_DATA_VERDICT
	__NFTA_DATA_MAX
	NFTA_DATA_MAX = __NFTA_DATA_MAX - 1
)

// NFT_DATA_VALUE_MAXLEN is the maximum length of a netfilter data value.
const NFT_DATA_VALUE_MAXLEN = 64

// NfTableVerdictAttributes represents the netfilter verdict attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_VERDICT_UNSPEC uint16 = iota
	NFTA_VERDICT_CODE
	NFTA_VERDICT_CHAIN
	NFTA_VERDICT_CHAIN_ID
	__NFTA_VERDICT_MAX
	NFTA_VERDICT_MAX = __NFTA_VERDICT_MAX - 1
)

// NfTableExprAttributes represents the netfilter expression attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_EXPR_UNSPEC uint16 = iota
	NFTA_EXPR_NAME
	NFTA_EXPR_DATA
	__NFTA_EXPR_MAX
	NFTA_EXPR_MAX = __NFTA_EXPR_MAX - 1
)

// NfTableImmediateAttributes represents the netfilter immediate attributes.
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_IMMEDIATE_UNSPEC uint16 = iota
	NFTA_IMMEDIATE_DREG
	NFTA_IMMEDIATE_DATA
	__NFTA_IMMEDIATE_MAX
	NFTA_IMMEDIATE_MAX = __NFTA_IMMEDIATE_MAX - 1
)

// Nf table relational operators.
// Used by the nft comparison operation to compare values in registers.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_CMP_EQ  = iota // equal
	NFT_CMP_NEQ        // not equal
	NFT_CMP_LT         // less than
	NFT_CMP_LTE        // less than or equal to
	NFT_CMP_GT         // greater than
	NFT_CMP_GTE        // greater than or equal to
)

// Nf table range operators.
// Used by the nft range operation to compare values in registers.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_RANGE_EQ = iota
	NFT_RANGE_NEQ
)

// Nf table payload expression offset bases.
// Used by the nft payload operations to access appropriate data in the packet.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_PAYLOAD_LL_HEADER        = iota // link layer header
	NFT_PAYLOAD_NETWORK_HEADER          // network header
	NFT_PAYLOAD_TRANSPORT_HEADER        // transport header
	NFT_PAYLOAD_INNER_HEADER            // inner header / payload
	NFT_PAYLOAD_TUN_HEADER              // tunneling protocol header
)

// Nf table payload expression checksum types.
// Used by the nft payload set operation to mark the type of checksum to use.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_PAYLOAD_CSUM_NONE = iota // no checksumming
	NFT_PAYLOAD_CSUM_INET        // internet checksum (RFC 791)
	NFT_PAYLOAD_CSUM_SCTP        // CRC-32c, for use in SCTP header (RFC 3309)
)

// Nf table payload expression checksum flags.
// Used by the nft payload set operation to mark the flags for checksumming.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_PAYLOAD_L4CSUM_PSEUDOHDR = (1 << 0) // use pseudoheader for L4 checksum
)

// Nf table bitwise operators.
// Used by the nft bitwise operation to perform bitwise math over register data.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_BITWISE_BOOL   = iota // mask-and-xor operation for NOT, AND, OR, & XOR
	NFT_BITWISE_LSHIFT        // left-shift operation
	NFT_BITWISE_RSHIFT        // right-shift operation
)

// Nf table route expression keys.
// Used by the nft route operation to determine the routing data to retrieve.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	// Traffic Class Identifier (Realm) associated with route
	NFT_RT_CLASSID = iota

	// Routing nexthop for IPv4 (next IPv4 address to jump to)
	NFT_RT_NEXTHOP4

	// Routing nexthop for IPv6 (next IPv6 address to jump to)
	NFT_RT_NEXTHOP6

	// Maximum Segment Size for TCP connections (largest size for a single packet)
	NFT_RT_TCPMSS

	// Bool for whether packet route involves a IPsec transform st xfrm is applied
	NFT_RT_XFRM
)

// Nf table byteorder operators.
// Used by the nft byteorder operation to convert data in a register to a
// specific byte order.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_BYTEORDER_NTOH = iota // network to host operator
	NFT_BYTEORDER_HTON        // host to network operator
)

// Nf tables meta expression keys.
// Used by the nft meta operation to retrieve meta data from the packet.
// These correspond to enum values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFT_META_LEN           = iota // Packet length
	NFT_META_PROTOCOL             // Packet ethertype protocol, invalid in OUTPUT
	NFT_META_PRIORITY             // Packet priority
	NFT_META_MARK                 // Packet mark
	NFT_META_IIF                  // Packet input interface index
	NFT_META_OIF                  // Packet output interface index
	NFT_META_IIFNAME              // Packet input interface name
	NFT_META_OIFNAME              // Packet output interface name
	NFT_META_IIFTYPE              // Packet input interface type
	NFT_META_OIFTYPE              // Packet output interface type
	NFT_META_SKUID                // Originating socket UID
	NFT_META_SKGID                // Originating socket GID
	NFT_META_NFTRACE              // Packet nftrace bit
	NFT_META_RTCLASSID            // Realm value of packet's route
	NFT_META_SECMARK              // Packet secmark
	NFT_META_NFPROTO              // Netfilter protocol
	NFT_META_L4PROTO              // Layer 4 protocol number
	NFT_META_BRI_IIFNAME          // Packet input bridge interface name
	NFT_META_BRI_OIFNAME          // Packet output bridge interface name
	NFT_META_PKTTYPE              // Packet type, special handling for loopback
	NFT_META_CPU                  // CPU id through smp_processor_id()
	NFT_META_IIFGROUP             // Packet input interface group
	NFT_META_OIFGROUP             // Packet output interface group
	NFT_META_CGROUP               // Socket control group
	NFT_META_PRANDOM              // A 32bit pseudo-random number
	NFT_META_SECPATH              // Boolean, secpath_exists
	NFT_META_IIFKIND              // Packet input interface kind name
	NFT_META_OIFKIND              // Packet output interface kind name
	NFT_META_BRI_IIFPVID          // Packet input bridge port pvid
	NFT_META_BRI_IIFVPROTO        // Packet input bridge vlan proto
	NFT_META_TIME_NS              // Time since epoch (in nanoseconds)
	NFT_META_TIME_DAY             // Day of week (from 0 = Sunday to 6 = Saturday)
	NFT_META_TIME_HOUR            // Hour of day (in sec), secs since start of day
	NFT_META_SDIF                 // Slave device interface index
	NFT_META_SDIFNAME             // Slave device interface name
	NFT_META_BRI_BROUTE           // Packet br_netfilter_broute bit
)

// Nftables Generation Attributes
// These correspond to values in include/uapi/linux/netfilter/nf_tables.h.
const (
	NFTA_GEN_UNSPEC uint16 = iota
	NFTA_GEN_ID
	NFTA_GEN_PROC_PID
	NFTA_GEN_PROC_NAME
	__NFTA_GEN_MAX
	NFTA_GEN_MAX = __NFTA_GEN_MAX - 1
)
