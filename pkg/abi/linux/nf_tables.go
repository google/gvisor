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
