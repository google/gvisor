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
	NFT_BREAK = -2

	// Push the current chain on the jump stack and jump to a chain.
	NFT_JUMP = -3

	// Jump to a chain without pushing the current chain on the jump stack.
	NFT_GOTO = -4

	// Return to the topmost chain on the jump stack.
	NFT_RETURN = -5
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
