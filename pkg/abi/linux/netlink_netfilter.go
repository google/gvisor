// Copyright 2025 The gVisor Authors.
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

// Group describes Netlink Netfilter groups, from uapi/linux/netfilter/nfnetlink.h.
// Users bind to specific groups to receive processing logs from those groups.
type Group uint16

// Netlink Netfilter groups.
const (
	NFNLGPR_NONE Group = iota
	NFNLGRP_CONNTRACK_NEW
	NFNLGRP_CONNTRACK_UPDATE
	NFNLGRP_CONNTRACK_DESTROY
	NFNLGRP_CONNTRACK_EXP_NEW
	NFNLGRP_CONNTRACK_EXP_UPDATE
	NFNLGRP_CONNTRACK_EXP_DESTROY
	NFNLGRP_NFTABLES
	NFNLGRP_ACCT_QUOTA
	NFNLGRP_NFTRACE
	__NFNLGRP_MAX
	NFNLGRP_MAX = __NFNLGRP_MAX - 1
)

// NetFilterGenMsg describes the netlink netfilter genmsg message, from uapi/linux/netfilter/nfnetlink.h.
//
// +marshal
type NetFilterGenMsg struct {
	Family     uint8
	Version    uint8
	ResourceID uint16
}

// SizeOfNetfilterGenMsg is the size of the netlink netfilter genmsg message.
const SizeOfNetfilterGenMsg = 4

// NFNETLINK_V0 is the default version of the netlink netfilter.
const NFNETLINK_V0 = 0

// Netlink Netfilter subsystem IDs, from uapi/linux/netfilter/nfnetlink.h.
const (
	NFNL_SUBSYS_NONE = iota
	NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_QUEUE
	NFNL_SUBSYS_ULOG
	NFNL_SUBSYS_OSF
	NFNL_SUBSYS_IPSET
	NFNL_SUBSYS_ACCT
	NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFNL_SUBSYS_CTHELPER
	NFNL_SUBSYS_NFTABLES
	NFNL_SUBSYS_NFT_COMPAT
	NFNL_SUBSYS_HOOK
	NFNL_SUBSYS_COUNT
)

// NetFilterSubsysID returns the Netfilter Subsystem ID from the netlink message header.
func (hdr *NetlinkMessageHeader) NetFilterSubsysID() uint16 {
	return (hdr.Type & 0xff00) >> 8
}

// NetFilterMsgType returns the Netfilter Message Type from the netlink message header.
func (hdr *NetlinkMessageHeader) NetFilterMsgType() NfTableMsgType {
	return NfTableMsgType(hdr.Type & 0x00ff)
}

// Reserved control Netlink Netfilter messages, from uapi/linux/netfilter/nfnetlink.h.
const (
	NFNL_MSG_BATCH_BEGIN = NLMSG_MIN_TYPE
	NFNL_MSG_BATCH_END   = NLMSG_MIN_TYPE + 1
)

// Netlink Netfilter batch attributes.
const (
	NFNL_BATCH_UNSPEC = iota
	NFNL_BATCH_GENID
	__NFNL_BATCH_MAX
	NFNL_BATCH_MAX = __NFNL_BATCH_MAX - 1
)
