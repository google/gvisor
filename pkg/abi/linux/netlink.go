// Copyright 2018 Google Inc.
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

// Netlink protocols, from uapi/linux/netlink.h.
const (
	NETLINK_ROUTE          = 0
	NETLINK_UNUSED         = 1
	NETLINK_USERSOCK       = 2
	NETLINK_FIREWALL       = 3
	NETLINK_SOCK_DIAG      = 4
	NETLINK_NFLOG          = 5
	NETLINK_XFRM           = 6
	NETLINK_SELINUX        = 7
	NETLINK_ISCSI          = 8
	NETLINK_AUDIT          = 9
	NETLINK_FIB_LOOKUP     = 10
	NETLINK_CONNECTOR      = 11
	NETLINK_NETFILTER      = 12
	NETLINK_IP6_FW         = 13
	NETLINK_DNRTMSG        = 14
	NETLINK_KOBJECT_UEVENT = 15
	NETLINK_GENERIC        = 16
	NETLINK_SCSITRANSPORT  = 18
	NETLINK_ECRYPTFS       = 19
	NETLINK_RDMA           = 20
	NETLINK_CRYPTO         = 21
)

// SockAddrNetlink is struct sockaddr_nl, from uapi/linux/netlink.h.
type SockAddrNetlink struct {
	Family  uint16
	Padding uint16
	PortID  uint32
	Groups  uint32
}

// SockAddrNetlinkSize is the size of SockAddrNetlink.
const SockAddrNetlinkSize = 12

// NetlinkMessageHeader is struct nlmsghdr, from uapi/linux/netlink.h.
type NetlinkMessageHeader struct {
	Length uint32
	Type   uint16
	Flags  uint16
	Seq    uint32
	PortID uint32
}

// NetlinkMessageHeaderSize is the size of NetlinkMessageHeader.
const NetlinkMessageHeaderSize = 16

// Netlink message header flags, from uapi/linux/netlink.h.
const (
	NLM_F_REQUEST   = 0x1
	NLM_F_MULTI     = 0x2
	NLM_F_ACK       = 0x4
	NLM_F_ECHO      = 0x8
	NLM_F_DUMP_INTR = 0x10
	NLM_F_ROOT      = 0x100
	NLM_F_MATCH     = 0x200
	NLM_F_ATOMIC    = 0x400
	NLM_F_DUMP      = NLM_F_ROOT | NLM_F_MATCH
	NLM_F_REPLACE   = 0x100
	NLM_F_EXCL      = 0x200
	NLM_F_CREATE    = 0x400
	NLM_F_APPEND    = 0x800
)

// Standard netlink message types, from uapi/linux/netlink.h.
const (
	NLMSG_NOOP    = 0x1
	NLMSG_ERROR   = 0x2
	NLMSG_DONE    = 0x3
	NLMSG_OVERRUN = 0x4

	// NLMSG_MIN_TYPE is the first value for protocol-level types.
	NLMSG_MIN_TYPE = 0x10
)

// NLMSG_ALIGNTO is the alignment of netlink messages, from
// uapi/linux/netlink.h.
const NLMSG_ALIGNTO = 4

// NetlinkAttrHeader is the header of a netlink attribute, followed by payload.
//
// This is struct nlattr, from uapi/linux/netlink.h.
type NetlinkAttrHeader struct {
	Length uint16
	Type   uint16
}

// NetlinkAttrHeaderSize is the size of NetlinkAttrHeader.
const NetlinkAttrHeaderSize = 4

// NLA_ALIGNTO is the alignment of netlink attributes, from
// uapi/linux/netlink.h.
const NLA_ALIGNTO = 4
