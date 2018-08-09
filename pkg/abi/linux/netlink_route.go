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

// Netlink message types for NETLINK_ROUTE sockets, from uapi/linux/rtnetlink.h.
const (
	RTM_NEWLINK = 16
	RTM_DELLINK = 17
	RTM_GETLINK = 18
	RTM_SETLINK = 19

	RTM_NEWADDR = 20
	RTM_DELADDR = 21
	RTM_GETADDR = 22

	RTM_NEWROUTE = 24
	RTM_DELROUTE = 25
	RTM_GETROUTE = 26

	RTM_NEWNEIGH = 28
	RTM_DELNEIGH = 29
	RTM_GETNEIGH = 30

	RTM_NEWRULE = 32
	RTM_DELRULE = 33
	RTM_GETRULE = 34

	RTM_NEWQDISC = 36
	RTM_DELQDISC = 37
	RTM_GETQDISC = 38

	RTM_NEWTCLASS = 40
	RTM_DELTCLASS = 41
	RTM_GETTCLASS = 42

	RTM_NEWTFILTER = 44
	RTM_DELTFILTER = 45
	RTM_GETTFILTER = 46

	RTM_NEWACTION = 48
	RTM_DELACTION = 49
	RTM_GETACTION = 50

	RTM_NEWPREFIX = 52

	RTM_GETMULTICAST = 58

	RTM_GETANYCAST = 62

	RTM_NEWNEIGHTBL = 64
	RTM_GETNEIGHTBL = 66
	RTM_SETNEIGHTBL = 67

	RTM_NEWNDUSEROPT = 68

	RTM_NEWADDRLABEL = 72
	RTM_DELADDRLABEL = 73
	RTM_GETADDRLABEL = 74

	RTM_GETDCB = 78
	RTM_SETDCB = 79

	RTM_NEWNETCONF = 80
	RTM_GETNETCONF = 82

	RTM_NEWMDB = 84
	RTM_DELMDB = 85
	RTM_GETMDB = 86

	RTM_NEWNSID = 88
	RTM_DELNSID = 89
	RTM_GETNSID = 90
)

// InterfaceInfoMessage is struct ifinfomsg, from uapi/linux/rtnetlink.h.
type InterfaceInfoMessage struct {
	Family  uint8
	Padding uint8
	Type    uint16
	Index   int32
	Flags   uint32
	Change  uint32
}

// Interface flags, from uapi/linux/if.h.
const (
	IFF_UP          = 1 << 0
	IFF_BROADCAST   = 1 << 1
	IFF_DEBUG       = 1 << 2
	IFF_LOOPBACK    = 1 << 3
	IFF_POINTOPOINT = 1 << 4
	IFF_NOTRAILERS  = 1 << 5
	IFF_RUNNING     = 1 << 6
	IFF_NOARP       = 1 << 7
	IFF_PROMISC     = 1 << 8
	IFF_ALLMULTI    = 1 << 9
	IFF_MASTER      = 1 << 10
	IFF_SLAVE       = 1 << 11
	IFF_MULTICAST   = 1 << 12
	IFF_PORTSEL     = 1 << 13
	IFF_AUTOMEDIA   = 1 << 14
	IFF_DYNAMIC     = 1 << 15
	IFF_LOWER_UP    = 1 << 16
	IFF_DORMANT     = 1 << 17
	IFF_ECHO        = 1 << 18
)

// Interface link attributes, from uapi/linux/if_link.h.
const (
	IFLA_UNSPEC          = 0
	IFLA_ADDRESS         = 1
	IFLA_BROADCAST       = 2
	IFLA_IFNAME          = 3
	IFLA_MTU             = 4
	IFLA_LINK            = 5
	IFLA_QDISC           = 6
	IFLA_STATS           = 7
	IFLA_COST            = 8
	IFLA_PRIORITY        = 9
	IFLA_MASTER          = 10
	IFLA_WIRELESS        = 11
	IFLA_PROTINFO        = 12
	IFLA_TXQLEN          = 13
	IFLA_MAP             = 14
	IFLA_WEIGHT          = 15
	IFLA_OPERSTATE       = 16
	IFLA_LINKMODE        = 17
	IFLA_LINKINFO        = 18
	IFLA_NET_NS_PID      = 19
	IFLA_IFALIAS         = 20
	IFLA_NUM_VF          = 21
	IFLA_VFINFO_LIST     = 22
	IFLA_STATS64         = 23
	IFLA_VF_PORTS        = 24
	IFLA_PORT_SELF       = 25
	IFLA_AF_SPEC         = 26
	IFLA_GROUP           = 27
	IFLA_NET_NS_FD       = 28
	IFLA_EXT_MASK        = 29
	IFLA_PROMISCUITY     = 30
	IFLA_NUM_TX_QUEUES   = 31
	IFLA_NUM_RX_QUEUES   = 32
	IFLA_CARRIER         = 33
	IFLA_PHYS_PORT_ID    = 34
	IFLA_CARRIER_CHANGES = 35
	IFLA_PHYS_SWITCH_ID  = 36
	IFLA_LINK_NETNSID    = 37
	IFLA_PHYS_PORT_NAME  = 38
	IFLA_PROTO_DOWN      = 39
	IFLA_GSO_MAX_SEGS    = 40
	IFLA_GSO_MAX_SIZE    = 41
)

// InterfaceAddrMessage is struct ifaddrmsg, from uapi/linux/if_addr.h.
type InterfaceAddrMessage struct {
	Family    uint8
	PrefixLen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

// Interface attributes, from uapi/linux/if_addr.h.
const (
	IFA_UNSPEC    = 0
	IFA_ADDRESS   = 1
	IFA_LOCAL     = 2
	IFA_LABEL     = 3
	IFA_BROADCAST = 4
	IFA_ANYCAST   = 5
	IFA_CACHEINFO = 6
	IFA_MULTICAST = 7
	IFA_FLAGS     = 8
)

// Device types, from uapi/linux/if_arp.h.
const (
	ARPHRD_LOOPBACK = 772
)
