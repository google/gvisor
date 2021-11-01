// Copyright 2018 The gVisor Authors.
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
//
// +marshal
type InterfaceInfoMessage struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
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

// Interface link info attributes, from uapi/linux/if_link.h.
const (
	IFLA_INFO_UNSPEC     = 0
	IFLA_INFO_KIND       = 1
	IFLA_INFO_DATA       = 2
	IFLA_INFO_XSTATS     = 3
	IFLA_INFO_SLAVE_KIND = 4
	IFLA_INFO_SLAVE_DATA = 5
)

// InterfaceAddrMessage is struct ifaddrmsg, from uapi/linux/if_addr.h.
//
// +marshal
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
	ARPHRD_NONE     = 65534
	ARPHRD_ETHER    = 1
	ARPHRD_LOOPBACK = 772
)

// RouteMessage is struct rtmsg, from uapi/linux/rtnetlink.h.
//
// +marshal
type RouteMessage struct {
	Family uint8
	DstLen uint8
	SrcLen uint8
	TOS    uint8

	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8

	Flags uint32
}

// SizeOfRouteMessage is the size of RouteMessage.
const SizeOfRouteMessage = 12

// Route types, from uapi/linux/rtnetlink.h.
const (
	// RTN_UNSPEC represents an unspecified route type.
	RTN_UNSPEC = 0

	// RTN_UNICAST represents a unicast route.
	RTN_UNICAST = 1

	// RTN_LOCAL represents a route that is accepted locally.
	RTN_LOCAL = 2

	// RTN_BROADCAST represents a broadcast route (Traffic is accepted locally
	// as broadcast, and sent as broadcast).
	RTN_BROADCAST = 3

	// RTN_ANYCAST represents a anycast route (Traffic is accepted locally as
	// broadcast but sent as unicast).
	RTN_ANYCAST = 6

	// RTN_MULTICAST represents a multicast route.
	RTN_MULTICAST = 5

	// RTN_BLACKHOLE represents a route where all traffic is dropped.
	RTN_BLACKHOLE = 6

	// RTN_UNREACHABLE represents a route where the destination is unreachable.
	RTN_UNREACHABLE = 7

	RTN_PROHIBIT = 8
	RTN_THROW    = 9
	RTN_NAT      = 10
	RTN_XRESOLVE = 11
)

// Route protocols/origins, from uapi/linux/rtnetlink.h.
const (
	RTPROT_UNSPEC   = 0
	RTPROT_REDIRECT = 1
	RTPROT_KERNEL   = 2
	RTPROT_BOOT     = 3
	RTPROT_STATIC   = 4
	RTPROT_GATED    = 8
	RTPROT_RA       = 9
	RTPROT_MRT      = 10
	RTPROT_ZEBRA    = 11
	RTPROT_BIRD     = 12
	RTPROT_DNROUTED = 13
	RTPROT_XORP     = 14
	RTPROT_NTK      = 15
	RTPROT_DHCP     = 16
	RTPROT_MROUTED  = 17
	RTPROT_BABEL    = 42
	RTPROT_BGP      = 186
	RTPROT_ISIS     = 187
	RTPROT_OSPF     = 188
	RTPROT_RIP      = 189
	RTPROT_EIGRP    = 192
)

// Route scopes, from uapi/linux/rtnetlink.h.
const (
	RT_SCOPE_UNIVERSE = 0
	RT_SCOPE_SITE     = 200
	RT_SCOPE_LINK     = 253
	RT_SCOPE_HOST     = 254
	RT_SCOPE_NOWHERE  = 255
)

// Route flags, from uapi/linux/rtnetlink.h.
const (
	RTM_F_NOTIFY       = 0x100
	RTM_F_CLONED       = 0x200
	RTM_F_EQUALIZE     = 0x400
	RTM_F_PREFIX       = 0x800
	RTM_F_LOOKUP_TABLE = 0x1000
	RTM_F_FIB_MATCH    = 0x2000
)

// Route tables, from uapi/linux/rtnetlink.h.
const (
	RT_TABLE_UNSPEC  = 0
	RT_TABLE_COMPAT  = 252
	RT_TABLE_DEFAULT = 253
	RT_TABLE_MAIN    = 254
	RT_TABLE_LOCAL   = 255
)

// Route attributes, from uapi/linux/rtnetlink.h.
const (
	RTA_UNSPEC        = 0
	RTA_DST           = 1
	RTA_SRC           = 2
	RTA_IIF           = 3
	RTA_OIF           = 4
	RTA_GATEWAY       = 5
	RTA_PRIORITY      = 6
	RTA_PREFSRC       = 7
	RTA_METRICS       = 8
	RTA_MULTIPATH     = 9
	RTA_PROTOINFO     = 10
	RTA_FLOW          = 11
	RTA_CACHEINFO     = 12
	RTA_SESSION       = 13
	RTA_MP_ALGO       = 14
	RTA_TABLE         = 15
	RTA_MARK          = 16
	RTA_MFC_STATS     = 17
	RTA_VIA           = 18
	RTA_NEWDST        = 19
	RTA_PREF          = 20
	RTA_ENCAP_TYPE    = 21
	RTA_ENCAP         = 22
	RTA_EXPIRES       = 23
	RTA_PAD           = 24
	RTA_UID           = 25
	RTA_TTL_PROPAGATE = 26
	RTA_IP_PROTO      = 27
	RTA_SPORT         = 28
	RTA_DPORT         = 29
)

// Route flags, from include/uapi/linux/route.h.
const (
	RTF_GATEWAY = 0x2
	RTF_UP      = 0x1
)

// RtAttr is the header of optional addition route information, as a netlink
// attribute. From include/uapi/linux/rtnetlink.h.
type RtAttr struct {
	Len  uint16
	Type uint16
}

// SizeOfRtAttr is the size of RtAttr.
const SizeOfRtAttr = 4

// NeighborMessage is struct ifaddrmsg, from uapi/linux/if_addr.h.
//
// +marshal
type NeighborMessage struct {
	Family    uint8
	Pad1      uint8
	Pad2      uint16
	IfIndex   int32
	State     uint16
	Flags     uint8
	Type      uint8
}

// Neighbor attributes, from uapi/linux/if_addr.h.
const (
	NDA_UNSPEC       = 0
	NDA_DST          = 1
	NDA_LLADDR       = 2
	NDA_CACHEINFO    = 3
	NDA_PROBES       = 4
	NDA_VLAN         = 5
	NDA_PORT         = 6
	NDA_VNI          = 7
	NDA_IFINDEX      = 8
	NDA_MASTER       = 9
	NDA_LINK_NETNSID = 10
	NDA_SRC_VNI      = 11
	NDA_PROTOCOL     = 12  /* Originator of entry */
)

// Neighbor Cache Entry Flags, from uapi/linux/neighbour.h
const (
	NTF_USE         = 0x01
	NTF_SELF        = 0x02
	NTF_MASTER      = 0x04
	NTF_PROXY       = 0x08    /* == ATF_PUBL */
	NTF_EXT_LEARNED = 0x10
	NTF_OFFLOADED   = 0x20
	NTF_STICKY      = 0x40
	NTF_ROUTER      = 0x80
)

// Neighbor Cache Entry States.
const (
	NUD_INCOMPLETE  = 0x01
	NUD_REACHABLE   = 0x02
	NUD_STALE       = 0x04
	NUD_DELAY       = 0x08
	NUD_PROBE       = 0x10
	NUD_FAILED      = 0x20

	/* Dummy states */
	NUD_NOARP       = 0x40
	NUD_PERMANENT   = 0x80
	NUD_NONE        = 0x00
)

type NeighborCacheInfo struct {
	Confirmed uint32
	Used      uint32
	Updated   uint32
	RefCount  uint32
}
