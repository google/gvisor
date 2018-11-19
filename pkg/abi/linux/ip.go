// Copyright 2018 Google LLC
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

// IP protocols
const (
	IPPROTO_IP      = 0
	IPPROTO_ICMP    = 1
	IPPROTO_IGMP    = 2
	IPPROTO_IPIP    = 4
	IPPROTO_TCP     = 6
	IPPROTO_EGP     = 8
	IPPROTO_PUP     = 12
	IPPROTO_UDP     = 17
	IPPROTO_IDP     = 22
	IPPROTO_TP      = 29
	IPPROTO_DCCP    = 33
	IPPROTO_IPV6    = 41
	IPPROTO_RSVP    = 46
	IPPROTO_GRE     = 47
	IPPROTO_ESP     = 50
	IPPROTO_AH      = 51
	IPPROTO_MTP     = 92
	IPPROTO_BEETPH  = 94
	IPPROTO_ENCAP   = 98
	IPPROTO_PIM     = 103
	IPPROTO_COMP    = 108
	IPPROTO_SCTP    = 132
	IPPROTO_UDPLITE = 136
	IPPROTO_MPLS    = 137
	IPPROTO_RAW     = 255
)

// Socket options from uapi/linux/in.h
const (
	IP_TOS                    = 1
	IP_TTL                    = 2
	IP_HDRINCL                = 3
	IP_OPTIONS                = 4
	IP_ROUTER_ALERT           = 5
	IP_RECVOPTS               = 6
	IP_RETOPTS                = 7
	IP_PKTINFO                = 8
	IP_PKTOPTIONS             = 9
	IP_MTU_DISCOVER           = 10
	IP_RECVERR                = 11
	IP_RECVTTL                = 12
	IP_RECVTOS                = 13
	IP_MTU                    = 14
	IP_FREEBIND               = 15
	IP_IPSEC_POLICY           = 16
	IP_XFRM_POLICY            = 17
	IP_PASSSEC                = 18
	IP_TRANSPARENT            = 19
	IP_ORIGDSTADDR            = 20
	IP_RECVORIGDSTADDR        = IP_ORIGDSTADDR
	IP_MINTTL                 = 21
	IP_NODEFRAG               = 22
	IP_CHECKSUM               = 23
	IP_BIND_ADDRESS_NO_PORT   = 24
	IP_RECVFRAGSIZE           = 25
	IP_MULTICAST_IF           = 32
	IP_MULTICAST_TTL          = 33
	IP_MULTICAST_LOOP         = 34
	IP_ADD_MEMBERSHIP         = 35
	IP_DROP_MEMBERSHIP        = 36
	IP_UNBLOCK_SOURCE         = 37
	IP_BLOCK_SOURCE           = 38
	IP_ADD_SOURCE_MEMBERSHIP  = 39
	IP_DROP_SOURCE_MEMBERSHIP = 40
	IP_MSFILTER               = 41
	MCAST_JOIN_GROUP          = 42
	MCAST_BLOCK_SOURCE        = 43
	MCAST_UNBLOCK_SOURCE      = 44
	MCAST_LEAVE_GROUP         = 45
	MCAST_JOIN_SOURCE_GROUP   = 46
	MCAST_LEAVE_SOURCE_GROUP  = 47
	MCAST_MSFILTER            = 48
	IP_MULTICAST_ALL          = 49
	IP_UNICAST_IF             = 50
)

// Socket options from uapi/linux/in6.h
const (
	IPV6_ADDRFORM         = 1
	IPV6_2292PKTINFO      = 2
	IPV6_2292HOPOPTS      = 3
	IPV6_2292DSTOPTS      = 4
	IPV6_2292RTHDR        = 5
	IPV6_2292PKTOPTIONS   = 6
	IPV6_CHECKSUM         = 7
	IPV6_2292HOPLIMIT     = 8
	IPV6_NEXTHOP          = 9
	IPV6_FLOWINFO         = 11
	IPV6_UNICAST_HOPS     = 16
	IPV6_MULTICAST_IF     = 17
	IPV6_MULTICAST_HOPS   = 18
	IPV6_MULTICAST_LOOP   = 19
	IPV6_ADD_MEMBERSHIP   = 20
	IPV6_DROP_MEMBERSHIP  = 21
	IPV6_ROUTER_ALERT     = 22
	IPV6_MTU_DISCOVER     = 23
	IPV6_MTU              = 24
	IPV6_RECVERR          = 25
	IPV6_V6ONLY           = 26
	IPV6_JOIN_ANYCAST     = 27
	IPV6_LEAVE_ANYCAST    = 28
	IPV6_MULTICAST_ALL    = 29
	IPV6_FLOWLABEL_MGR    = 32
	IPV6_FLOWINFO_SEND    = 33
	IPV6_IPSEC_POLICY     = 34
	IPV6_XFRM_POLICY      = 35
	IPV6_HDRINCL          = 36
	IPV6_RECVPKTINFO      = 49
	IPV6_PKTINFO          = 50
	IPV6_RECVHOPLIMIT     = 51
	IPV6_HOPLIMIT         = 52
	IPV6_RECVHOPOPTS      = 53
	IPV6_HOPOPTS          = 54
	IPV6_RTHDRDSTOPTS     = 55
	IPV6_RECVRTHDR        = 56
	IPV6_RTHDR            = 57
	IPV6_RECVDSTOPTS      = 58
	IPV6_DSTOPTS          = 59
	IPV6_RECVPATHMTU      = 60
	IPV6_PATHMTU          = 61
	IPV6_DONTFRAG         = 62
	IPV6_RECVTCLASS       = 66
	IPV6_TCLASS           = 67
	IPV6_AUTOFLOWLABEL    = 70
	IPV6_ADDR_PREFERENCES = 72
	IPV6_MINHOPCOUNT      = 73
	IPV6_ORIGDSTADDR      = 74
	IPV6_RECVORIGDSTADDR  = IPV6_ORIGDSTADDR
	IPV6_TRANSPARENT      = 75
	IPV6_UNICAST_IF       = 76
	IPV6_RECVFRAGSIZE     = 77
	IPV6_FREEBIND         = 78
)
