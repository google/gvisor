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

package strace

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
)

// SocketFamily are the possible socket(2) families.
var SocketFamily = abi.ValueSet{
	linux.AF_UNSPEC:     "AF_UNSPEC",
	linux.AF_UNIX:       "AF_UNIX",
	linux.AF_INET:       "AF_INET",
	linux.AF_AX25:       "AF_AX25",
	linux.AF_IPX:        "AF_IPX",
	linux.AF_APPLETALK:  "AF_APPLETALK",
	linux.AF_NETROM:     "AF_NETROM",
	linux.AF_BRIDGE:     "AF_BRIDGE",
	linux.AF_ATMPVC:     "AF_ATMPVC",
	linux.AF_X25:        "AF_X25",
	linux.AF_INET6:      "AF_INET6",
	linux.AF_ROSE:       "AF_ROSE",
	linux.AF_DECnet:     "AF_DECnet",
	linux.AF_NETBEUI:    "AF_NETBEUI",
	linux.AF_SECURITY:   "AF_SECURITY",
	linux.AF_KEY:        "AF_KEY",
	linux.AF_NETLINK:    "AF_NETLINK",
	linux.AF_PACKET:     "AF_PACKET",
	linux.AF_ASH:        "AF_ASH",
	linux.AF_ECONET:     "AF_ECONET",
	linux.AF_ATMSVC:     "AF_ATMSVC",
	linux.AF_RDS:        "AF_RDS",
	linux.AF_SNA:        "AF_SNA",
	linux.AF_IRDA:       "AF_IRDA",
	linux.AF_PPPOX:      "AF_PPPOX",
	linux.AF_WANPIPE:    "AF_WANPIPE",
	linux.AF_LLC:        "AF_LLC",
	linux.AF_IB:         "AF_IB",
	linux.AF_MPLS:       "AF_MPLS",
	linux.AF_CAN:        "AF_CAN",
	linux.AF_TIPC:       "AF_TIPC",
	linux.AF_BLUETOOTH:  "AF_BLUETOOTH",
	linux.AF_IUCV:       "AF_IUCV",
	linux.AF_RXRPC:      "AF_RXRPC",
	linux.AF_ISDN:       "AF_ISDN",
	linux.AF_PHONET:     "AF_PHONET",
	linux.AF_IEEE802154: "AF_IEEE802154",
	linux.AF_CAIF:       "AF_CAIF",
	linux.AF_ALG:        "AF_ALG",
	linux.AF_NFC:        "AF_NFC",
	linux.AF_VSOCK:      "AF_VSOCK",
}

// SocketType are the possible socket(2) types.
var SocketType = abi.ValueSet{
	uint64(linux.SOCK_STREAM):    "SOCK_STREAM",
	uint64(linux.SOCK_DGRAM):     "SOCK_DGRAM",
	uint64(linux.SOCK_RAW):       "SOCK_RAW",
	uint64(linux.SOCK_RDM):       "SOCK_RDM",
	uint64(linux.SOCK_SEQPACKET): "SOCK_SEQPACKET",
	uint64(linux.SOCK_DCCP):      "SOCK_DCCP",
	uint64(linux.SOCK_PACKET):    "SOCK_PACKET",
}

// SocketFlagSet are the possible socket(2) flags.
var SocketFlagSet = abi.FlagSet{
	{
		Flag: linux.SOCK_CLOEXEC,
		Name: "SOCK_CLOEXEC",
	},
	{
		Flag: linux.SOCK_NONBLOCK,
		Name: "SOCK_NONBLOCK",
	},
}

// ipProtocol are the possible socket(2) types for INET and INET6 sockets.
var ipProtocol = abi.ValueSet{
	linux.IPPROTO_IP:      "IPPROTO_IP",
	linux.IPPROTO_ICMP:    "IPPROTO_ICMP",
	linux.IPPROTO_IGMP:    "IPPROTO_IGMP",
	linux.IPPROTO_IPIP:    "IPPROTO_IPIP",
	linux.IPPROTO_TCP:     "IPPROTO_TCP",
	linux.IPPROTO_EGP:     "IPPROTO_EGP",
	linux.IPPROTO_PUP:     "IPPROTO_PUP",
	linux.IPPROTO_UDP:     "IPPROTO_UDP",
	linux.IPPROTO_IDP:     "IPPROTO_IDP",
	linux.IPPROTO_TP:      "IPPROTO_TP",
	linux.IPPROTO_DCCP:    "IPPROTO_DCCP",
	linux.IPPROTO_IPV6:    "IPPROTO_IPV6",
	linux.IPPROTO_RSVP:    "IPPROTO_RSVP",
	linux.IPPROTO_GRE:     "IPPROTO_GRE",
	linux.IPPROTO_ESP:     "IPPROTO_ESP",
	linux.IPPROTO_AH:      "IPPROTO_AH",
	linux.IPPROTO_MTP:     "IPPROTO_MTP",
	linux.IPPROTO_BEETPH:  "IPPROTO_BEETPH",
	linux.IPPROTO_ENCAP:   "IPPROTO_ENCAP",
	linux.IPPROTO_PIM:     "IPPROTO_PIM",
	linux.IPPROTO_COMP:    "IPPROTO_COMP",
	linux.IPPROTO_SCTP:    "IPPROTO_SCTP",
	linux.IPPROTO_UDPLITE: "IPPROTO_UDPLITE",
	linux.IPPROTO_MPLS:    "IPPROTO_MPLS",
	linux.IPPROTO_RAW:     "IPPROTO_RAW",
}

// SocketProtocol are the possible socket(2) protocols for each protocol family.
var SocketProtocol = map[int32]abi.ValueSet{
	linux.AF_INET:  ipProtocol,
	linux.AF_INET6: ipProtocol,
	linux.AF_NETLINK: {
		linux.NETLINK_ROUTE:          "NETLINK_ROUTE",
		linux.NETLINK_UNUSED:         "NETLINK_UNUSED",
		linux.NETLINK_USERSOCK:       "NETLINK_USERSOCK",
		linux.NETLINK_FIREWALL:       "NETLINK_FIREWALL",
		linux.NETLINK_SOCK_DIAG:      "NETLINK_SOCK_DIAG",
		linux.NETLINK_NFLOG:          "NETLINK_NFLOG",
		linux.NETLINK_XFRM:           "NETLINK_XFRM",
		linux.NETLINK_SELINUX:        "NETLINK_SELINUX",
		linux.NETLINK_ISCSI:          "NETLINK_ISCSI",
		linux.NETLINK_AUDIT:          "NETLINK_AUDIT",
		linux.NETLINK_FIB_LOOKUP:     "NETLINK_FIB_LOOKUP",
		linux.NETLINK_CONNECTOR:      "NETLINK_CONNECTOR",
		linux.NETLINK_NETFILTER:      "NETLINK_NETFILTER",
		linux.NETLINK_IP6_FW:         "NETLINK_IP6_FW",
		linux.NETLINK_DNRTMSG:        "NETLINK_DNRTMSG",
		linux.NETLINK_KOBJECT_UEVENT: "NETLINK_KOBJECT_UEVENT",
		linux.NETLINK_GENERIC:        "NETLINK_GENERIC",
		linux.NETLINK_SCSITRANSPORT:  "NETLINK_SCSITRANSPORT",
		linux.NETLINK_ECRYPTFS:       "NETLINK_ECRYPTFS",
		linux.NETLINK_RDMA:           "NETLINK_RDMA",
		linux.NETLINK_CRYPTO:         "NETLINK_CRYPTO",
	},
}

var controlMessageType = map[int32]string{
	linux.SCM_RIGHTS:      "SCM_RIGHTS",
	linux.SCM_CREDENTIALS: "SCM_CREDENTIALS",
	linux.SO_TIMESTAMP:    "SO_TIMESTAMP",
}

func unmarshalControlMessageRights(src []byte) []primitive.Int32 {
	count := len(src) / linux.SizeOfControlMessageRight
	cmr := make([]primitive.Int32, count)
	primitive.UnmarshalUnsafeInt32Slice(cmr, src)
	return cmr
}

func cmsghdr(t *kernel.Task, addr hostarch.Addr, length uint64, maxBytes uint64) string {
	if length > maxBytes {
		return fmt.Sprintf("%#x (error decoding control: invalid length (%d))", addr, length)
	}

	buf := make([]byte, length)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return fmt.Sprintf("%#x (error decoding control: %v)", addr, err)
	}

	var strs []string

	for len(buf) > 0 {
		if linux.SizeOfControlMessageHeader > len(buf) {
			strs = append(strs, "{invalid control message (too short)}")
			break
		}

		var h linux.ControlMessageHeader
		buf = h.UnmarshalUnsafe(buf)

		var skipData bool
		level := "SOL_SOCKET"
		if h.Level != linux.SOL_SOCKET {
			skipData = true
			level = fmt.Sprint(h.Level)
		}

		typ, ok := controlMessageType[h.Type]
		if !ok {
			skipData = true
			typ = fmt.Sprint(h.Type)
		}

		width := t.Arch().Width()
		length := int(h.Length) - linux.SizeOfControlMessageHeader
		if length > len(buf) {
			strs = append(strs, fmt.Sprintf(
				"{level=%s, type=%s, length=%d, content extends beyond buffer}",
				level,
				typ,
				h.Length,
			))
			break
		}

		if length < 0 {
			strs = append(strs, fmt.Sprintf(
				"{level=%s, type=%s, length=%d, content too short}",
				level,
				typ,
				h.Length,
			))
			break
		}

		if skipData {
			strs = append(strs, fmt.Sprintf("{level=%s, type=%s, length=%d}", level, typ, h.Length))
		} else {
			switch h.Type {
			case linux.SCM_RIGHTS:
				rightsSize := bits.AlignDown(length, linux.SizeOfControlMessageRight)
				fds := unmarshalControlMessageRights(buf[:rightsSize])
				rights := make([]string, 0, len(fds))
				for _, fd := range fds {
					rights = append(rights, fmt.Sprint(fd))
				}

				strs = append(strs, fmt.Sprintf(
					"{level=%s, type=%s, length=%d, content: %s}",
					level,
					typ,
					h.Length,
					strings.Join(rights, ","),
				))

			case linux.SCM_CREDENTIALS:
				if length < linux.SizeOfControlMessageCredentials {
					strs = append(strs, fmt.Sprintf(
						"{level=%s, type=%s, length=%d, content too short}",
						level,
						typ,
						h.Length,
					))
					break
				}

				var creds linux.ControlMessageCredentials
				creds.UnmarshalUnsafe(buf)

				strs = append(strs, fmt.Sprintf(
					"{level=%s, type=%s, length=%d, pid: %d, uid: %d, gid: %d}",
					level,
					typ,
					h.Length,
					creds.PID,
					creds.UID,
					creds.GID,
				))

			case linux.SO_TIMESTAMP:
				if length < linux.SizeOfTimeval {
					strs = append(strs, fmt.Sprintf(
						"{level=%s, type=%s, length=%d, content too short}",
						level,
						typ,
						h.Length,
					))
					break
				}

				var tv linux.Timeval
				tv.UnmarshalUnsafe(buf)

				strs = append(strs, fmt.Sprintf(
					"{level=%s, type=%s, length=%d, Sec: %d, Usec: %d}",
					level,
					typ,
					h.Length,
					tv.Sec,
					tv.Usec,
				))

			default:
				panic("unreachable")
			}
		}
		if shift := bits.AlignUp(length, width); shift > len(buf) {
			buf = buf[:0]
		} else {
			buf = buf[shift:]
		}
	}

	return fmt.Sprintf("%#x %s", addr, strings.Join(strs, ", "))
}

func msghdr(t *kernel.Task, addr hostarch.Addr, printContent bool, maxBytes uint64) string {
	var msg slinux.MessageHeader64
	if _, err := msg.CopyIn(t, addr); err != nil {
		return fmt.Sprintf("%#x (error decoding msghdr: %v)", addr, err)
	}
	s := fmt.Sprintf(
		"%#x {name=%#x, namelen=%d, iovecs=%s",
		addr,
		msg.Name,
		msg.NameLen,
		iovecs(t, hostarch.Addr(msg.Iov), int(msg.IovLen), printContent, maxBytes),
	)
	if printContent {
		s = fmt.Sprintf("%s, control={%s}", s, cmsghdr(t, hostarch.Addr(msg.Control), msg.ControlLen, maxBytes))
	} else {
		s = fmt.Sprintf("%s, control=%#x, control_len=%d", s, msg.Control, msg.ControlLen)
	}
	return fmt.Sprintf("%s, flags=%d}", s, msg.Flags)
}

func sockAddr(t *kernel.Task, addr hostarch.Addr, length uint32) string {
	if addr == 0 {
		return "null"
	}

	b, err := slinux.CaptureAddress(t, addr, length)
	if err != nil {
		return fmt.Sprintf("%#x {error reading address: %v}", addr, err)
	}

	// Extract address family.
	if len(b) < 2 {
		return fmt.Sprintf("%#x {address too short: %d bytes}", addr, len(b))
	}
	family := hostarch.ByteOrder.Uint16(b)

	familyStr := SocketFamily.Parse(uint64(family))

	switch family {
	case linux.AF_INET, linux.AF_INET6, linux.AF_UNIX:
		fa, _, err := socket.AddressAndFamily(b)
		if err != nil {
			return fmt.Sprintf("%#x {Family: %s, error extracting address: %v}", addr, familyStr, err)
		}

		if family == linux.AF_UNIX {
			return fmt.Sprintf("%#x {Family: %s, Addr: %q}", addr, familyStr, string(fa.Addr))
		}

		return fmt.Sprintf("%#x {Family: %s, Addr: %v, Port: %d}", addr, familyStr, fa.Addr, fa.Port)
	case linux.AF_NETLINK:
		sa, err := netlink.ExtractSockAddr(b)
		if err != nil {
			return fmt.Sprintf("%#x {Family: %s, error extracting address: %v}", addr, familyStr, err)
		}
		return fmt.Sprintf("%#x {Family: %s, PortID: %d, Groups: %d}", addr, familyStr, sa.PortID, sa.Groups)
	default:
		return fmt.Sprintf("%#x {Family: %s, family addr format unknown}", addr, familyStr)
	}
}

func postSockAddr(t *kernel.Task, addr hostarch.Addr, lengthPtr hostarch.Addr) string {
	if addr == 0 {
		return "null"
	}

	if lengthPtr == 0 {
		return fmt.Sprintf("%#x {length null}", addr)
	}

	l, err := copySockLen(t, lengthPtr)
	if err != nil {
		return fmt.Sprintf("%#x {error reading length: %v}", addr, err)
	}

	return sockAddr(t, addr, l)
}

func copySockLen(t *kernel.Task, addr hostarch.Addr) (uint32, error) {
	// socklen_t is 32-bits.
	var l primitive.Uint32
	_, err := l.CopyIn(t, addr)
	return uint32(l), err
}

func sockLenPointer(t *kernel.Task, addr hostarch.Addr) string {
	if addr == 0 {
		return "null"
	}
	l, err := copySockLen(t, addr)
	if err != nil {
		return fmt.Sprintf("%#x {error reading length: %v}", addr, err)
	}
	return fmt.Sprintf("%#x {length=%v}", addr, l)
}

func sockType(stype int32) string {
	s := SocketType.Parse(uint64(stype & linux.SOCK_TYPE_MASK))
	if flags := SocketFlagSet.Parse(uint64(stype &^ linux.SOCK_TYPE_MASK)); flags != "" {
		s += "|" + flags
	}
	return s
}

func sockProtocol(family, protocol int32) string {
	protocols, ok := SocketProtocol[family]
	if !ok {
		return fmt.Sprintf("%#x", protocol)
	}
	return protocols.Parse(uint64(protocol))
}

func sockFlags(flags int32) string {
	if flags == 0 {
		return "0"
	}
	return SocketFlagSet.Parse(uint64(flags))
}

func getSockOptVal(t *kernel.Task, level, optname uint64, optVal hostarch.Addr, optLen hostarch.Addr, maximumBlobSize uint, rval uintptr) string {
	if int(rval) < 0 {
		return hexNum(uint64(optVal))
	}
	if optVal == 0 {
		return "null"
	}
	l, err := copySockLen(t, optLen)
	if err != nil {
		return fmt.Sprintf("%#x {error reading length: %v}", optLen, err)
	}
	return sockOptVal(t, level, optname, optVal, uint64(l), maximumBlobSize)
}

func sockOptVal(t *kernel.Task, level, optname uint64, optVal hostarch.Addr, optLen uint64, maximumBlobSize uint) string {
	switch optLen {
	case 1:
		var v primitive.Uint8
		_, err := v.CopyIn(t, optVal)
		if err != nil {
			return fmt.Sprintf("%#x {error reading optval: %v}", optVal, err)
		}
		return fmt.Sprintf("%#x {value=%v}", optVal, v)
	case 2:
		var v primitive.Uint16
		_, err := v.CopyIn(t, optVal)
		if err != nil {
			return fmt.Sprintf("%#x {error reading optval: %v}", optVal, err)
		}
		return fmt.Sprintf("%#x {value=%v}", optVal, v)
	case 4:
		var v primitive.Uint32
		_, err := v.CopyIn(t, optVal)
		if err != nil {
			return fmt.Sprintf("%#x {error reading optval: %v}", optVal, err)
		}
		return fmt.Sprintf("%#x {value=%v}", optVal, v)
	default:
		return dump(t, optVal, uint(optLen), maximumBlobSize)
	}
}

var sockOptLevels = abi.ValueSet{
	linux.SOL_IP:      "SOL_IP",
	linux.SOL_SOCKET:  "SOL_SOCKET",
	linux.SOL_TCP:     "SOL_TCP",
	linux.SOL_UDP:     "SOL_UDP",
	linux.SOL_IPV6:    "SOL_IPV6",
	linux.SOL_ICMPV6:  "SOL_ICMPV6",
	linux.SOL_RAW:     "SOL_RAW",
	linux.SOL_PACKET:  "SOL_PACKET",
	linux.SOL_NETLINK: "SOL_NETLINK",
}

var sockOptNames = map[uint64]abi.ValueSet{
	linux.SOL_IP: {
		linux.IP_TTL:                    "IP_TTL",
		linux.IP_MULTICAST_TTL:          "IP_MULTICAST_TTL",
		linux.IP_MULTICAST_IF:           "IP_MULTICAST_IF",
		linux.IP_MULTICAST_LOOP:         "IP_MULTICAST_LOOP",
		linux.IP_TOS:                    "IP_TOS",
		linux.IP_RECVTOS:                "IP_RECVTOS",
		linux.IPT_SO_GET_INFO:           "IPT_SO_GET_INFO",
		linux.IPT_SO_GET_ENTRIES:        "IPT_SO_GET_ENTRIES",
		linux.IP_ADD_MEMBERSHIP:         "IP_ADD_MEMBERSHIP",
		linux.IP_DROP_MEMBERSHIP:        "IP_DROP_MEMBERSHIP",
		linux.MCAST_JOIN_GROUP:          "MCAST_JOIN_GROUP",
		linux.IP_ADD_SOURCE_MEMBERSHIP:  "IP_ADD_SOURCE_MEMBERSHIP",
		linux.IP_BIND_ADDRESS_NO_PORT:   "IP_BIND_ADDRESS_NO_PORT",
		linux.IP_BLOCK_SOURCE:           "IP_BLOCK_SOURCE",
		linux.IP_CHECKSUM:               "IP_CHECKSUM",
		linux.IP_DROP_SOURCE_MEMBERSHIP: "IP_DROP_SOURCE_MEMBERSHIP",
		linux.IP_FREEBIND:               "IP_FREEBIND",
		linux.IP_HDRINCL:                "IP_HDRINCL",
		linux.IP_IPSEC_POLICY:           "IP_IPSEC_POLICY",
		linux.IP_MINTTL:                 "IP_MINTTL",
		linux.IP_MSFILTER:               "IP_MSFILTER",
		linux.IP_MTU_DISCOVER:           "IP_MTU_DISCOVER",
		linux.IP_MULTICAST_ALL:          "IP_MULTICAST_ALL",
		linux.IP_NODEFRAG:               "IP_NODEFRAG",
		linux.IP_OPTIONS:                "IP_OPTIONS",
		linux.IP_PASSSEC:                "IP_PASSSEC",
		linux.IP_PKTINFO:                "IP_PKTINFO",
		linux.IP_RECVERR:                "IP_RECVERR",
		linux.IP_RECVFRAGSIZE:           "IP_RECVFRAGSIZE",
		linux.IP_RECVOPTS:               "IP_RECVOPTS",
		linux.IP_RECVORIGDSTADDR:        "IP_RECVORIGDSTADDR",
		linux.IP_RECVTTL:                "IP_RECVTTL",
		linux.IP_RETOPTS:                "IP_RETOPTS",
		linux.IP_TRANSPARENT:            "IP_TRANSPARENT",
		linux.IP_UNBLOCK_SOURCE:         "IP_UNBLOCK_SOURCE",
		linux.IP_UNICAST_IF:             "IP_UNICAST_IF",
		linux.IP_XFRM_POLICY:            "IP_XFRM_POLICY",
		linux.MCAST_BLOCK_SOURCE:        "MCAST_BLOCK_SOURCE",
		linux.MCAST_JOIN_SOURCE_GROUP:   "MCAST_JOIN_SOURCE_GROUP",
		linux.MCAST_LEAVE_GROUP:         "MCAST_LEAVE_GROUP",
		linux.MCAST_LEAVE_SOURCE_GROUP:  "MCAST_LEAVE_SOURCE_GROUP",
		linux.MCAST_MSFILTER:            "MCAST_MSFILTER",
		linux.MCAST_UNBLOCK_SOURCE:      "MCAST_UNBLOCK_SOURCE",
		linux.IP_ROUTER_ALERT:           "IP_ROUTER_ALERT",
		linux.IP_PKTOPTIONS:             "IP_PKTOPTIONS",
		linux.IP_MTU:                    "IP_MTU",
		linux.SO_ORIGINAL_DST:           "SO_ORIGINAL_DST",
	},
	linux.SOL_SOCKET: {
		linux.SO_ERROR:        "SO_ERROR",
		linux.SO_PEERCRED:     "SO_PEERCRED",
		linux.SO_PASSCRED:     "SO_PASSCRED",
		linux.SO_SNDBUF:       "SO_SNDBUF",
		linux.SO_RCVBUF:       "SO_RCVBUF",
		linux.SO_REUSEADDR:    "SO_REUSEADDR",
		linux.SO_REUSEPORT:    "SO_REUSEPORT",
		linux.SO_BINDTODEVICE: "SO_BINDTODEVICE",
		linux.SO_BROADCAST:    "SO_BROADCAST",
		linux.SO_KEEPALIVE:    "SO_KEEPALIVE",
		linux.SO_LINGER:       "SO_LINGER",
		linux.SO_SNDTIMEO:     "SO_SNDTIMEO",
		linux.SO_RCVTIMEO:     "SO_RCVTIMEO",
		linux.SO_OOBINLINE:    "SO_OOBINLINE",
		linux.SO_TIMESTAMP:    "SO_TIMESTAMP",
	},
	linux.SOL_TCP: {
		linux.TCP_NODELAY:              "TCP_NODELAY",
		linux.TCP_CORK:                 "TCP_CORK",
		linux.TCP_QUICKACK:             "TCP_QUICKACK",
		linux.TCP_MAXSEG:               "TCP_MAXSEG",
		linux.TCP_KEEPIDLE:             "TCP_KEEPIDLE",
		linux.TCP_KEEPINTVL:            "TCP_KEEPINTVL",
		linux.TCP_USER_TIMEOUT:         "TCP_USER_TIMEOUT",
		linux.TCP_INFO:                 "TCP_INFO",
		linux.TCP_CC_INFO:              "TCP_CC_INFO",
		linux.TCP_NOTSENT_LOWAT:        "TCP_NOTSENT_LOWAT",
		linux.TCP_ZEROCOPY_RECEIVE:     "TCP_ZEROCOPY_RECEIVE",
		linux.TCP_CONGESTION:           "TCP_CONGESTION",
		linux.TCP_LINGER2:              "TCP_LINGER2",
		linux.TCP_DEFER_ACCEPT:         "TCP_DEFER_ACCEPT",
		linux.TCP_REPAIR_OPTIONS:       "TCP_REPAIR_OPTIONS",
		linux.TCP_INQ:                  "TCP_INQ",
		linux.TCP_FASTOPEN:             "TCP_FASTOPEN",
		linux.TCP_FASTOPEN_CONNECT:     "TCP_FASTOPEN_CONNECT",
		linux.TCP_FASTOPEN_KEY:         "TCP_FASTOPEN_KEY",
		linux.TCP_FASTOPEN_NO_COOKIE:   "TCP_FASTOPEN_NO_COOKIE",
		linux.TCP_KEEPCNT:              "TCP_KEEPCNT",
		linux.TCP_QUEUE_SEQ:            "TCP_QUEUE_SEQ",
		linux.TCP_REPAIR:               "TCP_REPAIR",
		linux.TCP_REPAIR_QUEUE:         "TCP_REPAIR_QUEUE",
		linux.TCP_REPAIR_WINDOW:        "TCP_REPAIR_WINDOW",
		linux.TCP_SAVED_SYN:            "TCP_SAVED_SYN",
		linux.TCP_SAVE_SYN:             "TCP_SAVE_SYN",
		linux.TCP_SYNCNT:               "TCP_SYNCNT",
		linux.TCP_THIN_DUPACK:          "TCP_THIN_DUPACK",
		linux.TCP_THIN_LINEAR_TIMEOUTS: "TCP_THIN_LINEAR_TIMEOUTS",
		linux.TCP_TIMESTAMP:            "TCP_TIMESTAMP",
		linux.TCP_ULP:                  "TCP_ULP",
		linux.TCP_WINDOW_CLAMP:         "TCP_WINDOW_CLAMP",
	},
	linux.SOL_IPV6: {
		linux.IPV6_V6ONLY:              "IPV6_V6ONLY",
		linux.IPV6_PATHMTU:             "IPV6_PATHMTU",
		linux.IPV6_TCLASS:              "IPV6_TCLASS",
		linux.IPV6_ADD_MEMBERSHIP:      "IPV6_ADD_MEMBERSHIP",
		linux.IPV6_DROP_MEMBERSHIP:     "IPV6_DROP_MEMBERSHIP",
		linux.IPV6_IPSEC_POLICY:        "IPV6_IPSEC_POLICY",
		linux.IPV6_JOIN_ANYCAST:        "IPV6_JOIN_ANYCAST",
		linux.IPV6_LEAVE_ANYCAST:       "IPV6_LEAVE_ANYCAST",
		linux.IPV6_PKTINFO:             "IPV6_PKTINFO",
		linux.IPV6_ROUTER_ALERT:        "IPV6_ROUTER_ALERT",
		linux.IPV6_XFRM_POLICY:         "IPV6_XFRM_POLICY",
		linux.MCAST_BLOCK_SOURCE:       "MCAST_BLOCK_SOURCE",
		linux.MCAST_JOIN_GROUP:         "MCAST_JOIN_GROUP",
		linux.MCAST_JOIN_SOURCE_GROUP:  "MCAST_JOIN_SOURCE_GROUP",
		linux.MCAST_LEAVE_GROUP:        "MCAST_LEAVE_GROUP",
		linux.MCAST_LEAVE_SOURCE_GROUP: "MCAST_LEAVE_SOURCE_GROUP",
		linux.MCAST_UNBLOCK_SOURCE:     "MCAST_UNBLOCK_SOURCE",
		linux.IPV6_2292DSTOPTS:         "IPV6_2292DSTOPTS",
		linux.IPV6_2292HOPLIMIT:        "IPV6_2292HOPLIMIT",
		linux.IPV6_2292HOPOPTS:         "IPV6_2292HOPOPTS",
		linux.IPV6_2292PKTINFO:         "IPV6_2292PKTINFO",
		linux.IPV6_2292PKTOPTIONS:      "IPV6_2292PKTOPTIONS",
		linux.IPV6_2292RTHDR:           "IPV6_2292RTHDR",
		linux.IPV6_ADDR_PREFERENCES:    "IPV6_ADDR_PREFERENCES",
		linux.IPV6_AUTOFLOWLABEL:       "IPV6_AUTOFLOWLABEL",
		linux.IPV6_DONTFRAG:            "IPV6_DONTFRAG",
		linux.IPV6_DSTOPTS:             "IPV6_DSTOPTS",
		linux.IPV6_FLOWINFO:            "IPV6_FLOWINFO",
		linux.IPV6_FLOWINFO_SEND:       "IPV6_FLOWINFO_SEND",
		linux.IPV6_FLOWLABEL_MGR:       "IPV6_FLOWLABEL_MGR",
		linux.IPV6_FREEBIND:            "IPV6_FREEBIND",
		linux.IPV6_HOPOPTS:             "IPV6_HOPOPTS",
		linux.IPV6_MINHOPCOUNT:         "IPV6_MINHOPCOUNT",
		linux.IPV6_MTU:                 "IPV6_MTU",
		linux.IPV6_MTU_DISCOVER:        "IPV6_MTU_DISCOVER",
		linux.IPV6_MULTICAST_ALL:       "IPV6_MULTICAST_ALL",
		linux.IPV6_MULTICAST_HOPS:      "IPV6_MULTICAST_HOPS",
		linux.IPV6_MULTICAST_IF:        "IPV6_MULTICAST_IF",
		linux.IPV6_MULTICAST_LOOP:      "IPV6_MULTICAST_LOOP",
		linux.IPV6_RECVDSTOPTS:         "IPV6_RECVDSTOPTS",
		linux.IPV6_RECVERR:             "IPV6_RECVERR",
		linux.IPV6_RECVFRAGSIZE:        "IPV6_RECVFRAGSIZE",
		linux.IPV6_RECVHOPLIMIT:        "IPV6_RECVHOPLIMIT",
		linux.IPV6_RECVHOPOPTS:         "IPV6_RECVHOPOPTS",
		linux.IPV6_RECVORIGDSTADDR:     "IPV6_RECVORIGDSTADDR",
		linux.IPV6_RECVPATHMTU:         "IPV6_RECVPATHMTU",
		linux.IPV6_RECVPKTINFO:         "IPV6_RECVPKTINFO",
		linux.IPV6_RECVRTHDR:           "IPV6_RECVRTHDR",
		linux.IPV6_RECVTCLASS:          "IPV6_RECVTCLASS",
		linux.IPV6_RTHDR:               "IPV6_RTHDR",
		linux.IPV6_RTHDRDSTOPTS:        "IPV6_RTHDRDSTOPTS",
		linux.IPV6_TRANSPARENT:         "IPV6_TRANSPARENT",
		linux.IPV6_UNICAST_HOPS:        "IPV6_UNICAST_HOPS",
		linux.IPV6_UNICAST_IF:          "IPV6_UNICAST_IF",
		linux.MCAST_MSFILTER:           "MCAST_MSFILTER",
		linux.IPV6_ADDRFORM:            "IPV6_ADDRFORM",
		linux.IP6T_SO_GET_INFO:         "IP6T_SO_GET_INFO",
		linux.IP6T_SO_GET_ENTRIES:      "IP6T_SO_GET_ENTRIES",
	},
	linux.SOL_NETLINK: {
		linux.NETLINK_BROADCAST_ERROR:  "NETLINK_BROADCAST_ERROR",
		linux.NETLINK_CAP_ACK:          "NETLINK_CAP_ACK",
		linux.NETLINK_DUMP_STRICT_CHK:  "NETLINK_DUMP_STRICT_CHK",
		linux.NETLINK_EXT_ACK:          "NETLINK_EXT_ACK",
		linux.NETLINK_LIST_MEMBERSHIPS: "NETLINK_LIST_MEMBERSHIPS",
		linux.NETLINK_NO_ENOBUFS:       "NETLINK_NO_ENOBUFS",
		linux.NETLINK_PKTINFO:          "NETLINK_PKTINFO",
	},
}
