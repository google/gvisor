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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
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

func cmsghdr(t *kernel.Task, addr usermem.Addr, length uint64, maxBytes uint64) string {
	if length > maxBytes {
		return fmt.Sprintf("%#x (error decoding control: invalid length (%d))", addr, length)
	}

	buf := make([]byte, length)
	if _, err := t.CopyIn(addr, &buf); err != nil {
		return fmt.Sprintf("%#x (error decoding control: %v)", addr, err)
	}

	var strs []string

	for i := 0; i < len(buf); {
		if i+linux.SizeOfControlMessageHeader > len(buf) {
			strs = append(strs, "{invalid control message (too short)}")
			break
		}

		var h linux.ControlMessageHeader
		binary.Unmarshal(buf[i:i+linux.SizeOfControlMessageHeader], usermem.ByteOrder, &h)

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

		if h.Length > uint64(len(buf)-i) {
			strs = append(strs, fmt.Sprintf(
				"{level=%s, type=%s, length=%d, content extends beyond buffer}",
				level,
				typ,
				h.Length,
			))
			break
		}

		i += linux.SizeOfControlMessageHeader
		width := t.Arch().Width()
		length := int(h.Length) - linux.SizeOfControlMessageHeader

		if skipData {
			strs = append(strs, fmt.Sprintf("{level=%s, type=%s, length=%d}", level, typ, h.Length))
			i += control.AlignUp(length, width)
			continue
		}

		switch h.Type {
		case linux.SCM_RIGHTS:
			rightsSize := control.AlignDown(length, linux.SizeOfControlMessageRight)

			numRights := rightsSize / linux.SizeOfControlMessageRight
			fds := make(linux.ControlMessageRights, numRights)
			binary.Unmarshal(buf[i:i+rightsSize], usermem.ByteOrder, &fds)

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
			binary.Unmarshal(buf[i:i+linux.SizeOfControlMessageCredentials], usermem.ByteOrder, &creds)

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
			binary.Unmarshal(buf[i:i+linux.SizeOfTimeval], usermem.ByteOrder, &tv)

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
		i += control.AlignUp(length, width)
	}

	return fmt.Sprintf("%#x %s", addr, strings.Join(strs, ", "))
}

func msghdr(t *kernel.Task, addr usermem.Addr, printContent bool, maxBytes uint64) string {
	var msg slinux.MessageHeader64
	if err := slinux.CopyInMessageHeader64(t, addr, &msg); err != nil {
		return fmt.Sprintf("%#x (error decoding msghdr: %v)", addr, err)
	}
	s := fmt.Sprintf(
		"%#x {name=%#x, namelen=%d, iovecs=%s",
		addr,
		msg.Name,
		msg.NameLen,
		iovecs(t, usermem.Addr(msg.Iov), int(msg.IovLen), printContent, maxBytes),
	)
	if printContent {
		s = fmt.Sprintf("%s, control={%s}", s, cmsghdr(t, usermem.Addr(msg.Control), msg.ControlLen, maxBytes))
	} else {
		s = fmt.Sprintf("%s, control=%#x, control_len=%d", s, msg.Control, msg.ControlLen)
	}
	return fmt.Sprintf("%s, flags=%d}", s, msg.Flags)
}

func sockAddr(t *kernel.Task, addr usermem.Addr, length uint32) string {
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
	family := usermem.ByteOrder.Uint16(b)

	familyStr := SocketFamily.Parse(uint64(family))

	switch family {
	case linux.AF_INET, linux.AF_INET6, linux.AF_UNIX:
		fa, err := epsocket.GetAddress(int(family), b, true /* strict */)
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

func postSockAddr(t *kernel.Task, addr usermem.Addr, lengthPtr usermem.Addr) string {
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

func copySockLen(t *kernel.Task, addr usermem.Addr) (uint32, error) {
	// socklen_t is 32-bits.
	var l uint32
	_, err := t.CopyIn(addr, &l)
	return l, err
}

func sockLenPointer(t *kernel.Task, addr usermem.Addr) string {
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
