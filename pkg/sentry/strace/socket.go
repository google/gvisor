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

package strace

import (
	"fmt"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink"
	slinux "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// SocketFamily are the possible socket(2) families.
var SocketFamily = abi.ValueSet{
	{
		Value: linux.AF_UNSPEC,
		Name:  "AF_UNSPEC",
	},
	{
		Value: linux.AF_UNIX,
		Name:  "AF_UNIX",
	},
	{
		Value: linux.AF_INET,
		Name:  "AF_INET",
	},
	{
		Value: linux.AF_AX25,
		Name:  "AF_AX25",
	},
	{
		Value: linux.AF_IPX,
		Name:  "AF_IPX",
	},
	{
		Value: linux.AF_APPLETALK,
		Name:  "AF_APPLETALK",
	},
	{
		Value: linux.AF_NETROM,
		Name:  "AF_NETROM",
	},
	{
		Value: linux.AF_BRIDGE,
		Name:  "AF_BRIDGE",
	},
	{
		Value: linux.AF_ATMPVC,
		Name:  "AF_ATMPVC",
	},
	{
		Value: linux.AF_X25,
		Name:  "AF_X25",
	},
	{
		Value: linux.AF_INET6,
		Name:  "AF_INET6",
	},
	{
		Value: linux.AF_ROSE,
		Name:  "AF_ROSE",
	},
	{
		Value: linux.AF_DECnet,
		Name:  "AF_DECnet",
	},
	{
		Value: linux.AF_NETBEUI,
		Name:  "AF_NETBEUI",
	},
	{
		Value: linux.AF_SECURITY,
		Name:  "AF_SECURITY",
	},
	{
		Value: linux.AF_KEY,
		Name:  "AF_KEY",
	},
	{
		Value: linux.AF_NETLINK,
		Name:  "AF_NETLINK",
	},
	{
		Value: linux.AF_PACKET,
		Name:  "AF_PACKET",
	},
	{
		Value: linux.AF_ASH,
		Name:  "AF_ASH",
	},
	{
		Value: linux.AF_ECONET,
		Name:  "AF_ECONET",
	},
	{
		Value: linux.AF_ATMSVC,
		Name:  "AF_ATMSVC",
	},
	{
		Value: linux.AF_RDS,
		Name:  "AF_RDS",
	},
	{
		Value: linux.AF_SNA,
		Name:  "AF_SNA",
	},
	{
		Value: linux.AF_IRDA,
		Name:  "AF_IRDA",
	},
	{
		Value: linux.AF_PPPOX,
		Name:  "AF_PPPOX",
	},
	{
		Value: linux.AF_WANPIPE,
		Name:  "AF_WANPIPE",
	},
	{
		Value: linux.AF_LLC,
		Name:  "AF_LLC",
	},
	{
		Value: linux.AF_IB,
		Name:  "AF_IB",
	},
	{
		Value: linux.AF_MPLS,
		Name:  "AF_MPLS",
	},
	{
		Value: linux.AF_CAN,
		Name:  "AF_CAN",
	},
	{
		Value: linux.AF_TIPC,
		Name:  "AF_TIPC",
	},
	{
		Value: linux.AF_BLUETOOTH,
		Name:  "AF_BLUETOOTH",
	},
	{
		Value: linux.AF_IUCV,
		Name:  "AF_IUCV",
	},
	{
		Value: linux.AF_RXRPC,
		Name:  "AF_RXRPC",
	},
	{
		Value: linux.AF_ISDN,
		Name:  "AF_ISDN",
	},
	{
		Value: linux.AF_PHONET,
		Name:  "AF_PHONET",
	},
	{
		Value: linux.AF_IEEE802154,
		Name:  "AF_IEEE802154",
	},
	{
		Value: linux.AF_CAIF,
		Name:  "AF_CAIF",
	},
	{
		Value: linux.AF_ALG,
		Name:  "AF_ALG",
	},
	{
		Value: linux.AF_NFC,
		Name:  "AF_NFC",
	},
	{
		Value: linux.AF_VSOCK,
		Name:  "AF_VSOCK",
	},
}

// SocketType are the possible socket(2) types.
var SocketType = abi.ValueSet{
	{
		Value: linux.SOCK_STREAM,
		Name:  "SOCK_STREAM",
	},
	{
		Value: linux.SOCK_DGRAM,
		Name:  "SOCK_DGRAM",
	},
	{
		Value: linux.SOCK_RAW,
		Name:  "SOCK_RAW",
	},
	{
		Value: linux.SOCK_RDM,
		Name:  "SOCK_RDM",
	},
	{
		Value: linux.SOCK_SEQPACKET,
		Name:  "SOCK_SEQPACKET",
	},
	{
		Value: linux.SOCK_DCCP,
		Name:  "SOCK_DCCP",
	},
	{
		Value: linux.SOCK_PACKET,
		Name:  "SOCK_PACKET",
	},
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
	{
		Value: linux.IPPROTO_IP,
		Name:  "IPPROTO_IP",
	},
	{
		Value: linux.IPPROTO_ICMP,
		Name:  "IPPROTO_ICMP",
	},
	{
		Value: linux.IPPROTO_IGMP,
		Name:  "IPPROTO_IGMP",
	},
	{
		Value: linux.IPPROTO_IPIP,
		Name:  "IPPROTO_IPIP",
	},
	{
		Value: linux.IPPROTO_TCP,
		Name:  "IPPROTO_TCP",
	},
	{
		Value: linux.IPPROTO_EGP,
		Name:  "IPPROTO_EGP",
	},
	{
		Value: linux.IPPROTO_PUP,
		Name:  "IPPROTO_PUP",
	},
	{
		Value: linux.IPPROTO_UDP,
		Name:  "IPPROTO_UDP",
	},
	{
		Value: linux.IPPROTO_IDP,
		Name:  "IPPROTO_IDP",
	},
	{
		Value: linux.IPPROTO_TP,
		Name:  "IPPROTO_TP",
	},
	{
		Value: linux.IPPROTO_DCCP,
		Name:  "IPPROTO_DCCP",
	},
	{
		Value: linux.IPPROTO_IPV6,
		Name:  "IPPROTO_IPV6",
	},
	{
		Value: linux.IPPROTO_RSVP,
		Name:  "IPPROTO_RSVP",
	},
	{
		Value: linux.IPPROTO_GRE,
		Name:  "IPPROTO_GRE",
	},
	{
		Value: linux.IPPROTO_ESP,
		Name:  "IPPROTO_ESP",
	},
	{
		Value: linux.IPPROTO_AH,
		Name:  "IPPROTO_AH",
	},
	{
		Value: linux.IPPROTO_MTP,
		Name:  "IPPROTO_MTP",
	},
	{
		Value: linux.IPPROTO_BEETPH,
		Name:  "IPPROTO_BEETPH",
	},
	{
		Value: linux.IPPROTO_ENCAP,
		Name:  "IPPROTO_ENCAP",
	},
	{
		Value: linux.IPPROTO_PIM,
		Name:  "IPPROTO_PIM",
	},
	{
		Value: linux.IPPROTO_COMP,
		Name:  "IPPROTO_COMP",
	},
	{
		Value: linux.IPPROTO_SCTP,
		Name:  "IPPROTO_SCTP",
	},
	{
		Value: linux.IPPROTO_UDPLITE,
		Name:  "IPPROTO_UDPLITE",
	},
	{
		Value: linux.IPPROTO_MPLS,
		Name:  "IPPROTO_MPLS",
	},
	{
		Value: linux.IPPROTO_RAW,
		Name:  "IPPROTO_RAW",
	},
}

// SocketProtocol are the possible socket(2) protocols for each protocol family.
var SocketProtocol = map[int32]abi.ValueSet{
	linux.AF_INET:  ipProtocol,
	linux.AF_INET6: ipProtocol,
	linux.AF_NETLINK: {
		{
			Value: linux.NETLINK_ROUTE,
			Name:  "NETLINK_ROUTE",
		},
		{
			Value: linux.NETLINK_UNUSED,
			Name:  "NETLINK_UNUSED",
		},
		{
			Value: linux.NETLINK_USERSOCK,
			Name:  "NETLINK_USERSOCK",
		},
		{
			Value: linux.NETLINK_FIREWALL,
			Name:  "NETLINK_FIREWALL",
		},
		{
			Value: linux.NETLINK_SOCK_DIAG,
			Name:  "NETLINK_SOCK_DIAG",
		},
		{
			Value: linux.NETLINK_NFLOG,
			Name:  "NETLINK_NFLOG",
		},
		{
			Value: linux.NETLINK_XFRM,
			Name:  "NETLINK_XFRM",
		},
		{
			Value: linux.NETLINK_SELINUX,
			Name:  "NETLINK_SELINUX",
		},
		{
			Value: linux.NETLINK_ISCSI,
			Name:  "NETLINK_ISCSI",
		},
		{
			Value: linux.NETLINK_AUDIT,
			Name:  "NETLINK_AUDIT",
		},
		{
			Value: linux.NETLINK_FIB_LOOKUP,
			Name:  "NETLINK_FIB_LOOKUP",
		},
		{
			Value: linux.NETLINK_CONNECTOR,
			Name:  "NETLINK_CONNECTOR",
		},
		{
			Value: linux.NETLINK_NETFILTER,
			Name:  "NETLINK_NETFILTER",
		},
		{
			Value: linux.NETLINK_IP6_FW,
			Name:  "NETLINK_IP6_FW",
		},
		{
			Value: linux.NETLINK_DNRTMSG,
			Name:  "NETLINK_DNRTMSG",
		},
		{
			Value: linux.NETLINK_KOBJECT_UEVENT,
			Name:  "NETLINK_KOBJECT_UEVENT",
		},
		{
			Value: linux.NETLINK_GENERIC,
			Name:  "NETLINK_GENERIC",
		},
		{
			Value: linux.NETLINK_SCSITRANSPORT,
			Name:  "NETLINK_SCSITRANSPORT",
		},
		{
			Value: linux.NETLINK_ECRYPTFS,
			Name:  "NETLINK_ECRYPTFS",
		},
		{
			Value: linux.NETLINK_RDMA,
			Name:  "NETLINK_RDMA",
		},
		{
			Value: linux.NETLINK_CRYPTO,
			Name:  "NETLINK_CRYPTO",
		},
	},
}

var controlMessageType = map[int32]string{
	linux.SCM_RIGHTS:      "SCM_RIGHTS",
	linux.SCM_CREDENTIALS: "SCM_CREDENTIALS",
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
		i += linux.SizeOfControlMessageHeader

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

		width := t.Arch().Width()
		length := int(h.Length) - linux.SizeOfControlMessageHeader

		if skipData {
			strs = append(strs, fmt.Sprintf("{level=%s, type=%s, length=%d}", level, typ, h.Length))
			i += control.AlignUp(i+length, width)
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

			i += control.AlignUp(length, width)

		case linux.SCM_CREDENTIALS:
			if length < linux.SizeOfControlMessageCredentials {
				strs = append(strs, fmt.Sprintf(
					"{level=%s, type=%s, length=%d, content too short}",
					level,
					typ,
					h.Length,
				))
				i += control.AlignUp(length, width)
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

			i += control.AlignUp(length, width)

		default:
			panic("unreachable")
		}
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
		fa, err := epsocket.GetAddress(int(family), b)
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
