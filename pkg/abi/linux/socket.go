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

import "gvisor.googlesource.com/gvisor/pkg/binary"

// Address families, from linux/socket.h.
const (
	AF_UNSPEC     = 0
	AF_UNIX       = 1
	AF_INET       = 2
	AF_AX25       = 3
	AF_IPX        = 4
	AF_APPLETALK  = 5
	AF_NETROM     = 6
	AF_BRIDGE     = 7
	AF_ATMPVC     = 8
	AF_X25        = 9
	AF_INET6      = 10
	AF_ROSE       = 11
	AF_DECnet     = 12
	AF_NETBEUI    = 13
	AF_SECURITY   = 14
	AF_KEY        = 15
	AF_NETLINK    = 16
	AF_PACKET     = 17
	AF_ASH        = 18
	AF_ECONET     = 19
	AF_ATMSVC     = 20
	AF_RDS        = 21
	AF_SNA        = 22
	AF_IRDA       = 23
	AF_PPPOX      = 24
	AF_WANPIPE    = 25
	AF_LLC        = 26
	AF_IB         = 27
	AF_MPLS       = 28
	AF_CAN        = 29
	AF_TIPC       = 30
	AF_BLUETOOTH  = 31
	AF_IUCV       = 32
	AF_RXRPC      = 33
	AF_ISDN       = 34
	AF_PHONET     = 35
	AF_IEEE802154 = 36
	AF_CAIF       = 37
	AF_ALG        = 38
	AF_NFC        = 39
	AF_VSOCK      = 40
)

// sendmsg(2)/recvmsg(2) flags, from linux/socket.h.
const (
	MSG_OOB              = 0x1
	MSG_PEEK             = 0x2
	MSG_DONTROUTE        = 0x4
	MSG_TRYHARD          = 0x4
	MSG_CTRUNC           = 0x8
	MSG_PROBE            = 0x10
	MSG_TRUNC            = 0x20
	MSG_DONTWAIT         = 0x40
	MSG_EOR              = 0x80
	MSG_WAITALL          = 0x100
	MSG_FIN              = 0x200
	MSG_EOF              = MSG_FIN
	MSG_SYN              = 0x400
	MSG_CONFIRM          = 0x800
	MSG_RST              = 0x1000
	MSG_ERRQUEUE         = 0x2000
	MSG_NOSIGNAL         = 0x4000
	MSG_MORE             = 0x8000
	MSG_WAITFORONE       = 0x10000
	MSG_SENDPAGE_NOTLAST = 0x20000
	MSG_REINJECT         = 0x8000000
	MSG_ZEROCOPY         = 0x4000000
	MSG_FASTOPEN         = 0x20000000
	MSG_CMSG_CLOEXEC     = 0x40000000
)

// SOL_SOCKET is from socket.h
const SOL_SOCKET = 1

// Socket types, from linux/net.h.
const (
	SOCK_STREAM    = 1
	SOCK_DGRAM     = 2
	SOCK_RAW       = 3
	SOCK_RDM       = 4
	SOCK_SEQPACKET = 5
	SOCK_DCCP      = 6
	SOCK_PACKET    = 10
)

// SOCK_TYPE_MASK covers all of the above socket types. The remaining bits are
// flags. From linux/net.h.
const SOCK_TYPE_MASK = 0xf

// socket(2)/socketpair(2)/accept4(2) flags, from linux/net.h.
const (
	SOCK_CLOEXEC  = O_CLOEXEC
	SOCK_NONBLOCK = O_NONBLOCK
)

// shutdown(2) how commands, from <linux/net.h>.
const (
	SHUT_RD   = 0
	SHUT_WR   = 1
	SHUT_RDWR = 2
)

// Socket options from socket.h.
const (
	SO_ERROR       = 4
	SO_KEEPALIVE   = 9
	SO_LINGER      = 13
	SO_MARK        = 36
	SO_PASSCRED    = 16
	SO_PEERCRED    = 17
	SO_PEERNAME    = 28
	SO_PROTOCOL    = 38
	SO_RCVBUF      = 8
	SO_RCVTIMEO    = 20
	SO_REUSEADDR   = 2
	SO_SNDBUF      = 7
	SO_SNDTIMEO    = 21
	SO_TIMESTAMP   = 29
	SO_TIMESTAMPNS = 35
	SO_TYPE        = 3
)

// SockAddrInt is struct sockaddr_in, from uapi/linux/in.h.
type SockAddrInet struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]uint8 // pad to sizeof(struct sockaddr).
}

// SockAddrInt6 is struct sockaddr_in6, from uapi/linux/in6.h.
type SockAddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	Scope_id uint32
}

// UnixPathMax is the maximum length of the path in an AF_UNIX socket.
//
// From uapi/linux/un.h.
const UnixPathMax = 108

// SockAddrUnix is struct sockaddr_un, from uapi/linux/un.h.
type SockAddrUnix struct {
	Family uint16
	Path   [UnixPathMax]int8
}

// TCPInfo is a collection of TCP statistics.
//
// From uapi/linux/tcp.h.
type TCPInfo struct {
	State       uint8
	CaState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	// WindowScale is the combination of snd_wscale (first 4 bits) and rcv_wscale (second 4 bits)
	WindowScale uint8
	// DeliveryRateAppLimited is a boolean and only the first bit is meaningful.
	DeliveryRateAppLimited uint8

	RTO    uint32
	ATO    uint32
	SndMss uint32
	RcvMss uint32

	Unacked uint32
	Sacked  uint32
	Lost    uint32
	Retrans uint32
	Fackets uint32

	// Times.
	LastDataSent uint32
	LastAckSent  uint32
	LastDataRecv uint32
	LastAckRecv  uint32

	// Metrics.
	PMTU        uint32
	RcvSsthresh uint32
	RTT         uint32
	RTTVar      uint32
	SndSsthresh uint32
	SndCwnd     uint32
	Advmss      uint32
	Reordering  uint32

	RcvRTT   uint32
	RcvSpace uint32

	TotalRetrans uint32

	PacingRate    uint64
	MaxPacingRate uint64
	// BytesAcked is RFC4898 tcpEStatsAppHCThruOctetsAcked.
	BytesAcked uint64
	// BytesReceived is RFC4898 tcpEStatsAppHCThruOctetsReceived.
	BytesReceived uint64
	// SegsOut is RFC4898 tcpEStatsPerfSegsOut.
	SegsOut uint32
	// SegsIn is RFC4898 tcpEStatsPerfSegsIn.
	SegsIn uint32

	NotSentBytes uint32
	MinRTT       uint32
	// DataSegsIn is RFC4898 tcpEStatsDataSegsIn.
	DataSegsIn uint32
	// DataSegsOut is RFC4898 tcpEStatsDataSegsOut.
	DataSegsOut uint32

	DeliveryRate uint64

	// BusyTime is the time in microseconds busy sending data.
	BusyTime uint64
	// RwndLimited is the time in microseconds limited by receive window.
	RwndLimited uint64
	// SndBufLimited is the time in microseconds limited by send buffer.
	SndBufLimited uint64
}

// SizeOfTCPInfo is the binary size of a TCPInfo struct (104 bytes).
var SizeOfTCPInfo = binary.Size(TCPInfo{})

// Control message types, from linux/socket.h.
const (
	SCM_CREDENTIALS = 0x2
	SCM_RIGHTS      = 0x1
)

// A ControlMessageHeader is the header for a socket control message.
//
// ControlMessageHeader represents struct cmsghdr from linux/socket.h.
type ControlMessageHeader struct {
	Length uint64
	Level  int32
	Type   int32
}

// SizeOfControlMessageHeader is the binary size of a ControlMessageHeader
// struct.
var SizeOfControlMessageHeader = int(binary.Size(ControlMessageHeader{}))

// A ControlMessageCredentials is an SCM_CREDENTIALS socket control message.
//
// ControlMessageCredentials represents struct ucred from linux/socket.h.
type ControlMessageCredentials struct {
	PID int32
	UID uint32
	GID uint32
}

// SizeOfControlMessageCredentials is the binary size of a
// ControlMessageCredentials struct.
var SizeOfControlMessageCredentials = int(binary.Size(ControlMessageCredentials{}))

// A ControlMessageRights is an SCM_RIGHTS socket control message.
type ControlMessageRights []int32

// SizeOfControlMessageRight is the size of a single element in
// ControlMessageRights.
const SizeOfControlMessageRight = 4

// SCM_MAX_FD is the maximum number of FDs accepted in a single sendmsg call.
// From net/scm.h.
const SCM_MAX_FD = 253
