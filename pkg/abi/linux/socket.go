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

import (
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/marshal"
)

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
	MSG_ZEROCOPY         = 0x4000000
	MSG_FASTOPEN         = 0x20000000
	MSG_CMSG_CLOEXEC     = 0x40000000
)

// Set/get socket option levels, from socket.h.
const (
	SOL_IP      = 0
	SOL_SOCKET  = 1
	SOL_TCP     = 6
	SOL_UDP     = 17
	SOL_IPV6    = 41
	SOL_ICMPV6  = 58
	SOL_RAW     = 255
	SOL_PACKET  = 263
	SOL_NETLINK = 270
)

// A SockType is a type (as opposed to family) of sockets. These are enumerated
// below as SOCK_* constants.
type SockType int

// Socket types, from linux/net.h.
const (
	SOCK_STREAM    SockType = 1
	SOCK_DGRAM     SockType = 2
	SOCK_RAW       SockType = 3
	SOCK_RDM       SockType = 4
	SOCK_SEQPACKET SockType = 5
	SOCK_DCCP      SockType = 6
	SOCK_PACKET    SockType = 10
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

// Packet types from <linux/if_packet.h>
const (
	PACKET_HOST      = 0 // To us
	PACKET_BROADCAST = 1 // To all
	PACKET_MULTICAST = 2 // To group
	PACKET_OTHERHOST = 3 // To someone else
	PACKET_OUTGOING  = 4 // Outgoing of any type
)

// Socket options from socket.h.
const (
	SO_DEBUG                 = 1
	SO_REUSEADDR             = 2
	SO_TYPE                  = 3
	SO_ERROR                 = 4
	SO_DONTROUTE             = 5
	SO_BROADCAST             = 6
	SO_SNDBUF                = 7
	SO_RCVBUF                = 8
	SO_KEEPALIVE             = 9
	SO_OOBINLINE             = 10
	SO_NO_CHECK              = 11
	SO_PRIORITY              = 12
	SO_LINGER                = 13
	SO_BSDCOMPAT             = 14
	SO_REUSEPORT             = 15
	SO_PASSCRED              = 16
	SO_PEERCRED              = 17
	SO_RCVLOWAT              = 18
	SO_SNDLOWAT              = 19
	SO_RCVTIMEO              = 20
	SO_SNDTIMEO              = 21
	SO_BINDTODEVICE          = 25
	SO_ATTACH_FILTER         = 26
	SO_DETACH_FILTER         = 27
	SO_GET_FILTER            = SO_ATTACH_FILTER
	SO_PEERNAME              = 28
	SO_TIMESTAMP             = 29
	SO_ACCEPTCONN            = 30
	SO_PEERSEC               = 31
	SO_SNDBUFFORCE           = 32
	SO_RCVBUFFORCE           = 33
	SO_PASSSEC               = 34
	SO_TIMESTAMPNS           = 35
	SO_MARK                  = 36
	SO_TIMESTAMPING          = 37
	SO_PROTOCOL              = 38
	SO_DOMAIN                = 39
	SO_RXQ_OVFL              = 40
	SO_WIFI_STATUS           = 41
	SO_PEEK_OFF              = 42
	SO_NOFCS                 = 43
	SO_LOCK_FILTER           = 44
	SO_SELECT_ERR_QUEUE      = 45
	SO_BUSY_POLL             = 46
	SO_MAX_PACING_RATE       = 47
	SO_BPF_EXTENSIONS        = 48
	SO_INCOMING_CPU          = 49
	SO_ATTACH_BPF            = 50
	SO_ATTACH_REUSEPORT_CBPF = 51
	SO_ATTACH_REUSEPORT_EBPF = 52
	SO_CNX_ADVICE            = 53
	SO_MEMINFO               = 55
	SO_INCOMING_NAPI_ID      = 56
	SO_COOKIE                = 57
	SO_PEERGROUPS            = 59
	SO_ZEROCOPY              = 60
	SO_TXTIME                = 61
)

// enum socket_state, from uapi/linux/net.h.
const (
	SS_FREE          = 0 // Not allocated.
	SS_UNCONNECTED   = 1 // Unconnected to any socket.
	SS_CONNECTING    = 2 // In process of connecting.
	SS_CONNECTED     = 3 // Connected to socket.
	SS_DISCONNECTING = 4 // In process of disconnecting.
)

// TCP protocol states, from include/net/tcp_states.h.
const (
	TCP_ESTABLISHED uint32 = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	TCP_NEW_SYN_RECV
)

// SockAddrMax is the maximum size of a struct sockaddr, from
// uapi/linux/socket.h.
const SockAddrMax = 128

// InetAddr is struct in_addr, from uapi/linux/in.h.
//
// +marshal
type InetAddr [4]byte

// SockAddrInet is struct sockaddr_in, from uapi/linux/in.h.
//
// +marshal
type SockAddrInet struct {
	Family uint16
	Port   uint16
	Addr   InetAddr
	_      [8]uint8 // pad to sizeof(struct sockaddr).
}

// Inet6MulticastRequest is struct ipv6_mreq, from uapi/linux/in6.h.
type Inet6MulticastRequest struct {
	MulticastAddr  Inet6Addr
	InterfaceIndex int32
}

// InetMulticastRequest is struct ip_mreq, from uapi/linux/in.h.
type InetMulticastRequest struct {
	MulticastAddr InetAddr
	InterfaceAddr InetAddr
}

// InetMulticastRequestWithNIC is struct ip_mreqn, from uapi/linux/in.h.
type InetMulticastRequestWithNIC struct {
	InetMulticastRequest
	InterfaceIndex int32
}

// Inet6Addr is struct in6_addr, from uapi/linux/in6.h.
//
// +marshal
type Inet6Addr [16]byte

// SockAddrInet6 is struct sockaddr_in6, from uapi/linux/in6.h.
//
// +marshal
type SockAddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	Scope_id uint32
}

// SockAddrLink is a struct sockaddr_ll, from uapi/linux/if_packet.h.
//
// +marshal
type SockAddrLink struct {
	Family          uint16
	Protocol        uint16
	InterfaceIndex  int32
	ARPHardwareType uint16
	PacketType      byte
	HardwareAddrLen byte
	HardwareAddr    [8]byte
}

// UnixPathMax is the maximum length of the path in an AF_UNIX socket.
//
// From uapi/linux/un.h.
const UnixPathMax = 108

// SockAddrUnix is struct sockaddr_un, from uapi/linux/un.h.
//
// +marshal
type SockAddrUnix struct {
	Family uint16
	Path   [UnixPathMax]int8
}

// SockAddr represents a union of valid socket address types. This is logically
// equivalent to struct sockaddr. SockAddr ensures that a well-defined set of
// types can be used as socket addresses.
type SockAddr interface {
	marshal.Marshallable

	// implementsSockAddr exists purely to allow a type to indicate that they
	// implement this interface. This method is a no-op and shouldn't be called.
	implementsSockAddr()
}

func (s *SockAddrInet) implementsSockAddr()    {}
func (s *SockAddrInet6) implementsSockAddr()   {}
func (s *SockAddrLink) implementsSockAddr()    {}
func (s *SockAddrUnix) implementsSockAddr()    {}
func (s *SockAddrNetlink) implementsSockAddr() {}

// Linger is struct linger, from include/linux/socket.h.
//
// +marshal
type Linger struct {
	OnOff  int32
	Linger int32
}

// SizeOfLinger is the binary size of a Linger struct.
const SizeOfLinger = 8

// TCPInfo is a collection of TCP statistics.
//
// From uapi/linux/tcp.h. Newer versions of Linux continue to add new fields to
// the end of this struct or within existing unusued space, so its size grows
// over time. The current iteration is based on linux v4.17. New versions are
// always backwards compatible.
//
// +marshal
type TCPInfo struct {
	// State is the state of the connection.
	State uint8

	// CaState is the congestion control state.
	CaState uint8

	// Retransmits is the number of retransmissions triggered by RTO.
	Retransmits uint8

	// Probes is the number of unanswered zero window probes.
	Probes uint8

	// BackOff indicates exponential backoff.
	Backoff uint8

	// Options indicates the options enabled for the connection.
	Options uint8

	// WindowScale is the combination of snd_wscale (first 4 bits) and
	// rcv_wscale (second 4 bits)
	WindowScale uint8

	// DeliveryRateAppLimited is a boolean and only the first bit is
	// meaningful.
	DeliveryRateAppLimited uint8

	// RTO is the retransmission timeout.
	RTO uint32

	// ATO is the acknowledgement timeout interval.
	ATO uint32

	// SndMss is the send maximum segment size.
	SndMss uint32

	// RcvMss is the receive maximum segment size.
	RcvMss uint32

	// Unacked is the number of packets sent but not acknowledged.
	Unacked uint32

	// Sacked is the number of packets which are selectively acknowledged.
	Sacked uint32

	// Lost is the number of packets marked as lost.
	Lost uint32

	// Retrans is the number of retransmitted packets.
	Retrans uint32

	// Fackets is not used and is always zero.
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

	// RcvRTT is the receiver round trip time.
	RcvRTT uint32

	// RcvSpace is the current buffer space available for receiving data.
	RcvSpace uint32

	// TotalRetrans is the total number of retransmits seen since the start
	// of the connection.
	TotalRetrans uint32

	// PacingRate is the pacing rate in bytes per second.
	PacingRate uint64

	// MaxPacingRate is the maximum pacing rate.
	MaxPacingRate uint64

	// BytesAcked is RFC4898 tcpEStatsAppHCThruOctetsAcked.
	BytesAcked uint64

	// BytesReceived is RFC4898 tcpEStatsAppHCThruOctetsReceived.
	BytesReceived uint64

	// SegsOut is RFC4898 tcpEStatsPerfSegsOut.
	SegsOut uint32

	// SegsIn is RFC4898 tcpEStatsPerfSegsIn.
	SegsIn uint32

	// NotSentBytes is the amount of bytes in the write queue that are not
	// yet sent.
	NotSentBytes uint32

	// MinRTT is the minimum round trip time seen in the connection.
	MinRTT uint32

	// DataSegsIn is RFC4898 tcpEStatsDataSegsIn.
	DataSegsIn uint32

	// DataSegsOut is RFC4898 tcpEStatsDataSegsOut.
	DataSegsOut uint32

	// DeliveryRate is the most recent delivery rate in bytes per second.
	DeliveryRate uint64

	// BusyTime is the time in microseconds busy sending data.
	BusyTime uint64

	// RwndLimited is the time in microseconds limited by receive window.
	RwndLimited uint64

	// SndBufLimited is the time in microseconds limited by send buffer.
	SndBufLimited uint64

	// Delivered is the total data packets delivered including retransmits.
	Delivered uint32

	// DeliveredCE is the total ECE marked data packets delivered including
	// retransmits.
	DeliveredCE uint32

	// BytesSent is RFC4898 tcpEStatsPerfHCDataOctetsOut.
	BytesSent uint64

	// BytesRetrans is RFC4898 tcpEStatsPerfOctetsRetrans.
	BytesRetrans uint64

	// DSACKDups is RFC4898 tcpEStatsStackDSACKDups.
	DSACKDups uint32

	// ReordSeen is the number of reordering events seen since the start of
	// the connection.
	ReordSeen uint32
}

// SizeOfTCPInfo is the binary size of a TCPInfo struct.
var SizeOfTCPInfo = int(binary.Size(TCPInfo{}))

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
//
// +marshal
type ControlMessageCredentials struct {
	PID int32
	UID uint32
	GID uint32
}

// A ControlMessageIPPacketInfo is IP_PKTINFO socket control message.
//
// ControlMessageIPPacketInfo represents struct in_pktinfo from linux/in.h.
//
// +stateify savable
type ControlMessageIPPacketInfo struct {
	NIC             int32
	LocalAddr       InetAddr
	DestinationAddr InetAddr
}

// SizeOfControlMessageCredentials is the binary size of a
// ControlMessageCredentials struct.
var SizeOfControlMessageCredentials = int(binary.Size(ControlMessageCredentials{}))

// A ControlMessageRights is an SCM_RIGHTS socket control message.
type ControlMessageRights []int32

// SizeOfControlMessageRight is the size of a single element in
// ControlMessageRights.
const SizeOfControlMessageRight = 4

// SizeOfControlMessageInq is the size of a TCP_INQ control message.
const SizeOfControlMessageInq = 4

// SizeOfControlMessageTOS is the size of an IP_TOS control message.
const SizeOfControlMessageTOS = 1

// SizeOfControlMessageTClass is the size of an IPV6_TCLASS control message.
const SizeOfControlMessageTClass = 4

// SizeOfControlMessageIPPacketInfo is the size of an IP_PKTINFO
// control message.
const SizeOfControlMessageIPPacketInfo = 12

// SCM_MAX_FD is the maximum number of FDs accepted in a single sendmsg call.
// From net/scm.h.
const SCM_MAX_FD = 253

// SO_ACCEPTCON is defined as __SO_ACCEPTCON in
// include/uapi/linux/net.h, which represents a listening socket
// state. Note that this is distinct from SO_ACCEPTCONN, which is a
// socket option for querying whether a socket is in a listening
// state.
const SO_ACCEPTCON = 1 << 16
