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

// Package netstack provides an implementation of the socket.Socket interface
// that is backed by a tcpip.Endpoint.
//
// It does not depend on any particular endpoint implementation, and thus can
// be used to expose certain endpoints to the sentry while leaving others out,
// for example, TCP endpoints and Unix-domain endpoints.
//
// Lock ordering: netstack => mm: ioSequencePayload copies user memory inside
// tcpip.Endpoint.Write(). Netstack is allowed to (and does) hold locks during
// this operation.
package netstack

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/amutex"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
	"gvisor.dev/gvisor/tools/go_marshal/primitive"
)

func mustCreateMetric(name, description string) *tcpip.StatCounter {
	var cm tcpip.StatCounter
	metric.MustRegisterCustomUint64Metric(name, true /* cumulative */, false /* sync */, description, cm.Value)
	return &cm
}

func mustCreateGauge(name, description string) *tcpip.StatCounter {
	var cm tcpip.StatCounter
	metric.MustRegisterCustomUint64Metric(name, false /* cumulative */, false /* sync */, description, cm.Value)
	return &cm
}

// Metrics contains metrics exported by netstack.
var Metrics = tcpip.Stats{
	UnknownProtocolRcvdPackets: mustCreateMetric("/netstack/unknown_protocol_received_packets", "Number of packets received by netstack that were for an unknown or unsupported protocol."),
	MalformedRcvdPackets:       mustCreateMetric("/netstack/malformed_received_packets", "Number of packets received by netstack that were deemed malformed."),
	DroppedPackets:             mustCreateMetric("/netstack/dropped_packets", "Number of packets dropped by netstack due to full queues."),
	ICMP: tcpip.ICMPStats{
		V4PacketsSent: tcpip.ICMPv4SentPacketStats{
			ICMPv4PacketStats: tcpip.ICMPv4PacketStats{
				Echo:           mustCreateMetric("/netstack/icmp/v4/packets_sent/echo", "Total number of ICMPv4 echo packets sent by netstack."),
				EchoReply:      mustCreateMetric("/netstack/icmp/v4/packets_sent/echo_reply", "Total number of ICMPv4 echo reply packets sent by netstack."),
				DstUnreachable: mustCreateMetric("/netstack/icmp/v4/packets_sent/dst_unreachable", "Total number of ICMPv4 destination unreachable packets sent by netstack."),
				SrcQuench:      mustCreateMetric("/netstack/icmp/v4/packets_sent/src_quench", "Total number of ICMPv4 source quench packets sent by netstack."),
				Redirect:       mustCreateMetric("/netstack/icmp/v4/packets_sent/redirect", "Total number of ICMPv4 redirect packets sent by netstack."),
				TimeExceeded:   mustCreateMetric("/netstack/icmp/v4/packets_sent/time_exceeded", "Total number of ICMPv4 time exceeded packets sent by netstack."),
				ParamProblem:   mustCreateMetric("/netstack/icmp/v4/packets_sent/param_problem", "Total number of ICMPv4 parameter problem packets sent by netstack."),
				Timestamp:      mustCreateMetric("/netstack/icmp/v4/packets_sent/timestamp", "Total number of ICMPv4 timestamp packets sent by netstack."),
				TimestampReply: mustCreateMetric("/netstack/icmp/v4/packets_sent/timestamp_reply", "Total number of ICMPv4 timestamp reply packets sent by netstack."),
				InfoRequest:    mustCreateMetric("/netstack/icmp/v4/packets_sent/info_request", "Total number of ICMPv4 information request packets sent by netstack."),
				InfoReply:      mustCreateMetric("/netstack/icmp/v4/packets_sent/info_reply", "Total number of ICMPv4 information reply packets sent by netstack."),
			},
			Dropped: mustCreateMetric("/netstack/icmp/v4/packets_sent/dropped", "Total number of ICMPv4 packets dropped by netstack due to link layer errors."),
		},
		V4PacketsReceived: tcpip.ICMPv4ReceivedPacketStats{
			ICMPv4PacketStats: tcpip.ICMPv4PacketStats{
				Echo:           mustCreateMetric("/netstack/icmp/v4/packets_received/echo", "Total number of ICMPv4 echo packets received by netstack."),
				EchoReply:      mustCreateMetric("/netstack/icmp/v4/packets_received/echo_reply", "Total number of ICMPv4 echo reply packets received by netstack."),
				DstUnreachable: mustCreateMetric("/netstack/icmp/v4/packets_received/dst_unreachable", "Total number of ICMPv4 destination unreachable packets received by netstack."),
				SrcQuench:      mustCreateMetric("/netstack/icmp/v4/packets_received/src_quench", "Total number of ICMPv4 source quench packets received by netstack."),
				Redirect:       mustCreateMetric("/netstack/icmp/v4/packets_received/redirect", "Total number of ICMPv4 redirect packets received by netstack."),
				TimeExceeded:   mustCreateMetric("/netstack/icmp/v4/packets_received/time_exceeded", "Total number of ICMPv4 time exceeded packets received by netstack."),
				ParamProblem:   mustCreateMetric("/netstack/icmp/v4/packets_received/param_problem", "Total number of ICMPv4 parameter problem packets received by netstack."),
				Timestamp:      mustCreateMetric("/netstack/icmp/v4/packets_received/timestamp", "Total number of ICMPv4 timestamp packets received by netstack."),
				TimestampReply: mustCreateMetric("/netstack/icmp/v4/packets_received/timestamp_reply", "Total number of ICMPv4 timestamp reply packets received by netstack."),
				InfoRequest:    mustCreateMetric("/netstack/icmp/v4/packets_received/info_request", "Total number of ICMPv4 information request packets received by netstack."),
				InfoReply:      mustCreateMetric("/netstack/icmp/v4/packets_received/info_reply", "Total number of ICMPv4 information reply packets received by netstack."),
			},
			Invalid: mustCreateMetric("/netstack/icmp/v4/packets_received/invalid", "Total number of ICMPv4 packets received that the transport layer could not parse."),
		},
		V6PacketsSent: tcpip.ICMPv6SentPacketStats{
			ICMPv6PacketStats: tcpip.ICMPv6PacketStats{
				EchoRequest:     mustCreateMetric("/netstack/icmp/v6/packets_sent/echo_request", "Total number of ICMPv6 echo request packets sent by netstack."),
				EchoReply:       mustCreateMetric("/netstack/icmp/v6/packets_sent/echo_reply", "Total number of ICMPv6 echo reply packets sent by netstack."),
				DstUnreachable:  mustCreateMetric("/netstack/icmp/v6/packets_sent/dst_unreachable", "Total number of ICMPv6 destination unreachable packets sent by netstack."),
				PacketTooBig:    mustCreateMetric("/netstack/icmp/v6/packets_sent/packet_too_big", "Total number of ICMPv6 packet too big packets sent by netstack."),
				TimeExceeded:    mustCreateMetric("/netstack/icmp/v6/packets_sent/time_exceeded", "Total number of ICMPv6 time exceeded packets sent by netstack."),
				ParamProblem:    mustCreateMetric("/netstack/icmp/v6/packets_sent/param_problem", "Total number of ICMPv6 parameter problem packets sent by netstack."),
				RouterSolicit:   mustCreateMetric("/netstack/icmp/v6/packets_sent/router_solicit", "Total number of ICMPv6 router solicit packets sent by netstack."),
				RouterAdvert:    mustCreateMetric("/netstack/icmp/v6/packets_sent/router_advert", "Total number of ICMPv6 router advert packets sent by netstack."),
				NeighborSolicit: mustCreateMetric("/netstack/icmp/v6/packets_sent/neighbor_solicit", "Total number of ICMPv6 neighbor solicit packets sent by netstack."),
				NeighborAdvert:  mustCreateMetric("/netstack/icmp/v6/packets_sent/neighbor_advert", "Total number of ICMPv6 neighbor advert packets sent by netstack."),
				RedirectMsg:     mustCreateMetric("/netstack/icmp/v6/packets_sent/redirect_msg", "Total number of ICMPv6 redirect message packets sent by netstack."),
			},
			Dropped: mustCreateMetric("/netstack/icmp/v6/packets_sent/dropped", "Total number of ICMPv6 packets dropped by netstack due to link layer errors."),
		},
		V6PacketsReceived: tcpip.ICMPv6ReceivedPacketStats{
			ICMPv6PacketStats: tcpip.ICMPv6PacketStats{
				EchoRequest:     mustCreateMetric("/netstack/icmp/v6/packets_received/echo_request", "Total number of ICMPv6 echo request packets received by netstack."),
				EchoReply:       mustCreateMetric("/netstack/icmp/v6/packets_received/echo_reply", "Total number of ICMPv6 echo reply packets received by netstack."),
				DstUnreachable:  mustCreateMetric("/netstack/icmp/v6/packets_received/dst_unreachable", "Total number of ICMPv6 destination unreachable packets received by netstack."),
				PacketTooBig:    mustCreateMetric("/netstack/icmp/v6/packets_received/packet_too_big", "Total number of ICMPv6 packet too big packets received by netstack."),
				TimeExceeded:    mustCreateMetric("/netstack/icmp/v6/packets_received/time_exceeded", "Total number of ICMPv6 time exceeded packets received by netstack."),
				ParamProblem:    mustCreateMetric("/netstack/icmp/v6/packets_received/param_problem", "Total number of ICMPv6 parameter problem packets received by netstack."),
				RouterSolicit:   mustCreateMetric("/netstack/icmp/v6/packets_received/router_solicit", "Total number of ICMPv6 router solicit packets received by netstack."),
				RouterAdvert:    mustCreateMetric("/netstack/icmp/v6/packets_received/router_advert", "Total number of ICMPv6 router advert packets received by netstack."),
				NeighborSolicit: mustCreateMetric("/netstack/icmp/v6/packets_received/neighbor_solicit", "Total number of ICMPv6 neighbor solicit packets received by netstack."),
				NeighborAdvert:  mustCreateMetric("/netstack/icmp/v6/packets_received/neighbor_advert", "Total number of ICMPv6 neighbor advert packets received by netstack."),
				RedirectMsg:     mustCreateMetric("/netstack/icmp/v6/packets_received/redirect_msg", "Total number of ICMPv6 redirect message packets received by netstack."),
			},
			Invalid: mustCreateMetric("/netstack/icmp/v6/packets_received/invalid", "Total number of ICMPv6 packets received that the transport layer could not parse."),
		},
	},
	IP: tcpip.IPStats{
		PacketsReceived:                     mustCreateMetric("/netstack/ip/packets_received", "Total number of IP packets received from the link layer in nic.DeliverNetworkPacket."),
		InvalidDestinationAddressesReceived: mustCreateMetric("/netstack/ip/invalid_addresses_received", "Total number of IP packets received with an unknown or invalid destination address."),
		InvalidSourceAddressesReceived:      mustCreateMetric("/netstack/ip/invalid_source_addresses_received", "Total number of IP packets received with an unknown or invalid source address."),
		PacketsDelivered:                    mustCreateMetric("/netstack/ip/packets_delivered", "Total number of incoming IP packets that are successfully delivered to the transport layer via HandlePacket."),
		PacketsSent:                         mustCreateMetric("/netstack/ip/packets_sent", "Total number of IP packets sent via WritePacket."),
		OutgoingPacketErrors:                mustCreateMetric("/netstack/ip/outgoing_packet_errors", "Total number of IP packets which failed to write to a link-layer endpoint."),
		MalformedPacketsReceived:            mustCreateMetric("/netstack/ip/malformed_packets_received", "Total number of IP packets which failed IP header validation checks."),
		MalformedFragmentsReceived:          mustCreateMetric("/netstack/ip/malformed_fragments_received", "Total number of IP fragments which failed IP fragment validation checks."),
	},
	TCP: tcpip.TCPStats{
		ActiveConnectionOpenings:           mustCreateMetric("/netstack/tcp/active_connection_openings", "Number of connections opened successfully via Connect."),
		PassiveConnectionOpenings:          mustCreateMetric("/netstack/tcp/passive_connection_openings", "Number of connections opened successfully via Listen."),
		CurrentEstablished:                 mustCreateGauge("/netstack/tcp/current_established", "Number of connections in ESTABLISHED state now."),
		CurrentConnected:                   mustCreateGauge("/netstack/tcp/current_open", "Number of connections that are in connected state."),
		EstablishedResets:                  mustCreateMetric("/netstack/tcp/established_resets", "Number of times TCP connections have made a direct transition to the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT state"),
		EstablishedClosed:                  mustCreateMetric("/netstack/tcp/established_closed", "Number of times established TCP connections made a transition to CLOSED state."),
		EstablishedTimedout:                mustCreateMetric("/netstack/tcp/established_timedout", "Number of times  an established connection was reset because of keep-alive time out."),
		ListenOverflowSynDrop:              mustCreateMetric("/netstack/tcp/listen_overflow_syn_drop", "Number of times the listen queue overflowed and a SYN was dropped."),
		ListenOverflowAckDrop:              mustCreateMetric("/netstack/tcp/listen_overflow_ack_drop", "Number of times the listen queue overflowed and the final ACK in the handshake was dropped."),
		ListenOverflowSynCookieSent:        mustCreateMetric("/netstack/tcp/listen_overflow_syn_cookie_sent", "Number of times a SYN cookie was sent."),
		ListenOverflowSynCookieRcvd:        mustCreateMetric("/netstack/tcp/listen_overflow_syn_cookie_rcvd", "Number of times a SYN cookie was received."),
		ListenOverflowInvalidSynCookieRcvd: mustCreateMetric("/netstack/tcp/listen_overflow_invalid_syn_cookie_rcvd", "Number of times an invalid SYN cookie was received."),
		FailedConnectionAttempts:           mustCreateMetric("/netstack/tcp/failed_connection_attempts", "Number of calls to Connect or Listen (active and passive openings, respectively) that end in an error."),
		ValidSegmentsReceived:              mustCreateMetric("/netstack/tcp/valid_segments_received", "Number of TCP segments received that the transport layer successfully parsed."),
		InvalidSegmentsReceived:            mustCreateMetric("/netstack/tcp/invalid_segments_received", "Number of TCP segments received that the transport layer could not parse."),
		SegmentsSent:                       mustCreateMetric("/netstack/tcp/segments_sent", "Number of TCP segments sent."),
		SegmentSendErrors:                  mustCreateMetric("/netstack/tcp/segment_send_errors", "Number of TCP segments failed to be sent."),
		ResetsSent:                         mustCreateMetric("/netstack/tcp/resets_sent", "Number of TCP resets sent."),
		ResetsReceived:                     mustCreateMetric("/netstack/tcp/resets_received", "Number of TCP resets received."),
		Retransmits:                        mustCreateMetric("/netstack/tcp/retransmits", "Number of TCP segments retransmitted."),
		FastRecovery:                       mustCreateMetric("/netstack/tcp/fast_recovery", "Number of times fast recovery was used to recover from packet loss."),
		SACKRecovery:                       mustCreateMetric("/netstack/tcp/sack_recovery", "Number of times SACK recovery was used to recover from packet loss."),
		SlowStartRetransmits:               mustCreateMetric("/netstack/tcp/slow_start_retransmits", "Number of segments retransmitted in slow start mode."),
		FastRetransmit:                     mustCreateMetric("/netstack/tcp/fast_retransmit", "Number of TCP segments which were fast retransmitted."),
		Timeouts:                           mustCreateMetric("/netstack/tcp/timeouts", "Number of times RTO expired."),
		ChecksumErrors:                     mustCreateMetric("/netstack/tcp/checksum_errors", "Number of segments dropped due to bad checksums."),
	},
	UDP: tcpip.UDPStats{
		PacketsReceived:          mustCreateMetric("/netstack/udp/packets_received", "Number of UDP datagrams received via HandlePacket."),
		UnknownPortErrors:        mustCreateMetric("/netstack/udp/unknown_port_errors", "Number of incoming UDP datagrams dropped because they did not have a known destination port."),
		ReceiveBufferErrors:      mustCreateMetric("/netstack/udp/receive_buffer_errors", "Number of incoming UDP datagrams dropped due to the receiving buffer being in an invalid state."),
		MalformedPacketsReceived: mustCreateMetric("/netstack/udp/malformed_packets_received", "Number of incoming UDP datagrams dropped due to the UDP header being in a malformed state."),
		PacketsSent:              mustCreateMetric("/netstack/udp/packets_sent", "Number of UDP datagrams sent."),
		PacketSendErrors:         mustCreateMetric("/netstack/udp/packet_send_errors", "Number of UDP datagrams failed to be sent."),
		ChecksumErrors:           mustCreateMetric("/netstack/udp/checksum_errors", "Number of UDP datagrams dropped due to bad checksums."),
		InvalidSourceAddress:     mustCreateMetric("/netstack/udp/invalid_source", "Number of UDP datagrams dropped due to invalid source address."),
	},
}

// DefaultTTL is linux's default TTL. All network protocols in all stacks used
// with this package must have this value set as their default TTL.
const DefaultTTL = 64

const sizeOfInt32 int = 4

var errStackType = syserr.New("expected but did not receive a netstack.Stack", linux.EINVAL)

// ntohs converts a 16-bit number from network byte order to host byte order. It
// assumes that the host is little endian.
func ntohs(v uint16) uint16 {
	return v<<8 | v>>8
}

// htons converts a 16-bit number from host byte order to network byte order. It
// assumes that the host is little endian.
func htons(v uint16) uint16 {
	return ntohs(v)
}

// commonEndpoint represents the intersection of a tcpip.Endpoint and a
// transport.Endpoint.
type commonEndpoint interface {
	// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress and
	// transport.Endpoint.GetLocalAddress.
	GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

	// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress and
	// transport.Endpoint.GetRemoteAddress.
	GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error)

	// Readiness implements tcpip.Endpoint.Readiness and
	// transport.Endpoint.Readiness.
	Readiness(mask waiter.EventMask) waiter.EventMask

	// SetSockOpt implements tcpip.Endpoint.SetSockOpt and
	// transport.Endpoint.SetSockOpt.
	SetSockOpt(interface{}) *tcpip.Error

	// SetSockOptBool implements tcpip.Endpoint.SetSockOptBool and
	// transport.Endpoint.SetSockOptBool.
	SetSockOptBool(opt tcpip.SockOptBool, v bool) *tcpip.Error

	// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt and
	// transport.Endpoint.SetSockOptInt.
	SetSockOptInt(opt tcpip.SockOptInt, v int) *tcpip.Error

	// GetSockOpt implements tcpip.Endpoint.GetSockOpt and
	// transport.Endpoint.GetSockOpt.
	GetSockOpt(interface{}) *tcpip.Error

	// GetSockOptBool implements tcpip.Endpoint.GetSockOptBool and
	// transport.Endpoint.GetSockOpt.
	GetSockOptBool(opt tcpip.SockOptBool) (bool, *tcpip.Error)

	// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt and
	// transport.Endpoint.GetSockOpt.
	GetSockOptInt(opt tcpip.SockOptInt) (int, *tcpip.Error)
}

// LINT.IfChange

// SocketOperations encapsulates all the state needed to represent a network stack
// endpoint in the kernel context.
//
// +stateify savable
type SocketOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	socketOpsCommon
}

// socketOpsCommon contains the socket operations common to VFS1 and VFS2.
//
// +stateify savable
type socketOpsCommon struct {
	socket.SendReceiveTimeout
	*waiter.Queue

	family   int
	Endpoint tcpip.Endpoint
	skType   linux.SockType
	protocol int

	// readViewHasData is 1 iff readView has data to be read, 0 otherwise.
	// Must be accessed using atomic operations. It must only be written
	// with readMu held but can be read without holding readMu. The latter
	// is required to avoid deadlocks in epoll Readiness checks.
	readViewHasData uint32

	// readMu protects access to the below fields.
	readMu sync.Mutex `state:"nosave"`
	// readView contains the remaining payload from the last packet.
	readView buffer.View
	// readCM holds control message information for the last packet read
	// from Endpoint.
	readCM         tcpip.ControlMessages
	sender         tcpip.FullAddress
	linkPacketInfo tcpip.LinkPacketInfo

	// sockOptTimestamp corresponds to SO_TIMESTAMP. When true, timestamps
	// of returned messages can be returned via control messages. When
	// false, the same timestamp is instead stored and can be read via the
	// SIOCGSTAMP ioctl. It is protected by readMu. See socket(7).
	sockOptTimestamp bool
	// timestampValid indicates whether timestamp for SIOCGSTAMP has been
	// set. It is protected by readMu.
	timestampValid bool
	// timestampNS holds the timestamp to use with SIOCTSTAMP. It is only
	// valid when timestampValid is true. It is protected by readMu.
	timestampNS int64

	// sockOptInq corresponds to TCP_INQ. It is implemented at this level
	// because it takes into account data from readView.
	sockOptInq bool
}

// New creates a new endpoint socket.
func New(t *kernel.Task, family int, skType linux.SockType, protocol int, queue *waiter.Queue, endpoint tcpip.Endpoint) (*fs.File, *syserr.Error) {
	if skType == linux.SOCK_STREAM {
		if err := endpoint.SetSockOptBool(tcpip.DelayOption, true); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
	}

	dirent := socket.NewDirent(t, netstackDevice)
	defer dirent.DecRef(t)
	return fs.NewFile(t, dirent, fs.FileFlags{Read: true, Write: true, NonSeekable: true}, &SocketOperations{
		socketOpsCommon: socketOpsCommon{
			Queue:    queue,
			family:   family,
			Endpoint: endpoint,
			skType:   skType,
			protocol: protocol,
		},
	}), nil
}

var sockAddrInetSize = int(binary.Size(linux.SockAddrInet{}))
var sockAddrInet6Size = int(binary.Size(linux.SockAddrInet6{}))
var sockAddrLinkSize = int(binary.Size(linux.SockAddrLink{}))

// bytesToIPAddress converts an IPv4 or IPv6 address from the user to the
// netstack representation taking any addresses into account.
func bytesToIPAddress(addr []byte) tcpip.Address {
	if bytes.Equal(addr, make([]byte, 4)) || bytes.Equal(addr, make([]byte, 16)) {
		return ""
	}
	return tcpip.Address(addr)
}

// AddressAndFamily reads an sockaddr struct from the given address and
// converts it to the FullAddress format. It supports AF_UNIX, AF_INET,
// AF_INET6, and AF_PACKET addresses.
//
// AddressAndFamily returns an address and its family.
func AddressAndFamily(addr []byte) (tcpip.FullAddress, uint16, *syserr.Error) {
	// Make sure we have at least 2 bytes for the address family.
	if len(addr) < 2 {
		return tcpip.FullAddress{}, 0, syserr.ErrInvalidArgument
	}

	// Get the rest of the fields based on the address family.
	switch family := usermem.ByteOrder.Uint16(addr); family {
	case linux.AF_UNIX:
		path := addr[2:]
		if len(path) > linux.UnixPathMax {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		// Drop the terminating NUL (if one exists) and everything after
		// it for filesystem (non-abstract) addresses.
		if len(path) > 0 && path[0] != 0 {
			if n := bytes.IndexByte(path[1:], 0); n >= 0 {
				path = path[:n+1]
			}
		}
		return tcpip.FullAddress{
			Addr: tcpip.Address(path),
		}, family, nil

	case linux.AF_INET:
		var a linux.SockAddrInet
		if len(addr) < sockAddrInetSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		binary.Unmarshal(addr[:sockAddrInetSize], usermem.ByteOrder, &a)

		out := tcpip.FullAddress{
			Addr: bytesToIPAddress(a.Addr[:]),
			Port: ntohs(a.Port),
		}
		return out, family, nil

	case linux.AF_INET6:
		var a linux.SockAddrInet6
		if len(addr) < sockAddrInet6Size {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		binary.Unmarshal(addr[:sockAddrInet6Size], usermem.ByteOrder, &a)

		out := tcpip.FullAddress{
			Addr: bytesToIPAddress(a.Addr[:]),
			Port: ntohs(a.Port),
		}
		if isLinkLocal(out.Addr) {
			out.NIC = tcpip.NICID(a.Scope_id)
		}
		return out, family, nil

	case linux.AF_PACKET:
		var a linux.SockAddrLink
		if len(addr) < sockAddrLinkSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		binary.Unmarshal(addr[:sockAddrLinkSize], usermem.ByteOrder, &a)
		if a.Family != linux.AF_PACKET || a.HardwareAddrLen != header.EthernetAddressSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/173): Return protocol too.
		return tcpip.FullAddress{
			NIC:  tcpip.NICID(a.InterfaceIndex),
			Addr: tcpip.Address(a.HardwareAddr[:header.EthernetAddressSize]),
		}, family, nil

	case linux.AF_UNSPEC:
		return tcpip.FullAddress{}, family, nil

	default:
		return tcpip.FullAddress{}, 0, syserr.ErrAddressFamilyNotSupported
	}
}

func (s *socketOpsCommon) isPacketBased() bool {
	return s.skType == linux.SOCK_DGRAM || s.skType == linux.SOCK_SEQPACKET || s.skType == linux.SOCK_RDM || s.skType == linux.SOCK_RAW
}

// fetchReadView updates the readView field of the socket if it's currently
// empty. It assumes that the socket is locked.
//
// Precondition: s.readMu must be held.
func (s *socketOpsCommon) fetchReadView() *syserr.Error {
	if len(s.readView) > 0 {
		return nil
	}
	s.readView = nil
	s.sender = tcpip.FullAddress{}
	s.linkPacketInfo = tcpip.LinkPacketInfo{}

	var v buffer.View
	var cms tcpip.ControlMessages
	var err *tcpip.Error

	switch e := s.Endpoint.(type) {
	// The ordering of these interfaces matters. The most specific
	// interfaces must be specified before the more generic Endpoint
	// interface.
	case tcpip.PacketEndpoint:
		v, cms, err = e.ReadPacket(&s.sender, &s.linkPacketInfo)
	case tcpip.Endpoint:
		v, cms, err = e.Read(&s.sender)
	}
	if err != nil {
		atomic.StoreUint32(&s.readViewHasData, 0)
		return syserr.TranslateNetstackError(err)
	}

	s.readView = v
	s.readCM = cms
	atomic.StoreUint32(&s.readViewHasData, 1)

	return nil
}

// Release implements fs.FileOperations.Release.
func (s *socketOpsCommon) Release(context.Context) {
	s.Endpoint.Close()
}

// Read implements fs.FileOperations.Read.
func (s *SocketOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	n, _, _, _, _, err := s.nonBlockingRead(ctx, dst, false, false, false)
	if err == syserr.ErrWouldBlock {
		return int64(n), syserror.ErrWouldBlock
	}
	if err != nil {
		return 0, err.ToError()
	}
	return int64(n), nil
}

// WriteTo implements fs.FileOperations.WriteTo.
func (s *SocketOperations) WriteTo(ctx context.Context, _ *fs.File, dst io.Writer, count int64, dup bool) (int64, error) {
	s.readMu.Lock()

	// Copy as much data as possible.
	done := int64(0)
	for count > 0 {
		// This may return a blocking error.
		if err := s.fetchReadView(); err != nil {
			s.readMu.Unlock()
			return done, err.ToError()
		}

		// Write to the underlying file.
		n, err := dst.Write(s.readView)
		done += int64(n)
		count -= int64(n)
		if dup {
			// That's all we support for dup. This is generally
			// supported by any Linux system calls, but the
			// expectation is that now a caller will call read to
			// actually remove these bytes from the socket.
			break
		}

		// Drop that part of the view.
		s.readView.TrimFront(n)
		if err != nil {
			s.readMu.Unlock()
			return done, err
		}
	}

	s.readMu.Unlock()
	return done, nil
}

// ioSequencePayload implements tcpip.Payload.
//
// t copies user memory bytes on demand based on the requested size.
type ioSequencePayload struct {
	ctx context.Context
	src usermem.IOSequence
}

// FullPayload implements tcpip.Payloader.FullPayload
func (i *ioSequencePayload) FullPayload() ([]byte, *tcpip.Error) {
	return i.Payload(int(i.src.NumBytes()))
}

// Payload implements tcpip.Payloader.Payload.
func (i *ioSequencePayload) Payload(size int) ([]byte, *tcpip.Error) {
	if max := int(i.src.NumBytes()); size > max {
		size = max
	}
	v := buffer.NewView(size)
	if _, err := i.src.CopyIn(i.ctx, v); err != nil {
		return nil, tcpip.ErrBadAddress
	}
	return v, nil
}

// DropFirst drops the first n bytes from underlying src.
func (i *ioSequencePayload) DropFirst(n int) {
	i.src = i.src.DropFirst(int(n))
}

// Write implements fs.FileOperations.Write.
func (s *SocketOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	f := &ioSequencePayload{ctx: ctx, src: src}
	n, resCh, err := s.Endpoint.Write(f, tcpip.WriteOptions{})
	if err == tcpip.ErrWouldBlock {
		return 0, syserror.ErrWouldBlock
	}

	if resCh != nil {
		if err := amutex.Block(ctx, resCh); err != nil {
			return 0, err
		}
		n, _, err = s.Endpoint.Write(f, tcpip.WriteOptions{})
	}

	if err != nil {
		return 0, syserr.TranslateNetstackError(err).ToError()
	}

	if int64(n) < src.NumBytes() {
		return int64(n), syserror.ErrWouldBlock
	}

	return int64(n), nil
}

// readerPayload implements tcpip.Payloader.
//
// It allocates a view and reads from a reader on-demand, based on available
// capacity in the endpoint.
type readerPayload struct {
	ctx   context.Context
	r     io.Reader
	count int64
	err   error
}

// FullPayload implements tcpip.Payloader.FullPayload.
func (r *readerPayload) FullPayload() ([]byte, *tcpip.Error) {
	return r.Payload(int(r.count))
}

// Payload implements tcpip.Payloader.Payload.
func (r *readerPayload) Payload(size int) ([]byte, *tcpip.Error) {
	if size > int(r.count) {
		size = int(r.count)
	}
	v := buffer.NewView(size)
	n, err := r.r.Read(v)
	if n > 0 {
		// We ignore the error here. It may re-occur on subsequent
		// reads, but for now we can enqueue some amount of data.
		r.count -= int64(n)
		return v[:n], nil
	}
	if err == syserror.ErrWouldBlock {
		return nil, tcpip.ErrWouldBlock
	} else if err != nil {
		r.err = err // Save for propation.
		return nil, tcpip.ErrBadAddress
	}

	// There is no data and no error. Return an error, which will propagate
	// r.err, which will be nil. This is the desired result: (0, nil).
	return nil, tcpip.ErrBadAddress
}

// ReadFrom implements fs.FileOperations.ReadFrom.
func (s *SocketOperations) ReadFrom(ctx context.Context, _ *fs.File, r io.Reader, count int64) (int64, error) {
	f := &readerPayload{ctx: ctx, r: r, count: count}
	n, resCh, err := s.Endpoint.Write(f, tcpip.WriteOptions{
		// Reads may be destructive but should be very fast,
		// so we can't release the lock while copying data.
		Atomic: true,
	})
	if err == tcpip.ErrWouldBlock {
		return 0, syserror.ErrWouldBlock
	}

	if resCh != nil {
		if err := amutex.Block(ctx, resCh); err != nil {
			return 0, err
		}
		n, _, err = s.Endpoint.Write(f, tcpip.WriteOptions{
			Atomic: true, // See above.
		})
	}
	if err == tcpip.ErrWouldBlock {
		return n, syserror.ErrWouldBlock
	} else if err != nil {
		return int64(n), f.err // Propagate error.
	}

	return int64(n), nil
}

// Readiness returns a mask of ready events for socket s.
func (s *socketOpsCommon) Readiness(mask waiter.EventMask) waiter.EventMask {
	r := s.Endpoint.Readiness(mask)

	// Check our cached value iff the caller asked for readability and the
	// endpoint itself is currently not readable.
	if (mask & ^r & waiter.EventIn) != 0 {
		if atomic.LoadUint32(&s.readViewHasData) == 1 {
			r |= waiter.EventIn
		}
	}

	return r
}

func (s *socketOpsCommon) checkFamily(family uint16, exact bool) *syserr.Error {
	if family == uint16(s.family) {
		return nil
	}
	if !exact && family == linux.AF_INET && s.family == linux.AF_INET6 {
		v, err := s.Endpoint.GetSockOptBool(tcpip.V6OnlyOption)
		if err != nil {
			return syserr.TranslateNetstackError(err)
		}
		if !v {
			return nil
		}
	}
	return syserr.ErrInvalidArgument
}

// mapFamily maps the AF_INET ANY address to the IPv4-mapped IPv6 ANY if the
// receiver's family is AF_INET6.
//
// This is a hack to work around the fact that both IPv4 and IPv6 ANY are
// represented by the empty string.
//
// TODO(gvisor.dev/issue/1556): remove this function.
func (s *socketOpsCommon) mapFamily(addr tcpip.FullAddress, family uint16) tcpip.FullAddress {
	if len(addr.Addr) == 0 && s.family == linux.AF_INET6 && family == linux.AF_INET {
		addr.Addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"
	}
	return addr
}

// Connect implements the linux syscall connect(2) for sockets backed by
// tpcip.Endpoint.
func (s *socketOpsCommon) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	addr, family, err := AddressAndFamily(sockaddr)
	if err != nil {
		return err
	}

	if family == linux.AF_UNSPEC {
		err := s.Endpoint.Disconnect()
		if err == tcpip.ErrNotSupported {
			return syserr.ErrAddressFamilyNotSupported
		}
		return syserr.TranslateNetstackError(err)
	}

	if err := s.checkFamily(family, false /* exact */); err != nil {
		return err
	}
	addr = s.mapFamily(addr, family)

	// Always return right away in the non-blocking case.
	if !blocking {
		return syserr.TranslateNetstackError(s.Endpoint.Connect(addr))
	}

	// Register for notification when the endpoint becomes writable, then
	// initiate the connection.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	if err := s.Endpoint.Connect(addr); err != tcpip.ErrConnectStarted && err != tcpip.ErrAlreadyConnecting {
		if (s.family == unix.AF_INET || s.family == unix.AF_INET6) && s.skType == linux.SOCK_STREAM {
			// TCP unlike UDP returns EADDRNOTAVAIL when it can't
			// find an available local ephemeral port.
			if err == tcpip.ErrNoPortAvailable {
				return syserr.ErrAddressNotAvailable
			}
		}

		return syserr.TranslateNetstackError(err)
	}

	// It's pending, so we have to wait for a notification, and fetch the
	// result once the wait completes.
	if err := t.Block(ch); err != nil {
		return syserr.FromError(err)
	}

	// Call Connect() again after blocking to find connect's result.
	return syserr.TranslateNetstackError(s.Endpoint.Connect(addr))
}

// Bind implements the linux syscall bind(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	if len(sockaddr) < 2 {
		return syserr.ErrInvalidArgument
	}

	family := usermem.ByteOrder.Uint16(sockaddr)
	var addr tcpip.FullAddress

	// Bind for AF_PACKET requires only family, protocol and ifindex.
	// In function AddressAndFamily, we check the address length which is
	// not needed for AF_PACKET bind.
	if family == linux.AF_PACKET {
		var a linux.SockAddrLink
		if len(sockaddr) < sockAddrLinkSize {
			return syserr.ErrInvalidArgument
		}
		binary.Unmarshal(sockaddr[:sockAddrLinkSize], usermem.ByteOrder, &a)

		if a.Protocol != uint16(s.protocol) {
			return syserr.ErrInvalidArgument
		}

		addr = tcpip.FullAddress{
			NIC:  tcpip.NICID(a.InterfaceIndex),
			Addr: tcpip.Address(a.HardwareAddr[:header.EthernetAddressSize]),
		}
	} else {
		var err *syserr.Error
		addr, family, err = AddressAndFamily(sockaddr)
		if err != nil {
			return err
		}

		if err = s.checkFamily(family, true /* exact */); err != nil {
			return err
		}

		addr = s.mapFamily(addr, family)
	}

	// Issue the bind request to the endpoint.
	err := s.Endpoint.Bind(addr)
	if err == tcpip.ErrNoPortAvailable {
		// Bind always returns EADDRINUSE irrespective of if the specified port was
		// already bound or if an ephemeral port was requested but none were
		// available.
		//
		// tcpip.ErrNoPortAvailable is mapped to EAGAIN in syserr package because
		// UDP connect returns EAGAIN on ephemeral port exhaustion.
		//
		// TCP connect returns EADDRNOTAVAIL on ephemeral port exhaustion.
		err = tcpip.ErrPortInUse
	}

	return syserr.TranslateNetstackError(err)
}

// Listen implements the linux syscall listen(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return syserr.TranslateNetstackError(s.Endpoint.Listen(backlog))
}

// blockingAccept implements a blocking version of accept(2), that is, if no
// connections are ready to be accept, it will block until one becomes ready.
func (s *socketOpsCommon) blockingAccept(t *kernel.Task) (tcpip.Endpoint, *waiter.Queue, *syserr.Error) {
	// Register for notifications.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	// Try to accept the connection again; if it fails, then wait until we
	// get a notification.
	for {
		if ep, wq, err := s.Endpoint.Accept(); err != tcpip.ErrWouldBlock {
			return ep, wq, syserr.TranslateNetstackError(err)
		}

		if err := t.Block(ch); err != nil {
			return nil, nil, syserr.FromError(err)
		}
	}
}

// Accept implements the linux syscall accept(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	// Issue the accept request to get the new endpoint.
	ep, wq, terr := s.Endpoint.Accept()
	if terr != nil {
		if terr != tcpip.ErrWouldBlock || !blocking {
			return 0, nil, 0, syserr.TranslateNetstackError(terr)
		}

		var err *syserr.Error
		ep, wq, err = s.blockingAccept(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	ns, err := New(t, s.family, s.skType, s.protocol, wq, ep)
	if err != nil {
		return 0, nil, 0, err
	}
	defer ns.DecRef(t)

	if flags&linux.SOCK_NONBLOCK != 0 {
		flags := ns.Flags()
		flags.NonBlocking = true
		ns.SetFlags(flags.Settable())
	}

	var addr linux.SockAddr
	var addrLen uint32
	if peerRequested {
		// Get address of the peer and write it to peer slice.
		var err *syserr.Error
		addr, addrLen, err = ns.FileOperations.(*SocketOperations).GetPeerName(t)
		if err != nil {
			return 0, nil, 0, err
		}
	}

	fd, e := t.NewFDFrom(0, ns, kernel.FDFlags{
		CloseOnExec: flags&linux.SOCK_CLOEXEC != 0,
	})

	t.Kernel().RecordSocket(ns)

	return fd, addr, addrLen, syserr.FromError(e)
}

// ConvertShutdown converts Linux shutdown flags into tcpip shutdown flags.
func ConvertShutdown(how int) (tcpip.ShutdownFlags, *syserr.Error) {
	var f tcpip.ShutdownFlags
	switch how {
	case linux.SHUT_RD:
		f = tcpip.ShutdownRead
	case linux.SHUT_WR:
		f = tcpip.ShutdownWrite
	case linux.SHUT_RDWR:
		f = tcpip.ShutdownRead | tcpip.ShutdownWrite
	default:
		return 0, syserr.ErrInvalidArgument
	}
	return f, nil
}

// Shutdown implements the linux syscall shutdown(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) Shutdown(t *kernel.Task, how int) *syserr.Error {
	f, err := ConvertShutdown(how)
	if err != nil {
		return err
	}

	// Issue shutdown request.
	return syserr.TranslateNetstackError(s.Endpoint.Shutdown(f))
}

// GetSockOpt implements the linux syscall getsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) GetSockOpt(t *kernel.Task, level, name int, outPtr usermem.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	// TODO(b/78348848): Unlike other socket options, SO_TIMESTAMP is
	// implemented specifically for netstack.SocketOperations rather than
	// commonEndpoint. commonEndpoint should be extended to support socket
	// options where the implementation is not shared, as unix sockets need
	// their own support for SO_TIMESTAMP.
	if level == linux.SOL_SOCKET && name == linux.SO_TIMESTAMP {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := primitive.Int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptTimestamp {
			val = 1
		}
		return &val, nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}
		val := primitive.Int32(0)
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.sockOptInq {
			val = 1
		}
		return &val, nil
	}

	if s.skType == linux.SOCK_RAW && level == linux.IPPROTO_IP {
		switch name {
		case linux.IPT_SO_GET_INFO:
			if outLen < linux.SizeOfIPTGetinfo {
				return nil, syserr.ErrInvalidArgument
			}
			if s.family != linux.AF_INET {
				return nil, syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return nil, syserr.ErrNoDevice
			}
			info, err := netfilter.GetInfo(t, stack.(*Stack).Stack, outPtr)
			if err != nil {
				return nil, err
			}
			return &info, nil

		case linux.IPT_SO_GET_ENTRIES:
			if outLen < linux.SizeOfIPTGetEntries {
				return nil, syserr.ErrInvalidArgument
			}
			if s.family != linux.AF_INET {
				return nil, syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return nil, syserr.ErrNoDevice
			}
			entries, err := netfilter.GetEntries4(t, stack.(*Stack).Stack, outPtr, outLen)
			if err != nil {
				return nil, err
			}
			return &entries, nil

		}
	}

	return GetSockOpt(t, s, s.Endpoint, s.family, s.skType, level, name, outLen)
}

// GetSockOpt can be used to implement the linux syscall getsockopt(2) for
// sockets backed by a commonEndpoint.
func GetSockOpt(t *kernel.Task, s socket.SocketOps, ep commonEndpoint, family int, skType linux.SockType, level, name, outLen int) (marshal.Marshallable, *syserr.Error) {
	switch level {
	case linux.SOL_SOCKET:
		return getSockOptSocket(t, s, ep, family, skType, name, outLen)

	case linux.SOL_TCP:
		return getSockOptTCP(t, ep, name, outLen)

	case linux.SOL_IPV6:
		return getSockOptIPv6(t, ep, name, outLen)

	case linux.SOL_IP:
		return getSockOptIP(t, ep, name, outLen, family)

	case linux.SOL_UDP,
		linux.SOL_ICMPV6,
		linux.SOL_RAW,
		linux.SOL_PACKET:

		t.Kernel().EmitUnimplementedEvent(t)
	}

	return nil, syserr.ErrProtocolNotAvailable
}

func boolToInt32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

// getSockOptSocket implements GetSockOpt when level is SOL_SOCKET.
func getSockOptSocket(t *kernel.Task, s socket.SocketOps, ep commonEndpoint, family int, skType linux.SockType, name, outLen int) (marshal.Marshallable, *syserr.Error) {
	// TODO(b/124056281): Stop rejecting short optLen values in getsockopt.
	switch name {
	case linux.SO_ERROR:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		// Get the last error and convert it.
		err := ep.GetSockOpt(tcpip.ErrorOption{})
		if err == nil {
			optP := primitive.Int32(0)
			return &optP, nil
		}

		optP := primitive.Int32(syserr.TranslateNetstackError(err).ToLinux().Number())
		return &optP, nil

	case linux.SO_PEERCRED:
		if family != linux.AF_UNIX || outLen < syscall.SizeofUcred {
			return nil, syserr.ErrInvalidArgument
		}

		tcred := t.Credentials()
		creds := linux.ControlMessageCredentials{
			PID: int32(t.ThreadGroup().ID()),
			UID: uint32(tcred.EffectiveKUID.In(tcred.UserNamespace).OrOverflow()),
			GID: uint32(tcred.EffectiveKGID.In(tcred.UserNamespace).OrOverflow()),
		}
		return &creds, nil

	case linux.SO_PASSCRED:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.PasscredOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_SNDBUF:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		size, err := ep.GetSockOptInt(tcpip.SendBufferSizeOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		if size > math.MaxInt32 {
			size = math.MaxInt32
		}

		sizeP := primitive.Int32(size)
		return &sizeP, nil

	case linux.SO_RCVBUF:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		size, err := ep.GetSockOptInt(tcpip.ReceiveBufferSizeOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		if size > math.MaxInt32 {
			size = math.MaxInt32
		}

		sizeP := primitive.Int32(size)
		return &sizeP, nil

	case linux.SO_REUSEADDR:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.ReuseAddressOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_REUSEPORT:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.ReusePortOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_BINDTODEVICE:
		var v tcpip.BindToDeviceOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		if v == 0 {
			var b primitive.ByteSlice
			return &b, nil
		}
		if outLen < linux.IFNAMSIZ {
			return nil, syserr.ErrInvalidArgument
		}
		s := t.NetworkContext()
		if s == nil {
			return nil, syserr.ErrNoDevice
		}
		nic, ok := s.Interfaces()[int32(v)]
		if !ok {
			// The NICID no longer indicates a valid interface, probably because that
			// interface was removed.
			return nil, syserr.ErrUnknownDevice
		}

		name := primitive.ByteSlice(append([]byte(nic.Name), 0))
		return &name, nil

	case linux.SO_BROADCAST:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.BroadcastOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_KEEPALIVE:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.KeepaliveEnabledOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_LINGER:
		if outLen < linux.SizeOfLinger {
			return nil, syserr.ErrInvalidArgument
		}

		linger := linux.Linger{}
		return &linger, nil

	case linux.SO_SNDTIMEO:
		// TODO(igudger): Linux allows shorter lengths for partial results.
		if outLen < linux.SizeOfTimeval {
			return nil, syserr.ErrInvalidArgument
		}

		sendTimeout := linux.NsecToTimeval(s.SendTimeout())
		return &sendTimeout, nil

	case linux.SO_RCVTIMEO:
		// TODO(igudger): Linux allows shorter lengths for partial results.
		if outLen < linux.SizeOfTimeval {
			return nil, syserr.ErrInvalidArgument
		}

		recvTimeout := linux.NsecToTimeval(s.RecvTimeout())
		return &recvTimeout, nil

	case linux.SO_OOBINLINE:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.OutOfBandInlineOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(v)
		return &vP, nil

	case linux.SO_NO_CHECK:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.NoChecksumOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	default:
		socket.GetSockOptEmitUnimplementedEvent(t, name)
	}
	return nil, syserr.ErrProtocolNotAvailable
}

// getSockOptTCP implements GetSockOpt when level is SOL_TCP.
func getSockOptTCP(t *kernel.Task, ep commonEndpoint, name, outLen int) (marshal.Marshallable, *syserr.Error) {
	switch name {
	case linux.TCP_NODELAY:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.DelayOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(!v))
		return &vP, nil

	case linux.TCP_CORK:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.CorkOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.TCP_QUICKACK:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.QuickAckOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.TCP_MAXSEG:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.MaxSegOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(v)
		return &vP, nil

	case linux.TCP_KEEPIDLE:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.KeepaliveIdleOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		keepAliveIdle := primitive.Int32(time.Duration(v) / time.Second)
		return &keepAliveIdle, nil

	case linux.TCP_KEEPINTVL:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.KeepaliveIntervalOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		keepAliveInterval := primitive.Int32(time.Duration(v) / time.Second)
		return &keepAliveInterval, nil

	case linux.TCP_KEEPCNT:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.KeepaliveCountOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(v)
		return &vP, nil

	case linux.TCP_USER_TIMEOUT:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.TCPUserTimeoutOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		tcpUserTimeout := primitive.Int32(time.Duration(v) / time.Millisecond)
		return &tcpUserTimeout, nil

	case linux.TCP_INFO:
		var v tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		// TODO(b/64800844): Translate fields once they are added to
		// tcpip.TCPInfoOption.
		info := linux.TCPInfo{}

		// Linux truncates the output binary to outLen.
		buf := t.CopyScratchBuffer(info.SizeBytes())
		info.MarshalUnsafe(buf)
		if len(buf) > outLen {
			buf = buf[:outLen]
		}
		bufP := primitive.ByteSlice(buf)
		return &bufP, nil

	case linux.TCP_CC_INFO,
		linux.TCP_NOTSENT_LOWAT,
		linux.TCP_ZEROCOPY_RECEIVE:

		t.Kernel().EmitUnimplementedEvent(t)

	case linux.TCP_CONGESTION:
		if outLen <= 0 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.CongestionControlOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		// We match linux behaviour here where it returns the lower of
		// TCP_CA_NAME_MAX bytes or the value of the option length.
		//
		// This is Linux's net/tcp.h TCP_CA_NAME_MAX.
		const tcpCANameMax = 16

		toCopy := tcpCANameMax
		if outLen < tcpCANameMax {
			toCopy = outLen
		}
		b := make([]byte, toCopy)
		copy(b, v)

		bP := primitive.ByteSlice(b)
		return &bP, nil

	case linux.TCP_LINGER2:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.TCPLingerTimeoutOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		var lingerTimeout primitive.Int32
		if v >= 0 {
			lingerTimeout = primitive.Int32(time.Duration(v) / time.Second)
		} else {
			lingerTimeout = -1
		}
		return &lingerTimeout, nil

	case linux.TCP_DEFER_ACCEPT:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.TCPDeferAcceptOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		tcpDeferAccept := primitive.Int32(time.Duration(v) / time.Second)
		return &tcpDeferAccept, nil

	case linux.TCP_SYNCNT:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.TCPSynCountOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(v)
		return &vP, nil

	case linux.TCP_WINDOW_CLAMP:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.TCPWindowClampOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		vP := primitive.Int32(v)
		return &vP, nil
	default:
		emitUnimplementedEventTCP(t, name)
	}
	return nil, syserr.ErrProtocolNotAvailable
}

// getSockOptIPv6 implements GetSockOpt when level is SOL_IPV6.
func getSockOptIPv6(t *kernel.Task, ep commonEndpoint, name, outLen int) (marshal.Marshallable, *syserr.Error) {
	switch name {
	case linux.IPV6_V6ONLY:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.V6OnlyOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.IPV6_PATHMTU:
		t.Kernel().EmitUnimplementedEvent(t)

	case linux.IPV6_TCLASS:
		// Length handling for parity with Linux.
		if outLen == 0 {
			var b primitive.ByteSlice
			return &b, nil
		}
		v, err := ep.GetSockOptInt(tcpip.IPv6TrafficClassOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		uintv := primitive.Uint32(v)
		// Linux truncates the output binary to outLen.
		ib := t.CopyScratchBuffer(uintv.SizeBytes())
		uintv.MarshalUnsafe(ib)
		// Handle cases where outLen is lesser than sizeOfInt32.
		if len(ib) > outLen {
			ib = ib[:outLen]
		}
		ibP := primitive.ByteSlice(ib)
		return &ibP, nil

	case linux.IPV6_RECVTCLASS:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.ReceiveTClassOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_ORIGINAL_DST:
		// TODO(gvisor.dev/issue/170): ip6tables.
		return nil, syserr.ErrInvalidArgument

	default:
		emitUnimplementedEventIPv6(t, name)
	}
	return nil, syserr.ErrProtocolNotAvailable
}

// getSockOptIP implements GetSockOpt when level is SOL_IP.
func getSockOptIP(t *kernel.Task, ep commonEndpoint, name, outLen int, family int) (marshal.Marshallable, *syserr.Error) {
	switch name {
	case linux.IP_TTL:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.TTLOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		// Fill in the default value, if needed.
		vP := primitive.Int32(v)
		if vP == 0 {
			vP = DefaultTTL
		}

		return &vP, nil

	case linux.IP_MULTICAST_TTL:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptInt(tcpip.MulticastTTLOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(v)
		return &vP, nil

	case linux.IP_MULTICAST_IF:
		if outLen < len(linux.InetAddr{}) {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.MulticastInterfaceOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		a, _ := ConvertAddress(linux.AF_INET, tcpip.FullAddress{Addr: v.InterfaceAddr})

		return &a.(*linux.SockAddrInet).Addr, nil

	case linux.IP_MULTICAST_LOOP:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.MulticastLoopOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.IP_TOS:
		// Length handling for parity with Linux.
		if outLen == 0 {
			var b primitive.ByteSlice
			return &b, nil
		}
		v, err := ep.GetSockOptInt(tcpip.IPv4TOSOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}
		if outLen < sizeOfInt32 {
			vP := primitive.Uint8(v)
			return &vP, nil
		}
		vP := primitive.Int32(v)
		return &vP, nil

	case linux.IP_RECVTOS:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.ReceiveTOSOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.IP_PKTINFO:
		if outLen < sizeOfInt32 {
			return nil, syserr.ErrInvalidArgument
		}

		v, err := ep.GetSockOptBool(tcpip.ReceiveIPPacketInfoOption)
		if err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		vP := primitive.Int32(boolToInt32(v))
		return &vP, nil

	case linux.SO_ORIGINAL_DST:
		if outLen < int(binary.Size(linux.SockAddrInet{})) {
			return nil, syserr.ErrInvalidArgument
		}

		var v tcpip.OriginalDestinationOption
		if err := ep.GetSockOpt(&v); err != nil {
			return nil, syserr.TranslateNetstackError(err)
		}

		a, _ := ConvertAddress(linux.AF_INET, tcpip.FullAddress(v))
		return a.(*linux.SockAddrInet), nil

	default:
		emitUnimplementedEventIP(t, name)
	}
	return nil, syserr.ErrProtocolNotAvailable
}

// SetSockOpt implements the linux syscall setsockopt(2) for sockets backed by
// tcpip.Endpoint.
func (s *SocketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	// TODO(b/78348848): Unlike other socket options, SO_TIMESTAMP is
	// implemented specifically for netstack.SocketOperations rather than
	// commonEndpoint. commonEndpoint should be extended to support socket
	// options where the implementation is not shared, as unix sockets need
	// their own support for SO_TIMESTAMP.
	if level == linux.SOL_SOCKET && name == linux.SO_TIMESTAMP {
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		s.sockOptTimestamp = usermem.ByteOrder.Uint32(optVal) != 0
		return nil
	}
	if level == linux.SOL_TCP && name == linux.TCP_INQ {
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		s.sockOptInq = usermem.ByteOrder.Uint32(optVal) != 0
		return nil
	}

	if s.skType == linux.SOCK_RAW && level == linux.SOL_IP {
		switch name {
		case linux.IPT_SO_SET_REPLACE:
			if len(optVal) < linux.SizeOfIPTReplace {
				return syserr.ErrInvalidArgument
			}
			if s.family != linux.AF_INET {
				return syserr.ErrInvalidArgument
			}

			stack := inet.StackFromContext(t)
			if stack == nil {
				return syserr.ErrNoDevice
			}
			// Stack must be a netstack stack.
			return netfilter.SetEntries(stack.(*Stack).Stack, optVal)

		case linux.IPT_SO_SET_ADD_COUNTERS:
			// TODO(gvisor.dev/issue/170): Counter support.
			return nil
		}
	}

	return SetSockOpt(t, s, s.Endpoint, level, name, optVal)
}

// SetSockOpt can be used to implement the linux syscall setsockopt(2) for
// sockets backed by a commonEndpoint.
func SetSockOpt(t *kernel.Task, s socket.SocketOps, ep commonEndpoint, level int, name int, optVal []byte) *syserr.Error {
	switch level {
	case linux.SOL_SOCKET:
		return setSockOptSocket(t, s, ep, name, optVal)

	case linux.SOL_TCP:
		return setSockOptTCP(t, ep, name, optVal)

	case linux.SOL_IPV6:
		return setSockOptIPv6(t, ep, name, optVal)

	case linux.SOL_IP:
		return setSockOptIP(t, ep, name, optVal)

	case linux.SOL_UDP,
		linux.SOL_ICMPV6,
		linux.SOL_RAW,
		linux.SOL_PACKET:

		t.Kernel().EmitUnimplementedEvent(t)
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

// setSockOptSocket implements SetSockOpt when level is SOL_SOCKET.
func setSockOptSocket(t *kernel.Task, s socket.SocketOps, ep commonEndpoint, name int, optVal []byte) *syserr.Error {
	switch name {
	case linux.SO_SNDBUF:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.SendBufferSizeOption, int(v)))

	case linux.SO_RCVBUF:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.ReceiveBufferSizeOption, int(v)))

	case linux.SO_REUSEADDR:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.ReuseAddressOption, v != 0))

	case linux.SO_REUSEPORT:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.ReusePortOption, v != 0))

	case linux.SO_BINDTODEVICE:
		n := bytes.IndexByte(optVal, 0)
		if n == -1 {
			n = len(optVal)
		}
		name := string(optVal[:n])
		if name == "" {
			return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.BindToDeviceOption(0)))
		}
		s := t.NetworkContext()
		if s == nil {
			return syserr.ErrNoDevice
		}
		for nicID, nic := range s.Interfaces() {
			if nic.Name == name {
				return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.BindToDeviceOption(nicID)))
			}
		}
		return syserr.ErrUnknownDevice

	case linux.SO_BROADCAST:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.BroadcastOption, v != 0))

	case linux.SO_PASSCRED:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.PasscredOption, v != 0))

	case linux.SO_KEEPALIVE:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.KeepaliveEnabledOption, v != 0))

	case linux.SO_SNDTIMEO:
		if len(optVal) < linux.SizeOfTimeval {
			return syserr.ErrInvalidArgument
		}

		var v linux.Timeval
		binary.Unmarshal(optVal[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
		if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
			return syserr.ErrDomain
		}
		s.SetSendTimeout(v.ToNsecCapped())
		return nil

	case linux.SO_RCVTIMEO:
		if len(optVal) < linux.SizeOfTimeval {
			return syserr.ErrInvalidArgument
		}

		var v linux.Timeval
		binary.Unmarshal(optVal[:linux.SizeOfTimeval], usermem.ByteOrder, &v)
		if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
			return syserr.ErrDomain
		}
		s.SetRecvTimeout(v.ToNsecCapped())
		return nil

	case linux.SO_OOBINLINE:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)

		if v == 0 {
			socket.SetSockOptEmitUnimplementedEvent(t, name)
		}

		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.OutOfBandInlineOption(v)))

	case linux.SO_NO_CHECK:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.NoChecksumOption, v != 0))

	case linux.SO_LINGER:
		if len(optVal) < linux.SizeOfLinger {
			return syserr.ErrInvalidArgument
		}

		var v linux.Linger
		binary.Unmarshal(optVal[:linux.SizeOfLinger], usermem.ByteOrder, &v)

		if v != (linux.Linger{}) {
			socket.SetSockOptEmitUnimplementedEvent(t, name)
		}

		return nil

	case linux.SO_DETACH_FILTER:
		// optval is ignored.
		var v tcpip.SocketDetachFilterOption
		return syserr.TranslateNetstackError(ep.SetSockOpt(v))

	default:
		socket.SetSockOptEmitUnimplementedEvent(t, name)
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

// setSockOptTCP implements SetSockOpt when level is SOL_TCP.
func setSockOptTCP(t *kernel.Task, ep commonEndpoint, name int, optVal []byte) *syserr.Error {
	switch name {
	case linux.TCP_NODELAY:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.DelayOption, v == 0))

	case linux.TCP_CORK:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.CorkOption, v != 0))

	case linux.TCP_QUICKACK:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.QuickAckOption, v != 0))

	case linux.TCP_MAXSEG:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.MaxSegOption, int(v)))

	case linux.TCP_KEEPIDLE:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		if v < 1 || v > linux.MAX_TCP_KEEPIDLE {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.KeepaliveIdleOption(time.Second * time.Duration(v))))

	case linux.TCP_KEEPINTVL:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		if v < 1 || v > linux.MAX_TCP_KEEPINTVL {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.KeepaliveIntervalOption(time.Second * time.Duration(v))))

	case linux.TCP_KEEPCNT:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		if v < 1 || v > linux.MAX_TCP_KEEPCNT {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.KeepaliveCountOption, int(v)))

	case linux.TCP_USER_TIMEOUT:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := int32(usermem.ByteOrder.Uint32(optVal))
		if v < 0 {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.TCPUserTimeoutOption(time.Millisecond * time.Duration(v))))

	case linux.TCP_CONGESTION:
		v := tcpip.CongestionControlOption(optVal)
		if err := ep.SetSockOpt(v); err != nil {
			return syserr.TranslateNetstackError(err)
		}
		return nil

	case linux.TCP_LINGER2:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := int32(usermem.ByteOrder.Uint32(optVal))
		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.TCPLingerTimeoutOption(time.Second * time.Duration(v))))

	case linux.TCP_DEFER_ACCEPT:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		v := int32(usermem.ByteOrder.Uint32(optVal))
		if v < 0 {
			v = 0
		}
		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.TCPDeferAcceptOption(time.Second * time.Duration(v))))

	case linux.TCP_SYNCNT:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		v := usermem.ByteOrder.Uint32(optVal)

		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.TCPSynCountOption, int(v)))

	case linux.TCP_WINDOW_CLAMP:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		v := usermem.ByteOrder.Uint32(optVal)

		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.TCPWindowClampOption, int(v)))

	case linux.TCP_REPAIR_OPTIONS:
		t.Kernel().EmitUnimplementedEvent(t)

	default:
		emitUnimplementedEventTCP(t, name)
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

// setSockOptIPv6 implements SetSockOpt when level is SOL_IPV6.
func setSockOptIPv6(t *kernel.Task, ep commonEndpoint, name int, optVal []byte) *syserr.Error {
	switch name {
	case linux.IPV6_V6ONLY:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}

		v := usermem.ByteOrder.Uint32(optVal)
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.V6OnlyOption, v != 0))

	case linux.IPV6_ADD_MEMBERSHIP,
		linux.IPV6_DROP_MEMBERSHIP,
		linux.IPV6_IPSEC_POLICY,
		linux.IPV6_JOIN_ANYCAST,
		linux.IPV6_LEAVE_ANYCAST,
		// TODO(b/148887420): Add support for IPV6_PKTINFO.
		linux.IPV6_PKTINFO,
		linux.IPV6_ROUTER_ALERT,
		linux.IPV6_XFRM_POLICY,
		linux.MCAST_BLOCK_SOURCE,
		linux.MCAST_JOIN_GROUP,
		linux.MCAST_JOIN_SOURCE_GROUP,
		linux.MCAST_LEAVE_GROUP,
		linux.MCAST_LEAVE_SOURCE_GROUP,
		linux.MCAST_UNBLOCK_SOURCE:

		t.Kernel().EmitUnimplementedEvent(t)

	case linux.IPV6_TCLASS:
		if len(optVal) < sizeOfInt32 {
			return syserr.ErrInvalidArgument
		}
		v := int32(usermem.ByteOrder.Uint32(optVal))
		if v < -1 || v > 255 {
			return syserr.ErrInvalidArgument
		}
		if v == -1 {
			v = 0
		}
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.IPv6TrafficClassOption, int(v)))

	case linux.IPV6_RECVTCLASS:
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}

		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.ReceiveTClassOption, v != 0))

	default:
		emitUnimplementedEventIPv6(t, name)
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

var (
	inetMulticastRequestSize        = int(binary.Size(linux.InetMulticastRequest{}))
	inetMulticastRequestWithNICSize = int(binary.Size(linux.InetMulticastRequestWithNIC{}))
)

// copyInMulticastRequest copies in a variable-size multicast request. The
// kernel determines which structure was passed by its length. IP_MULTICAST_IF
// supports ip_mreqn, ip_mreq and in_addr, while IP_ADD_MEMBERSHIP and
// IP_DROP_MEMBERSHIP only support ip_mreqn and ip_mreq. To handle this,
// allowAddr controls whether in_addr is accepted or rejected.
func copyInMulticastRequest(optVal []byte, allowAddr bool) (linux.InetMulticastRequestWithNIC, *syserr.Error) {
	if len(optVal) < len(linux.InetAddr{}) {
		return linux.InetMulticastRequestWithNIC{}, syserr.ErrInvalidArgument
	}

	if len(optVal) < inetMulticastRequestSize {
		if !allowAddr {
			return linux.InetMulticastRequestWithNIC{}, syserr.ErrInvalidArgument
		}

		var req linux.InetMulticastRequestWithNIC
		copy(req.InterfaceAddr[:], optVal)
		return req, nil
	}

	if len(optVal) >= inetMulticastRequestWithNICSize {
		var req linux.InetMulticastRequestWithNIC
		binary.Unmarshal(optVal[:inetMulticastRequestWithNICSize], usermem.ByteOrder, &req)
		return req, nil
	}

	var req linux.InetMulticastRequestWithNIC
	binary.Unmarshal(optVal[:inetMulticastRequestSize], usermem.ByteOrder, &req.InetMulticastRequest)
	return req, nil
}

// parseIntOrChar copies either a 32-bit int or an 8-bit uint out of buf.
//
// net/ipv4/ip_sockglue.c:do_ip_setsockopt does this for its socket options.
func parseIntOrChar(buf []byte) (int32, *syserr.Error) {
	if len(buf) == 0 {
		return 0, syserr.ErrInvalidArgument
	}

	if len(buf) >= sizeOfInt32 {
		return int32(usermem.ByteOrder.Uint32(buf)), nil
	}

	return int32(buf[0]), nil
}

// setSockOptIP implements SetSockOpt when level is SOL_IP.
func setSockOptIP(t *kernel.Task, ep commonEndpoint, name int, optVal []byte) *syserr.Error {
	switch name {
	case linux.IP_MULTICAST_TTL:
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}

		if v == -1 {
			// Linux translates -1 to 1.
			v = 1
		}
		if v < 0 || v > 255 {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.MulticastTTLOption, int(v)))

	case linux.IP_ADD_MEMBERSHIP:
		req, err := copyInMulticastRequest(optVal, false /* allowAddr */)
		if err != nil {
			return err
		}

		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.AddMembershipOption{
			NIC: tcpip.NICID(req.InterfaceIndex),
			// TODO(igudger): Change AddMembership to use the standard
			// any address representation.
			InterfaceAddr: tcpip.Address(req.InterfaceAddr[:]),
			MulticastAddr: tcpip.Address(req.MulticastAddr[:]),
		}))

	case linux.IP_DROP_MEMBERSHIP:
		req, err := copyInMulticastRequest(optVal, false /* allowAddr */)
		if err != nil {
			return err
		}

		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.RemoveMembershipOption{
			NIC: tcpip.NICID(req.InterfaceIndex),
			// TODO(igudger): Change DropMembership to use the standard
			// any address representation.
			InterfaceAddr: tcpip.Address(req.InterfaceAddr[:]),
			MulticastAddr: tcpip.Address(req.MulticastAddr[:]),
		}))

	case linux.IP_MULTICAST_IF:
		req, err := copyInMulticastRequest(optVal, true /* allowAddr */)
		if err != nil {
			return err
		}

		return syserr.TranslateNetstackError(ep.SetSockOpt(tcpip.MulticastInterfaceOption{
			NIC:           tcpip.NICID(req.InterfaceIndex),
			InterfaceAddr: bytesToIPAddress(req.InterfaceAddr[:]),
		}))

	case linux.IP_MULTICAST_LOOP:
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}

		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.MulticastLoopOption, v != 0))

	case linux.MCAST_JOIN_GROUP:
		// FIXME(b/124219304): Implement MCAST_JOIN_GROUP.
		t.Kernel().EmitUnimplementedEvent(t)
		return syserr.ErrInvalidArgument

	case linux.IP_TTL:
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}

		// -1 means default TTL.
		if v == -1 {
			v = 0
		} else if v < 1 || v > 255 {
			return syserr.ErrInvalidArgument
		}
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.TTLOption, int(v)))

	case linux.IP_TOS:
		if len(optVal) == 0 {
			return nil
		}
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}
		return syserr.TranslateNetstackError(ep.SetSockOptInt(tcpip.IPv4TOSOption, int(v)))

	case linux.IP_RECVTOS:
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.ReceiveTOSOption, v != 0))

	case linux.IP_PKTINFO:
		if len(optVal) == 0 {
			return nil
		}
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.ReceiveIPPacketInfoOption, v != 0))

	case linux.IP_HDRINCL:
		if len(optVal) == 0 {
			return nil
		}
		v, err := parseIntOrChar(optVal)
		if err != nil {
			return err
		}
		return syserr.TranslateNetstackError(ep.SetSockOptBool(tcpip.IPHdrIncludedOption, v != 0))

	case linux.IP_ADD_SOURCE_MEMBERSHIP,
		linux.IP_BIND_ADDRESS_NO_PORT,
		linux.IP_BLOCK_SOURCE,
		linux.IP_CHECKSUM,
		linux.IP_DROP_SOURCE_MEMBERSHIP,
		linux.IP_FREEBIND,
		linux.IP_IPSEC_POLICY,
		linux.IP_MINTTL,
		linux.IP_MSFILTER,
		linux.IP_MTU_DISCOVER,
		linux.IP_MULTICAST_ALL,
		linux.IP_NODEFRAG,
		linux.IP_OPTIONS,
		linux.IP_PASSSEC,
		linux.IP_RECVERR,
		linux.IP_RECVFRAGSIZE,
		linux.IP_RECVOPTS,
		linux.IP_RECVORIGDSTADDR,
		linux.IP_RECVTTL,
		linux.IP_RETOPTS,
		linux.IP_TRANSPARENT,
		linux.IP_UNBLOCK_SOURCE,
		linux.IP_UNICAST_IF,
		linux.IP_XFRM_POLICY,
		linux.MCAST_BLOCK_SOURCE,
		linux.MCAST_JOIN_SOURCE_GROUP,
		linux.MCAST_LEAVE_GROUP,
		linux.MCAST_LEAVE_SOURCE_GROUP,
		linux.MCAST_MSFILTER,
		linux.MCAST_UNBLOCK_SOURCE:

		t.Kernel().EmitUnimplementedEvent(t)
	}

	// Default to the old behavior; hand off to network stack.
	return syserr.TranslateNetstackError(ep.SetSockOpt(struct{}{}))
}

// emitUnimplementedEventTCP emits unimplemented event if name is valid. This
// function contains names that are common between Get and SetSockOpt when
// level is SOL_TCP.
func emitUnimplementedEventTCP(t *kernel.Task, name int) {
	switch name {
	case linux.TCP_CONGESTION,
		linux.TCP_CORK,
		linux.TCP_FASTOPEN,
		linux.TCP_FASTOPEN_CONNECT,
		linux.TCP_FASTOPEN_KEY,
		linux.TCP_FASTOPEN_NO_COOKIE,
		linux.TCP_QUEUE_SEQ,
		linux.TCP_REPAIR,
		linux.TCP_REPAIR_QUEUE,
		linux.TCP_REPAIR_WINDOW,
		linux.TCP_SAVED_SYN,
		linux.TCP_SAVE_SYN,
		linux.TCP_THIN_DUPACK,
		linux.TCP_THIN_LINEAR_TIMEOUTS,
		linux.TCP_TIMESTAMP,
		linux.TCP_ULP:

		t.Kernel().EmitUnimplementedEvent(t)
	}
}

// emitUnimplementedEventIPv6 emits unimplemented event if name is valid. It
// contains names that are common between Get and SetSockOpt when level is
// SOL_IPV6.
func emitUnimplementedEventIPv6(t *kernel.Task, name int) {
	switch name {
	case linux.IPV6_2292DSTOPTS,
		linux.IPV6_2292HOPLIMIT,
		linux.IPV6_2292HOPOPTS,
		linux.IPV6_2292PKTINFO,
		linux.IPV6_2292PKTOPTIONS,
		linux.IPV6_2292RTHDR,
		linux.IPV6_ADDR_PREFERENCES,
		linux.IPV6_AUTOFLOWLABEL,
		linux.IPV6_DONTFRAG,
		linux.IPV6_DSTOPTS,
		linux.IPV6_FLOWINFO,
		linux.IPV6_FLOWINFO_SEND,
		linux.IPV6_FLOWLABEL_MGR,
		linux.IPV6_FREEBIND,
		linux.IPV6_HOPOPTS,
		linux.IPV6_MINHOPCOUNT,
		linux.IPV6_MTU,
		linux.IPV6_MTU_DISCOVER,
		linux.IPV6_MULTICAST_ALL,
		linux.IPV6_MULTICAST_HOPS,
		linux.IPV6_MULTICAST_IF,
		linux.IPV6_MULTICAST_LOOP,
		linux.IPV6_RECVDSTOPTS,
		linux.IPV6_RECVERR,
		linux.IPV6_RECVFRAGSIZE,
		linux.IPV6_RECVHOPLIMIT,
		linux.IPV6_RECVHOPOPTS,
		linux.IPV6_RECVORIGDSTADDR,
		linux.IPV6_RECVPATHMTU,
		linux.IPV6_RECVPKTINFO,
		linux.IPV6_RECVRTHDR,
		linux.IPV6_RTHDR,
		linux.IPV6_RTHDRDSTOPTS,
		linux.IPV6_TCLASS,
		linux.IPV6_TRANSPARENT,
		linux.IPV6_UNICAST_HOPS,
		linux.IPV6_UNICAST_IF,
		linux.MCAST_MSFILTER,
		linux.IPV6_ADDRFORM:

		t.Kernel().EmitUnimplementedEvent(t)
	}
}

// emitUnimplementedEventIP emits unimplemented event if name is valid. It
// contains names that are common between Get and SetSockOpt when level is
// SOL_IP.
func emitUnimplementedEventIP(t *kernel.Task, name int) {
	switch name {
	case linux.IP_TOS,
		linux.IP_TTL,
		linux.IP_HDRINCL,
		linux.IP_OPTIONS,
		linux.IP_ROUTER_ALERT,
		linux.IP_RECVOPTS,
		linux.IP_RETOPTS,
		linux.IP_PKTINFO,
		linux.IP_PKTOPTIONS,
		linux.IP_MTU_DISCOVER,
		linux.IP_RECVERR,
		linux.IP_RECVTTL,
		linux.IP_RECVTOS,
		linux.IP_MTU,
		linux.IP_FREEBIND,
		linux.IP_IPSEC_POLICY,
		linux.IP_XFRM_POLICY,
		linux.IP_PASSSEC,
		linux.IP_TRANSPARENT,
		linux.IP_ORIGDSTADDR,
		linux.IP_MINTTL,
		linux.IP_NODEFRAG,
		linux.IP_CHECKSUM,
		linux.IP_BIND_ADDRESS_NO_PORT,
		linux.IP_RECVFRAGSIZE,
		linux.IP_MULTICAST_IF,
		linux.IP_MULTICAST_TTL,
		linux.IP_MULTICAST_LOOP,
		linux.IP_ADD_MEMBERSHIP,
		linux.IP_DROP_MEMBERSHIP,
		linux.IP_UNBLOCK_SOURCE,
		linux.IP_BLOCK_SOURCE,
		linux.IP_ADD_SOURCE_MEMBERSHIP,
		linux.IP_DROP_SOURCE_MEMBERSHIP,
		linux.IP_MSFILTER,
		linux.MCAST_JOIN_GROUP,
		linux.MCAST_BLOCK_SOURCE,
		linux.MCAST_UNBLOCK_SOURCE,
		linux.MCAST_LEAVE_GROUP,
		linux.MCAST_JOIN_SOURCE_GROUP,
		linux.MCAST_LEAVE_SOURCE_GROUP,
		linux.MCAST_MSFILTER,
		linux.IP_MULTICAST_ALL,
		linux.IP_UNICAST_IF:

		t.Kernel().EmitUnimplementedEvent(t)
	}
}

// isLinkLocal determines if the given IPv6 address is link-local. This is the
// case when it has the fe80::/10 prefix. This check is used to determine when
// the NICID is relevant for a given IPv6 address.
func isLinkLocal(addr tcpip.Address) bool {
	return len(addr) >= 2 && addr[0] == 0xfe && addr[1]&0xc0 == 0x80
}

// ConvertAddress converts the given address to a native format.
func ConvertAddress(family int, addr tcpip.FullAddress) (linux.SockAddr, uint32) {
	switch family {
	case linux.AF_UNIX:
		var out linux.SockAddrUnix
		out.Family = linux.AF_UNIX
		l := len([]byte(addr.Addr))
		for i := 0; i < l; i++ {
			out.Path[i] = int8(addr.Addr[i])
		}

		// Linux returns the used length of the address struct (including the
		// null terminator) for filesystem paths. The Family field is 2 bytes.
		// It is sometimes allowed to exclude the null terminator if the
		// address length is the max. Abstract and empty paths always return
		// the full exact length.
		if l == 0 || out.Path[0] == 0 || l == len(out.Path) {
			return &out, uint32(2 + l)
		}
		return &out, uint32(3 + l)

	case linux.AF_INET:
		var out linux.SockAddrInet
		copy(out.Addr[:], addr.Addr)
		out.Family = linux.AF_INET
		out.Port = htons(addr.Port)
		return &out, uint32(sockAddrInetSize)

	case linux.AF_INET6:
		var out linux.SockAddrInet6
		if len(addr.Addr) == header.IPv4AddressSize {
			// Copy address in v4-mapped format.
			copy(out.Addr[12:], addr.Addr)
			out.Addr[10] = 0xff
			out.Addr[11] = 0xff
		} else {
			copy(out.Addr[:], addr.Addr)
		}
		out.Family = linux.AF_INET6
		out.Port = htons(addr.Port)
		if isLinkLocal(addr.Addr) {
			out.Scope_id = uint32(addr.NIC)
		}
		return &out, uint32(sockAddrInet6Size)

	case linux.AF_PACKET:
		// TODO(gvisor.dev/issue/173): Return protocol too.
		var out linux.SockAddrLink
		out.Family = linux.AF_PACKET
		out.InterfaceIndex = int32(addr.NIC)
		out.HardwareAddrLen = header.EthernetAddressSize
		copy(out.HardwareAddr[:], addr.Addr)
		return &out, uint32(sockAddrLinkSize)

	default:
		return nil, 0
	}
}

// GetSockName implements the linux syscall getsockname(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.Endpoint.GetLocalAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := ConvertAddress(s.family, addr)
	return a, l, nil
}

// GetPeerName implements the linux syscall getpeername(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr, err := s.Endpoint.GetRemoteAddress()
	if err != nil {
		return nil, 0, syserr.TranslateNetstackError(err)
	}

	a, l := ConvertAddress(s.family, addr)
	return a, l, nil
}

// coalescingRead is the fast path for non-blocking, non-peek, stream-based
// case. It coalesces as many packets as possible before returning to the
// caller.
//
// Precondition: s.readMu must be locked.
func (s *socketOpsCommon) coalescingRead(ctx context.Context, dst usermem.IOSequence, discard bool) (int, *syserr.Error) {
	var err *syserr.Error
	var copied int

	// Copy as many views as possible into the user-provided buffer.
	for {
		// Always do at least one fetchReadView, even if the number of bytes to
		// read is 0.
		err = s.fetchReadView()
		if err != nil {
			break
		}
		if dst.NumBytes() == 0 {
			break
		}

		var n int
		var e error
		if discard {
			n = len(s.readView)
			if int64(n) > dst.NumBytes() {
				n = int(dst.NumBytes())
			}
		} else {
			n, e = dst.CopyOut(ctx, s.readView)
			// Set the control message, even if 0 bytes were read.
			if e == nil {
				s.updateTimestamp()
			}
		}
		copied += n
		s.readView.TrimFront(n)
		if len(s.readView) == 0 {
			atomic.StoreUint32(&s.readViewHasData, 0)
		}

		dst = dst.DropFirst(n)
		if e != nil {
			err = syserr.FromError(e)
			break
		}
	}

	// If we managed to copy something, we must deliver it.
	if copied > 0 {
		s.Endpoint.ModerateRecvBuf(copied)
		return copied, nil
	}

	return 0, err
}

func (s *socketOpsCommon) fillCmsgInq(cmsg *socket.ControlMessages) {
	if !s.sockOptInq {
		return
	}
	rcvBufUsed, err := s.Endpoint.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
	if err != nil {
		return
	}
	cmsg.IP.HasInq = true
	cmsg.IP.Inq = int32(len(s.readView) + rcvBufUsed)
}

func toLinuxPacketType(pktType tcpip.PacketType) uint8 {
	switch pktType {
	case tcpip.PacketHost:
		return linux.PACKET_HOST
	case tcpip.PacketOtherHost:
		return linux.PACKET_OTHERHOST
	case tcpip.PacketOutgoing:
		return linux.PACKET_OUTGOING
	case tcpip.PacketBroadcast:
		return linux.PACKET_BROADCAST
	case tcpip.PacketMulticast:
		return linux.PACKET_MULTICAST
	default:
		panic(fmt.Sprintf("unknown packet type: %d", pktType))
	}
}

// nonBlockingRead issues a non-blocking read.
//
// TODO(b/78348848): Support timestamps for stream sockets.
func (s *socketOpsCommon) nonBlockingRead(ctx context.Context, dst usermem.IOSequence, peek, trunc, senderRequested bool) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	isPacket := s.isPacketBased()

	// Fast path for regular reads from stream (e.g., TCP) endpoints. Note
	// that senderRequested is ignored for stream sockets.
	if !peek && !isPacket {
		// TCP sockets discard the data if MSG_TRUNC is set.
		//
		// This behavior is documented in man 7 tcp:
		// Since version 2.4, Linux supports the use of MSG_TRUNC in the flags
		// argument of recv(2) (and recvmsg(2)). This flag causes the received
		// bytes of data to be discarded, rather than passed back in a
		// caller-supplied  buffer.
		s.readMu.Lock()
		n, err := s.coalescingRead(ctx, dst, trunc)
		cmsg := s.controlMessages()
		s.fillCmsgInq(&cmsg)
		s.readMu.Unlock()
		return n, 0, nil, 0, cmsg, err
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if err := s.fetchReadView(); err != nil {
		return 0, 0, nil, 0, socket.ControlMessages{}, err
	}

	if !isPacket && peek && trunc {
		// MSG_TRUNC with MSG_PEEK on a TCP socket returns the
		// amount that could be read.
		rql, err := s.Endpoint.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		if err != nil {
			return 0, 0, nil, 0, socket.ControlMessages{}, syserr.TranslateNetstackError(err)
		}
		available := len(s.readView) + int(rql)
		bufLen := int(dst.NumBytes())
		if available < bufLen {
			return available, 0, nil, 0, socket.ControlMessages{}, nil
		}
		return bufLen, 0, nil, 0, socket.ControlMessages{}, nil
	}

	n, err := dst.CopyOut(ctx, s.readView)
	// Set the control message, even if 0 bytes were read.
	if err == nil {
		s.updateTimestamp()
	}
	var addr linux.SockAddr
	var addrLen uint32
	if isPacket && senderRequested {
		addr, addrLen = ConvertAddress(s.family, s.sender)
		switch v := addr.(type) {
		case *linux.SockAddrLink:
			v.Protocol = htons(uint16(s.linkPacketInfo.Protocol))
			v.PacketType = toLinuxPacketType(s.linkPacketInfo.PktType)
		}
	}

	if peek {
		if l := len(s.readView); trunc && l > n {
			// isPacket must be true.
			return l, linux.MSG_TRUNC, addr, addrLen, s.controlMessages(), syserr.FromError(err)
		}

		if isPacket || err != nil {
			return n, 0, addr, addrLen, s.controlMessages(), syserr.FromError(err)
		}

		// We need to peek beyond the first message.
		dst = dst.DropFirst(n)
		num, err := dst.CopyOutFrom(ctx, safemem.FromVecReaderFunc{func(dsts [][]byte) (int64, error) {
			n, _, err := s.Endpoint.Peek(dsts)
			// TODO(b/78348848): Handle peek timestamp.
			if err != nil {
				return int64(n), syserr.TranslateNetstackError(err).ToError()
			}
			return int64(n), nil
		}})
		n += int(num)
		if err == syserror.ErrWouldBlock && n > 0 {
			// We got some data, so no need to return an error.
			err = nil
		}
		return n, 0, nil, 0, s.controlMessages(), syserr.FromError(err)
	}

	var msgLen int
	if isPacket {
		msgLen = len(s.readView)
		s.readView = nil
	} else {
		msgLen = int(n)
		s.readView.TrimFront(int(n))
	}

	if len(s.readView) == 0 {
		atomic.StoreUint32(&s.readViewHasData, 0)
	}

	var flags int
	if msgLen > int(n) {
		flags |= linux.MSG_TRUNC
	}

	if trunc {
		n = msgLen
	}

	cmsg := s.controlMessages()
	s.fillCmsgInq(&cmsg)
	return n, flags, addr, addrLen, cmsg, syserr.FromError(err)
}

func (s *socketOpsCommon) controlMessages() socket.ControlMessages {
	return socket.ControlMessages{
		IP: tcpip.ControlMessages{
			HasTimestamp:    s.readCM.HasTimestamp && s.sockOptTimestamp,
			Timestamp:       s.readCM.Timestamp,
			HasTOS:          s.readCM.HasTOS,
			TOS:             s.readCM.TOS,
			HasTClass:       s.readCM.HasTClass,
			TClass:          s.readCM.TClass,
			HasIPPacketInfo: s.readCM.HasIPPacketInfo,
			PacketInfo:      s.readCM.PacketInfo,
		},
	}
}

// updateTimestamp sets the timestamp for SIOCGSTAMP. It should be called after
// successfully writing packet data out to userspace.
//
// Precondition: s.readMu must be locked.
func (s *socketOpsCommon) updateTimestamp() {
	// Save the SIOCGSTAMP timestamp only if SO_TIMESTAMP is disabled.
	if !s.sockOptTimestamp {
		s.timestampValid = true
		s.timestampNS = s.readCM.Timestamp
	}
}

// RecvMsg implements the linux syscall recvmsg(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr linux.SockAddr, senderAddrLen uint32, controlMessages socket.ControlMessages, err *syserr.Error) {
	trunc := flags&linux.MSG_TRUNC != 0
	peek := flags&linux.MSG_PEEK != 0
	dontWait := flags&linux.MSG_DONTWAIT != 0
	waitAll := flags&linux.MSG_WAITALL != 0
	if senderRequested && !s.isPacketBased() {
		// Stream sockets ignore the sender address.
		senderRequested = false
	}
	n, msgFlags, senderAddr, senderAddrLen, controlMessages, err = s.nonBlockingRead(t, dst, peek, trunc, senderRequested)

	if s.isPacketBased() && err == syserr.ErrClosedForReceive && flags&linux.MSG_DONTWAIT != 0 {
		// In this situation we should return EAGAIN.
		return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
	}

	if err != nil && (err != syserr.ErrWouldBlock || dontWait) {
		// Read failed and we should not retry.
		return 0, 0, nil, 0, socket.ControlMessages{}, err
	}

	if err == nil && (dontWait || !waitAll || s.isPacketBased() || int64(n) >= dst.NumBytes()) {
		// We got all the data we need.
		return
	}

	// Don't overwrite any data we received.
	dst = dst.DropFirst(n)

	// We'll have to block. Register for notifications and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventIn)
	defer s.EventUnregister(&e)

	for {
		var rn int
		rn, msgFlags, senderAddr, senderAddrLen, controlMessages, err = s.nonBlockingRead(t, dst, peek, trunc, senderRequested)
		n += rn
		if err != nil && err != syserr.ErrWouldBlock {
			// Always stop on errors other than would block as we generally
			// won't be able to get any more data. Eat the error if we got
			// any data.
			if n > 0 {
				err = nil
			}
			return
		}
		if err == nil && (s.isPacketBased() || !waitAll || int64(rn) >= dst.NumBytes()) {
			// We got all the data we need.
			return
		}
		dst = dst.DropFirst(rn)

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if n > 0 {
				return n, msgFlags, senderAddr, senderAddrLen, controlMessages, nil
			}
			if err == syserror.ETIMEDOUT {
				return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrTryAgain
			}
			return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
		}
	}
}

// SendMsg implements the linux syscall sendmsg(2) for sockets backed by
// tcpip.Endpoint.
func (s *socketOpsCommon) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	// Reject Unix control messages.
	if !controlMessages.Unix.Empty() {
		return 0, syserr.ErrInvalidArgument
	}

	var addr *tcpip.FullAddress
	if len(to) > 0 {
		addrBuf, family, err := AddressAndFamily(to)
		if err != nil {
			return 0, err
		}
		if err := s.checkFamily(family, false /* exact */); err != nil {
			return 0, err
		}
		addrBuf = s.mapFamily(addrBuf, family)

		addr = &addrBuf
	}

	opts := tcpip.WriteOptions{
		To:          addr,
		More:        flags&linux.MSG_MORE != 0,
		EndOfRecord: flags&linux.MSG_EOR != 0,
	}

	v := &ioSequencePayload{t, src}
	n, resCh, err := s.Endpoint.Write(v, opts)
	if resCh != nil {
		if err := t.Block(resCh); err != nil {
			return 0, syserr.FromError(err)
		}
		n, _, err = s.Endpoint.Write(v, opts)
	}
	dontWait := flags&linux.MSG_DONTWAIT != 0
	if err == nil && (n >= v.src.NumBytes() || dontWait) {
		// Complete write.
		return int(n), nil
	}
	if err != nil && (err != tcpip.ErrWouldBlock || dontWait) {
		return int(n), syserr.TranslateNetstackError(err)
	}

	// We'll have to block. Register for notification and keep trying to
	// send all the data.
	e, ch := waiter.NewChannelEntry(nil)
	s.EventRegister(&e, waiter.EventOut)
	defer s.EventUnregister(&e)

	v.DropFirst(int(n))
	total := n
	for {
		n, _, err = s.Endpoint.Write(v, opts)
		v.DropFirst(int(n))
		total += n

		if err != nil && err != tcpip.ErrWouldBlock && total == 0 {
			return 0, syserr.TranslateNetstackError(err)
		}

		if err == nil && v.src.NumBytes() == 0 || err != nil && err != tcpip.ErrWouldBlock {
			return int(total), nil
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if err == syserror.ETIMEDOUT {
				return int(total), syserr.ErrTryAgain
			}
			// handleIOError will consume errors from t.Block if needed.
			return int(total), syserr.FromError(err)
		}
	}
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *SocketOperations) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return s.socketOpsCommon.ioctl(ctx, io, args)
}

func (s *socketOpsCommon) ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("ioctl(2) may only be called from a task goroutine")
	}

	// SIOCGSTAMP is implemented by netstack rather than all commonEndpoint
	// sockets.
	// TODO(b/78348848): Add a commonEndpoint method to support SIOCGSTAMP.
	switch args[1].Int() {
	case linux.SIOCGSTAMP:
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if !s.timestampValid {
			return 0, syserror.ENOENT
		}

		tv := linux.NsecToTimeval(s.timestampNS)
		_, err := tv.CopyOut(t, args[2].Pointer())
		return 0, err

	case linux.TIOCINQ:
		v, terr := s.Endpoint.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		if terr != nil {
			return 0, syserr.TranslateNetstackError(terr).ToError()
		}

		// Add bytes removed from the endpoint but not yet sent to the caller.
		s.readMu.Lock()
		v += len(s.readView)
		s.readMu.Unlock()

		if v > math.MaxInt32 {
			v = math.MaxInt32
		}

		// Copy result to userspace.
		vP := primitive.Int32(v)
		_, err := vP.CopyOut(t, args[2].Pointer())
		return 0, err
	}

	return Ioctl(ctx, s.Endpoint, io, args)
}

// Ioctl performs a socket ioctl.
func Ioctl(ctx context.Context, ep commonEndpoint, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("ioctl(2) may only be called from a task goroutine")
	}

	switch arg := int(args[1].Int()); arg {
	case linux.SIOCGIFFLAGS,
		linux.SIOCGIFADDR,
		linux.SIOCGIFBRDADDR,
		linux.SIOCGIFDSTADDR,
		linux.SIOCGIFHWADDR,
		linux.SIOCGIFINDEX,
		linux.SIOCGIFMAP,
		linux.SIOCGIFMETRIC,
		linux.SIOCGIFMTU,
		linux.SIOCGIFNAME,
		linux.SIOCGIFNETMASK,
		linux.SIOCGIFTXQLEN,
		linux.SIOCETHTOOL:

		var ifr linux.IFReq
		if _, err := ifr.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}
		if err := interfaceIoctl(ctx, io, arg, &ifr); err != nil {
			return 0, err.ToError()
		}
		_, err := ifr.CopyOut(t, args[2].Pointer())
		return 0, err

	case linux.SIOCGIFCONF:
		// Return a list of interface addresses or the buffer size
		// necessary to hold the list.
		var ifc linux.IFConf
		if _, err := ifc.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}

		if err := ifconfIoctl(ctx, t, io, &ifc); err != nil {
			return 0, err
		}

		_, err := ifc.CopyOut(t, args[2].Pointer())
		return 0, err

	case linux.TIOCINQ:
		v, terr := ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		if terr != nil {
			return 0, syserr.TranslateNetstackError(terr).ToError()
		}

		if v > math.MaxInt32 {
			v = math.MaxInt32
		}
		// Copy result to userspace.
		vP := primitive.Int32(v)
		_, err := vP.CopyOut(t, args[2].Pointer())
		return 0, err

	case linux.TIOCOUTQ:
		v, terr := ep.GetSockOptInt(tcpip.SendQueueSizeOption)
		if terr != nil {
			return 0, syserr.TranslateNetstackError(terr).ToError()
		}

		if v > math.MaxInt32 {
			v = math.MaxInt32
		}

		// Copy result to userspace.
		vP := primitive.Int32(v)
		_, err := vP.CopyOut(t, args[2].Pointer())
		return 0, err

	case linux.SIOCGIFMEM, linux.SIOCGIFPFLAGS, linux.SIOCGMIIPHY, linux.SIOCGMIIREG:
		unimpl.EmitUnimplementedEvent(ctx)
	}

	return 0, syserror.ENOTTY
}

// interfaceIoctl implements interface requests.
func interfaceIoctl(ctx context.Context, io usermem.IO, arg int, ifr *linux.IFReq) *syserr.Error {
	var (
		iface inet.Interface
		index int32
		found bool
	)

	// Find the relevant device.
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		return syserr.ErrNoDevice
	}

	// SIOCGIFNAME uses ifr.ifr_ifindex rather than ifr.ifr_name to
	// identify a device.
	if arg == linux.SIOCGIFNAME {
		// Gets the name of the interface given the interface index
		// stored in ifr_ifindex.
		index = int32(usermem.ByteOrder.Uint32(ifr.Data[:4]))
		if iface, ok := stack.Interfaces()[index]; ok {
			ifr.SetName(iface.Name)
			return nil
		}
		return syserr.ErrNoDevice
	}

	// Find the relevant device.
	for index, iface = range stack.Interfaces() {
		if iface.Name == ifr.Name() {
			found = true
			break
		}
	}
	if !found {
		return syserr.ErrNoDevice
	}

	switch arg {
	case linux.SIOCGIFINDEX:
		// Copy out the index to the data.
		usermem.ByteOrder.PutUint32(ifr.Data[:], uint32(index))

	case linux.SIOCGIFHWADDR:
		// Copy the hardware address out.
		//
		// Refer: https://linux.die.net/man/7/netdevice
		// SIOCGIFHWADDR, SIOCSIFHWADDR
		//
		// Get or set the hardware address of a device using
		// ifr_hwaddr. The hardware address is specified in a struct
		// sockaddr. sa_family contains the ARPHRD_* device type,
		// sa_data the L2 hardware address starting from byte 0. Setting
		// the hardware address is a privileged operation.
		usermem.ByteOrder.PutUint16(ifr.Data[:], iface.DeviceType)
		n := copy(ifr.Data[2:], iface.Addr)
		for i := 2 + n; i < len(ifr.Data); i++ {
			ifr.Data[i] = 0 // Clear padding.
		}

	case linux.SIOCGIFFLAGS:
		f, err := interfaceStatusFlags(stack, iface.Name)
		if err != nil {
			return err
		}
		// Drop the flags that don't fit in the size that we need to return. This
		// matches Linux behavior.
		usermem.ByteOrder.PutUint16(ifr.Data[:2], uint16(f))

	case linux.SIOCGIFADDR:
		// Copy the IPv4 address out.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			copy(ifr.Data[4:8], addr.Addr)
			break
		}

	case linux.SIOCGIFMETRIC:
		// Gets the metric of the device. As per netdevice(7), this
		// always just sets ifr_metric to 0.
		usermem.ByteOrder.PutUint32(ifr.Data[:4], 0)

	case linux.SIOCGIFMTU:
		// Gets the MTU of the device.
		usermem.ByteOrder.PutUint32(ifr.Data[:4], iface.MTU)

	case linux.SIOCGIFMAP:
		// Gets the hardware parameters of the device.
		// TODO(gvisor.dev/issue/505): Implement.

	case linux.SIOCGIFTXQLEN:
		// Gets the transmit queue length of the device.
		// TODO(gvisor.dev/issue/505): Implement.

	case linux.SIOCGIFDSTADDR:
		// Gets the destination address of a point-to-point device.
		// TODO(gvisor.dev/issue/505): Implement.

	case linux.SIOCGIFBRDADDR:
		// Gets the broadcast address of a device.
		// TODO(gvisor.dev/issue/505): Implement.

	case linux.SIOCGIFNETMASK:
		// Gets the network mask of a device.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			// Populate ifr.ifr_netmask (type sockaddr).
			usermem.ByteOrder.PutUint16(ifr.Data[0:2], uint16(linux.AF_INET))
			usermem.ByteOrder.PutUint16(ifr.Data[2:4], 0)
			var mask uint32 = 0xffffffff << (32 - addr.PrefixLen)
			// Netmask is expected to be returned as a big endian
			// value.
			binary.BigEndian.PutUint32(ifr.Data[4:8], mask)
			break
		}

	case linux.SIOCETHTOOL:
		// Stubbed out for now, Ideally we should implement the required
		// sub-commands for ETHTOOL
		//
		// See:
		// https://github.com/torvalds/linux/blob/aa0c9086b40c17a7ad94425b3b70dd1fdd7497bf/net/core/dev_ioctl.c
		return syserr.ErrEndpointOperation

	default:
		// Not a valid call.
		return syserr.ErrInvalidArgument
	}

	return nil
}

// ifconfIoctl populates a struct ifconf for the SIOCGIFCONF ioctl.
func ifconfIoctl(ctx context.Context, t *kernel.Task, io usermem.IO, ifc *linux.IFConf) error {
	// If Ptr is NULL, return the necessary buffer size via Len.
	// Otherwise, write up to Len bytes starting at Ptr containing ifreq
	// structs.
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		return syserr.ErrNoDevice.ToError()
	}

	if ifc.Ptr == 0 {
		ifc.Len = int32(len(stack.Interfaces())) * int32(linux.SizeOfIFReq)
		return nil
	}

	max := ifc.Len
	ifc.Len = 0
	for key, ifaceAddrs := range stack.InterfaceAddrs() {
		iface := stack.Interfaces()[key]
		for _, ifaceAddr := range ifaceAddrs {
			// Don't write past the end of the buffer.
			if ifc.Len+int32(linux.SizeOfIFReq) > max {
				break
			}
			if ifaceAddr.Family != linux.AF_INET {
				continue
			}

			// Populate ifr.ifr_addr.
			ifr := linux.IFReq{}
			ifr.SetName(iface.Name)
			usermem.ByteOrder.PutUint16(ifr.Data[0:2], uint16(ifaceAddr.Family))
			usermem.ByteOrder.PutUint16(ifr.Data[2:4], 0)
			copy(ifr.Data[4:8], ifaceAddr.Addr[:4])

			// Copy the ifr to userspace.
			dst := uintptr(ifc.Ptr) + uintptr(ifc.Len)
			ifc.Len += int32(linux.SizeOfIFReq)
			if _, err := ifr.CopyOut(t, usermem.Addr(dst)); err != nil {
				return err
			}
		}
	}
	return nil
}

// interfaceStatusFlags returns status flags for an interface in the stack.
// Flag values and meanings are described in greater detail in netdevice(7) in
// the SIOCGIFFLAGS section.
func interfaceStatusFlags(stack inet.Stack, name string) (uint32, *syserr.Error) {
	// We should only ever be passed a netstack.Stack.
	epstack, ok := stack.(*Stack)
	if !ok {
		return 0, errStackType
	}

	// Find the NIC corresponding to this interface.
	for _, info := range epstack.Stack.NICInfo() {
		if info.Name == name {
			return nicStateFlagsToLinux(info.Flags), nil
		}
	}
	return 0, syserr.ErrNoDevice
}

func nicStateFlagsToLinux(f stack.NICStateFlags) uint32 {
	var rv uint32
	if f.Up {
		rv |= linux.IFF_UP | linux.IFF_LOWER_UP
	}
	if f.Running {
		rv |= linux.IFF_RUNNING
	}
	if f.Promiscuous {
		rv |= linux.IFF_PROMISC
	}
	if f.Loopback {
		rv |= linux.IFF_LOOPBACK
	}
	return rv
}

// State implements socket.Socket.State. State translates the internal state
// returned by netstack to values defined by Linux.
func (s *socketOpsCommon) State() uint32 {
	if s.family != linux.AF_INET && s.family != linux.AF_INET6 {
		// States not implemented for this socket's family.
		return 0
	}

	switch {
	case s.skType == linux.SOCK_STREAM && s.protocol == 0 || s.protocol == syscall.IPPROTO_TCP:
		// TCP socket.
		switch tcp.EndpointState(s.Endpoint.State()) {
		case tcp.StateEstablished:
			return linux.TCP_ESTABLISHED
		case tcp.StateSynSent:
			return linux.TCP_SYN_SENT
		case tcp.StateSynRecv:
			return linux.TCP_SYN_RECV
		case tcp.StateFinWait1:
			return linux.TCP_FIN_WAIT1
		case tcp.StateFinWait2:
			return linux.TCP_FIN_WAIT2
		case tcp.StateTimeWait:
			return linux.TCP_TIME_WAIT
		case tcp.StateClose, tcp.StateInitial, tcp.StateBound, tcp.StateConnecting, tcp.StateError:
			return linux.TCP_CLOSE
		case tcp.StateCloseWait:
			return linux.TCP_CLOSE_WAIT
		case tcp.StateLastAck:
			return linux.TCP_LAST_ACK
		case tcp.StateListen:
			return linux.TCP_LISTEN
		case tcp.StateClosing:
			return linux.TCP_CLOSING
		default:
			// Internal or unknown state.
			return 0
		}
	case s.skType == linux.SOCK_DGRAM && s.protocol == 0 || s.protocol == syscall.IPPROTO_UDP:
		// UDP socket.
		switch udp.EndpointState(s.Endpoint.State()) {
		case udp.StateInitial, udp.StateBound, udp.StateClosed:
			return linux.TCP_CLOSE
		case udp.StateConnected:
			return linux.TCP_ESTABLISHED
		default:
			return 0
		}
	case s.skType == linux.SOCK_DGRAM && s.protocol == syscall.IPPROTO_ICMP || s.protocol == syscall.IPPROTO_ICMPV6:
		// TODO(b/112063468): Export states for ICMP sockets.
	case s.skType == linux.SOCK_RAW:
		// TODO(b/112063468): Export states for raw sockets.
	default:
		// Unknown transport protocol, how did we make this socket?
		log.Warningf("Unknown transport protocol for an existing socket: family=%v, type=%v, protocol=%v, internal type %v", s.family, s.skType, s.protocol, reflect.TypeOf(s.Endpoint).Elem())
		return 0
	}

	return 0
}

// Type implements socket.Socket.Type.
func (s *socketOpsCommon) Type() (family int, skType linux.SockType, protocol int) {
	return s.family, s.skType, s.protocol
}

// LINT.ThenChange(./netstack_vfs2.go)
