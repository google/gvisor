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

// Package tcpip provides the interfaces and related types that users of the
// tcpip stack will use in order to create endpoints used to send and receive
// data over the network stack.
//
// The starting point is the creation and configuration of a stack. A stack can
// be created by calling the New() function of the tcpip/stack/stack package;
// configuring a stack involves creating NICs (via calls to Stack.CreateNIC()),
// adding network addresses (via calls to Stack.AddAddress()), and
// setting a route table (via a call to Stack.SetRouteTable()).
//
// Once a stack is configured, endpoints can be created by calling
// Stack.NewEndpoint(). Such endpoints can be used to send/receive data, connect
// to peers, listen for connections, accept connections, etc., depending on the
// transport protocol selected.
package tcpip

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Error represents an error in the netstack error space. Using a special type
// ensures that errors outside of this space are not accidentally introduced.
//
// Note: to support save / restore, it is important that all tcpip errors have
// distinct error messages.
type Error struct {
	msg string

	ignoreStats bool
}

// String implements fmt.Stringer.String.
func (e *Error) String() string {
	return e.msg
}

// IgnoreStats indicates whether this error type should be included in failure
// counts in tcpip.Stats structs.
func (e *Error) IgnoreStats() bool {
	return e.ignoreStats
}

// Errors that can be returned by the network stack.
var (
	ErrUnknownProtocol       = &Error{msg: "unknown protocol"}
	ErrUnknownNICID          = &Error{msg: "unknown nic id"}
	ErrUnknownDevice         = &Error{msg: "unknown device"}
	ErrUnknownProtocolOption = &Error{msg: "unknown option for protocol"}
	ErrDuplicateNICID        = &Error{msg: "duplicate nic id"}
	ErrDuplicateAddress      = &Error{msg: "duplicate address"}
	ErrNoRoute               = &Error{msg: "no route"}
	ErrBadLinkEndpoint       = &Error{msg: "bad link layer endpoint"}
	ErrAlreadyBound          = &Error{msg: "endpoint already bound", ignoreStats: true}
	ErrInvalidEndpointState  = &Error{msg: "endpoint is in invalid state"}
	ErrAlreadyConnecting     = &Error{msg: "endpoint is already connecting", ignoreStats: true}
	ErrAlreadyConnected      = &Error{msg: "endpoint is already connected", ignoreStats: true}
	ErrNoPortAvailable       = &Error{msg: "no ports are available"}
	ErrPortInUse             = &Error{msg: "port is in use"}
	ErrBadLocalAddress       = &Error{msg: "bad local address"}
	ErrClosedForSend         = &Error{msg: "endpoint is closed for send"}
	ErrClosedForReceive      = &Error{msg: "endpoint is closed for receive"}
	ErrWouldBlock            = &Error{msg: "operation would block", ignoreStats: true}
	ErrConnectionRefused     = &Error{msg: "connection was refused"}
	ErrTimeout               = &Error{msg: "operation timed out"}
	ErrAborted               = &Error{msg: "operation aborted"}
	ErrConnectStarted        = &Error{msg: "connection attempt started", ignoreStats: true}
	ErrDestinationRequired   = &Error{msg: "destination address is required"}
	ErrNotSupported          = &Error{msg: "operation not supported"}
	ErrQueueSizeNotSupported = &Error{msg: "queue size querying not supported"}
	ErrNotConnected          = &Error{msg: "endpoint not connected"}
	ErrConnectionReset       = &Error{msg: "connection reset by peer"}
	ErrConnectionAborted     = &Error{msg: "connection aborted"}
	ErrNoSuchFile            = &Error{msg: "no such file"}
	ErrInvalidOptionValue    = &Error{msg: "invalid option value specified"}
	ErrNoLinkAddress         = &Error{msg: "no remote link address"}
	ErrBadAddress            = &Error{msg: "bad address"}
	ErrNetworkUnreachable    = &Error{msg: "network is unreachable"}
	ErrMessageTooLong        = &Error{msg: "message too long"}
	ErrNoBufferSpace         = &Error{msg: "no buffer space available"}
	ErrBroadcastDisabled     = &Error{msg: "broadcast socket option disabled"}
	ErrNotPermitted          = &Error{msg: "operation not permitted"}
)

// Errors related to Subnet
var (
	errSubnetLengthMismatch = errors.New("subnet length of address and mask differ")
	errSubnetAddressMasked  = errors.New("subnet address has bits set outside the mask")
)

// ErrSaveRejection indicates a failed save due to unsupported networking state.
// This type of errors is only used for save logic.
type ErrSaveRejection struct {
	Err error
}

// Error returns a sensible description of the save rejection error.
func (e ErrSaveRejection) Error() string {
	return "save rejected due to unsupported networking state: " + e.Err.Error()
}

// A Clock provides the current time.
//
// Times returned by a Clock should always be used for application-visible
// time. Only monotonic times should be used for netstack internal timekeeping.
type Clock interface {
	// NowNanoseconds returns the current real time as a number of
	// nanoseconds since the Unix epoch.
	NowNanoseconds() int64

	// NowMonotonic returns a monotonic time value.
	NowMonotonic() int64
}

// Address is a byte slice cast as a string that represents the address of a
// network node. Or, in the case of unix endpoints, it may represent a path.
type Address string

// AddressMask is a bitmask for an address.
type AddressMask string

// String implements Stringer.
func (a AddressMask) String() string {
	return Address(a).String()
}

// Subnet is a subnet defined by its address and mask.
type Subnet struct {
	address Address
	mask    AddressMask
}

// NewSubnet creates a new Subnet, checking that the address and mask are the same length.
func NewSubnet(a Address, m AddressMask) (Subnet, error) {
	if len(a) != len(m) {
		return Subnet{}, errSubnetLengthMismatch
	}
	for i := 0; i < len(a); i++ {
		if a[i]&^m[i] != 0 {
			return Subnet{}, errSubnetAddressMasked
		}
	}
	return Subnet{a, m}, nil
}

// Contains returns true iff the address is of the same length and matches the
// subnet address and mask.
func (s *Subnet) Contains(a Address) bool {
	if len(a) != len(s.address) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]&s.mask[i] != s.address[i] {
			return false
		}
	}
	return true
}

// ID returns the subnet ID.
func (s *Subnet) ID() Address {
	return s.address
}

// Bits returns the number of ones (network bits) and zeros (host bits) in the
// subnet mask.
func (s *Subnet) Bits() (ones int, zeros int) {
	for _, b := range []byte(s.mask) {
		for i := uint(0); i < 8; i++ {
			if b&(1<<i) == 0 {
				zeros++
			} else {
				ones++
			}
		}
	}
	return
}

// Prefix returns the number of bits before the first host bit.
func (s *Subnet) Prefix() int {
	for i, b := range []byte(s.mask) {
		for j := 7; j >= 0; j-- {
			if b&(1<<uint(j)) == 0 {
				return i*8 + 7 - j
			}
		}
	}
	return len(s.mask) * 8
}

// Mask returns the subnet mask.
func (s *Subnet) Mask() AddressMask {
	return s.mask
}

// NICID is a number that uniquely identifies a NIC.
type NICID int32

// ShutdownFlags represents flags that can be passed to the Shutdown() method
// of the Endpoint interface.
type ShutdownFlags int

// Values of the flags that can be passed to the Shutdown() method. They can
// be OR'ed together.
const (
	ShutdownRead ShutdownFlags = 1 << iota
	ShutdownWrite
)

// FullAddress represents a full transport node address, as required by the
// Connect() and Bind() methods.
//
// +stateify savable
type FullAddress struct {
	// NIC is the ID of the NIC this address refers to.
	//
	// This may not be used by all endpoint types.
	NIC NICID

	// Addr is the network address.
	Addr Address

	// Port is the transport port.
	//
	// This may not be used by all endpoint types.
	Port uint16
}

// Payload provides an interface around data that is being sent to an endpoint.
// This allows the endpoint to request the amount of data it needs based on
// internal buffers without exposing them. 'p.Get(p.Size())' reads all the data.
type Payload interface {
	// Get returns a slice containing exactly 'min(size, p.Size())' bytes.
	Get(size int) ([]byte, *Error)

	// Size returns the payload size.
	Size() int
}

// SlicePayload implements Payload on top of slices for convenience.
type SlicePayload []byte

// Get implements Payload.
func (s SlicePayload) Get(size int) ([]byte, *Error) {
	if size > s.Size() {
		size = s.Size()
	}
	return s[:size], nil
}

// Size implements Payload.
func (s SlicePayload) Size() int {
	return len(s)
}

// A ControlMessages contains socket control messages for IP sockets.
//
// +stateify savable
type ControlMessages struct {
	// HasTimestamp indicates whether Timestamp is valid/set.
	HasTimestamp bool

	// Timestamp is the time (in ns) that the last packed used to create
	// the read data was received.
	Timestamp int64
}

// Endpoint is the interface implemented by transport protocols (e.g., tcp, udp)
// that exposes functionality like read, write, connect, etc. to users of the
// networking stack.
type Endpoint interface {
	// Close puts the endpoint in a closed state and frees all resources
	// associated with it.
	Close()

	// Read reads data from the endpoint and optionally returns the sender.
	//
	// This method does not block if there is no data pending. It will also
	// either return an error or data, never both.
	Read(*FullAddress) (buffer.View, ControlMessages, *Error)

	// Write writes data to the endpoint's peer. This method does not block if
	// the data cannot be written.
	//
	// Unlike io.Writer.Write, Endpoint.Write transfers ownership of any bytes
	// successfully written to the Endpoint. That is, if a call to
	// Write(SlicePayload{data}) returns (n, err), it may retain data[:n], and
	// the caller should not use data[:n] after Write returns.
	//
	// Note that unlike io.Writer.Write, it is not an error for Write to
	// perform a partial write (if n > 0, no error may be returned). Only
	// stream (TCP) Endpoints may return partial writes, and even then only
	// in the case where writing additional data would block. Other Endpoints
	// will either write the entire message or return an error.
	//
	// For UDP and Ping sockets if address resolution is required,
	// ErrNoLinkAddress and a notification channel is returned for the caller to
	// block. Channel is closed once address resolution is complete (success or
	// not). The channel is only non-nil in this case.
	Write(Payload, WriteOptions) (uintptr, <-chan struct{}, *Error)

	// Peek reads data without consuming it from the endpoint.
	//
	// This method does not block if there is no data pending.
	Peek([][]byte) (uintptr, ControlMessages, *Error)

	// Connect connects the endpoint to its peer. Specifying a NIC is
	// optional.
	//
	// There are three classes of return values:
	//	nil -- the attempt to connect succeeded.
	//	ErrConnectStarted/ErrAlreadyConnecting -- the connect attempt started
	//		but hasn't completed yet. In this case, the caller must call Connect
	//		or GetSockOpt(ErrorOption) when the endpoint becomes writable to
	//		get the actual result. The first call to Connect after the socket has
	//		connected returns nil. Calling connect again results in ErrAlreadyConnected.
	//	Anything else -- the attempt to connect failed.
	Connect(address FullAddress) *Error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags ShutdownFlags) *Error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(backlog int) *Error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	Accept() (Endpoint, *waiter.Queue, *Error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	Bind(address FullAddress) *Error

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (FullAddress, *Error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (FullAddress, *Error)

	// Readiness returns the current readiness of the endpoint. For example,
	// if waiter.EventIn is set, the endpoint is immediately readable.
	Readiness(mask waiter.EventMask) waiter.EventMask

	// SetSockOpt sets a socket option. opt should be one of the *Option types.
	SetSockOpt(opt interface{}) *Error

	// GetSockOpt gets a socket option. opt should be a pointer to one of the
	// *Option types.
	GetSockOpt(opt interface{}) *Error

	// State returns a socket's lifecycle state. The returned value is
	// protocol-specific and is primarily used for diagnostics.
	State() uint32

	// ModerateRecvBuf should be called everytime data is copied to the user
	// space. This allows for dynamic tuning of recv buffer space for a
	// given socket.
	//
	// NOTE: This method is a no-op for sockets other than TCP.
	ModerateRecvBuf(copied int)
}

// WriteOptions contains options for Endpoint.Write.
type WriteOptions struct {
	// If To is not nil, write to the given address instead of the endpoint's
	// peer.
	To *FullAddress

	// More has the same semantics as Linux's MSG_MORE.
	More bool

	// EndOfRecord has the same semantics as Linux's MSG_EOR.
	EndOfRecord bool
}

// ErrorOption is used in GetSockOpt to specify that the last error reported by
// the endpoint should be cleared and returned.
type ErrorOption struct{}

// SendBufferSizeOption is used by SetSockOpt/GetSockOpt to specify the send
// buffer size option.
type SendBufferSizeOption int

// ReceiveBufferSizeOption is used by SetSockOpt/GetSockOpt to specify the
// receive buffer size option.
type ReceiveBufferSizeOption int

// SendQueueSizeOption is used in GetSockOpt to specify that the number of
// unread bytes in the output buffer should be returned.
type SendQueueSizeOption int

// ReceiveQueueSizeOption is used in GetSockOpt to specify that the number of
// unread bytes in the input buffer should be returned.
type ReceiveQueueSizeOption int

// V6OnlyOption is used by SetSockOpt/GetSockOpt to specify whether an IPv6
// socket is to be restricted to sending and receiving IPv6 packets only.
type V6OnlyOption int

// DelayOption is used by SetSockOpt/GetSockOpt to specify if data should be
// sent out immediately by the transport protocol. For TCP, it determines if the
// Nagle algorithm is on or off.
type DelayOption int

// CorkOption is used by SetSockOpt/GetSockOpt to specify if data should be
// held until segments are full by the TCP transport protocol.
type CorkOption int

// ReuseAddressOption is used by SetSockOpt/GetSockOpt to specify whether Bind()
// should allow reuse of local address.
type ReuseAddressOption int

// ReusePortOption is used by SetSockOpt/GetSockOpt to permit multiple sockets
// to be bound to an identical socket address.
type ReusePortOption int

// QuickAckOption is stubbed out in SetSockOpt/GetSockOpt.
type QuickAckOption int

// PasscredOption is used by SetSockOpt/GetSockOpt to specify whether
// SCM_CREDENTIALS socket control messages are enabled.
//
// Only supported on Unix sockets.
type PasscredOption int

// TCPInfoOption is used by GetSockOpt to expose TCP statistics.
//
// TODO(b/64800844): Add and populate stat fields.
type TCPInfoOption struct {
	RTT    time.Duration
	RTTVar time.Duration
}

// KeepaliveEnabledOption is used by SetSockOpt/GetSockOpt to specify whether
// TCP keepalive is enabled for this socket.
type KeepaliveEnabledOption int

// KeepaliveIdleOption is used by SetSockOpt/GetSockOpt to specify the time a
// connection must remain idle before the first TCP keepalive packet is sent.
// Once this time is reached, KeepaliveIntervalOption is used instead.
type KeepaliveIdleOption time.Duration

// KeepaliveIntervalOption is used by SetSockOpt/GetSockOpt to specify the
// interval between sending TCP keepalive packets.
type KeepaliveIntervalOption time.Duration

// KeepaliveCountOption is used by SetSockOpt/GetSockOpt to specify the number
// of un-ACKed TCP keepalives that will be sent before the connection is
// closed.
type KeepaliveCountOption int

// CongestionControlOption is used by SetSockOpt/GetSockOpt to set/get
// the current congestion control algorithm.
type CongestionControlOption string

// AvailableCongestionControlOption is used to query the supported congestion
// control algorithms.
type AvailableCongestionControlOption string

// ModerateReceiveBufferOption allows the caller to enable/disable TCP receive
// buffer moderation.
type ModerateReceiveBufferOption bool

// DelayedAckEnabledOption is used to enable/disable the use of delayed acks.
type DelayedAckEnabledOption bool

// MulticastTTLOption is used by SetSockOpt/GetSockOpt to control the default
// TTL value for multicast messages. The default is 1.
type MulticastTTLOption uint8

// MulticastInterfaceOption is used by SetSockOpt/GetSockOpt to specify a
// default interface for multicast.
type MulticastInterfaceOption struct {
	NIC           NICID
	InterfaceAddr Address
}

// MulticastLoopOption is used by SetSockOpt/GetSockOpt to specify whether
// multicast packets sent over a non-loopback interface will be looped back.
type MulticastLoopOption bool

// MembershipOption is used by SetSockOpt/GetSockOpt as an argument to
// AddMembershipOption and RemoveMembershipOption.
type MembershipOption struct {
	NIC           NICID
	InterfaceAddr Address
	MulticastAddr Address
}

// AddMembershipOption is used by SetSockOpt/GetSockOpt to join a multicast
// group identified by the given multicast address, on the interface matching
// the given interface address.
type AddMembershipOption MembershipOption

// RemoveMembershipOption is used by SetSockOpt/GetSockOpt to leave a multicast
// group identified by the given multicast address, on the interface matching
// the given interface address.
type RemoveMembershipOption MembershipOption

// OutOfBandInlineOption is used by SetSockOpt/GetSockOpt to specify whether
// TCP out-of-band data is delivered along with the normal in-band data.
type OutOfBandInlineOption int

// BroadcastOption is used by SetSockOpt/GetSockOpt to specify whether
// datagram sockets are allowed to send packets to a broadcast address.
type BroadcastOption int

// Route is a row in the routing table. It specifies through which NIC (and
// gateway) sets of packets should be routed. A row is considered viable if the
// masked target address matches the destination adddress in the row.
type Route struct {
	// Destination is the address that must be matched against the masked
	// target address to check if this row is viable.
	Destination Address

	// Mask specifies which bits of the Destination and the target address
	// must match for this row to be viable.
	Mask AddressMask

	// Gateway is the gateway to be used if this row is viable.
	Gateway Address

	// NIC is the id of the nic to be used if this row is viable.
	NIC NICID
}

// Match determines if r is viable for the given destination address.
func (r *Route) Match(addr Address) bool {
	if len(addr) != len(r.Destination) {
		return false
	}

	// Using header.Ipv4Broadcast would introduce an import cycle, so
	// we'll use a literal instead.
	if addr == "\xff\xff\xff\xff" {
		return true
	}

	for i := 0; i < len(r.Destination); i++ {
		if (addr[i] & r.Mask[i]) != r.Destination[i] {
			return false
		}
	}

	return true
}

// LinkEndpointID represents a data link layer endpoint.
type LinkEndpointID uint64

// TransportProtocolNumber is the number of a transport protocol.
type TransportProtocolNumber uint32

// NetworkProtocolNumber is the number of a network protocol.
type NetworkProtocolNumber uint32

// A StatCounter keeps track of a statistic.
type StatCounter struct {
	count uint64
}

// Increment adds one to the counter.
func (s *StatCounter) Increment() {
	s.IncrementBy(1)
}

// Value returns the current value of the counter.
func (s *StatCounter) Value() uint64 {
	return atomic.LoadUint64(&s.count)
}

// IncrementBy increments the counter by v.
func (s *StatCounter) IncrementBy(v uint64) {
	atomic.AddUint64(&s.count, v)
}

func (s *StatCounter) String() string {
	return strconv.FormatUint(s.Value(), 10)
}

// ICMPv4PacketStats enumerates counts for all ICMPv4 packet types.
type ICMPv4PacketStats struct {
	// Echo is the total number of ICMPv4 echo packets counted.
	Echo *StatCounter

	// EchoReply is the total number of ICMPv4 echo reply packets counted.
	EchoReply *StatCounter

	// DstUnreachable is the total number of ICMPv4 destination unreachable
	// packets counted.
	DstUnreachable *StatCounter

	// SrcQuench is the total number of ICMPv4 source quench packets
	// counted.
	SrcQuench *StatCounter

	// Redirect is the total number of ICMPv4 redirect packets counted.
	Redirect *StatCounter

	// TimeExceeded is the total number of ICMPv4 time exceeded packets
	// counted.
	TimeExceeded *StatCounter

	// ParamProblem is the total number of ICMPv4 parameter problem packets
	// counted.
	ParamProblem *StatCounter

	// Timestamp is the total number of ICMPv4 timestamp packets counted.
	Timestamp *StatCounter

	// TimestampReply is the total number of ICMPv4 timestamp reply packets
	// counted.
	TimestampReply *StatCounter

	// InfoRequest is the total number of ICMPv4 information request
	// packets counted.
	InfoRequest *StatCounter

	// InfoReply is the total number of ICMPv4 information reply packets
	// counted.
	InfoReply *StatCounter
}

// ICMPv6PacketStats enumerates counts for all ICMPv6 packet types.
type ICMPv6PacketStats struct {
	// EchoRequest is the total number of ICMPv6 echo request packets
	// counted.
	EchoRequest *StatCounter

	// EchoReply is the total number of ICMPv6 echo reply packets counted.
	EchoReply *StatCounter

	// DstUnreachable is the total number of ICMPv6 destination unreachable
	// packets counted.
	DstUnreachable *StatCounter

	// PacketTooBig is the total number of ICMPv6 packet too big packets
	// counted.
	PacketTooBig *StatCounter

	// TimeExceeded is the total number of ICMPv6 time exceeded packets
	// counted.
	TimeExceeded *StatCounter

	// ParamProblem is the total number of ICMPv6 parameter problem packets
	// counted.
	ParamProblem *StatCounter

	// RouterSolicit is the total number of ICMPv6 router solicit packets
	// counted.
	RouterSolicit *StatCounter

	// RouterAdvert is the total number of ICMPv6 router advert packets
	// counted.
	RouterAdvert *StatCounter

	// NeighborSolicit is the total number of ICMPv6 neighbor solicit
	// packets counted.
	NeighborSolicit *StatCounter

	// NeighborAdvert is the total number of ICMPv6 neighbor advert packets
	// counted.
	NeighborAdvert *StatCounter

	// RedirectMsg is the total number of ICMPv6 redirect message packets
	// counted.
	RedirectMsg *StatCounter
}

// ICMPv4SentPacketStats collects outbound ICMPv4-specific stats.
type ICMPv4SentPacketStats struct {
	ICMPv4PacketStats

	// Dropped is the total number of ICMPv4 packets dropped due to link
	// layer errors.
	Dropped *StatCounter
}

// ICMPv4ReceivedPacketStats collects inbound ICMPv4-specific stats.
type ICMPv4ReceivedPacketStats struct {
	ICMPv4PacketStats

	// Invalid is the total number of ICMPv4 packets received that the
	// transport layer could not parse.
	Invalid *StatCounter
}

// ICMPv6SentPacketStats collects outbound ICMPv6-specific stats.
type ICMPv6SentPacketStats struct {
	ICMPv6PacketStats

	// Dropped is the total number of ICMPv6 packets dropped due to link
	// layer errors.
	Dropped *StatCounter
}

// ICMPv6ReceivedPacketStats collects inbound ICMPv6-specific stats.
type ICMPv6ReceivedPacketStats struct {
	ICMPv6PacketStats

	// Invalid is the total number of ICMPv6 packets received that the
	// transport layer could not parse.
	Invalid *StatCounter
}

// ICMPStats collects ICMP-specific stats (both v4 and v6).
type ICMPStats struct {
	// ICMPv4SentPacketStats contains counts of sent packets by ICMPv4 packet type
	// and a single count of packets which failed to write to the link
	// layer.
	V4PacketsSent ICMPv4SentPacketStats

	// ICMPv4ReceivedPacketStats contains counts of received packets by ICMPv4
	// packet type and a single count of invalid packets received.
	V4PacketsReceived ICMPv4ReceivedPacketStats

	// ICMPv6SentPacketStats contains counts of sent packets by ICMPv6 packet type
	// and a single count of packets which failed to write to the link
	// layer.
	V6PacketsSent ICMPv6SentPacketStats

	// ICMPv6ReceivedPacketStats contains counts of received packets by ICMPv6
	// packet type and a single count of invalid packets received.
	V6PacketsReceived ICMPv6ReceivedPacketStats
}

// IPStats collects IP-specific stats (both v4 and v6).
type IPStats struct {
	// PacketsReceived is the total number of IP packets received from the
	// link layer in nic.DeliverNetworkPacket.
	PacketsReceived *StatCounter

	// InvalidAddressesReceived is the total number of IP packets received
	// with an unknown or invalid destination address.
	InvalidAddressesReceived *StatCounter

	// PacketsDelivered is the total number of incoming IP packets that
	// are successfully delivered to the transport layer via HandlePacket.
	PacketsDelivered *StatCounter

	// PacketsSent is the total number of IP packets sent via WritePacket.
	PacketsSent *StatCounter

	// OutgoingPacketErrors is the total number of IP packets which failed
	// to write to a link-layer endpoint.
	OutgoingPacketErrors *StatCounter
}

// TCPStats collects TCP-specific stats.
type TCPStats struct {
	// ActiveConnectionOpenings is the number of connections opened
	// successfully via Connect.
	ActiveConnectionOpenings *StatCounter

	// PassiveConnectionOpenings is the number of connections opened
	// successfully via Listen.
	PassiveConnectionOpenings *StatCounter

	// ListenOverflowSynDrop is the number of times the listen queue overflowed
	// and a SYN was dropped.
	ListenOverflowSynDrop *StatCounter

	// ListenOverflowAckDrop is the number of times the final ACK
	// in the handshake was dropped due to overflow.
	ListenOverflowAckDrop *StatCounter

	// ListenOverflowCookieSent is the number of times a SYN cookie was sent.
	ListenOverflowSynCookieSent *StatCounter

	// ListenOverflowSynCookieRcvd is the number of times a valid SYN
	// cookie was received.
	ListenOverflowSynCookieRcvd *StatCounter

	// ListenOverflowInvalidSynCookieRcvd is the number of times an invalid SYN cookie
	// was received.
	ListenOverflowInvalidSynCookieRcvd *StatCounter

	// FailedConnectionAttempts is the number of calls to Connect or Listen
	// (active and passive openings, respectively) that end in an error.
	FailedConnectionAttempts *StatCounter

	// ValidSegmentsReceived is the number of TCP segments received that
	// the transport layer successfully parsed.
	ValidSegmentsReceived *StatCounter

	// InvalidSegmentsReceived is the number of TCP segments received that
	// the transport layer could not parse.
	InvalidSegmentsReceived *StatCounter

	// SegmentsSent is the number of TCP segments sent.
	SegmentsSent *StatCounter

	// ResetsSent is the number of TCP resets sent.
	ResetsSent *StatCounter

	// ResetsReceived is the number of TCP resets received.
	ResetsReceived *StatCounter

	// Retransmits is the number of TCP segments retransmitted.
	Retransmits *StatCounter

	// FastRecovery is the number of times Fast Recovery was used to
	// recover from packet loss.
	FastRecovery *StatCounter

	// SACKRecovery is the number of times SACK Recovery was used to
	// recover from packet loss.
	SACKRecovery *StatCounter

	// SlowStartRetransmits is the number of segments retransmitted in slow
	// start.
	SlowStartRetransmits *StatCounter

	// FastRetransmit is the number of segments retransmitted in fast
	// recovery.
	FastRetransmit *StatCounter

	// Timeouts is the number of times the RTO expired.
	Timeouts *StatCounter

	// ChecksumErrors is the number of segments dropped due to bad checksums.
	ChecksumErrors *StatCounter
}

// UDPStats collects UDP-specific stats.
type UDPStats struct {
	// PacketsReceived is the number of UDP datagrams received via
	// HandlePacket.
	PacketsReceived *StatCounter

	// UnknownPortErrors is the number of incoming UDP datagrams dropped
	// because they did not have a known destination port.
	UnknownPortErrors *StatCounter

	// ReceiveBufferErrors is the number of incoming UDP datagrams dropped
	// due to the receiving buffer being in an invalid state.
	ReceiveBufferErrors *StatCounter

	// MalformedPacketsReceived is the number of incoming UDP datagrams
	// dropped due to the UDP header being in a malformed state.
	MalformedPacketsReceived *StatCounter

	// PacketsSent is the number of UDP datagrams sent via sendUDP.
	PacketsSent *StatCounter
}

// Stats holds statistics about the networking stack.
//
// All fields are optional.
type Stats struct {
	// UnknownProtocolRcvdPackets is the number of packets received by the
	// stack that were for an unknown or unsupported protocol.
	UnknownProtocolRcvdPackets *StatCounter

	// MalformedRcvPackets is the number of packets received by the stack
	// that were deemed malformed.
	MalformedRcvdPackets *StatCounter

	// DroppedPackets is the number of packets dropped due to full queues.
	DroppedPackets *StatCounter

	// ICMP breaks out ICMP-specific stats (both v4 and v6).
	ICMP ICMPStats

	// IP breaks out IP-specific stats (both v4 and v6).
	IP IPStats

	// TCP breaks out TCP-specific stats.
	TCP TCPStats

	// UDP breaks out UDP-specific stats.
	UDP UDPStats
}

func fillIn(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		switch v.Kind() {
		case reflect.Ptr:
			if s := v.Addr().Interface().(**StatCounter); *s == nil {
				*s = &StatCounter{}
			}
		case reflect.Struct:
			fillIn(v)
		default:
			panic(fmt.Sprintf("unexpected type %s", v.Type()))
		}
	}
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s Stats) FillIn() Stats {
	fillIn(reflect.ValueOf(&s).Elem())
	return s
}

// String implements the fmt.Stringer interface.
func (a Address) String() string {
	switch len(a) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", int(a[0]), int(a[1]), int(a[2]), int(a[3]))
	case 16:
		// Find the longest subsequence of hexadecimal zeros.
		start, end := -1, -1
		for i := 0; i < len(a); i += 2 {
			j := i
			for j < len(a) && a[j] == 0 && a[j+1] == 0 {
				j += 2
			}
			if j > i+2 && j-i > end-start {
				start, end = i, j
			}
		}

		var b strings.Builder
		for i := 0; i < len(a); i += 2 {
			if i == start {
				b.WriteString("::")
				i = end
				if end >= len(a) {
					break
				}
			} else if i > 0 {
				b.WriteByte(':')
			}
			v := uint16(a[i+0])<<8 | uint16(a[i+1])
			if v == 0 {
				b.WriteByte('0')
			} else {
				const digits = "0123456789abcdef"
				for i := uint(3); i < 4; i-- {
					if v := v >> (i * 4); v != 0 {
						b.WriteByte(digits[v&0xf])
					}
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

// To4 converts the IPv4 address to a 4-byte representation.
// If the address is not an IPv4 address, To4 returns "".
func (a Address) To4() Address {
	const (
		ipv4len = 4
		ipv6len = 16
	)
	if len(a) == ipv4len {
		return a
	}
	if len(a) == ipv6len &&
		isZeros(a[0:10]) &&
		a[10] == 0xff &&
		a[11] == 0xff {
		return a[12:16]
	}
	return ""
}

// isZeros reports whether a is all zeros.
func isZeros(a Address) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != 0 {
			return false
		}
	}
	return true
}

// LinkAddress is a byte slice cast as a string that represents a link address.
// It is typically a 6-byte MAC address.
type LinkAddress string

// String implements the fmt.Stringer interface.
func (a LinkAddress) String() string {
	switch len(a) {
	case 6:
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

// ParseMACAddress parses an IEEE 802 address.
//
// It must be in the format aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
func ParseMACAddress(s string) (LinkAddress, error) {
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ':' || c == '-'
	})
	if len(parts) != 6 {
		return "", fmt.Errorf("inconsistent parts: %s", s)
	}
	addr := make([]byte, 0, len(parts))
	for _, part := range parts {
		u, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex digits: %s", s)
		}
		addr = append(addr, byte(u))
	}
	return LinkAddress(addr), nil
}

// ProtocolAddress is an address and the network protocol it is associated
// with.
type ProtocolAddress struct {
	// Protocol is the protocol of the address.
	Protocol NetworkProtocolNumber

	// Address is a network address.
	Address Address
}

// danglingEndpointsMu protects access to danglingEndpoints.
var danglingEndpointsMu sync.Mutex

// danglingEndpoints tracks all dangling endpoints no longer owned by the app.
var danglingEndpoints = make(map[Endpoint]struct{})

// GetDanglingEndpoints returns all dangling endpoints.
func GetDanglingEndpoints() []Endpoint {
	es := make([]Endpoint, 0, len(danglingEndpoints))
	danglingEndpointsMu.Lock()
	for e := range danglingEndpoints {
		es = append(es, e)
	}
	danglingEndpointsMu.Unlock()
	return es
}

// AddDanglingEndpoint adds a dangling endpoint.
func AddDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	danglingEndpoints[e] = struct{}{}
	danglingEndpointsMu.Unlock()
}

// DeleteDanglingEndpoint removes a dangling endpoint.
func DeleteDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	delete(danglingEndpoints, e)
	danglingEndpointsMu.Unlock()
}

// AsyncLoading is the global barrier for asynchronous endpoint loading
// activities.
var AsyncLoading sync.WaitGroup
