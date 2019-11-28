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
	"math/bits"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
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
	if e == nil {
		return "<nil>"
	}
	return e.msg
}

// IgnoreStats indicates whether this error type should be included in failure
// counts in tcpip.Stats structs.
func (e *Error) IgnoreStats() bool {
	return e.ignoreStats
}

// Errors that can be returned by the network stack.
var (
	ErrUnknownProtocol           = &Error{msg: "unknown protocol"}
	ErrUnknownNICID              = &Error{msg: "unknown nic id"}
	ErrUnknownDevice             = &Error{msg: "unknown device"}
	ErrUnknownProtocolOption     = &Error{msg: "unknown option for protocol"}
	ErrDuplicateNICID            = &Error{msg: "duplicate nic id"}
	ErrDuplicateAddress          = &Error{msg: "duplicate address"}
	ErrNoRoute                   = &Error{msg: "no route"}
	ErrBadLinkEndpoint           = &Error{msg: "bad link layer endpoint"}
	ErrAlreadyBound              = &Error{msg: "endpoint already bound", ignoreStats: true}
	ErrInvalidEndpointState      = &Error{msg: "endpoint is in invalid state"}
	ErrAlreadyConnecting         = &Error{msg: "endpoint is already connecting", ignoreStats: true}
	ErrAlreadyConnected          = &Error{msg: "endpoint is already connected", ignoreStats: true}
	ErrNoPortAvailable           = &Error{msg: "no ports are available"}
	ErrPortInUse                 = &Error{msg: "port is in use"}
	ErrBadLocalAddress           = &Error{msg: "bad local address"}
	ErrClosedForSend             = &Error{msg: "endpoint is closed for send"}
	ErrClosedForReceive          = &Error{msg: "endpoint is closed for receive"}
	ErrWouldBlock                = &Error{msg: "operation would block", ignoreStats: true}
	ErrConnectionRefused         = &Error{msg: "connection was refused"}
	ErrTimeout                   = &Error{msg: "operation timed out"}
	ErrAborted                   = &Error{msg: "operation aborted"}
	ErrConnectStarted            = &Error{msg: "connection attempt started", ignoreStats: true}
	ErrDestinationRequired       = &Error{msg: "destination address is required"}
	ErrNotSupported              = &Error{msg: "operation not supported"}
	ErrQueueSizeNotSupported     = &Error{msg: "queue size querying not supported"}
	ErrNotConnected              = &Error{msg: "endpoint not connected"}
	ErrConnectionReset           = &Error{msg: "connection reset by peer"}
	ErrConnectionAborted         = &Error{msg: "connection aborted"}
	ErrNoSuchFile                = &Error{msg: "no such file"}
	ErrInvalidOptionValue        = &Error{msg: "invalid option value specified"}
	ErrNoLinkAddress             = &Error{msg: "no remote link address"}
	ErrBadAddress                = &Error{msg: "bad address"}
	ErrNetworkUnreachable        = &Error{msg: "network is unreachable"}
	ErrMessageTooLong            = &Error{msg: "message too long"}
	ErrNoBufferSpace             = &Error{msg: "no buffer space available"}
	ErrBroadcastDisabled         = &Error{msg: "broadcast socket option disabled"}
	ErrNotPermitted              = &Error{msg: "operation not permitted"}
	ErrAddressFamilyNotSupported = &Error{msg: "address family not supported by protocol"}
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
func (m AddressMask) String() string {
	return Address(m).String()
}

// Prefix returns the number of bits before the first host bit.
func (m AddressMask) Prefix() int {
	p := 0
	for _, b := range []byte(m) {
		p += bits.LeadingZeros8(^b)
	}
	return p
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

// String implements Stringer.
func (s Subnet) String() string {
	return fmt.Sprintf("%s/%d", s.ID(), s.Prefix())
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
	ones = s.mask.Prefix()
	return ones, len(s.mask)*8 - ones
}

// Prefix returns the number of bits before the first host bit.
func (s *Subnet) Prefix() int {
	return s.mask.Prefix()
}

// Mask returns the subnet mask.
func (s *Subnet) Mask() AddressMask {
	return s.mask
}

// Broadcast returns the subnet's broadcast address.
func (s *Subnet) Broadcast() Address {
	addr := []byte(s.address)
	for i := range addr {
		addr[i] |= ^s.mask[i]
	}
	return Address(addr)
}

// Equal returns true if s equals o.
//
// Needed to use cmp.Equal on Subnet as its fields are unexported.
func (s Subnet) Equal(o Subnet) bool {
	return s == o
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

	// Addr is the network or link layer address.
	Addr Address

	// Port is the transport port.
	//
	// This may not be used by all endpoint types.
	Port uint16
}

// Payloader is an interface that provides data.
//
// This interface allows the endpoint to request the amount of data it needs
// based on internal buffers without exposing them.
type Payloader interface {
	// FullPayload returns all available bytes.
	FullPayload() ([]byte, *Error)

	// Payload returns a slice containing at most size bytes.
	Payload(size int) ([]byte, *Error)
}

// SlicePayload implements Payloader for slices.
//
// This is typically used for tests.
type SlicePayload []byte

// FullPayload implements Payloader.FullPayload.
func (s SlicePayload) FullPayload() ([]byte, *Error) {
	return s, nil
}

// Payload implements Payloader.Payload.
func (s SlicePayload) Payload(size int) ([]byte, *Error) {
	if size > len(s) {
		size = len(s)
	}
	return s[:size], nil
}

// A ControlMessages contains socket control messages for IP sockets.
//
// +stateify savable
type ControlMessages struct {
	// HasTimestamp indicates whether Timestamp is valid/set.
	HasTimestamp bool

	// Timestamp is the time (in ns) that the last packet used to create
	// the read data was received.
	Timestamp int64

	// HasInq indicates whether Inq is valid/set.
	HasInq bool

	// Inq is the number of bytes ready to be received.
	Inq int32

	// HasTOS indicates whether Tos is valid/set.
	HasTOS bool

	// TOS is the IPv4 type of service of the associated packet.
	TOS int8

	// HasTClass indicates whether Tclass is valid/set.
	HasTClass bool

	// Tclass is the IPv6 traffic class of the associated packet.
	TClass int32
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
	Write(Payloader, WriteOptions) (int64, <-chan struct{}, *Error)

	// Peek reads data without consuming it from the endpoint.
	//
	// This method does not block if there is no data pending.
	Peek([][]byte) (int64, ControlMessages, *Error)

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
	//
	// If address.Addr is empty, this means that Enpoint has to be
	// disconnected if this is supported, otherwise
	// ErrAddressFamilyNotSupported must be returned.
	Connect(address FullAddress) *Error

	// Disconnect disconnects the endpoint from its peer.
	Disconnect() *Error

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

	// SetSockOptInt sets a socket option, for simple cases where a value
	// has the int type.
	SetSockOptInt(opt SockOpt, v int) *Error

	// GetSockOpt gets a socket option. opt should be a pointer to one of the
	// *Option types.
	GetSockOpt(opt interface{}) *Error

	// GetSockOptInt gets a socket option for simple cases where a return
	// value has the int type.
	GetSockOptInt(SockOpt) (int, *Error)

	// State returns a socket's lifecycle state. The returned value is
	// protocol-specific and is primarily used for diagnostics.
	State() uint32

	// ModerateRecvBuf should be called everytime data is copied to the user
	// space. This allows for dynamic tuning of recv buffer space for a
	// given socket.
	//
	// NOTE: This method is a no-op for sockets other than TCP.
	ModerateRecvBuf(copied int)

	// IPTables returns the iptables for this endpoint's stack.
	IPTables() (iptables.IPTables, error)

	// Info returns a copy to the transport endpoint info.
	Info() EndpointInfo

	// Stats returns a reference to the endpoint stats.
	Stats() EndpointStats
}

// EndpointInfo is the interface implemented by each endpoint info struct.
type EndpointInfo interface {
	// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
	// marker interface.
	IsEndpointInfo()
}

// EndpointStats is the interface implemented by each endpoint stats struct.
type EndpointStats interface {
	// IsEndpointStats is an empty method to implement the tcpip.EndpointStats
	// marker interface.
	IsEndpointStats()
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

	// Atomic means that all data fetched from Payloader must be written to the
	// endpoint. If Atomic is false, then data fetched from the Payloader may be
	// discarded if available endpoint buffer space is unsufficient.
	Atomic bool
}

// SockOpt represents socket options which values have the int type.
type SockOpt int

const (
	// ReceiveQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the input buffer should be returned.
	ReceiveQueueSizeOption SockOpt = iota

	// SendBufferSizeOption is used by SetSockOptInt/GetSockOptInt to
	// specify the send buffer size option.
	SendBufferSizeOption

	// ReceiveBufferSizeOption is used by SetSockOptInt/GetSockOptInt to
	// specify the receive buffer size option.
	ReceiveBufferSizeOption

	// SendQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the output buffer should be returned.
	SendQueueSizeOption

	// DelayOption is used by SetSockOpt/GetSockOpt to specify if data
	// should be sent out immediately by the transport protocol. For TCP,
	// it determines if the Nagle algorithm is on or off.
	DelayOption

	// TODO(b/137664753): convert all int socket options to be handled via
	// GetSockOptInt.
)

// ErrorOption is used in GetSockOpt to specify that the last error reported by
// the endpoint should be cleared and returned.
type ErrorOption struct{}

// V6OnlyOption is used by SetSockOpt/GetSockOpt to specify whether an IPv6
// socket is to be restricted to sending and receiving IPv6 packets only.
type V6OnlyOption int

// CorkOption is used by SetSockOpt/GetSockOpt to specify if data should be
// held until segments are full by the TCP transport protocol.
type CorkOption int

// ReuseAddressOption is used by SetSockOpt/GetSockOpt to specify whether Bind()
// should allow reuse of local address.
type ReuseAddressOption int

// ReusePortOption is used by SetSockOpt/GetSockOpt to permit multiple sockets
// to be bound to an identical socket address.
type ReusePortOption int

// BindToDeviceOption is used by SetSockOpt/GetSockOpt to specify that sockets
// should bind only on a specific NIC.
type BindToDeviceOption string

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

// MaxSegOption is used by SetSockOpt/GetSockOpt to set/get the current
// Maximum Segment Size(MSS) value as specified using the TCP_MAXSEG option.
type MaxSegOption int

// TTLOption is used by SetSockOpt/GetSockOpt to control the default TTL/hop
// limit value for unicast messages. The default is protocol specific.
//
// A zero value indicates the default.
type TTLOption uint8

// TCPLingerTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TCP_FIN_WAIT_2 state
// before being marked closed.
type TCPLingerTimeoutOption time.Duration

// TCPTimeWaitTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TIME_WAIT state
// before being marked closed.
type TCPTimeWaitTimeoutOption time.Duration

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

// DefaultTTLOption is used by stack.(*Stack).NetworkProtocolOption to specify
// a default TTL.
type DefaultTTLOption uint8

// IPv4TOSOption is used by SetSockOpt/GetSockOpt to specify TOS
// for all subsequent outgoing IPv4 packets from the endpoint.
type IPv4TOSOption uint8

// IPv6TrafficClassOption is used by SetSockOpt/GetSockOpt to specify TOS
// for all subsequent outgoing IPv6 packets from the endpoint.
type IPv6TrafficClassOption uint8

// Route is a row in the routing table. It specifies through which NIC (and
// gateway) sets of packets should be routed. A row is considered viable if the
// masked target address matches the destination address in the row.
type Route struct {
	// Destination must contain the target address for this row to be viable.
	Destination Subnet

	// Gateway is the gateway to be used if this row is viable.
	Gateway Address

	// NIC is the id of the nic to be used if this row is viable.
	NIC NICID
}

// String implements the fmt.Stringer interface.
func (r Route) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s", r.Destination)
	if len(r.Gateway) > 0 {
		fmt.Fprintf(&out, " via %s", r.Gateway)
	}
	fmt.Fprintf(&out, " nic %d", r.NIC)
	return out.String()
}

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

// Decrement minuses one to the counter.
func (s *StatCounter) Decrement() {
	s.IncrementBy(^uint64(0))
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

	// RateLimited is the total number of ICMPv6 packets dropped due to
	// rate limit being exceeded.
	RateLimited *StatCounter
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

	// RateLimited is the total number of ICMPv6 packets dropped due to
	// rate limit being exceeded.
	RateLimited *StatCounter
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

	// MalformedPacketsReceived is the total number of IP Packets that were
	// dropped due to the IP packet header failing validation checks.
	MalformedPacketsReceived *StatCounter

	// MalformedFragmentsReceived is the total number of IP Fragments that were
	// dropped due to the fragment failing validation checks.
	MalformedFragmentsReceived *StatCounter
}

// TCPStats collects TCP-specific stats.
type TCPStats struct {
	// ActiveConnectionOpenings is the number of connections opened
	// successfully via Connect.
	ActiveConnectionOpenings *StatCounter

	// PassiveConnectionOpenings is the number of connections opened
	// successfully via Listen.
	PassiveConnectionOpenings *StatCounter

	// CurrentEstablished is the number of TCP connections for which the
	// current state is either ESTABLISHED or CLOSE-WAIT.
	CurrentEstablished *StatCounter

	// EstablishedResets is the number of times TCP connections have made
	// a direct transition to the CLOSED state from either the
	// ESTABLISHED state or the CLOSE-WAIT state.
	EstablishedResets *StatCounter

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

	// SegmentSendErrors is the number of TCP segments failed to be sent.
	SegmentSendErrors *StatCounter

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

	// PacketSendErrors is the number of datagrams failed to be sent.
	PacketSendErrors *StatCounter
}

// Stats holds statistics about the networking stack.
//
// All fields are optional.
type Stats struct {
	// UnknownProtocolRcvdPackets is the number of packets received by the
	// stack that were for an unknown or unsupported protocol.
	UnknownProtocolRcvdPackets *StatCounter

	// MalformedRcvdPackets is the number of packets received by the stack
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

// ReceiveErrors collects packet receive errors within transport endpoint.
type ReceiveErrors struct {
	// ReceiveBufferOverflow is the number of received packets dropped
	// due to the receive buffer being full.
	ReceiveBufferOverflow StatCounter

	// MalformedPacketsReceived is the number of incoming packets
	// dropped due to the packet header being in a malformed state.
	MalformedPacketsReceived StatCounter

	// ClosedReceiver is the number of received packets dropped because
	// of receiving endpoint state being closed.
	ClosedReceiver StatCounter
}

// SendErrors collects packet send errors within the transport layer for
// an endpoint.
type SendErrors struct {
	// SendToNetworkFailed is the number of packets failed to be written to
	// the network endpoint.
	SendToNetworkFailed StatCounter

	// NoRoute is the number of times we failed to resolve IP route.
	NoRoute StatCounter

	// NoLinkAddr is the number of times we failed to resolve ARP.
	NoLinkAddr StatCounter
}

// ReadErrors collects segment read errors from an endpoint read call.
type ReadErrors struct {
	// ReadClosed is the number of received packet drops because the endpoint
	// was shutdown for read.
	ReadClosed StatCounter

	// InvalidEndpointState is the number of times we found the endpoint state
	// to be unexpected.
	InvalidEndpointState StatCounter
}

// WriteErrors collects packet write errors from an endpoint write call.
type WriteErrors struct {
	// WriteClosed is the number of packet drops because the endpoint
	// was shutdown for write.
	WriteClosed StatCounter

	// InvalidEndpointState is the number of times we found the endpoint state
	// to be unexpected.
	InvalidEndpointState StatCounter

	// InvalidArgs is the number of times invalid input arguments were
	// provided for endpoint Write call.
	InvalidArgs StatCounter
}

// TransportEndpointStats collects statistics about the endpoint.
type TransportEndpointStats struct {
	// PacketsReceived is the number of successful packet receives.
	PacketsReceived StatCounter

	// PacketsSent is the number of successful packet sends.
	PacketsSent StatCounter

	// ReceiveErrors collects packet receive errors within transport layer.
	ReceiveErrors ReceiveErrors

	// ReadErrors collects packet read errors from an endpoint read call.
	ReadErrors ReadErrors

	// SendErrors collects packet send errors within the transport layer.
	SendErrors SendErrors

	// WriteErrors collects packet write errors from an endpoint write call.
	WriteErrors WriteErrors
}

// IsEndpointStats is an empty method to implement the tcpip.EndpointStats
// marker interface.
func (*TransportEndpointStats) IsEndpointStats() {}

func fillIn(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		if s, ok := v.Addr().Interface().(**StatCounter); ok {
			if *s == nil {
				*s = new(StatCounter)
			}
		} else {
			fillIn(v)
		}
	}
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s Stats) FillIn() Stats {
	fillIn(reflect.ValueOf(&s).Elem())
	return s
}

// Clone returns a copy of the TransportEndpointStats by atomically reading
// each field.
func (src *TransportEndpointStats) Clone() TransportEndpointStats {
	var dst TransportEndpointStats
	clone(reflect.ValueOf(&dst).Elem(), reflect.ValueOf(src).Elem())
	return dst
}

func clone(dst reflect.Value, src reflect.Value) {
	for i := 0; i < dst.NumField(); i++ {
		d := dst.Field(i)
		s := src.Field(i)
		if c, ok := s.Addr().Interface().(*StatCounter); ok {
			d.Addr().Interface().(*StatCounter).IncrementBy(c.Value())
		} else {
			clone(d, s)
		}
	}
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

// AddressWithPrefix is an address with its subnet prefix length.
type AddressWithPrefix struct {
	// Address is a network address.
	Address Address

	// PrefixLen is the subnet prefix length.
	PrefixLen int
}

// String implements the fmt.Stringer interface.
func (a AddressWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", a.Address, a.PrefixLen)
}

// Subnet converts the address and prefix into a Subnet value and returns it.
func (a AddressWithPrefix) Subnet() Subnet {
	addrLen := len(a.Address)
	if a.PrefixLen <= 0 {
		return Subnet{
			address: Address(strings.Repeat("\x00", addrLen)),
			mask:    AddressMask(strings.Repeat("\x00", addrLen)),
		}
	}
	if a.PrefixLen >= addrLen*8 {
		return Subnet{
			address: a.Address,
			mask:    AddressMask(strings.Repeat("\xff", addrLen)),
		}
	}

	sa := make([]byte, addrLen)
	sm := make([]byte, addrLen)
	n := uint(a.PrefixLen)
	for i := 0; i < addrLen; i++ {
		if n >= 8 {
			sa[i] = a.Address[i]
			sm[i] = 0xff
			n -= 8
			continue
		}
		sm[i] = ^byte(0xff >> n)
		sa[i] = a.Address[i] & sm[i]
		n = 0
	}

	// For extra caution, call NewSubnet rather than directly creating the Subnet
	// value. If that fails it indicates a serious bug in this code, so panic is
	// in order.
	s, err := NewSubnet(Address(sa), AddressMask(sm))
	if err != nil {
		panic("invalid subnet: " + err.Error())
	}
	return s
}

// ProtocolAddress is an address and the network protocol it is associated
// with.
type ProtocolAddress struct {
	// Protocol is the protocol of the address.
	Protocol NetworkProtocolNumber

	// AddressWithPrefix is a network address with its subnet prefix length.
	AddressWithPrefix AddressWithPrefix
}

var (
	// danglingEndpointsMu protects access to danglingEndpoints.
	danglingEndpointsMu sync.Mutex

	// danglingEndpoints tracks all dangling endpoints no longer owned by the app.
	danglingEndpoints = make(map[Endpoint]struct{})
)

// GetDanglingEndpoints returns all dangling endpoints.
func GetDanglingEndpoints() []Endpoint {
	danglingEndpointsMu.Lock()
	es := make([]Endpoint, 0, len(danglingEndpoints))
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
