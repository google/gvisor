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
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Using header.IPv4AddressSize would cause an import cycle.
const ipv4AddressSize = 4

// Error represents an error in the netstack error space. Using a special type
// ensures that errors outside of this space are not accidentally introduced.
//
// All errors must have unique msg strings.
//
// +stateify savable
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
	ErrMalformedHeader           = &Error{msg: "header is malformed"}
)

var messageToError map[string]*Error

var populate sync.Once

// StringToError converts an error message to the error.
func StringToError(s string) *Error {
	populate.Do(func() {
		var errors = []*Error{
			ErrUnknownProtocol,
			ErrUnknownNICID,
			ErrUnknownDevice,
			ErrUnknownProtocolOption,
			ErrDuplicateNICID,
			ErrDuplicateAddress,
			ErrNoRoute,
			ErrBadLinkEndpoint,
			ErrAlreadyBound,
			ErrInvalidEndpointState,
			ErrAlreadyConnecting,
			ErrAlreadyConnected,
			ErrNoPortAvailable,
			ErrPortInUse,
			ErrBadLocalAddress,
			ErrClosedForSend,
			ErrClosedForReceive,
			ErrWouldBlock,
			ErrConnectionRefused,
			ErrTimeout,
			ErrAborted,
			ErrConnectStarted,
			ErrDestinationRequired,
			ErrNotSupported,
			ErrQueueSizeNotSupported,
			ErrNotConnected,
			ErrConnectionReset,
			ErrConnectionAborted,
			ErrNoSuchFile,
			ErrInvalidOptionValue,
			ErrNoLinkAddress,
			ErrBadAddress,
			ErrNetworkUnreachable,
			ErrMessageTooLong,
			ErrNoBufferSpace,
			ErrBroadcastDisabled,
			ErrNotPermitted,
			ErrAddressFamilyNotSupported,
			ErrMalformedHeader,
		}

		messageToError = make(map[string]*Error)
		for _, e := range errors {
			if messageToError[e.String()] != nil {
				panic("tcpip errors with duplicated message: " + e.String())
			}
			messageToError[e.String()] = e
		}
	})

	e, ok := messageToError[s]
	if !ok {
		panic("unknown error message: " + s)
	}

	return e
}

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

// A Clock provides the current time and schedules work for execution.
//
// Times returned by a Clock should always be used for application-visible
// time. Only monotonic times should be used for netstack internal timekeeping.
type Clock interface {
	// NowNanoseconds returns the current real time as a number of
	// nanoseconds since the Unix epoch.
	NowNanoseconds() int64

	// NowMonotonic returns a monotonic time value.
	NowMonotonic() int64

	// AfterFunc waits for the duration to elapse and then calls f in its own
	// goroutine. It returns a Timer that can be used to cancel the call using
	// its Stop method.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer represents a single event. A Timer must be created with
// Clock.AfterFunc.
type Timer interface {
	// Stop prevents the Timer from firing. It returns true if the call stops the
	// timer, false if the timer has already expired or been stopped.
	//
	// If Stop returns false, then the timer has already expired and the function
	// f of Clock.AfterFunc(d, f) has been started in its own goroutine; Stop
	// does not wait for f to complete before returning. If the caller needs to
	// know whether f is completed, it must coordinate with f explicitly.
	Stop() bool

	// Reset changes the timer to expire after duration d.
	//
	// Reset should be invoked only on stopped or expired timers. If the timer is
	// known to have expired, Reset can be used directly. Otherwise, the caller
	// must coordinate with the function f of Clock.AfterFunc(d, f).
	Reset(d time.Duration)
}

// Address is a byte slice cast as a string that represents the address of a
// network node. Or, in the case of unix endpoints, it may represent a path.
type Address string

// WithPrefix returns the address with a prefix that represents a point subnet.
func (a Address) WithPrefix() AddressWithPrefix {
	return AddressWithPrefix{
		Address:   a,
		PrefixLen: len(a) * 8,
	}
}

// Unspecified returns true if the address is unspecified.
func (a Address) Unspecified() bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

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

// IsBroadcast returns true if the address is considered a broadcast address.
func (s *Subnet) IsBroadcast(address Address) bool {
	// Only IPv4 supports the notion of a broadcast address.
	if len(address) != ipv4AddressSize {
		return false
	}

	// Normally, we would just compare address with the subnet's broadcast
	// address but there is an exception where a simple comparison is not
	// correct. This exception is for /31 and /32 IPv4 subnets where all
	// addresses are considered valid host addresses.
	//
	// For /31 subnets, the case is easy. RFC 3021 Section 2.1 states that
	// both addresses in a /31 subnet "MUST be interpreted as host addresses."
	//
	// For /32, the case is a bit more vague. RFC 3021 makes no mention of /32
	// subnets. However, the same reasoning applies - if an exception is not
	// made, then there do not exist any host addresses in a /32 subnet. RFC
	// 4632 Section 3.1 also vaguely implies this interpretation by referring
	// to addresses in /32 subnets as "host routes."
	return s.Prefix() <= 30 && s.Broadcast() == address
}

// Equal returns true if this Subnet is equal to the given Subnet.
func (s Subnet) Equal(o Subnet) bool {
	// If this changes, update Route.Equal accordingly.
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

// PacketType is used to indicate the destination of the packet.
type PacketType uint8

const (
	// PacketHost indicates a packet addressed to the local host.
	PacketHost PacketType = iota

	// PacketOtherHost indicates an outgoing packet addressed to
	// another host caught by a NIC in promiscuous mode.
	PacketOtherHost

	// PacketOutgoing for a packet originating from the local host
	// that is looped back to a packet socket.
	PacketOutgoing

	// PacketBroadcast indicates a link layer broadcast packet.
	PacketBroadcast

	// PacketMulticast indicates a link layer multicast packet.
	PacketMulticast
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
	TOS uint8

	// HasTClass indicates whether TClass is valid/set.
	HasTClass bool

	// TClass is the IPv6 traffic class of the associated packet.
	TClass uint32

	// HasIPPacketInfo indicates whether PacketInfo is set.
	HasIPPacketInfo bool

	// PacketInfo holds interface and address data on an incoming packet.
	PacketInfo IPPacketInfo

	// HasOriginalDestinationAddress indicates whether OriginalDstAddress is
	// set.
	HasOriginalDstAddress bool

	// OriginalDestinationAddress holds the original destination address
	// and port of the incoming packet.
	OriginalDstAddress FullAddress

	// SockErr is the dequeued socket error on recvmsg(MSG_ERRQUEUE).
	SockErr *SockError
}

// PacketOwner is used to get UID and GID of the packet.
type PacketOwner interface {
	// UID returns UID of the packet.
	UID() uint32

	// GID returns GID of the packet.
	GID() uint32
}

// Endpoint is the interface implemented by transport protocols (e.g., tcp, udp)
// that exposes functionality like read, write, connect, etc. to users of the
// networking stack.
type Endpoint interface {
	// Close puts the endpoint in a closed state and frees all resources
	// associated with it. Close initiates the teardown process, the
	// Endpoint may not be fully closed when Close returns.
	Close()

	// Abort initiates an expedited endpoint teardown. As compared to
	// Close, Abort prioritizes closing the Endpoint quickly over cleanly.
	// Abort is best effort; implementing Abort with Close is acceptable.
	Abort()

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
	Peek([][]byte) (int64, *Error)

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
	//
	// If peerAddr is not nil then it is populated with the peer address of the
	// returned endpoint.
	Accept(peerAddr *FullAddress) (Endpoint, *waiter.Queue, *Error)

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

	// SetSockOpt sets a socket option.
	SetSockOpt(opt SettableSocketOption) *Error

	// SetSockOptInt sets a socket option, for simple cases where a value
	// has the int type.
	SetSockOptInt(opt SockOptInt, v int) *Error

	// GetSockOpt gets a socket option.
	GetSockOpt(opt GettableSocketOption) *Error

	// GetSockOptInt gets a socket option for simple cases where a return
	// value has the int type.
	GetSockOptInt(SockOptInt) (int, *Error)

	// State returns a socket's lifecycle state. The returned value is
	// protocol-specific and is primarily used for diagnostics.
	State() uint32

	// ModerateRecvBuf should be called everytime data is copied to the user
	// space. This allows for dynamic tuning of recv buffer space for a
	// given socket.
	//
	// NOTE: This method is a no-op for sockets other than TCP.
	ModerateRecvBuf(copied int)

	// Info returns a copy to the transport endpoint info.
	Info() EndpointInfo

	// Stats returns a reference to the endpoint stats.
	Stats() EndpointStats

	// SetOwner sets the task owner to the endpoint owner.
	SetOwner(owner PacketOwner)

	// LastError clears and returns the last error reported by the endpoint.
	LastError() *Error

	// SocketOptions returns the structure which contains all the socket
	// level options.
	SocketOptions() *SocketOptions
}

// LinkPacketInfo holds Link layer information for a received packet.
//
// +stateify savable
type LinkPacketInfo struct {
	// Protocol is the NetworkProtocolNumber for the packet.
	Protocol NetworkProtocolNumber

	// PktType is used to indicate the destination of the packet.
	PktType PacketType
}

// PacketEndpoint are additional methods that are only implemented by Packet
// endpoints.
type PacketEndpoint interface {
	// ReadPacket reads a datagram/packet from the endpoint and optionally
	// returns the sender and additional LinkPacketInfo.
	//
	// This method does not block if there is no data pending. It will also
	// either return an error or data, never both.
	ReadPacket(*FullAddress, *LinkPacketInfo) (buffer.View, ControlMessages, *Error)
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

// SockOptInt represents socket options which values have the int type.
type SockOptInt int

const (
	// KeepaliveCountOption is used by SetSockOptInt/GetSockOptInt to
	// specify the number of un-ACKed TCP keepalives that will be sent
	// before the connection is closed.
	KeepaliveCountOption SockOptInt = iota

	// IPv4TOSOption is used by SetSockOptInt/GetSockOptInt to specify TOS
	// for all subsequent outgoing IPv4 packets from the endpoint.
	IPv4TOSOption

	// IPv6TrafficClassOption is used by SetSockOptInt/GetSockOptInt to
	// specify TOS for all subsequent outgoing IPv6 packets from the
	// endpoint.
	IPv6TrafficClassOption

	// MaxSegOption is used by SetSockOptInt/GetSockOptInt to set/get the
	// current Maximum Segment Size(MSS) value as specified using the
	// TCP_MAXSEG option.
	MaxSegOption

	// MTUDiscoverOption is used to set/get the path MTU discovery setting.
	//
	// NOTE: Setting this option to any other value than PMTUDiscoveryDont
	// is not supported and will fail as such, and getting this option will
	// always return PMTUDiscoveryDont.
	MTUDiscoverOption

	// MulticastTTLOption is used by SetSockOptInt/GetSockOptInt to control
	// the default TTL value for multicast messages. The default is 1.
	MulticastTTLOption

	// ReceiveQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the input buffer should be returned.
	ReceiveQueueSizeOption

	// SendBufferSizeOption is used by SetSockOptInt/GetSockOptInt to
	// specify the send buffer size option.
	SendBufferSizeOption

	// ReceiveBufferSizeOption is used by SetSockOptInt/GetSockOptInt to
	// specify the receive buffer size option.
	ReceiveBufferSizeOption

	// SendQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the output buffer should be returned.
	SendQueueSizeOption

	// TTLOption is used by SetSockOptInt/GetSockOptInt to control the
	// default TTL/hop limit value for unicast messages. The default is
	// protocol specific.
	//
	// A zero value indicates the default.
	TTLOption

	// TCPSynCountOption is used by SetSockOptInt/GetSockOptInt to specify
	// the number of SYN retransmits that TCP should send before aborting
	// the attempt to connect. It cannot exceed 255.
	//
	// NOTE: This option is currently only stubbed out and is no-op.
	TCPSynCountOption

	// TCPWindowClampOption is used by SetSockOptInt/GetSockOptInt to bound
	// the size of the advertised window to this value.
	//
	// NOTE: This option is currently only stubed out and is a no-op
	TCPWindowClampOption
)

const (
	// PMTUDiscoveryWant is a setting of the MTUDiscoverOption to use
	// per-route settings.
	PMTUDiscoveryWant int = iota

	// PMTUDiscoveryDont is a setting of the MTUDiscoverOption to disable
	// path MTU discovery.
	PMTUDiscoveryDont

	// PMTUDiscoveryDo is a setting of the MTUDiscoverOption to always do
	// path MTU discovery.
	PMTUDiscoveryDo

	// PMTUDiscoveryProbe is a setting of the MTUDiscoverOption to set DF
	// but ignore path MTU.
	PMTUDiscoveryProbe
)

// GettableNetworkProtocolOption is a marker interface for network protocol
// options that may be queried.
type GettableNetworkProtocolOption interface {
	isGettableNetworkProtocolOption()
}

// SettableNetworkProtocolOption is a marker interface for network protocol
// options that may be set.
type SettableNetworkProtocolOption interface {
	isSettableNetworkProtocolOption()
}

// DefaultTTLOption is used by stack.(*Stack).NetworkProtocolOption to specify
// a default TTL.
type DefaultTTLOption uint8

func (*DefaultTTLOption) isGettableNetworkProtocolOption() {}

func (*DefaultTTLOption) isSettableNetworkProtocolOption() {}

// GettableTransportProtocolOption is a marker interface for transport protocol
// options that may be queried.
type GettableTransportProtocolOption interface {
	isGettableTransportProtocolOption()
}

// SettableTransportProtocolOption is a marker interface for transport protocol
// options that may be set.
type SettableTransportProtocolOption interface {
	isSettableTransportProtocolOption()
}

// TCPSACKEnabled the SACK option for TCP.
//
// See: https://tools.ietf.org/html/rfc2018.
type TCPSACKEnabled bool

func (*TCPSACKEnabled) isGettableTransportProtocolOption() {}

func (*TCPSACKEnabled) isSettableTransportProtocolOption() {}

// TCPRecovery is the loss deteoction algorithm used by TCP.
type TCPRecovery int32

func (*TCPRecovery) isGettableTransportProtocolOption() {}

func (*TCPRecovery) isSettableTransportProtocolOption() {}

const (
	// TCPRACKLossDetection indicates RACK is used for loss detection and
	// recovery.
	TCPRACKLossDetection TCPRecovery = 1 << iota

	// TCPRACKStaticReoWnd indicates the reordering window should not be
	// adjusted when DSACK is received.
	TCPRACKStaticReoWnd

	// TCPRACKNoDupTh indicates RACK should not consider the classic three
	// duplicate acknowledgements rule to mark the segments as lost. This
	// is used when reordering is not detected.
	TCPRACKNoDupTh
)

// TCPDelayEnabled enables/disables Nagle's algorithm in TCP.
type TCPDelayEnabled bool

func (*TCPDelayEnabled) isGettableTransportProtocolOption() {}

func (*TCPDelayEnabled) isSettableTransportProtocolOption() {}

// TCPSendBufferSizeRangeOption is the send buffer size range for TCP.
type TCPSendBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPSendBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPSendBufferSizeRangeOption) isSettableTransportProtocolOption() {}

// TCPReceiveBufferSizeRangeOption is the receive buffer size range for TCP.
type TCPReceiveBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPReceiveBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPReceiveBufferSizeRangeOption) isSettableTransportProtocolOption() {}

// TCPAvailableCongestionControlOption is the supported congestion control
// algorithms for TCP
type TCPAvailableCongestionControlOption string

func (*TCPAvailableCongestionControlOption) isGettableTransportProtocolOption() {}

func (*TCPAvailableCongestionControlOption) isSettableTransportProtocolOption() {}

// TCPModerateReceiveBufferOption enables/disables receive buffer moderation
// for TCP.
type TCPModerateReceiveBufferOption bool

func (*TCPModerateReceiveBufferOption) isGettableTransportProtocolOption() {}

func (*TCPModerateReceiveBufferOption) isSettableTransportProtocolOption() {}

// GettableSocketOption is a marker interface for socket options that may be
// queried.
type GettableSocketOption interface {
	isGettableSocketOption()
}

// SettableSocketOption is a marker interface for socket options that may be
// configured.
type SettableSocketOption interface {
	isSettableSocketOption()
}

// BindToDeviceOption is used by SetSockOpt/GetSockOpt to specify that sockets
// should bind only on a specific NIC.
type BindToDeviceOption NICID

func (*BindToDeviceOption) isGettableSocketOption() {}

func (*BindToDeviceOption) isSettableSocketOption() {}

// TCPInfoOption is used by GetSockOpt to expose TCP statistics.
//
// TODO(b/64800844): Add and populate stat fields.
type TCPInfoOption struct {
	RTT    time.Duration
	RTTVar time.Duration
}

func (*TCPInfoOption) isGettableSocketOption() {}

// KeepaliveIdleOption is used by SetSockOpt/GetSockOpt to specify the time a
// connection must remain idle before the first TCP keepalive packet is sent.
// Once this time is reached, KeepaliveIntervalOption is used instead.
type KeepaliveIdleOption time.Duration

func (*KeepaliveIdleOption) isGettableSocketOption() {}

func (*KeepaliveIdleOption) isSettableSocketOption() {}

// KeepaliveIntervalOption is used by SetSockOpt/GetSockOpt to specify the
// interval between sending TCP keepalive packets.
type KeepaliveIntervalOption time.Duration

func (*KeepaliveIntervalOption) isGettableSocketOption() {}

func (*KeepaliveIntervalOption) isSettableSocketOption() {}

// TCPUserTimeoutOption is used by SetSockOpt/GetSockOpt to specify a user
// specified timeout for a given TCP connection.
// See: RFC5482 for details.
type TCPUserTimeoutOption time.Duration

func (*TCPUserTimeoutOption) isGettableSocketOption() {}

func (*TCPUserTimeoutOption) isSettableSocketOption() {}

// CongestionControlOption is used by SetSockOpt/GetSockOpt to set/get
// the current congestion control algorithm.
type CongestionControlOption string

func (*CongestionControlOption) isGettableSocketOption() {}

func (*CongestionControlOption) isSettableSocketOption() {}

func (*CongestionControlOption) isGettableTransportProtocolOption() {}

func (*CongestionControlOption) isSettableTransportProtocolOption() {}

// TCPLingerTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TCP_FIN_WAIT_2 state
// before being marked closed.
type TCPLingerTimeoutOption time.Duration

func (*TCPLingerTimeoutOption) isGettableSocketOption() {}

func (*TCPLingerTimeoutOption) isSettableSocketOption() {}

func (*TCPLingerTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPLingerTimeoutOption) isSettableTransportProtocolOption() {}

// TCPTimeWaitTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TIME_WAIT state
// before being marked closed.
type TCPTimeWaitTimeoutOption time.Duration

func (*TCPTimeWaitTimeoutOption) isGettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableTransportProtocolOption() {}

// TCPDeferAcceptOption is used by SetSockOpt/GetSockOpt to allow a
// accept to return a completed connection only when there is data to be
// read. This usually means the listening socket will drop the final ACK
// for a handshake till the specified timeout until a segment with data arrives.
type TCPDeferAcceptOption time.Duration

func (*TCPDeferAcceptOption) isGettableSocketOption() {}

func (*TCPDeferAcceptOption) isSettableSocketOption() {}

// TCPMinRTOOption is use by SetSockOpt/GetSockOpt to allow overriding
// default MinRTO used by the Stack.
type TCPMinRTOOption time.Duration

func (*TCPMinRTOOption) isGettableSocketOption() {}

func (*TCPMinRTOOption) isSettableSocketOption() {}

func (*TCPMinRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMinRTOOption) isSettableTransportProtocolOption() {}

// TCPMaxRTOOption is use by SetSockOpt/GetSockOpt to allow overriding
// default MaxRTO used by the Stack.
type TCPMaxRTOOption time.Duration

func (*TCPMaxRTOOption) isGettableSocketOption() {}

func (*TCPMaxRTOOption) isSettableSocketOption() {}

func (*TCPMaxRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRTOOption) isSettableTransportProtocolOption() {}

// TCPMaxRetriesOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum number of retransmits after which we time out the connection.
type TCPMaxRetriesOption uint64

func (*TCPMaxRetriesOption) isGettableSocketOption() {}

func (*TCPMaxRetriesOption) isSettableSocketOption() {}

func (*TCPMaxRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRetriesOption) isSettableTransportProtocolOption() {}

// TCPSynRcvdCountThresholdOption is used by SetSockOpt/GetSockOpt to specify
// the number of endpoints that can be in SYN-RCVD state before the stack
// switches to using SYN cookies.
type TCPSynRcvdCountThresholdOption uint64

func (*TCPSynRcvdCountThresholdOption) isGettableSocketOption() {}

func (*TCPSynRcvdCountThresholdOption) isSettableSocketOption() {}

func (*TCPSynRcvdCountThresholdOption) isGettableTransportProtocolOption() {}

func (*TCPSynRcvdCountThresholdOption) isSettableTransportProtocolOption() {}

// TCPSynRetriesOption is used by SetSockOpt/GetSockOpt to specify stack-wide
// default for number of times SYN is retransmitted before aborting a connect.
type TCPSynRetriesOption uint8

func (*TCPSynRetriesOption) isGettableSocketOption() {}

func (*TCPSynRetriesOption) isSettableSocketOption() {}

func (*TCPSynRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPSynRetriesOption) isSettableTransportProtocolOption() {}

// MulticastInterfaceOption is used by SetSockOpt/GetSockOpt to specify a
// default interface for multicast.
type MulticastInterfaceOption struct {
	NIC           NICID
	InterfaceAddr Address
}

func (*MulticastInterfaceOption) isGettableSocketOption() {}

func (*MulticastInterfaceOption) isSettableSocketOption() {}

// MembershipOption is used to identify a multicast membership on an interface.
type MembershipOption struct {
	NIC           NICID
	InterfaceAddr Address
	MulticastAddr Address
}

// AddMembershipOption identifies a multicast group to join on some interface.
type AddMembershipOption MembershipOption

func (*AddMembershipOption) isSettableSocketOption() {}

// RemoveMembershipOption identifies a multicast group to leave on some
// interface.
type RemoveMembershipOption MembershipOption

func (*RemoveMembershipOption) isSettableSocketOption() {}

// SocketDetachFilterOption is used by SetSockOpt to detach a previously attached
// classic BPF filter on a given endpoint.
type SocketDetachFilterOption int

func (*SocketDetachFilterOption) isSettableSocketOption() {}

// OriginalDestinationOption is used to get the original destination address
// and port of a redirected packet.
type OriginalDestinationOption FullAddress

func (*OriginalDestinationOption) isGettableSocketOption() {}

// TCPTimeWaitReuseOption is used stack.(*Stack).TransportProtocolOption to
// specify if the stack can reuse the port bound by an endpoint in TIME-WAIT for
// new connections when it is safe from protocol viewpoint.
type TCPTimeWaitReuseOption uint8

func (*TCPTimeWaitReuseOption) isGettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isSettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitReuseOption) isSettableTransportProtocolOption() {}

const (
	// TCPTimeWaitReuseDisabled indicates reuse of port bound by endponts in TIME-WAIT cannot
	// be reused for new connections.
	TCPTimeWaitReuseDisabled TCPTimeWaitReuseOption = iota

	// TCPTimeWaitReuseGlobal indicates reuse of port bound by endponts in TIME-WAIT can
	// be reused for new connections irrespective of the src/dest addresses.
	TCPTimeWaitReuseGlobal

	// TCPTimeWaitReuseLoopbackOnly indicates reuse of port bound by endpoint in TIME-WAIT can
	// only be reused if the connection was a connection over loopback. i.e src/dest adddresses
	// are loopback addresses.
	TCPTimeWaitReuseLoopbackOnly
)

// LingerOption is used by SetSockOpt/GetSockOpt to set/get the
// duration for which a socket lingers before returning from Close.
//
// +stateify savable
type LingerOption struct {
	Enabled bool
	Timeout time.Duration
}

// IPPacketInfo is the message structure for IP_PKTINFO.
//
// +stateify savable
type IPPacketInfo struct {
	// NIC is the ID of the NIC to be used.
	NIC NICID

	// LocalAddr is the local address.
	LocalAddr Address

	// DestinationAddr is the destination address found in the IP header.
	DestinationAddr Address
}

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

// Equal returns true if the given Route is equal to this Route.
func (r Route) Equal(to Route) bool {
	// NOTE: This relies on the fact that r.Destination == to.Destination
	return r == to
}

// TransportProtocolNumber is the number of a transport protocol.
type TransportProtocolNumber uint32

// NetworkProtocolNumber is the EtherType of a network protocol in an Ethernet
// frame.
//
// See: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
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

	// MulticastListenerQuery is the total number of Multicast Listener Query
	// messages counted.
	MulticastListenerQuery *StatCounter

	// MulticastListenerReport is the total number of Multicast Listener Report
	// messages counted.
	MulticastListenerReport *StatCounter

	// MulticastListenerDone is the total number of Multicast Listener Done
	// messages counted.
	MulticastListenerDone *StatCounter
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

	// Unrecognized is the total number of ICMPv6 packets received that the
	// transport layer does not know how to parse.
	Unrecognized *StatCounter

	// Invalid is the total number of ICMPv6 packets received that the
	// transport layer could not parse.
	Invalid *StatCounter

	// RouterOnlyPacketsDroppedByHost is the total number of ICMPv6 packets
	// dropped due to being router-specific packets.
	RouterOnlyPacketsDroppedByHost *StatCounter
}

// ICMPv4Stats collects ICMPv4-specific stats.
type ICMPv4Stats struct {
	// ICMPv4SentPacketStats contains counts of sent packets by ICMPv4 packet type
	// and a single count of packets which failed to write to the link
	// layer.
	PacketsSent ICMPv4SentPacketStats

	// ICMPv4ReceivedPacketStats contains counts of received packets by ICMPv4
	// packet type and a single count of invalid packets received.
	PacketsReceived ICMPv4ReceivedPacketStats
}

// ICMPv6Stats collects ICMPv6-specific stats.
type ICMPv6Stats struct {
	// ICMPv6SentPacketStats contains counts of sent packets by ICMPv6 packet type
	// and a single count of packets which failed to write to the link
	// layer.
	PacketsSent ICMPv6SentPacketStats

	// ICMPv6ReceivedPacketStats contains counts of received packets by ICMPv6
	// packet type and a single count of invalid packets received.
	PacketsReceived ICMPv6ReceivedPacketStats
}

// ICMPStats collects ICMP-specific stats (both v4 and v6).
type ICMPStats struct {
	// V4 contains the ICMPv4-specifics stats.
	V4 ICMPv4Stats

	// V6 contains the ICMPv4-specifics stats.
	V6 ICMPv6Stats
}

// IGMPPacketStats enumerates counts for all IGMP packet types.
type IGMPPacketStats struct {
	// MembershipQuery is the total number of Membership Query messages counted.
	MembershipQuery *StatCounter

	// V1MembershipReport is the total number of Version 1 Membership Report
	// messages counted.
	V1MembershipReport *StatCounter

	// V2MembershipReport is the total number of Version 2 Membership Report
	// messages counted.
	V2MembershipReport *StatCounter

	// LeaveGroup is the total number of Leave Group messages counted.
	LeaveGroup *StatCounter
}

// IGMPSentPacketStats collects outbound IGMP-specific stats.
type IGMPSentPacketStats struct {
	IGMPPacketStats

	// Dropped is the total number of IGMP packets dropped.
	Dropped *StatCounter
}

// IGMPReceivedPacketStats collects inbound IGMP-specific stats.
type IGMPReceivedPacketStats struct {
	IGMPPacketStats

	// Invalid is the total number of IGMP packets received that IGMP could not
	// parse.
	Invalid *StatCounter

	// ChecksumErrors is the total number of IGMP packets dropped due to bad
	// checksums.
	ChecksumErrors *StatCounter

	// Unrecognized is the total number of unrecognized messages counted, these
	// are silently ignored for forward-compatibilty.
	Unrecognized *StatCounter
}

// IGMPStats colelcts IGMP-specific stats.
type IGMPStats struct {
	// IGMPSentPacketStats contains counts of sent packets by IGMP packet type
	// and a single count of invalid packets received.
	PacketsSent IGMPSentPacketStats

	// IGMPReceivedPacketStats contains counts of received packets by IGMP packet
	// type and a single count of invalid packets received.
	PacketsReceived IGMPReceivedPacketStats
}

// IPStats collects IP-specific stats (both v4 and v6).
type IPStats struct {
	// PacketsReceived is the total number of IP packets received from the
	// link layer.
	PacketsReceived *StatCounter

	// DisabledPacketsReceived is the total number of IP packets received from the
	// link layer when the IP layer is disabled.
	DisabledPacketsReceived *StatCounter

	// InvalidDestinationAddressesReceived is the total number of IP packets
	// received with an unknown or invalid destination address.
	InvalidDestinationAddressesReceived *StatCounter

	// InvalidSourceAddressesReceived is the total number of IP packets received
	// with a source address that should never have been received on the wire.
	InvalidSourceAddressesReceived *StatCounter

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

	// IPTablesPreroutingDropped is the total number of IP packets dropped
	// in the Prerouting chain.
	IPTablesPreroutingDropped *StatCounter

	// IPTablesInputDropped is the total number of IP packets dropped in
	// the Input chain.
	IPTablesInputDropped *StatCounter

	// IPTablesOutputDropped is the total number of IP packets dropped in
	// the Output chain.
	IPTablesOutputDropped *StatCounter

	// OptionTSReceived is the number of Timestamp options seen.
	OptionTSReceived *StatCounter

	// OptionRRReceived is the number of Record Route options seen.
	OptionRRReceived *StatCounter

	// OptionUnknownReceived is the number of unknown IP options seen.
	OptionUnknownReceived *StatCounter
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
	// current state is ESTABLISHED.
	CurrentEstablished *StatCounter

	// CurrentConnected is the number of TCP connections that
	// are in connected state.
	CurrentConnected *StatCounter

	// EstablishedResets is the number of times TCP connections have made
	// a direct transition to the CLOSED state from either the
	// ESTABLISHED state or the CLOSE-WAIT state.
	EstablishedResets *StatCounter

	// EstablishedClosed is the number of times established TCP connections
	// made a transition to CLOSED state.
	EstablishedClosed *StatCounter

	// EstablishedTimedout is the number of times an established connection
	// was reset because of keep-alive time out.
	EstablishedTimedout *StatCounter

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

	// ChecksumErrors is the number of datagrams dropped due to bad checksums.
	ChecksumErrors *StatCounter
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

	// IGMP breaks out IGMP-specific stats.
	IGMP IGMPStats

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

	// ChecksumErrors is the number of packets dropped due to bad checksums.
	ChecksumErrors StatCounter
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

	// NotConnected is the number of times we tried to read but found that the
	// endpoint was not connected.
	NotConnected StatCounter
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

// InitStatCounters initializes v's fields with nil StatCounter fields to new
// StatCounters.
func InitStatCounters(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		if s, ok := v.Addr().Interface().(**StatCounter); ok {
			if *s == nil {
				*s = new(StatCounter)
			}
		} else {
			InitStatCounters(v)
		}
	}
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s Stats) FillIn() Stats {
	InitStatCounters(reflect.ValueOf(&s).Elem())
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
