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

package stack

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/waiter"
)

// NetworkEndpointID is the identifier of a network layer protocol endpoint.
// Currently the local address is sufficient because all supported protocols
// (i.e., IPv4 and IPv6) have different sizes for their addresses.
type NetworkEndpointID struct {
	LocalAddress tcpip.Address
}

// TransportEndpointID is the identifier of a transport layer protocol endpoint.
//
// +stateify savable
type TransportEndpointID struct {
	// LocalPort is the local port associated with the endpoint.
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with
	// the endpoint.
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	RemotePort uint16

	// RemoteAddress it the remote [network layer] address associated with
	// the endpoint.
	RemoteAddress tcpip.Address
}

// NetworkPacketInfo holds information about a network layer packet.
//
// +stateify savable
type NetworkPacketInfo struct {
	// LocalAddressBroadcast is true if the packet's local address is a broadcast
	// address.
	LocalAddressBroadcast bool

	// IsForwardedPacket is true if the packet is being forwarded.
	IsForwardedPacket bool
}

// TransportErrorKind enumerates error types that are handled by the transport
// layer.
type TransportErrorKind int

const (
	// PacketTooBigTransportError indicates that a packet did not reach its
	// destination because a link on the path to the destination had an MTU that
	// was too small to carry the packet.
	PacketTooBigTransportError TransportErrorKind = iota

	// DestinationHostUnreachableTransportError indicates that the destination
	// host was unreachable.
	DestinationHostUnreachableTransportError

	// DestinationPortUnreachableTransportError indicates that a packet reached
	// the destination host, but the transport protocol was not active on the
	// destination port.
	DestinationPortUnreachableTransportError

	// DestinationNetworkUnreachableTransportError indicates that the destination
	// network was unreachable.
	DestinationNetworkUnreachableTransportError
)

// TransportError is a marker interface for errors that may be handled by the
// transport layer.
type TransportError interface {
	tcpip.SockErrorCause

	// Kind returns the type of the transport error.
	Kind() TransportErrorKind
}

// TransportEndpoint is the interface that needs to be implemented by transport
// protocol (e.g., tcp, udp) endpoints that can handle packets.
type TransportEndpoint interface {
	// UniqueID returns an unique ID for this transport endpoint.
	UniqueID() uint64

	// HandlePacket is called by the stack when new packets arrive to this
	// transport endpoint. It sets the packet buffer's transport header.
	//
	// HandlePacket may modify the packet.
	HandlePacket(TransportEndpointID, PacketBufferPtr)

	// HandleError is called when the transport endpoint receives an error.
	//
	// HandleError takes may modify the packet buffer.
	HandleError(TransportError, PacketBufferPtr)

	// Abort initiates an expedited endpoint teardown. It puts the endpoint
	// in a closed state and frees all resources associated with it. This
	// cleanup may happen asynchronously. Wait can be used to block on this
	// asynchronous cleanup.
	Abort()

	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// An endpoint can be requested to stop its worker goroutines by calling
	// its Close method.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	Wait()
}

// RawTransportEndpoint is the interface that needs to be implemented by raw
// transport protocol endpoints. RawTransportEndpoints receive the entire
// packet - including the network and transport headers - as delivered to
// netstack.
type RawTransportEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint. The packet contains all data from the link
	// layer up.
	//
	// HandlePacket may modify the packet.
	HandlePacket(PacketBufferPtr)
}

// PacketEndpoint is the interface that needs to be implemented by packet
// transport protocol endpoints. These endpoints receive link layer headers in
// addition to whatever they contain (usually network and transport layer
// headers and a payload).
type PacketEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive that
	// match the endpoint.
	//
	// Implementers should treat packet as immutable and should copy it
	// before before modification.
	//
	// linkHeader may have a length of 0, in which case the PacketEndpoint
	// should construct its own ethernet header for applications.
	//
	// HandlePacket may modify pkt.
	HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt PacketBufferPtr)
}

// UnknownDestinationPacketDisposition enumerates the possible return values from
// HandleUnknownDestinationPacket().
type UnknownDestinationPacketDisposition int

const (
	// UnknownDestinationPacketMalformed denotes that the packet was malformed
	// and no further processing should be attempted other than updating
	// statistics.
	UnknownDestinationPacketMalformed UnknownDestinationPacketDisposition = iota

	// UnknownDestinationPacketUnhandled tells the caller that the packet was
	// well formed but that the issue was not handled and the stack should take
	// the default action.
	UnknownDestinationPacketUnhandled

	// UnknownDestinationPacketHandled tells the caller that it should do
	// no further processing.
	UnknownDestinationPacketHandled
)

// TransportProtocol is the interface that needs to be implemented by transport
// protocols (e.g., tcp, udp) that want to be part of the networking stack.
type TransportProtocol interface {
	// Number returns the transport protocol number.
	Number() tcpip.TransportProtocolNumber

	// NewEndpoint creates a new endpoint of the transport protocol.
	NewEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// NewRawEndpoint creates a new raw endpoint of the transport protocol.
	NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// MinimumPacketSize returns the minimum valid packet size of this
	// transport protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParsePorts returns the source and destination ports stored in a
	// packet of this protocol.
	ParsePorts(b []byte) (src, dst uint16, err tcpip.Error)

	// HandleUnknownDestinationPacket handles packets targeted at this
	// protocol that don't match any existing endpoint. For example,
	// it is targeted at a port that has no listeners.
	//
	// HandleUnknownDestinationPacket may modify the packet if it handles
	// the issue.
	HandleUnknownDestinationPacket(TransportEndpointID, PacketBufferPtr) UnknownDestinationPacketDisposition

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableTransportProtocolOption) tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableTransportProtocolOption) tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Pause requests that any protocol level background workers pause.
	Pause()

	// Resume resumes any protocol level background workers that were
	// previously paused by Pause.
	Resume()

	// Parse sets pkt.TransportHeader and trims pkt.Data appropriately. It does
	// neither and returns false if pkt.Data is too small, i.e. pkt.Data.Size() <
	// MinimumPacketSize()
	Parse(pkt PacketBufferPtr) (ok bool)
}

// TransportPacketDisposition is the result from attempting to deliver a packet
// to the transport layer.
type TransportPacketDisposition int

const (
	// TransportPacketHandled indicates that a transport packet was handled by the
	// transport layer and callers need not take any further action.
	TransportPacketHandled TransportPacketDisposition = iota

	// TransportPacketProtocolUnreachable indicates that the transport
	// protocol requested in the packet is not supported.
	TransportPacketProtocolUnreachable

	// TransportPacketDestinationPortUnreachable indicates that there weren't any
	// listeners interested in the packet and the transport protocol has no means
	// to notify the sender.
	TransportPacketDestinationPortUnreachable
)

// TransportDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate transport endpoint after it has been handled by
// the network layer.
type TransportDispatcher interface {
	// DeliverTransportPacket delivers packets to the appropriate
	// transport protocol endpoint.
	//
	// pkt.NetworkHeader must be set before calling DeliverTransportPacket.
	//
	// DeliverTransportPacket may modify the packet.
	DeliverTransportPacket(tcpip.TransportProtocolNumber, PacketBufferPtr) TransportPacketDisposition

	// DeliverTransportError delivers an error to the appropriate transport
	// endpoint.
	//
	// DeliverTransportError may modify the packet buffer.
	DeliverTransportError(local, remote tcpip.Address, _ tcpip.NetworkProtocolNumber, _ tcpip.TransportProtocolNumber, _ TransportError, _ PacketBufferPtr)

	// DeliverRawPacket delivers a packet to any subscribed raw sockets.
	//
	// DeliverRawPacket does NOT take ownership of the packet buffer.
	DeliverRawPacket(tcpip.TransportProtocolNumber, PacketBufferPtr)
}

// PacketLooping specifies where an outbound packet should be sent.
type PacketLooping byte

const (
	// PacketOut indicates that the packet should be passed to the link
	// endpoint.
	PacketOut PacketLooping = 1 << iota

	// PacketLoop indicates that the packet should be handled locally.
	PacketLoop
)

// NetworkHeaderParams are the header parameters given as input by the
// transport endpoint to the network.
type NetworkHeaderParams struct {
	// Protocol refers to the transport protocol number.
	Protocol tcpip.TransportProtocolNumber

	// TTL refers to Time To Live field of the IP-header.
	TTL uint8

	// TOS refers to TypeOfService or TrafficClass field of the IP-header.
	TOS uint8
}

// GroupAddressableEndpoint is an endpoint that supports group addressing.
//
// An endpoint is considered to support group addressing when one or more
// endpoints may associate themselves with the same identifier (group address).
type GroupAddressableEndpoint interface {
	// JoinGroup joins the specified group.
	JoinGroup(group tcpip.Address) tcpip.Error

	// LeaveGroup attempts to leave the specified group.
	LeaveGroup(group tcpip.Address) tcpip.Error

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool
}

// PrimaryEndpointBehavior is an enumeration of an AddressEndpoint's primary
// behavior.
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, they are ordered by recency.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
)

func (peb PrimaryEndpointBehavior) String() string {
	switch peb {
	case CanBePrimaryEndpoint:
		return "CanBePrimaryEndpoint"
	case FirstPrimaryEndpoint:
		return "FirstPrimaryEndpoint"
	case NeverPrimaryEndpoint:
		return "NeverPrimaryEndpoint"
	default:
		panic(fmt.Sprintf("unknown primary endpoint behavior: %d", peb))
	}
}

// AddressConfigType is the method used to add an address.
type AddressConfigType int

const (
	// AddressConfigStatic is a statically configured address endpoint that was
	// added by some user-specified action (adding an explicit address, joining a
	// multicast group).
	AddressConfigStatic AddressConfigType = iota

	// AddressConfigSlaac is an address endpoint added by SLAAC, as per RFC 4862
	// section 5.5.3.
	AddressConfigSlaac
)

// AddressLifetimes encodes an address' preferred and valid lifetimes, as well
// as if the address is deprecated.
type AddressLifetimes struct {
	// Deprecated is whether the address is deprecated.
	Deprecated bool

	// PreferredUntil is the time at which the address will be deprecated.
	//
	// Note that for certain addresses, deprecating the address at the
	// PreferredUntil time is not handled as a scheduled job by the stack, but
	// is information provided by the owner as an indication of when it will
	// deprecate the address.
	//
	// PreferredUntil should be ignored if Deprecated is true. If Deprecated
	// is false, and PreferredUntil is the zero value, no information about
	// the preferred lifetime can be inferred.
	PreferredUntil tcpip.MonotonicTime

	// ValidUntil is the time at which the address will be invalidated.
	//
	// Note that for certain addresses, invalidating the address at the
	// ValidUntil time is not handled as a scheduled job by the stack, but
	// is information provided by the owner as an indication of when it will
	// invalidate the address.
	//
	// If ValidUntil is the zero value, no information about the valid lifetime
	// can be inferred.
	ValidUntil tcpip.MonotonicTime
}

// AddressProperties contains additional properties that can be configured when
// adding an address.
type AddressProperties struct {
	PEB        PrimaryEndpointBehavior
	ConfigType AddressConfigType
	// Lifetimes encodes the address' lifetimes.
	//
	// Lifetimes.PreferredUntil and Lifetimes.ValidUntil are informational, i.e.
	// the stack will not deprecated nor invalidate the address upon reaching
	// these timestamps.
	//
	// If Lifetimes.Deprecated is true, the address will be added as deprecated.
	Lifetimes AddressLifetimes
	// Temporary is as defined in RFC 4941, but applies not only to addresses
	// added via SLAAC, e.g. DHCPv6 can also add temporary addresses. Temporary
	// addresses are short-lived and are not to be valid (or preferred)
	// forever; hence the term temporary.
	Temporary bool
	Disp      AddressDispatcher
}

// AddressAssignmentState is an address' assignment state.
type AddressAssignmentState int

const (
	_ AddressAssignmentState = iota

	// AddressDisabled indicates the NIC the address is assigned to is disabled.
	AddressDisabled

	// AddressTentative indicates an address is yet to pass DAD (IPv4 addresses
	// are never tentative).
	AddressTentative

	// AddressAssigned indicates an address is assigned.
	AddressAssigned
)

func (state AddressAssignmentState) String() string {
	switch state {
	case AddressDisabled:
		return "Disabled"
	case AddressTentative:
		return "Tentative"
	case AddressAssigned:
		return "Assigned"
	default:
		panic(fmt.Sprintf("unknown address assignment state: %d", state))
	}
}

// AddressRemovalReason is the reason an address was removed.
type AddressRemovalReason int

const (
	_ AddressRemovalReason = iota

	// AddressRemovalManualAction indicates the address was removed explicitly
	// using the stack API.
	AddressRemovalManualAction

	// AddressRemovalInterfaceRemoved indicates the address was removed because
	// the NIC it is assigned to was removed.
	AddressRemovalInterfaceRemoved

	// AddressRemovalDADFailed indicates the address was removed because DAD
	// failed.
	AddressRemovalDADFailed

	// AddressRemovalInvalidated indicates the address was removed because it
	// was invalidated.
	AddressRemovalInvalidated
)

func (reason AddressRemovalReason) String() string {
	switch reason {
	case AddressRemovalManualAction:
		return "ManualAction"
	case AddressRemovalInterfaceRemoved:
		return "InterfaceRemoved"
	case AddressRemovalDADFailed:
		return "DADFailed"
	case AddressRemovalInvalidated:
		return "Invalidated"
	default:
		panic(fmt.Sprintf("unknown address removal reason: %d", reason))
	}
}

// AddressDispatcher is the interface integrators can implement to receive
// address-related events.
type AddressDispatcher interface {
	// OnChanged is called with an address' properties when they change.
	//
	// OnChanged is called once when the address is added with the initial state,
	// and every time a property changes.
	//
	// The PreferredUntil and ValidUntil fields in AddressLifetimes must be
	// considered informational, i.e. one must not consider an address to be
	// deprecated/invalid even if the monotonic clock timestamp is past these
	// deadlines. The Deprecated field indicates whether an address is
	// preferred or not; and OnRemoved will be called when an address is
	// removed due to invalidation.
	OnChanged(AddressLifetimes, AddressAssignmentState)

	// OnRemoved is called when an address is removed with the removal reason.
	OnRemoved(AddressRemovalReason)
}

// AssignableAddressEndpoint is a reference counted address endpoint that may be
// assigned to a NetworkEndpoint.
type AssignableAddressEndpoint interface {
	// AddressWithPrefix returns the endpoint's address.
	AddressWithPrefix() tcpip.AddressWithPrefix

	// Subnet returns the subnet of the endpoint's address.
	Subnet() tcpip.Subnet

	// IsAssigned returns whether or not the endpoint is considered bound
	// to its NetworkEndpoint.
	IsAssigned(allowExpired bool) bool

	// IncRef increments this endpoint's reference count.
	//
	// Returns true if it was successfully incremented. If it returns false, then
	// the endpoint is considered expired and should no longer be used.
	IncRef() bool

	// DecRef decrements this endpoint's reference count.
	DecRef()
}

// AddressEndpoint is an endpoint representing an address assigned to an
// AddressableEndpoint.
type AddressEndpoint interface {
	AssignableAddressEndpoint

	// GetKind returns the address kind for this endpoint.
	GetKind() AddressKind

	// SetKind sets the address kind for this endpoint.
	SetKind(AddressKind)

	// ConfigType returns the method used to add the address.
	ConfigType() AddressConfigType

	// Deprecated returns whether or not this endpoint is deprecated.
	Deprecated() bool

	// SetDeprecated sets this endpoint's deprecated status.
	SetDeprecated(bool)

	// Lifetimes returns this endpoint's lifetimes.
	Lifetimes() AddressLifetimes

	// SetLifetimes sets this endpoint's lifetimes.
	//
	// Note that setting preferred-until and valid-until times do not result in
	// deprecation/invalidation jobs to be scheduled by the stack.
	SetLifetimes(AddressLifetimes)

	// Temporary returns whether or not this endpoint is temporary.
	Temporary() bool

	// RegisterDispatcher registers an address dispatcher.
	//
	// OnChanged will be called immediately on the provided address dispatcher
	// with this endpoint's current state.
	RegisterDispatcher(AddressDispatcher)
}

// AddressKind is the kind of an address.
//
// See the values of AddressKind for more details.
type AddressKind int

const (
	// PermanentTentative is a permanent address endpoint that is not yet
	// considered to be fully bound to an interface in the traditional
	// sense. That is, the address is associated with a NIC, but packets
	// destined to the address MUST NOT be accepted and MUST be silently
	// dropped, and the address MUST NOT be used as a source address for
	// outgoing packets. For IPv6, addresses are of this kind until NDP's
	// Duplicate Address Detection (DAD) resolves. If DAD fails, the address
	// is removed.
	PermanentTentative AddressKind = iota

	// Permanent is a permanent endpoint (vs. a temporary one) assigned to the
	// NIC. Its reference count is biased by 1 to avoid removal when no route
	// holds a reference to it. It is removed by explicitly removing the address
	// from the NIC.
	Permanent

	// PermanentExpired is a permanent endpoint that had its address removed from
	// the NIC, and it is waiting to be removed once no references to it are held.
	//
	// If the address is re-added before the endpoint is removed, its type
	// changes back to Permanent.
	PermanentExpired

	// Temporary is an endpoint, created on a one-off basis to temporarily
	// consider the NIC bound an an address that it is not explicitly bound to
	// (such as a permanent address). Its reference count must not be biased by 1
	// so that the address is removed immediately when references to it are no
	// longer held.
	//
	// A temporary endpoint may be promoted to permanent if the address is added
	// permanently.
	Temporary
)

// IsPermanent returns true if the AddressKind represents a permanent address.
func (k AddressKind) IsPermanent() bool {
	switch k {
	case Permanent, PermanentTentative:
		return true
	case Temporary, PermanentExpired:
		return false
	default:
		panic(fmt.Sprintf("unrecognized address kind = %d", k))
	}
}

// AddressableEndpoint is an endpoint that supports addressing.
//
// An endpoint is considered to support addressing when the endpoint may
// associate itself with an identifier (address).
type AddressableEndpoint interface {
	// AddAndAcquirePermanentAddress adds the passed permanent address.
	//
	// Returns *tcpip.ErrDuplicateAddress if the address exists.
	//
	// Acquires and returns the AddressEndpoint for the added address.
	AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error)

	// RemovePermanentAddress removes the passed address if it is a permanent
	// address.
	//
	// Returns *tcpip.ErrBadLocalAddress if the endpoint does not have the passed
	// permanent address.
	RemovePermanentAddress(addr tcpip.Address) tcpip.Error

	// SetLifetimes sets an address' lifetimes (strictly informational) and
	// whether it should be deprecated or preferred.
	//
	// Returns *tcpip.ErrBadLocalAddress if the endpoint does not have the passed
	// address.
	SetLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error

	// MainAddress returns the endpoint's primary permanent address.
	MainAddress() tcpip.AddressWithPrefix

	// AcquireAssignedAddress returns an address endpoint for the passed address
	// that is considered bound to the endpoint, optionally creating a temporary
	// endpoint if requested and no existing address exists.
	//
	// The returned endpoint's reference count is incremented.
	//
	// Returns nil if the specified address is not local to this endpoint.
	AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint

	// AcquireOutgoingPrimaryAddress returns a primary address that may be used as
	// a source address when sending packets to the passed remote address.
	//
	// If allowExpired is true, expired addresses may be returned.
	//
	// The returned endpoint's reference count is incremented.
	//
	// Returns nil if a primary address is not available.
	AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) AddressEndpoint

	// PrimaryAddresses returns the primary addresses.
	PrimaryAddresses() []tcpip.AddressWithPrefix

	// PermanentAddresses returns all the permanent addresses.
	PermanentAddresses() []tcpip.AddressWithPrefix
}

// NDPEndpoint is a network endpoint that supports NDP.
type NDPEndpoint interface {
	NetworkEndpoint

	// InvalidateDefaultRouter invalidates a default router discovered through
	// NDP.
	InvalidateDefaultRouter(tcpip.Address)
}

// NetworkInterface is a network interface.
type NetworkInterface interface {
	NetworkLinkEndpoint

	// ID returns the interface's ID.
	ID() tcpip.NICID

	// IsLoopback returns true if the interface is a loopback interface.
	IsLoopback() bool

	// Name returns the name of the interface.
	//
	// May return an empty string if the interface is not configured with a name.
	Name() string

	// Enabled returns true if the interface is enabled.
	Enabled() bool

	// Promiscuous returns true if the interface is in promiscuous mode.
	//
	// When in promiscuous mode, the interface should accept all packets.
	Promiscuous() bool

	// Spoofing returns true if the interface is in spoofing mode.
	//
	// When in spoofing mode, the interface should consider all addresses as
	// assigned to it.
	Spoofing() bool

	// PrimaryAddress returns the primary address associated with the interface.
	//
	// PrimaryAddress will return the first non-deprecated address if such an
	// address exists. If no non-deprecated addresses exist, the first deprecated
	// address will be returned. If no deprecated addresses exist, the zero value
	// will be returned.
	PrimaryAddress(tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error)

	// CheckLocalAddress returns true if the address exists on the interface.
	CheckLocalAddress(tcpip.NetworkProtocolNumber, tcpip.Address) bool

	// WritePacketToRemote writes the packet to the given remote link address.
	WritePacketToRemote(tcpip.LinkAddress, PacketBufferPtr) tcpip.Error

	// WritePacket writes a packet through the given route.
	//
	// WritePacket may modify the packet buffer. The packet buffer's
	// network and transport header must be set.
	WritePacket(*Route, PacketBufferPtr) tcpip.Error

	// HandleNeighborProbe processes an incoming neighbor probe (e.g. ARP
	// request or NDP Neighbor Solicitation).
	//
	// HandleNeighborProbe assumes that the probe is valid for the network
	// interface the probe was received on.
	HandleNeighborProbe(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress) tcpip.Error

	// HandleNeighborConfirmation processes an incoming neighbor confirmation
	// (e.g. ARP reply or NDP Neighbor Advertisement).
	HandleNeighborConfirmation(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress, ReachabilityConfirmationFlags) tcpip.Error
}

// LinkResolvableNetworkEndpoint handles link resolution events.
type LinkResolvableNetworkEndpoint interface {
	// HandleLinkResolutionFailure is called when link resolution prevents the
	// argument from having been sent.
	HandleLinkResolutionFailure(PacketBufferPtr)
}

// NetworkEndpoint is the interface that needs to be implemented by endpoints
// of network layer protocols (e.g., ipv4, ipv6).
type NetworkEndpoint interface {
	// Enable enables the endpoint.
	//
	// Must only be called when the stack is in a state that allows the endpoint
	// to send and receive packets.
	//
	// Returns *tcpip.ErrNotPermitted if the endpoint cannot be enabled.
	Enable() tcpip.Error

	// Enabled returns true if the endpoint is enabled.
	Enabled() bool

	// Disable disables the endpoint.
	Disable()

	// DefaultTTL is the default time-to-live value (or hop limit, in ipv6)
	// for this endpoint.
	DefaultTTL() uint8

	// MTU is the maximum transmission unit for this endpoint. This is
	// generally calculated as the MTU of the underlying data link endpoint
	// minus the network endpoint max header length.
	MTU() uint32

	// MaxHeaderLength returns the maximum size the network (and lower
	// level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// WritePacket writes a packet to the given destination address and
	// protocol. It may modify pkt. pkt.TransportHeader must have
	// already been set.
	WritePacket(r *Route, params NetworkHeaderParams, pkt PacketBufferPtr) tcpip.Error

	// WriteHeaderIncludedPacket writes a packet that includes a network
	// header to the given destination address. It may modify pkt.
	WriteHeaderIncludedPacket(r *Route, pkt PacketBufferPtr) tcpip.Error

	// HandlePacket is called by the link layer when new packets arrive to
	// this network endpoint. It sets pkt.NetworkHeader.
	//
	// HandlePacket may modify pkt.
	HandlePacket(pkt PacketBufferPtr)

	// Close is called when the endpoint is removed from a stack.
	Close()

	// NetworkProtocolNumber returns the tcpip.NetworkProtocolNumber for
	// this endpoint.
	NetworkProtocolNumber() tcpip.NetworkProtocolNumber

	// Stats returns a reference to the network endpoint stats.
	Stats() NetworkEndpointStats
}

// NetworkEndpointStats is the interface implemented by each network endpoint
// stats struct.
type NetworkEndpointStats interface {
	// IsNetworkEndpointStats is an empty method to implement the
	// NetworkEndpointStats marker interface.
	IsNetworkEndpointStats()
}

// IPNetworkEndpointStats is a NetworkEndpointStats that tracks IP-related
// statistics.
type IPNetworkEndpointStats interface {
	NetworkEndpointStats

	// IPStats returns the IP statistics of a network endpoint.
	IPStats() *tcpip.IPStats
}

// ForwardingNetworkEndpoint is a network endpoint that may forward packets.
type ForwardingNetworkEndpoint interface {
	NetworkEndpoint

	// Forwarding returns the forwarding configuration.
	Forwarding() bool

	// SetForwarding sets the forwarding configuration.
	//
	// Returns the previous forwarding configuration.
	SetForwarding(bool) bool
}

// MulticastForwardingNetworkEndpoint is a network endpoint that may forward
// multicast packets.
type MulticastForwardingNetworkEndpoint interface {
	ForwardingNetworkEndpoint

	// MulticastForwarding returns true if multicast forwarding is enabled.
	// Otherwise, returns false.
	MulticastForwarding() bool

	// SetMulticastForwarding sets the multicast forwarding configuration.
	//
	// Returns the previous forwarding configuration.
	SetMulticastForwarding(bool) bool
}

// NetworkProtocol is the interface that needs to be implemented by network
// protocols (e.g., ipv4, ipv6) that want to be part of the networking stack.
type NetworkProtocol interface {
	// Number returns the network protocol number.
	Number() tcpip.NetworkProtocolNumber

	// MinimumPacketSize returns the minimum valid packet size of this
	// network protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParseAddresses returns the source and destination addresses stored in a
	// packet of this protocol.
	ParseAddresses(b []byte) (src, dst tcpip.Address)

	// NewEndpoint creates a new endpoint of this protocol.
	NewEndpoint(nic NetworkInterface, dispatcher TransportDispatcher) NetworkEndpoint

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Parse sets pkt.NetworkHeader and trims pkt.Data appropriately. It
	// returns:
	//	- The encapsulated protocol, if present.
	//	- Whether there is an encapsulated transport protocol payload (e.g. ARP
	//		does not encapsulate anything).
	//	- Whether pkt.Data was large enough to parse and set pkt.NetworkHeader.
	Parse(pkt PacketBufferPtr) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool)
}

// UnicastSourceAndMulticastDestination is a tuple that represents a unicast
// source address and a multicast destination address.
type UnicastSourceAndMulticastDestination struct {
	// Source represents a unicast source address.
	Source tcpip.Address
	// Destination represents a multicast destination address.
	Destination tcpip.Address
}

// MulticastRouteOutgoingInterface represents an outgoing interface in a
// multicast route.
type MulticastRouteOutgoingInterface struct {
	// ID corresponds to the outgoing NIC.
	ID tcpip.NICID

	// MinTTL represents the minumum TTL/HopLimit a multicast packet must have to
	// be sent through the outgoing interface.
	//
	// Note: a value of 0 allows all packets to be forwarded.
	MinTTL uint8
}

// MulticastRoute is a multicast route.
type MulticastRoute struct {
	// ExpectedInputInterface is the interface on which packets using this route
	// are expected to ingress.
	ExpectedInputInterface tcpip.NICID

	// OutgoingInterfaces is the set of interfaces that a multicast packet should
	// be forwarded out of.
	//
	// This field should not be empty.
	OutgoingInterfaces []MulticastRouteOutgoingInterface
}

// MulticastForwardingNetworkProtocol is the interface that needs to be
// implemented by the network protocols that support multicast forwarding.
type MulticastForwardingNetworkProtocol interface {
	NetworkProtocol

	// AddMulticastRoute adds a route to the multicast routing table such that
	// packets matching the addresses will be forwarded using the provided route.
	//
	// Returns an error if the addresses or route is invalid.
	AddMulticastRoute(UnicastSourceAndMulticastDestination, MulticastRoute) tcpip.Error

	// RemoveMulticastRoute removes the route matching the provided addresses
	// from the multicast routing table.
	//
	// Returns an error if the addresses are invalid or a matching route is not
	// found.
	RemoveMulticastRoute(UnicastSourceAndMulticastDestination) tcpip.Error

	// MulticastRouteLastUsedTime returns a monotonic timestamp that
	// represents the last time that the route matching the provided addresses
	// was used or updated.
	//
	// Returns an error if the addresses are invalid or a matching route was not
	// found.
	MulticastRouteLastUsedTime(UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, tcpip.Error)

	// EnableMulticastForwarding enables multicast forwarding for the protocol.
	//
	// Returns an error if the provided multicast forwarding event dispatcher is
	// nil. Otherwise, returns true if the multicast forwarding was already
	// enabled.
	EnableMulticastForwarding(MulticastForwardingEventDispatcher) (bool, tcpip.Error)

	// DisableMulticastForwarding disables multicast forwarding for the protocol.
	DisableMulticastForwarding()
}

// MulticastPacketContext is the context in which a multicast packet triggered
// a multicast forwarding event.
type MulticastPacketContext struct {
	// SourceAndDestination contains the unicast source address and the multicast
	// destination address found in the relevant multicast packet.
	SourceAndDestination UnicastSourceAndMulticastDestination
	// InputInterface is the interface on which the relevant multicast packet
	// arrived.
	InputInterface tcpip.NICID
}

// MulticastForwardingEventDispatcher is the interface that integrators should
// implement to handle multicast routing events.
type MulticastForwardingEventDispatcher interface {
	// OnMissingRoute is called when an incoming multicast packet does not match
	// any installed route.
	//
	// The packet that triggered this event may be queued so that it can be
	// transmitted once a route is installed. Even then, it may still be dropped
	// as per the routing table's GC/eviction policy.
	OnMissingRoute(MulticastPacketContext)

	// OnUnexpectedInputInterface is called when a multicast packet arrives at an
	// interface that does not match the installed route's expected input
	// interface.
	//
	// This may be an indication of a routing loop. The packet that triggered
	// this event is dropped without being forwarded.
	OnUnexpectedInputInterface(context MulticastPacketContext, expectedInputInterface tcpip.NICID)
}

// NetworkDispatcher contains the methods used by the network stack to deliver
// inbound/outbound packets to the appropriate network/packet(if any) endpoints.
type NetworkDispatcher interface {
	// DeliverNetworkPacket finds the appropriate network protocol endpoint
	// and hands the packet over for further processing.
	//
	//
	// If the link-layer has a header, the packet's link header must be populated.
	//
	// DeliverNetworkPacket may modify pkt.
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt PacketBufferPtr)

	// DeliverLinkPacket delivers a packet to any interested packet endpoints.
	//
	// This method should be called with both incoming and outgoing packets.
	//
	// If the link-layer has a header, the packet's link header must be populated.
	DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt PacketBufferPtr, incoming bool)
}

// LinkEndpointCapabilities is the type associated with the capabilities
// supported by a link-layer endpoint. It is a set of bitfields.
type LinkEndpointCapabilities uint

// The following are the supported link endpoint capabilities.
const (
	CapabilityNone LinkEndpointCapabilities = 0
	// CapabilityTXChecksumOffload indicates that the link endpoint supports
	// checksum computation for outgoing packets and the stack can skip
	// computing checksums when sending packets.
	CapabilityTXChecksumOffload LinkEndpointCapabilities = 1 << iota
	// CapabilityRXChecksumOffload indicates that the link endpoint supports
	// checksum verification on received packets and that it's safe for the
	// stack to skip checksum verification.
	CapabilityRXChecksumOffload
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOk
	CapabilityLoopback
)

// LinkWriter is an interface that supports sending packets via a data-link
// layer endpoint. It is used with QueueingDiscipline to batch writes from
// upper layer endpoints.
type LinkWriter interface {
	// WritePackets writes packets. Must not be called with an empty list of
	// packet buffers.
	//
	// WritePackets may modify the packet buffers, and takes ownership of the PacketBufferList.
	// it is not safe to use the PacketBufferList after a call to WritePackets.
	WritePackets(PacketBufferList) (int, tcpip.Error)
}

// NetworkLinkEndpoint is a data-link layer that supports sending network
// layer packets.
type NetworkLinkEndpoint interface {
	// MTU is the maximum transmission unit for this endpoint. This is
	// usually dictated by the backing physical network; when such a
	// physical network doesn't exist, the limit is generally 64k, which
	// includes the maximum size of an IP packet.
	MTU() uint32

	// MaxHeaderLength returns the maximum size the data link (and
	// lower level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// LinkAddress returns the link address (typically a MAC) of the
	// endpoint.
	LinkAddress() tcpip.LinkAddress

	// Capabilities returns the set of capabilities supported by the
	// endpoint.
	Capabilities() LinkEndpointCapabilities

	// Attach attaches the data link layer endpoint to the network-layer
	// dispatcher of the stack.
	//
	// Attach is called with a nil dispatcher when the endpoint's NIC is being
	// removed.
	Attach(dispatcher NetworkDispatcher)

	// IsAttached returns whether a NetworkDispatcher is attached to the
	// endpoint.
	IsAttached() bool

	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// For now, requesting that an endpoint's worker goroutine(s) stop is
	// implementation specific.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	Wait()

	// ARPHardwareType returns the ARPHRD_TYPE of the link endpoint.
	//
	// See:
	// https://github.com/torvalds/linux/blob/aa0c9086b40c17a7ad94425b3b70dd1fdd7497bf/include/uapi/linux/if_arp.h#L30
	ARPHardwareType() header.ARPHardwareType

	// AddHeader adds a link layer header to the packet if required.
	AddHeader(PacketBufferPtr)
}

// QueueingDiscipline provides a queueing strategy for outgoing packets (e.g
// FIFO, LIFO, Random Early Drop etc).
type QueueingDiscipline interface {
	// WritePacket writes a packet.
	//
	// WritePacket may modify the packet buffer. The packet buffer's
	// network and transport header must be set.
	//
	// To participate in transparent bridging, a LinkEndpoint implementation
	// should call eth.Encode with header.EthernetFields.SrcAddr set to
	// pkg.EgressRoute.LocalLinkAddress if it is provided.
	WritePacket(PacketBufferPtr) tcpip.Error

	Close()
}

// LinkEndpoint is the interface implemented by data link layer protocols (e.g.,
// ethernet, loopback, raw) and used by network layer protocols to send packets
// out through the implementer's data link endpoint. When a link header exists,
// it sets each PacketBuffer's LinkHeader field before passing it up the
// stack.
type LinkEndpoint interface {
	NetworkLinkEndpoint
	LinkWriter
}

// InjectableLinkEndpoint is a LinkEndpoint where inbound packets are
// delivered via the Inject method.
type InjectableLinkEndpoint interface {
	LinkEndpoint

	// InjectInbound injects an inbound packet.
	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt PacketBufferPtr)

	// InjectOutbound writes a fully formed outbound packet directly to the
	// link.
	//
	// dest is used by endpoints with multiple raw destinations.
	InjectOutbound(dest tcpip.Address, packet *bufferv2.View) tcpip.Error
}

// DADResult is a marker interface for the result of a duplicate address
// detection process.
type DADResult interface {
	isDADResult()
}

var _ DADResult = (*DADSucceeded)(nil)

// DADSucceeded indicates DAD completed without finding any duplicate addresses.
type DADSucceeded struct{}

func (*DADSucceeded) isDADResult() {}

var _ DADResult = (*DADError)(nil)

// DADError indicates DAD hit an error.
type DADError struct {
	Err tcpip.Error
}

func (*DADError) isDADResult() {}

var _ DADResult = (*DADAborted)(nil)

// DADAborted indicates DAD was aborted.
type DADAborted struct{}

func (*DADAborted) isDADResult() {}

var _ DADResult = (*DADDupAddrDetected)(nil)

// DADDupAddrDetected indicates DAD detected a duplicate address.
type DADDupAddrDetected struct {
	// HolderLinkAddress is the link address of the node that holds the duplicate
	// address.
	HolderLinkAddress tcpip.LinkAddress
}

func (*DADDupAddrDetected) isDADResult() {}

// DADCompletionHandler is a handler for DAD completion.
type DADCompletionHandler func(DADResult)

// DADCheckAddressDisposition enumerates the possible return values from
// DAD.CheckDuplicateAddress.
type DADCheckAddressDisposition int

const (
	_ DADCheckAddressDisposition = iota

	// DADDisabled indicates that DAD is disabled.
	DADDisabled

	// DADStarting indicates that DAD is starting for an address.
	DADStarting

	// DADAlreadyRunning indicates that DAD was already started for an address.
	DADAlreadyRunning
)

const (
	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	defaultDupAddrDetectTransmits = 1
)

// DADConfigurations holds configurations for duplicate address detection.
type DADConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor Solicitation
	// messages.
	//
	// Must be greater than or equal to 1ms.
	RetransmitTimer time.Duration
}

// DefaultDADConfigurations returns the default DAD configurations.
func DefaultDADConfigurations() DADConfigurations {
	return DADConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
	}
}

// Validate modifies the configuration with valid values. If invalid values are
// present in the configurations, the corresponding default values are used
// instead.
func (c *DADConfigurations) Validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

// DuplicateAddressDetector handles checking if an address is already assigned
// to some neighboring node on the link.
type DuplicateAddressDetector interface {
	// CheckDuplicateAddress checks if an address is assigned to a neighbor.
	//
	// If DAD is already being performed for the address, the handler will be
	// called with the result of the original DAD request.
	CheckDuplicateAddress(tcpip.Address, DADCompletionHandler) DADCheckAddressDisposition

	// SetDADConfigurations sets the configurations for DAD.
	SetDADConfigurations(c DADConfigurations)

	// DuplicateAddressProtocol returns the network protocol the receiver can
	// perform duplicate address detection for.
	DuplicateAddressProtocol() tcpip.NetworkProtocolNumber
}

// LinkAddressResolver handles link address resolution for a network protocol.
type LinkAddressResolver interface {
	// LinkAddressRequest sends a request for the link address of the target
	// address. The request is broadcast on the local network if a remote link
	// address is not provided.
	LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error

	// ResolveStaticAddress attempts to resolve address without sending
	// requests. It either resolves the name immediately or returns the
	// empty LinkAddress.
	//
	// It can be used to resolve broadcast addresses for example.
	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	// LinkAddressProtocol returns the network protocol of the
	// addresses this resolver can resolve.
	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

// RawFactory produces endpoints for writing various types of raw packets.
type RawFactory interface {
	// NewUnassociatedEndpoint produces endpoints for writing packets not
	// associated with a particular transport protocol. Such endpoints can
	// be used to write arbitrary packets that include the network header.
	NewUnassociatedEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// NewPacketEndpoint produces endpoints for reading and writing packets
	// that include network and (when cooked is false) link layer headers.
	NewPacketEndpoint(stack *Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)
}

// GSOType is the type of GSO segments.
//
// +stateify savable
type GSOType int

// Types of gso segments.
const (
	GSONone GSOType = iota

	// Hardware GSO types:
	GSOTCPv4
	GSOTCPv6

	// GSOGvisor is used for gVisor GSO segments which have to be sent by
	// endpoint.WritePackets.
	GSOGvisor
)

// GSO contains generic segmentation offload properties.
//
// +stateify savable
type GSO struct {
	// Type is one of GSONone, GSOTCPv4, etc.
	Type GSOType
	// NeedsCsum is set if the checksum offload is enabled.
	NeedsCsum bool
	// CsumOffset is offset after that to place checksum.
	CsumOffset uint16

	// Mss is maximum segment size.
	MSS uint16
	// L3Len is L3 (IP) header length.
	L3HdrLen uint16

	// MaxSize is maximum GSO packet size.
	MaxSize uint32
}

// SupportedGSO is the type of segmentation offloading supported.
type SupportedGSO int

const (
	// GSONotSupported indicates that segmentation offloading is not supported.
	GSONotSupported SupportedGSO = iota

	// HostGSOSupported indicates that segmentation offloading may be performed
	// by the host. This is typically true when netstack is attached to a host
	// AF_PACKET socket, and not true when attached to a unix socket or other
	// non-networking data layer.
	HostGSOSupported

	// GvisorGSOSupported indicates that segmentation offloading may be performed
	// in gVisor.
	GvisorGSOSupported
)

// GSOEndpoint provides access to GSO properties.
type GSOEndpoint interface {
	// GSOMaxSize returns the maximum GSO packet size.
	GSOMaxSize() uint32

	// SupportedGSO returns the supported segmentation offloading.
	SupportedGSO() SupportedGSO
}

// GvisorGSOMaxSize is a maximum allowed size of a software GSO segment.
// This isn't a hard limit, because it is never set into packet headers.
const GvisorGSOMaxSize = 1 << 16
