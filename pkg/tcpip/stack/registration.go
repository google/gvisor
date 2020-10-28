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

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
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

// ControlType is the type of network control message.
type ControlType int

// The following are the allowed values for ControlType values.
// TODO(http://gvisor.dev/issue/3210): Support time exceeded messages.
const (
	ControlNetworkUnreachable ControlType = iota
	ControlNoRoute
	ControlPacketTooBig
	ControlPortUnreachable
	ControlUnknown
)

// NetworkPacketInfo holds information about a network layer packet.
type NetworkPacketInfo struct {
	// RemoteAddressBroadcast is true if the packet's remote address is a
	// broadcast address.
	RemoteAddressBroadcast bool

	// LocalAddressBroadcast is true if the packet's local address is a broadcast
	// address.
	LocalAddressBroadcast bool
}

// TransportEndpoint is the interface that needs to be implemented by transport
// protocol (e.g., tcp, udp) endpoints that can handle packets.
type TransportEndpoint interface {
	// UniqueID returns an unique ID for this transport endpoint.
	UniqueID() uint64

	// HandlePacket is called by the stack when new packets arrive to this
	// transport endpoint. It sets the packet buffer's transport header.
	//
	// HandlePacket takes ownership of the packet.
	HandlePacket(TransportEndpointID, *PacketBuffer)

	// HandleControlPacket is called by the stack when new control (e.g.
	// ICMP) packets arrive to this transport endpoint.
	// HandleControlPacket takes ownership of pkt.
	HandleControlPacket(id TransportEndpointID, typ ControlType, extra uint32, pkt *PacketBuffer)

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
	// HandlePacket takes ownership of the packet.
	HandlePacket(*PacketBuffer)
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
	// HandlePacket takes ownership of pkt.
	HandlePacket(nicID tcpip.NICID, addr tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

// UnknownDestinationPacketDisposition enumerates the possible return vaues from
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
	NewEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// NewRawEndpoint creates a new raw endpoint of the transport protocol.
	NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// MinimumPacketSize returns the minimum valid packet size of this
	// transport protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParsePorts returns the source and destination ports stored in a
	// packet of this protocol.
	ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error)

	// HandleUnknownDestinationPacket handles packets targeted at this
	// protocol that don't match any existing endpoint. For example,
	// it is targeted at a port that has no listeners.
	//
	// HandleUnknownDestinationPacket takes ownership of the packet if it handles
	// the issue.
	HandleUnknownDestinationPacket(TransportEndpointID, *PacketBuffer) UnknownDestinationPacketDisposition

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableTransportProtocolOption) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableTransportProtocolOption) *tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Parse sets pkt.TransportHeader and trims pkt.Data appropriately. It does
	// neither and returns false if pkt.Data is too small, i.e. pkt.Data.Size() <
	// MinimumPacketSize()
	Parse(pkt *PacketBuffer) (ok bool)
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
	// DeliverTransportPacket takes ownership of the packet.
	DeliverTransportPacket(tcpip.TransportProtocolNumber, *PacketBuffer) TransportPacketDisposition

	// DeliverTransportControlPacket delivers control packets to the
	// appropriate transport protocol endpoint.
	//
	// pkt.NetworkHeader must be set before calling
	// DeliverTransportControlPacket.
	//
	// DeliverTransportControlPacket takes ownership of pkt.
	DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, pkt *PacketBuffer)
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
	// JoinGroup joins the spcified group.
	//
	// Returns true if the group was newly joined.
	JoinGroup(group tcpip.Address) (bool, *tcpip.Error)

	// LeaveGroup attempts to leave the specified group.
	//
	// Returns tcpip.ErrBadLocalAddress if the endpoint has not joined the group.
	LeaveGroup(group tcpip.Address) (bool, *tcpip.Error)

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool
}

// PrimaryEndpointBehavior is an enumeration of an AddressEndpoint's primary
// behavior.
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address. This is the
	// default when calling NIC.AddAddress.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, they are ordered by recency.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
)

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

	// AddressConfigSlaacTemp is a temporary address endpoint added by SLAAC as
	// per RFC 4941. Temporary SLAAC addresses are short-lived and are not
	// to be valid (or preferred) forever; hence the term temporary.
	AddressConfigSlaacTemp
)

// AssignableAddressEndpoint is a reference counted address endpoint that may be
// assigned to a NetworkEndpoint.
type AssignableAddressEndpoint interface {
	// AddressWithPrefix returns the endpoint's address.
	AddressWithPrefix() tcpip.AddressWithPrefix

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
}

// AddressKind is the kind of of an address.
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
	// consider the NIC bound an an address that it is not explictiy bound to
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
	// Returns tcpip.ErrDuplicateAddress if the address exists.
	//
	// Acquires and returns the AddressEndpoint for the added address.
	AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated bool) (AddressEndpoint, *tcpip.Error)

	// RemovePermanentAddress removes the passed address if it is a permanent
	// address.
	//
	// Returns tcpip.ErrBadLocalAddress if the endpoint does not have the passed
	// permanent address.
	RemovePermanentAddress(addr tcpip.Address) *tcpip.Error

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

	// WritePacketToRemote writes the packet to the given remote link address.
	WritePacketToRemote(tcpip.LinkAddress, *GSO, tcpip.NetworkProtocolNumber, *PacketBuffer) *tcpip.Error
}

// NetworkEndpoint is the interface that needs to be implemented by endpoints
// of network layer protocols (e.g., ipv4, ipv6).
type NetworkEndpoint interface {
	AddressableEndpoint

	// Enable enables the endpoint.
	//
	// Must only be called when the stack is in a state that allows the endpoint
	// to send and receive packets.
	//
	// Returns tcpip.ErrNotPermitted if the endpoint cannot be enabled.
	Enable() *tcpip.Error

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
	// protocol. It takes ownership of pkt. pkt.TransportHeader must have
	// already been set.
	WritePacket(r *Route, gso *GSO, params NetworkHeaderParams, pkt *PacketBuffer) *tcpip.Error

	// WritePackets writes packets to the given destination address and
	// protocol. pkts must not be zero length. It takes ownership of pkts and
	// underlying packets.
	WritePackets(r *Route, gso *GSO, pkts PacketBufferList, params NetworkHeaderParams) (int, *tcpip.Error)

	// WriteHeaderIncludedPacket writes a packet that includes a network
	// header to the given destination address. It takes ownership of pkt.
	WriteHeaderIncludedPacket(r *Route, pkt *PacketBuffer) *tcpip.Error

	// HandlePacket is called by the link layer when new packets arrive to
	// this network endpoint. It sets pkt.NetworkHeader.
	//
	// HandlePacket takes ownership of pkt.
	HandlePacket(pkt *PacketBuffer)

	// Close is called when the endpoint is reomved from a stack.
	Close()

	// NetworkProtocolNumber returns the tcpip.NetworkProtocolNumber for
	// this endpoint.
	NetworkProtocolNumber() tcpip.NetworkProtocolNumber
}

// ForwardingNetworkProtocol is a NetworkProtocol that may forward packets.
type ForwardingNetworkProtocol interface {
	NetworkProtocol

	// Forwarding returns the forwarding configuration.
	Forwarding() bool

	// SetForwarding sets the forwarding configuration.
	SetForwarding(bool)
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

	// DefaultPrefixLen returns the protocol's default prefix length.
	DefaultPrefixLen() int

	// ParseAddresses returns the source and destination addresses stored in a
	// packet of this protocol.
	ParseAddresses(v buffer.View) (src, dst tcpip.Address)

	// NewEndpoint creates a new endpoint of this protocol.
	NewEndpoint(nic NetworkInterface, linkAddrCache LinkAddressCache, nud NUDHandler, dispatcher TransportDispatcher) NetworkEndpoint

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableNetworkProtocolOption) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableNetworkProtocolOption) *tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Parse sets pkt.NetworkHeader and trims pkt.Data appropriately. It
	// returns:
	// - The encapsulated protocol, if present.
	// - Whether there is an encapsulated transport protocol payload (e.g. ARP
	//   does not encapsulate anything).
	// - Whether pkt.Data was large enough to parse and set pkt.NetworkHeader.
	Parse(pkt *PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool)
}

// NetworkDispatcher contains the methods used by the network stack to deliver
// inbound/outbound packets to the appropriate network/packet(if any) endpoints.
type NetworkDispatcher interface {
	// DeliverNetworkPacket finds the appropriate network protocol endpoint
	// and hands the packet over for further processing.
	//
	// pkt.LinkHeader may or may not be set before calling
	// DeliverNetworkPacket. Some packets do not have link headers (e.g.
	// packets sent via loopback), and won't have the field set.
	//
	// DeliverNetworkPacket takes ownership of pkt.
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

	// DeliverOutboundPacket is called by link layer when a packet is being
	// sent out.
	//
	// pkt.LinkHeader may or may not be set before calling
	// DeliverOutboundPacket. Some packets do not have link headers (e.g.
	// packets sent via loopback), and won't have the field set.
	//
	// DeliverOutboundPacket takes ownership of pkt.
	DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
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
	CapabilityHardwareGSO

	// CapabilitySoftwareGSO indicates the link endpoint supports of sending
	// multiple packets using a single call (LinkEndpoint.WritePackets).
	CapabilitySoftwareGSO
)

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

	// WritePacket writes a packet with the given protocol through the
	// given route. It takes ownership of pkt. pkt.NetworkHeader and
	// pkt.TransportHeader must have already been set.
	//
	// To participate in transparent bridging, a LinkEndpoint implementation
	// should call eth.Encode with header.EthernetFields.SrcAddr set to
	// r.LocalLinkAddress if it is provided.
	WritePacket(r *Route, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *tcpip.Error

	// WritePackets writes packets with the given protocol through the
	// given route. pkts must not be zero length. It takes ownership of pkts and
	// underlying packets.
	//
	// Right now, WritePackets is used only when the software segmentation
	// offload is enabled. If it will be used for something else, it may
	// require to change syscall filters.
	WritePackets(r *Route, gso *GSO, pkts PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error)
}

// LinkEndpoint is the interface implemented by data link layer protocols (e.g.,
// ethernet, loopback, raw) and used by network layer protocols to send packets
// out through the implementer's data link endpoint. When a link header exists,
// it sets each PacketBuffer's LinkHeader field before passing it up the
// stack.
type LinkEndpoint interface {
	NetworkLinkEndpoint

	// Capabilities returns the set of capabilities supported by the
	// endpoint.
	Capabilities() LinkEndpointCapabilities

	// WriteRawPacket writes a packet directly to the link. The packet
	// should already have an ethernet header. It takes ownership of vv.
	WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error

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

	// AddHeader adds a link layer header to pkt if required.
	AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

// InjectableLinkEndpoint is a LinkEndpoint where inbound packets are
// delivered via the Inject method.
type InjectableLinkEndpoint interface {
	LinkEndpoint

	// InjectInbound injects an inbound packet.
	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

	// InjectOutbound writes a fully formed outbound packet directly to the
	// link.
	//
	// dest is used by endpoints with multiple raw destinations.
	InjectOutbound(dest tcpip.Address, packet []byte) *tcpip.Error
}

// A LinkAddressResolver is an extension to a NetworkProtocol that
// can resolve link addresses.
type LinkAddressResolver interface {
	// LinkAddressRequest sends a request for the link address of the target
	// address. The request is broadcasted on the local network if a remote link
	// address is not provided.
	//
	// The request is sent from the passed network interface. If the interface
	// local address is unspecified, any interface local address may be used.
	LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, nic NetworkInterface) *tcpip.Error

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

// A LinkAddressCache caches link addresses.
type LinkAddressCache interface {
	// CheckLocalAddress determines if the given local address exists, and if it
	// does not exist.
	CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID

	// AddLinkAddress adds a link address to the cache.
	AddLinkAddress(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)

	// GetLinkAddress looks up the cache to translate address to link address (e.g. IP -> MAC).
	// If the LinkEndpoint requests address resolution and there is a LinkAddressResolver
	// registered with the network protocol, the cache attempts to resolve the address
	// and returns ErrWouldBlock. Waker is notified when address resolution is
	// complete (success or not).
	//
	// If address resolution is required, ErrNoLinkAddress and a notification channel is
	// returned for the top level caller to block. Channel is closed once address resolution
	// is complete (success or not).
	GetLinkAddress(nicID tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error)

	// RemoveWaker removes a waker that has been added in GetLinkAddress().
	RemoveWaker(nicID tcpip.NICID, addr tcpip.Address, waker *sleep.Waker)
}

// RawFactory produces endpoints for writing various types of raw packets.
type RawFactory interface {
	// NewUnassociatedEndpoint produces endpoints for writing packets not
	// associated with a particular transport protocol. Such endpoints can
	// be used to write arbitrary packets that include the network header.
	NewUnassociatedEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// NewPacketEndpoint produces endpoints for reading and writing packets
	// that include network and (when cooked is false) link layer headers.
	NewPacketEndpoint(stack *Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)
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

	// GSOSW is used for software GSO segments which have to be sent by
	// endpoint.WritePackets.
	GSOSW
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

// GSOEndpoint provides access to GSO properties.
type GSOEndpoint interface {
	// GSOMaxSize returns the maximum GSO packet size.
	GSOMaxSize() uint32
}

// SoftwareGSOMaxSize is a maximum allowed size of a software GSO segment.
// This isn't a hard limit, because it is never set into packet headers.
const SoftwareGSOMaxSize = (1 << 16)
