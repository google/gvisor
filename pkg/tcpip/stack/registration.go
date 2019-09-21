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
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
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
const (
	ControlPacketTooBig ControlType = iota
	ControlPortUnreachable
	ControlUnknown
)

// TransportEndpoint is the interface that needs to be implemented by transport
// protocol (e.g., tcp, udp) endpoints that can handle packets.
type TransportEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint.
	HandlePacket(r *Route, id TransportEndpointID, vv buffer.VectorisedView)

	// HandleControlPacket is called by the stack when new control (e.g.,
	// ICMP) packets arrive to this transport endpoint.
	HandleControlPacket(id TransportEndpointID, typ ControlType, extra uint32, vv buffer.VectorisedView)
}

// RawTransportEndpoint is the interface that needs to be implemented by raw
// transport protocol endpoints. RawTransportEndpoints receive the entire
// packet - including the link, network, and transport headers - as delivered
// to netstack.
type RawTransportEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint. The packet contains all data from the link
	// layer up.
	HandlePacket(r *Route, netHeader buffer.View, packet buffer.VectorisedView)
}

// TransportProtocol is the interface that needs to be implemented by transport
// protocols (e.g., tcp, udp) that want to be part of the networking stack.
type TransportProtocol interface {
	// Number returns the transport protocol number.
	Number() tcpip.TransportProtocolNumber

	// NewEndpoint creates a new endpoint of the transport protocol.
	NewEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// NewRawEndpoint creates a new raw endpoint of the transport protocol.
	NewRawEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// MinimumPacketSize returns the minimum valid packet size of this
	// transport protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParsePorts returns the source and destination ports stored in a
	// packet of this protocol.
	ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error)

	// HandleUnknownDestinationPacket handles packets targeted at this
	// protocol but that don't match any existing endpoint. For example,
	// it is targeted at a port that have no listeners.
	//
	// The return value indicates whether the packet was well-formed (for
	// stats purposes only).
	HandleUnknownDestinationPacket(r *Route, id TransportEndpointID, netHeader buffer.View, vv buffer.VectorisedView) bool

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option interface{}) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option interface{}) *tcpip.Error
}

// TransportDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate transport endpoint after it has been handled by
// the network layer.
type TransportDispatcher interface {
	// DeliverTransportPacket delivers packets to the appropriate
	// transport protocol endpoint. It also returns the network layer
	// header for the enpoint to inspect or pass up the stack.
	DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, netHeader buffer.View, vv buffer.VectorisedView)

	// DeliverTransportControlPacket delivers control packets to the
	// appropriate transport protocol endpoint.
	DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView)
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

// NetworkEndpoint is the interface that needs to be implemented by endpoints
// of network layer protocols (e.g., ipv4, ipv6).
type NetworkEndpoint interface {
	// DefaultTTL is the default time-to-live value (or hop limit, in ipv6)
	// for this endpoint.
	DefaultTTL() uint8

	// MTU is the maximum transmission unit for this endpoint. This is
	// generally calculated as the MTU of the underlying data link endpoint
	// minus the network endpoint max header length.
	MTU() uint32

	// Capabilities returns the set of capabilities supported by the
	// underlying link-layer endpoint.
	Capabilities() LinkEndpointCapabilities

	// MaxHeaderLength returns the maximum size the network (and lower
	// level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// WritePacket writes a packet to the given destination address and
	// protocol.
	WritePacket(r *Route, gso *GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber, ttl uint8, loop PacketLooping) *tcpip.Error

	WritePackets(r *Route, gso *GSO, hdrs []PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber, ttl uint8, loop PacketLooping) (int, *tcpip.Error)

	// WriteHeaderIncludedPacket writes a packet that includes a network
	// header to the given destination address.
	WriteHeaderIncludedPacket(r *Route, payload buffer.VectorisedView, loop PacketLooping) *tcpip.Error

	// ID returns the network protocol endpoint ID.
	ID() *NetworkEndpointID

	// PrefixLen returns the network endpoint's subnet prefix length in bits.
	PrefixLen() int

	// NICID returns the id of the NIC this endpoint belongs to.
	NICID() tcpip.NICID

	// HandlePacket is called by the link layer when new packets arrive to
	// this network endpoint.
	HandlePacket(r *Route, vv buffer.VectorisedView)

	// Close is called when the endpoint is reomved from a stack.
	Close()
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

	// ParsePorts returns the source and destination addresses stored in a
	// packet of this protocol.
	ParseAddresses(v buffer.View) (src, dst tcpip.Address)

	// NewEndpoint creates a new endpoint of this protocol.
	NewEndpoint(nicid tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache LinkAddressCache, dispatcher TransportDispatcher, sender LinkEndpoint) (NetworkEndpoint, *tcpip.Error)

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option interface{}) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option interface{}) *tcpip.Error
}

// NetworkDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate network endpoint after it has been handled by
// the data link layer.
type NetworkDispatcher interface {
	// DeliverNetworkPacket finds the appropriate network protocol
	// endpoint and hands the packet over for further processing.
	DeliverNetworkPacket(linkEP LinkEndpoint, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView)
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
	CapabilityHWGSO
	CapabilitySWGSO
)

// LinkEndpoint is the interface implemented by data link layer protocols (e.g.,
// ethernet, loopback, raw) and used by network layer protocols to send packets
// out through the implementer's data link endpoint.
type LinkEndpoint interface {
	// MTU is the maximum transmission unit for this endpoint. This is
	// usually dictated by the backing physical network; when such a
	// physical network doesn't exist, the limit is generally 64k, which
	// includes the maximum size of an IP packet.
	MTU() uint32

	// Capabilities returns the set of capabilities supported by the
	// endpoint.
	Capabilities() LinkEndpointCapabilities

	// MaxHeaderLength returns the maximum size the data link (and
	// lower level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// LinkAddress returns the link address (typically a MAC) of the
	// link endpoint.
	LinkAddress() tcpip.LinkAddress

	// WritePacket writes a packet with the given protocol through the given
	// route.
	//
	// To participate in transparent bridging, a LinkEndpoint implementation
	// should call eth.Encode with header.EthernetFields.SrcAddr set to
	// r.LocalLinkAddress if it is provided.
	WritePacket(r *Route, gso *GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error

	WritePackets(r *Route, gso *GSO, hdrs []PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error)

	// Attach attaches the data link layer endpoint to the network-layer
	// dispatcher of the stack.
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
}

// InjectableLinkEndpoint is a LinkEndpoint where inbound packets are
// delivered via the Inject method.
type InjectableLinkEndpoint interface {
	LinkEndpoint

	// Inject injects an inbound packet.
	Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView)

	// WriteRawPacket writes a fully formed outbound packet directly to the link.
	//
	// dest is used by endpoints with multiple raw destinations.
	WriteRawPacket(dest tcpip.Address, packet []byte) *tcpip.Error
}

// A LinkAddressResolver is an extension to a NetworkProtocol that
// can resolve link addresses.
type LinkAddressResolver interface {
	// LinkAddressRequest sends a request for the LinkAddress of addr.
	// The request is sent on linkEP with localAddr as the source.
	//
	// A valid response will cause the discovery protocol's network
	// endpoint to call AddLinkAddress.
	LinkAddressRequest(addr, localAddr tcpip.Address, linkEP LinkEndpoint) *tcpip.Error

	// ResolveStaticAddress attempts to resolve address without sending
	// requests. It either resolves the name immediately or returns the
	// empty LinkAddress.
	//
	// It can be used to resolve broadcast addresses for example.
	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	// LinkAddressProtocol returns the network protocol of the
	// addresses this this resolver can resolve.
	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

// A LinkAddressCache caches link addresses.
type LinkAddressCache interface {
	// CheckLocalAddress determines if the given local address exists, and if it
	// does not exist.
	CheckLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID

	// AddLinkAddress adds a link address to the cache.
	AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)

	// GetLinkAddress looks up the cache to translate address to link address (e.g. IP -> MAC).
	// If the LinkEndpoint requests address resolution and there is a LinkAddressResolver
	// registered with the network protocol, the cache attempts to resolve the address
	// and returns ErrWouldBlock. Waker is notified when address resolution is
	// complete (success or not).
	//
	// If address resolution is required, ErrNoLinkAddress and a notification channel is
	// returned for the top level caller to block. Channel is closed once address resolution
	// is complete (success or not).
	GetLinkAddress(nicid tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error)

	// RemoveWaker removes a waker that has been added in GetLinkAddress().
	RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker)
}

// TransportProtocolFactory functions are used by the stack to instantiate
// transport protocols.
type TransportProtocolFactory func() TransportProtocol

// NetworkProtocolFactory provides methods to be used by the stack to
// instantiate network protocols.
type NetworkProtocolFactory func() NetworkProtocol

// UnassociatedEndpointFactory produces endpoints for writing packets not
// associated with a particular transport protocol. Such endpoints can be used
// to write arbitrary packets that include the IP header.
type UnassociatedEndpointFactory interface {
	NewUnassociatedRawEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)
}

var (
	transportProtocols = make(map[string]TransportProtocolFactory)
	networkProtocols   = make(map[string]NetworkProtocolFactory)

	unassociatedFactory UnassociatedEndpointFactory
)

// RegisterTransportProtocolFactory registers a new transport protocol factory
// with the stack so that it becomes available to users of the stack. This
// function is intended to be called by init() functions of the protocols.
func RegisterTransportProtocolFactory(name string, p TransportProtocolFactory) {
	transportProtocols[name] = p
}

// RegisterNetworkProtocolFactory registers a new network protocol factory with
// the stack so that it becomes available to users of the stack. This function
// is intended to be called by init() functions of the protocols.
func RegisterNetworkProtocolFactory(name string, p NetworkProtocolFactory) {
	networkProtocols[name] = p
}

// RegisterUnassociatedFactory registers a factory to produce endpoints not
// associated with any particular transport protocol. This function is intended
// to be called by init() functions of the protocols.
func RegisterUnassociatedFactory(f UnassociatedEndpointFactory) {
	unassociatedFactory = f
}

// GSOType is the type of GSO segments.
//
// +stateify savable
type GSOType int

// Types of gso segments.
const (
	GSONone GSOType = iota
	GSOTCPv4
	GSOTCPv6
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
