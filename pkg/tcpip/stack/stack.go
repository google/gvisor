// Copyright 2018 Google LLC
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

// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
//
// For protocol implementers, RegisterTransportProtocolFactory() and
// RegisterNetworkProtocolFactory() are used to register protocol factories with
// the stack, which will then be used to instantiate protocol objects when
// consumers interact with the stack.
package stack

import (
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sleep"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/ports"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	// ageLimit is set to the same cache stale time used in Linux.
	ageLimit = 1 * time.Minute
	// resolutionTimeout is set to the same ARP timeout used in Linux.
	resolutionTimeout = 1 * time.Second
	// resolutionAttempts is set to the same ARP retries used in Linux.
	resolutionAttempts = 3
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(r *Route, id TransportEndpointID, netHeader buffer.View, vv buffer.VectorisedView) bool
}

// TCPProbeFunc is the expected function type for a TCP probe function to be
// passed to stack.AddTCPProbe.
type TCPProbeFunc func(s TCPEndpointState)

// TCPCubicState is used to hold a copy of the internal cubic state when the
// TCPProbeFunc is invoked.
type TCPCubicState struct {
	WLastMax                float64
	WMax                    float64
	T                       time.Time
	TimeSinceLastCongestion time.Duration
	C                       float64
	K                       float64
	Beta                    float64
	WC                      float64
	WEst                    float64
}

// TCPEndpointID is the unique 4 tuple that identifies a given endpoint.
type TCPEndpointID struct {
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

// TCPFastRecoveryState holds a copy of the internal fast recovery state of a
// TCP endpoint.
type TCPFastRecoveryState struct {
	// Active if true indicates the endpoint is in fast recovery.
	Active bool

	// First is the first unacknowledged sequence number being recovered.
	First seqnum.Value

	// Last is the 'recover' sequence number that indicates the point at
	// which we should exit recovery barring any timeouts etc.
	Last seqnum.Value

	// MaxCwnd is the maximum value we are permitted to grow the congestion
	// window during recovery. This is set at the time we enter recovery.
	MaxCwnd int
}

// TCPReceiverState holds a copy of the internal state of the receiver for
// a given TCP endpoint.
type TCPReceiverState struct {
	// RcvNxt is the TCP variable RCV.NXT.
	RcvNxt seqnum.Value

	// RcvAcc is the TCP variable RCV.ACC.
	RcvAcc seqnum.Value

	// RcvWndScale is the window scaling to use for inbound segments.
	RcvWndScale uint8

	// PendingBufUsed is the number of bytes pending in the receive
	// queue.
	PendingBufUsed seqnum.Size

	// PendingBufSize is the size of the socket receive buffer.
	PendingBufSize seqnum.Size
}

// TCPSenderState holds a copy of the internal state of the sender for
// a given TCP Endpoint.
type TCPSenderState struct {
	// LastSendTime is the time at which we sent the last segment.
	LastSendTime time.Time

	// DupAckCount is the number of Duplicate ACK's received.
	DupAckCount int

	// SndCwnd is the size of the sending congestion window in packets.
	SndCwnd int

	// Ssthresh is the slow start threshold in packets.
	Ssthresh int

	// SndCAAckCount is the number of packets consumed in congestion
	// avoidance mode.
	SndCAAckCount int

	// Outstanding is the number of packets in flight.
	Outstanding int

	// SndWnd is the send window size in bytes.
	SndWnd seqnum.Size

	// SndUna is the next unacknowledged sequence number.
	SndUna seqnum.Value

	// SndNxt is the sequence number of the next segment to be sent.
	SndNxt seqnum.Value

	// RTTMeasureSeqNum is the sequence number being used for the latest RTT
	// measurement.
	RTTMeasureSeqNum seqnum.Value

	// RTTMeasureTime is the time when the RTTMeasureSeqNum was sent.
	RTTMeasureTime time.Time

	// Closed indicates that the caller has closed the endpoint for sending.
	Closed bool

	// SRTT is the smoothed round-trip time as defined in section 2 of
	// RFC 6298.
	SRTT time.Duration

	// RTO is the retransmit timeout as defined in section of 2 of RFC 6298.
	RTO time.Duration

	// RTTVar is the round-trip time variation as defined in section 2 of
	// RFC 6298.
	RTTVar time.Duration

	// SRTTInited if true indicates take a valid RTT measurement has been
	// completed.
	SRTTInited bool

	// MaxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	MaxPayloadSize int

	// SndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	SndWndScale uint8

	// MaxSentAck is the highest acknowledgement number sent till now.
	MaxSentAck seqnum.Value

	// FastRecovery holds the fast recovery state for the endpoint.
	FastRecovery TCPFastRecoveryState

	// Cubic holds the state related to CUBIC congestion control.
	Cubic TCPCubicState
}

// TCPSACKInfo holds TCP SACK related information for a given TCP endpoint.
type TCPSACKInfo struct {
	// Blocks is the list of SACK Blocks that identify the out of order segments
	// held by a given TCP endpoint.
	Blocks []header.SACKBlock

	// ReceivedBlocks are the SACK blocks received by this endpoint
	// from the peer endpoint.
	ReceivedBlocks []header.SACKBlock

	// MaxSACKED is the highest sequence number that has been SACKED
	// by the peer.
	MaxSACKED seqnum.Value
}

// TCPEndpointState is a copy of the internal state of a TCP endpoint.
type TCPEndpointState struct {
	// ID is a copy of the TransportEndpointID for the endpoint.
	ID TCPEndpointID

	// SegTime denotes the absolute time when this segment was received.
	SegTime time.Time

	// RcvBufSize is the size of the receive socket buffer for the endpoint.
	RcvBufSize int

	// RcvBufUsed is the amount of bytes actually held in the receive socket
	// buffer for the endpoint.
	RcvBufUsed int

	// RcvClosed if true, indicates the endpoint has been closed for reading.
	RcvClosed bool

	// SendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1.
	SendTSOk bool

	// RecentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	RecentTS uint32

	// TSOffset is a randomized offset added to the value of the TSVal field
	// in the timestamp option.
	TSOffset uint32

	// SACKPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	SACKPermitted bool

	// SACK holds TCP SACK related information for this endpoint.
	SACK TCPSACKInfo

	// SndBufSize is the size of the socket send buffer.
	SndBufSize int

	// SndBufUsed is the number of bytes held in the socket send buffer.
	SndBufUsed int

	// SndClosed indicates that the endpoint has been closed for sends.
	SndClosed bool

	// SndBufInQueue is the number of bytes in the send queue.
	SndBufInQueue seqnum.Size

	// PacketTooBigCount is used to notify the main protocol routine how
	// many times a "packet too big" control packet is received.
	PacketTooBigCount int

	// SndMTU is the smallest MTU seen in the control packets received.
	SndMTU int

	// Receiver holds variables related to the TCP receiver for the endpoint.
	Receiver TCPReceiverState

	// Sender holds state related to the TCP Sender for the endpoint.
	Sender TCPSenderState
}

// Stack is a networking stack, with all supported protocols, NICs, and route
// table.
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver

	demux *transportDemuxer

	stats tcpip.Stats

	linkAddrCache *linkAddrCache

	// raw indicates whether raw sockets may be created. It is set during
	// Stack creation and is immutable.
	raw bool

	mu         sync.RWMutex
	nics       map[tcpip.NICID]*NIC
	forwarding bool

	// route is the route table passed in by the user via SetRouteTable(),
	// it is used by FindRoute() to build a route for a specific
	// destination.
	routeTable []tcpip.Route

	*ports.PortManager

	// If not nil, then any new endpoints will have this probe function
	// invoked everytime they receive a TCP segment.
	tcpProbeFunc TCPProbeFunc

	// clock is used to generate user-visible times.
	clock tcpip.Clock

	// handleLocal allows non-loopback interfaces to loop packets.
	handleLocal bool
}

// Options contains optional Stack configuration.
type Options struct {
	// Clock is an optional clock source used for timestampping packets.
	//
	// If no Clock is specified, the clock source will be time.Now.
	Clock tcpip.Clock

	// Stats are optional statistic counters.
	Stats tcpip.Stats

	// HandleLocal indicates whether packets destined to their source
	// should be handled by the stack internally (true) or outside the
	// stack (false).
	HandleLocal bool

	// Raw indicates whether raw sockets may be created.
	Raw bool
}

// New allocates a new networking stack with only the requested networking and
// transport protocols configured with default options.
//
// Protocol options can be changed by calling the
// SetNetworkProtocolOption/SetTransportProtocolOption methods provided by the
// stack. Please refer to individual protocol implementations as to what options
// are supported.
func New(network []string, transport []string, opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = &tcpip.StdClock{}
	}

	s := &Stack{
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		linkAddrResolvers:  make(map[tcpip.NetworkProtocolNumber]LinkAddressResolver),
		nics:               make(map[tcpip.NICID]*NIC),
		linkAddrCache:      newLinkAddrCache(ageLimit, resolutionTimeout, resolutionAttempts),
		PortManager:        ports.NewPortManager(),
		clock:              clock,
		stats:              opts.Stats.FillIn(),
		handleLocal:        opts.HandleLocal,
		raw:                opts.Raw,
	}

	// Add specified network protocols.
	for _, name := range network {
		netProtoFactory, ok := networkProtocols[name]
		if !ok {
			continue
		}
		netProto := netProtoFactory()
		s.networkProtocols[netProto.Number()] = netProto
		if r, ok := netProto.(LinkAddressResolver); ok {
			s.linkAddrResolvers[r.LinkAddressProtocol()] = r
		}
	}

	// Add specified transport protocols.
	for _, name := range transport {
		transProtoFactory, ok := transportProtocols[name]
		if !ok {
			continue
		}
		transProto := transProtoFactory()
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	// Create the global transport demuxer.
	s.demux = newTransportDemuxer(s)

	return s
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.SetOption(option)
}

// NetworkProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// e.g.
// var v ipv4.MyOption
// err := s.NetworkProtocolOption(tcpip.IPv4ProtocolNumber, &v)
// if err != nil {
//   ...
// }
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.SetOption(option)
}

// TransportProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// var v tcp.SACKEnabled
// if err := s.TransportProtocolOption(tcpip.TCPProtocolNumber, &v); err != nil {
//   ...
// }
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.Option(option)
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(*Route, TransportEndpointID, buffer.View, buffer.VectorisedView) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (s *Stack) NowNanoseconds() int64 {
	return s.clock.NowNanoseconds()
}

// Stats returns a mutable copy of the current stats.
//
// This is not generally exported via the public interface, but is available
// internally.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetForwarding enables or disables the packet forwarding between NICs.
func (s *Stack) SetForwarding(enable bool) {
	// TODO(igudger, bgeffon): Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.Lock()
	s.forwarding = enable
	s.mu.Unlock()
}

// Forwarding returns if the packet forwarding between NICs is enabled.
func (s *Stack) Forwarding() bool {
	// TODO(igudger, bgeffon): Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwarding
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routeTable = table
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tcpip.Route(nil), s.routeTable...)
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	return t.proto.NewEndpoint(s, network, waiterQueue)
}

// NewRawEndpoint creates a new raw transport layer endpoint of the given
// protocol. Raw endpoints receive all traffic for a given protocol regardless
// of address.
func (s *Stack) NewRawEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if !s.raw {
		return nil, tcpip.ErrNotPermitted
	}

	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	return t.proto.NewRawEndpoint(s, network, waiterQueue)
}

// createNIC creates a NIC with the provided id and link-layer endpoint, and
// optionally enable it.
func (s *Stack) createNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID, enabled, loopback bool) *tcpip.Error {
	ep := FindLinkEndpoint(linkEP)
	if ep == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique.
	if _, ok := s.nics[id]; ok {
		return tcpip.ErrDuplicateNICID
	}

	n := newNIC(s, id, name, ep, loopback)

	s.nics[id] = n
	if enabled {
		n.attachLinkEndpoint()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and link-layer endpoint.
func (s *Stack) CreateNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, "", linkEP, true, false)
}

// CreateNamedNIC creates a NIC with the provided id and link-layer endpoint,
// and a human-readable name.
func (s *Stack) CreateNamedNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, true, false)
}

// CreateNamedLoopbackNIC creates a NIC with the provided id and link-layer
// endpoint, and a human-readable name.
func (s *Stack) CreateNamedLoopbackNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, true, true)
}

// CreateDisabledNIC creates a NIC with the provided id and link-layer endpoint,
// but leave it disable. Stack.EnableNIC must be called before the link-layer
// endpoint starts delivering packets to it.
func (s *Stack) CreateDisabledNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, "", linkEP, false, false)
}

// CreateDisabledNamedNIC is a combination of CreateNamedNIC and
// CreateDisabledNIC.
func (s *Stack) CreateDisabledNamedNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, false, false)
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start
// delivering packets to it.
func (s *Stack) EnableNIC(id tcpip.NICID) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	nic.attachLinkEndpoint()

	return nil
}

// CheckNIC checks if a NIC is usable.
func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()
	if ok {
		return nic.linkEP.IsAttached()
	}
	return false
}

// NICSubnets returns a map of NICIDs to their associated subnets.
func (s *Stack) NICSubnets() map[tcpip.NICID][]tcpip.Subnet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := map[tcpip.NICID][]tcpip.Subnet{}

	for id, nic := range s.nics {
		nics[id] = append(nics[id], nic.Subnets()...)
	}
	return nics
}

// NICInfo captures the name and addresses assigned to a NIC.
type NICInfo struct {
	Name              string
	LinkAddress       tcpip.LinkAddress
	ProtocolAddresses []tcpip.ProtocolAddress

	// Flags indicate the state of the NIC.
	Flags NICStateFlags

	// MTU is the maximum transmission unit.
	MTU uint32

	Stats NICStats
}

// NICInfo returns a map of NICIDs to their associated information.
func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		flags := NICStateFlags{
			Up:          true, // Netstack interfaces are always up.
			Running:     nic.linkEP.IsAttached(),
			Promiscuous: nic.isPromiscuousMode(),
			Loopback:    nic.linkEP.Capabilities()&CapabilityLoopback != 0,
		}
		nics[id] = NICInfo{
			Name:              nic.name,
			LinkAddress:       nic.linkEP.LinkAddress(),
			ProtocolAddresses: nic.Addresses(),
			Flags:             flags,
			MTU:               nic.linkEP.MTU(),
			Stats:             nic.stats,
		}
	}
	return nics
}

// NICStateFlags holds information about the state of an NIC.
type NICStateFlags struct {
	// Up indicates whether the interface is running.
	Up bool

	// Running indicates whether resources are allocated.
	Running bool

	// Promiscuous indicates whether the interface is in promiscuous mode.
	Promiscuous bool

	// Loopback indicates whether the interface is a loopback.
	Loopback bool
}

// AddAddress adds a new network-layer address to the specified NIC.
func (s *Stack) AddAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	return s.AddAddressWithOptions(id, protocol, addr, CanBePrimaryEndpoint)
}

// AddAddressWithOptions is the same as AddAddress, but allows you to specify
// whether the new endpoint can be primary or not.
func (s *Stack) AddAddressWithOptions(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, peb PrimaryEndpointBehavior) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.AddAddressWithOptions(protocol, addr, peb)
}

// AddSubnet adds a subnet range to the specified NIC.
func (s *Stack) AddSubnet(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.AddSubnet(protocol, subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// RemoveSubnet removes the subnet range from the specified NIC.
func (s *Stack) RemoveSubnet(id tcpip.NICID, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.RemoveSubnet(subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// ContainsSubnet reports whether the specified NIC contains the specified
// subnet.
func (s *Stack) ContainsSubnet(id tcpip.NICID, subnet tcpip.Subnet) (bool, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.ContainsSubnet(subnet), nil
	}

	return false, tcpip.ErrUnknownNICID
}

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.RemoveAddress(addr)
	}

	return tcpip.ErrUnknownNICID
}

// GetMainNICAddress returns the first primary address (and the subnet that
// contains it) for the given NIC and protocol. Returns an arbitrary endpoint's
// address if no primary addresses exist. Returns an error if the NIC doesn't
// exist or has no endpoints.
func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.Address, tcpip.Subnet, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.getMainNICAddress(protocol)
	}

	return "", tcpip.Subnet{}, tcpip.ErrUnknownNICID
}

func (s *Stack) getRefEP(nic *NIC, localAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) (ref *referencedNetworkEndpoint) {
	if len(localAddr) == 0 {
		return nic.primaryEndpoint(netProto)
	}
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}

// FindRoute creates a route to the given destination address, leaving through
// the given nic and local address (if provided).
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (Route, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	isBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)
	needRoute := !(isBroadcast || isMulticast || header.IsV6LinkLocalAddress(remoteAddr))
	if id != 0 && !needRoute {
		if nic, ok := s.nics[id]; ok {
			if ref := s.getRefEP(nic, localAddr, netProto); ref != nil {
				return makeRoute(netProto, ref.ep.ID().LocalAddress, remoteAddr, nic.linkEP.LinkAddress(), ref, s.handleLocal && !nic.loopback, multicastLoop && !nic.loopback), nil
			}
		}
	} else {
		for _, route := range s.routeTable {
			if (id != 0 && id != route.NIC) || (len(remoteAddr) != 0 && !route.Match(remoteAddr)) {
				continue
			}
			if nic, ok := s.nics[route.NIC]; ok {
				if ref := s.getRefEP(nic, localAddr, netProto); ref != nil {
					if len(remoteAddr) == 0 {
						// If no remote address was provided, then the route
						// provided will refer to the link local address.
						remoteAddr = ref.ep.ID().LocalAddress
					}

					r := makeRoute(netProto, ref.ep.ID().LocalAddress, remoteAddr, nic.linkEP.LinkAddress(), ref, s.handleLocal && !nic.loopback, multicastLoop && !nic.loopback)
					if needRoute {
						r.NextHop = route.Gateway
					}
					return r, nil
				}
			}
		}
	}

	if !needRoute {
		return Route{}, tcpip.ErrNetworkUnreachable
	}

	return Route{}, tcpip.ErrNoRoute
}

// CheckNetworkProtocol checks if a given network protocol is enabled in the
// stack.
func (s *Stack) CheckNetworkProtocol(protocol tcpip.NetworkProtocolNumber) bool {
	_, ok := s.networkProtocols[protocol]
	return ok
}

// CheckLocalAddress determines if the given local address exists, and if it
// does, returns the id of the NIC it's bound to. Returns 0 if the address
// does not exist.
func (s *Stack) CheckLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, we try to find the address there only.
	if nicid != 0 {
		nic := s.nics[nicid]
		if nic == nil {
			return 0
		}

		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if ref == nil {
			return 0
		}

		ref.decRef()

		return nic.id
	}

	// Go through all the NICs.
	for _, nic := range s.nics {
		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if ref != nil {
			ref.decRef()
			return nic.id
		}
	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	nic.setPromiscuousMode(enable)

	return nil
}

// SetSpoofing enables or disables address spoofing in the given NIC, allowing
// endpoints to bind to any address in the NIC.
func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	nic.setSpoofing(enable)

	return nil
}

// AddLinkAddress adds a link address to the stack link cache.
func (s *Stack) AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
	s.linkAddrCache.add(fullAddr, linkAddr)
	// TODO: provide a way for a transport endpoint to receive a signal
	// that AddLinkAddress for a particular address has been called.
}

// GetLinkAddress implements LinkAddressCache.GetLinkAddress.
func (s *Stack) GetLinkAddress(nicid tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, waker *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	s.mu.RLock()
	nic := s.nics[nicid]
	if nic == nil {
		s.mu.RUnlock()
		return "", nil, tcpip.ErrUnknownNICID
	}
	s.mu.RUnlock()

	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
	linkRes := s.linkAddrResolvers[protocol]
	return s.linkAddrCache.get(fullAddr, linkRes, localAddr, nic.linkEP, waker)
}

// RemoveWaker implements LinkAddressCache.RemoveWaker.
func (s *Stack) RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic := s.nics[nicid]; nic == nil {
		fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
		s.linkAddrCache.removeWaker(fullAddr, waker)
	}
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optional, but
// nic-specific IDs have precedence over global ones.
func (s *Stack) RegisterTransportEndpoint(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, reusePort bool) *tcpip.Error {
	if nicID == 0 {
		return s.demux.registerEndpoint(netProtos, protocol, id, ep, reusePort)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.demux.registerEndpoint(netProtos, protocol, id, ep, reusePort)
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) {
	if nicID == 0 {
		s.demux.unregisterEndpoint(netProtos, protocol, id, ep)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic != nil {
		nic.demux.unregisterEndpoint(netProtos, protocol, id, ep)
	}
}

// RegisterRawTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided transport
// protocol will be delivered to the given endpoint.
func (s *Stack) RegisterRawTransportEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) *tcpip.Error {
	if nicID == 0 {
		return s.demux.registerRawEndpoint(netProto, transProto, ep)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.demux.registerRawEndpoint(netProto, transProto, ep)
}

// UnregisterRawTransportEndpoint removes the endpoint for the transport
// protocol from the stack transport dispatcher.
func (s *Stack) UnregisterRawTransportEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	if nicID == 0 {
		s.demux.unregisterRawEndpoint(netProto, transProto, ep)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic != nil {
		nic.demux.unregisterRawEndpoint(netProto, transProto, ep)
	}
}

// NetworkProtocolInstance returns the protocol instance in the stack for the
// specified network protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

// TransportProtocolInstance returns the protocol instance in the stack for the
// specified transport protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}

// AddTCPProbe installs a probe function that will be invoked on every segment
// received by a given TCP endpoint. The probe function is passed a copy of the
// TCP endpoint state.
//
// NOTE: TCPProbe is added only to endpoints created after this call. Endpoints
// created prior to this call will not call the probe function.
//
// Further, installing two different probes back to back can result in some
// endpoints calling the first one and some the second one. There is no
// guarantee provided on which probe will be invoked. Ideally this should only
// be called once per stack.
func (s *Stack) AddTCPProbe(probe TCPProbeFunc) {
	s.mu.Lock()
	s.tcpProbeFunc = probe
	s.mu.Unlock()
}

// GetTCPProbe returns the TCPProbeFunc if installed with AddTCPProbe, nil
// otherwise.
func (s *Stack) GetTCPProbe() TCPProbeFunc {
	s.mu.Lock()
	p := s.tcpProbeFunc
	s.mu.Unlock()
	return p
}

// RemoveTCPProbe removes an installed TCP probe.
//
// NOTE: This only ensures that endpoints created after this call do not
// have a probe attached. Endpoints already created will continue to invoke
// TCP probe.
func (s *Stack) RemoveTCPProbe() {
	s.mu.Lock()
	s.tcpProbeFunc = nil
	s.mu.Unlock()
}

// JoinGroup joins the given multicast group on the given NIC.
func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	// TODO: notify network of subscription via igmp protocol.
	return s.AddAddressWithOptions(nicID, protocol, multicastAddr, NeverPrimaryEndpoint)
}

// LeaveGroup leaves the given multicast group on the given NIC.
func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	return s.RemoveAddress(nicID, multicastAddr)
}
