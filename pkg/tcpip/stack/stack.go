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

// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
package stack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ageLimit is set to the same cache stale time used in Linux.
	ageLimit = 1 * time.Minute
	// resolutionTimeout is set to the same ARP timeout used in Linux.
	resolutionTimeout = 1 * time.Second
	// resolutionAttempts is set to the same ARP retries used in Linux.
	resolutionAttempts = 3

	// DefaultTOS is the default type of service value for network endpoints.
	DefaultTOS = 0
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(id TransportEndpointID, pkt *PacketBuffer) bool
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

// TCPRACKState is used to hold a copy of the internal RACK state when the
// TCPProbeFunc is invoked.
type TCPRACKState struct {
	XmitTime      time.Time
	EndSequence   seqnum.Value
	FACK          seqnum.Value
	RTT           time.Duration
	Reord         bool
	DSACKSeen     bool
	ReoWnd        time.Duration
	ReoWndIncr    uint8
	ReoWndPersist int8
	RTTSeq        seqnum.Value
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

	// HighRxt is the highest sequence number which has been retransmitted
	// during the current loss recovery phase.
	// See: RFC 6675 Section 2 for details.
	HighRxt seqnum.Value

	// RescueRxt is the highest sequence number which has been
	// optimistically retransmitted to prevent stalling of the ACK clock
	// when there is loss at the end of the window and no new data is
	// available for transmission.
	// See: RFC 6675 Section 2 for details.
	RescueRxt seqnum.Value
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
	PendingBufUsed int
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

	// SackedOut is the number of packets which have been selectively acked.
	SackedOut int

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

	// RACKState holds the state related to RACK loss detection algorithm.
	RACKState TCPRACKState
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

// RcvBufAutoTuneParams holds state related to TCP receive buffer auto-tuning.
type RcvBufAutoTuneParams struct {
	// MeasureTime is the time at which the current measurement
	// was started.
	MeasureTime time.Time

	// CopiedBytes is the number of bytes copied to user space since
	// this measure began.
	CopiedBytes int

	// PrevCopiedBytes is the number of bytes copied to userspace in
	// the previous RTT period.
	PrevCopiedBytes int

	// RcvBufSize is the auto tuned receive buffer size.
	RcvBufSize int

	// RTT is the smoothed RTT as measured by observing the time between
	// when a byte is first acknowledged and the receipt of data that is at
	// least one window beyond the sequence number that was acknowledged.
	RTT time.Duration

	// RTTVar is the "round-trip time variation" as defined in section 2
	// of RFC6298.
	RTTVar time.Duration

	// RTTMeasureSeqNumber is the highest acceptable sequence number at the
	// time this RTT measurement period began.
	RTTMeasureSeqNumber seqnum.Value

	// RTTMeasureTime is the absolute time at which the current RTT
	// measurement period began.
	RTTMeasureTime time.Time

	// Disabled is true if an explicit receive buffer is set for the
	// endpoint.
	Disabled bool
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

	// RcvBufAutoTuneParams is used to hold state variables to compute
	// the auto tuned receive buffer size.
	RcvAutoParams RcvBufAutoTuneParams

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

// ResumableEndpoint is an endpoint that needs to be resumed after restore.
type ResumableEndpoint interface {
	// Resume resumes an endpoint after restore. This can be used to restart
	// background workers such as protocol goroutines. This must be called after
	// all indirect dependencies of the endpoint has been restored, which
	// generally implies at the end of the restore process.
	Resume(*Stack)
}

// uniqueIDGenerator is a default unique ID generator.
type uniqueIDGenerator uint64

func (u *uniqueIDGenerator) UniqueID() uint64 {
	return atomic.AddUint64((*uint64)(u), 1)
}

// Stack is a networking stack, with all supported protocols, NICs, and route
// table.
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol

	// rawFactory creates raw endpoints. If nil, raw endpoints are
	// disabled. It is set during Stack creation and is immutable.
	rawFactory RawFactory

	demux *transportDemuxer

	stats tcpip.Stats

	// LOCK ORDERING: mu > route.mu.
	route struct {
		mu struct {
			sync.RWMutex

			table []tcpip.Route
		}
	}

	mu   sync.RWMutex
	nics map[tcpip.NICID]*NIC

	// cleanupEndpointsMu protects cleanupEndpoints.
	cleanupEndpointsMu sync.Mutex
	cleanupEndpoints   map[TransportEndpoint]struct{}

	*ports.PortManager

	// If not nil, then any new endpoints will have this probe function
	// invoked everytime they receive a TCP segment.
	tcpProbeFunc atomic.Value // TCPProbeFunc

	// clock is used to generate user-visible times.
	clock tcpip.Clock

	// handleLocal allows non-loopback interfaces to loop packets.
	handleLocal bool

	// tables are the iptables packet filtering and manipulation rules.
	// TODO(gvisor.dev/issue/170): S/R this field.
	tables *IPTables

	// resumableEndpoints is a list of endpoints that need to be resumed if the
	// stack is being restored.
	resumableEndpoints []ResumableEndpoint

	// icmpRateLimiter is a global rate limiter for all ICMP messages generated
	// by the stack.
	icmpRateLimiter *ICMPRateLimiter

	// seed is a one-time random value initialized at stack startup
	// and is used to seed the TCP port picking on active connections
	//
	// TODO(gvisor.dev/issue/940): S/R this field.
	seed uint32

	// nudConfigs is the default NUD configurations used by interfaces.
	nudConfigs NUDConfigurations

	// useNeighborCache indicates whether ARP and NDP packets should be handled
	// by the NIC's neighborCache instead of linkAddrCache.
	//
	// TODO(gvisor.dev/issue/4658): Remove this field.
	useNeighborCache bool

	// nudDisp is the NUD event dispatcher that is used to send the netstack
	// integrator NUD related events.
	nudDisp NUDDispatcher

	// uniqueIDGenerator is a generator of unique identifiers.
	uniqueIDGenerator UniqueID

	// randomGenerator is an injectable pseudo random generator that can be
	// used when a random number is required.
	randomGenerator *mathrand.Rand

	// sendBufferSize holds the min/default/max send buffer sizes for
	// endpoints other than TCP.
	sendBufferSize tcpip.SendBufferSizeOption

	// receiveBufferSize holds the min/default/max receive buffer sizes for
	// endpoints other than TCP.
	receiveBufferSize ReceiveBufferSizeOption

	// tcpInvalidRateLimit is the maximal rate for sending duplicate
	// acknowledgements in response to incoming TCP packets that are for an existing
	// connection but that are invalid due to any of the following reasons:
	//
	//   a) out-of-window sequence number.
	//   b) out-of-window acknowledgement number.
	//   c) PAWS check failure (when implemented).
	//
	// This is required to prevent potential ACK loops.
	// Setting this to 0 will disable all rate limiting.
	tcpInvalidRateLimit time.Duration
}

// UniqueID is an abstract generator of unique identifiers.
type UniqueID interface {
	UniqueID() uint64
}

// NetworkProtocolFactory instantiates a network protocol.
//
// NetworkProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type NetworkProtocolFactory func(*Stack) NetworkProtocol

// TransportProtocolFactory instantiates a transport protocol.
//
// TransportProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type TransportProtocolFactory func(*Stack) TransportProtocol

// Options contains optional Stack configuration.
type Options struct {
	// NetworkProtocols lists the network protocols to enable.
	NetworkProtocols []NetworkProtocolFactory

	// TransportProtocols lists the transport protocols to enable.
	TransportProtocols []TransportProtocolFactory

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

	// UniqueID is an optional generator of unique identifiers.
	UniqueID UniqueID

	// NUDConfigs is the default NUD configurations used by interfaces.
	NUDConfigs NUDConfigurations

	// UseNeighborCache is unused.
	//
	// TODO(gvisor.dev/issue/4658): Remove this field.
	UseNeighborCache bool

	// UseLinkAddrCache indicates that the legacy link address cache should be
	// used for link resolution.
	//
	// TODO(gvisor.dev/issue/4658): Remove this field.
	UseLinkAddrCache bool

	// NUDDisp is the NUD event dispatcher that an integrator can provide to
	// receive NUD related events.
	NUDDisp NUDDispatcher

	// RawFactory produces raw endpoints. Raw endpoints are enabled only if
	// this is non-nil.
	RawFactory RawFactory

	// RandSource is an optional source to use to generate random
	// numbers. If omitted it defaults to a Source seeded by the data
	// returned by rand.Read().
	//
	// RandSource must be thread-safe.
	RandSource mathrand.Source

	// IPTables are the initial iptables rules. If nil, iptables will allow
	// all traffic.
	IPTables *IPTables
}

// TransportEndpointInfo holds useful information about a transport endpoint
// which can be queried by monitoring tools.
//
// +stateify savable
type TransportEndpointInfo struct {
	// The following fields are initialized at creation time and are
	// immutable.

	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber

	// The following fields are protected by endpoint mu.

	ID TransportEndpointID
	// BindNICID and bindAddr are set via calls to Bind(). They are used to
	// reject attempts to send data or connect via a different NIC or
	// address
	BindNICID tcpip.NICID
	BindAddr  tcpip.Address
	// RegisterNICID is the default NICID registered as a side-effect of
	// connect or datagram write.
	RegisterNICID tcpip.NICID
}

// AddrNetProtoLocked unwraps the specified address if it is a V4-mapped V6
// address and returns the network protocol number to be used to communicate
// with the specified address. It returns an error if the passed address is
// incompatible with the receiver.
//
// Preconditon: the parent endpoint mu must be held while calling this method.
func (t *TransportEndpointInfo) AddrNetProtoLocked(addr tcpip.FullAddress, v6only bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	netProto := t.NetProto
	switch len(addr.Addr) {
	case header.IPv4AddressSize:
		netProto = header.IPv4ProtocolNumber
	case header.IPv6AddressSize:
		if header.IsV4MappedAddress(addr.Addr) {
			netProto = header.IPv4ProtocolNumber
			addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
			if addr.Addr == header.IPv4Any {
				addr.Addr = ""
			}
		}
	}

	switch len(t.ID.LocalAddress) {
	case header.IPv4AddressSize:
		if len(addr.Addr) == header.IPv6AddressSize {
			return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
		}
	case header.IPv6AddressSize:
		if len(addr.Addr) == header.IPv4AddressSize {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNetworkUnreachable{}
		}
	}

	switch {
	case netProto == t.NetProto:
	case netProto == header.IPv4ProtocolNumber && t.NetProto == header.IPv6ProtocolNumber:
		if v6only {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNoRoute{}
		}
	default:
		return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
	}

	return addr, netProto, nil
}

// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
// marker interface.
func (*TransportEndpointInfo) IsEndpointInfo() {}

// New allocates a new networking stack with only the requested networking and
// transport protocols configured with default options.
//
// Note, NDPConfigurations will be fixed before being used by the Stack. That
// is, if an invalid value was provided, it will be reset to the default value.
//
// Protocol options can be changed by calling the
// SetNetworkProtocolOption/SetTransportProtocolOption methods provided by the
// stack. Please refer to individual protocol implementations as to what options
// are supported.
func New(opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = &tcpip.StdClock{}
	}

	if opts.UniqueID == nil {
		opts.UniqueID = new(uniqueIDGenerator)
	}

	randSrc := opts.RandSource
	if randSrc == nil {
		// Source provided by mathrand.NewSource is not thread-safe so
		// we wrap it in a simple thread-safe version.
		randSrc = &lockedRandomSource{src: mathrand.NewSource(generateRandInt64())}
	}

	if opts.IPTables == nil {
		opts.IPTables = DefaultTables()
	}

	opts.NUDConfigs.resetInvalidFields()

	s := &Stack{
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		nics:               make(map[tcpip.NICID]*NIC),
		cleanupEndpoints:   make(map[TransportEndpoint]struct{}),
		PortManager:        ports.NewPortManager(),
		clock:              clock,
		stats:              opts.Stats.FillIn(),
		handleLocal:        opts.HandleLocal,
		tables:             opts.IPTables,
		icmpRateLimiter:    NewICMPRateLimiter(),
		seed:               generateRandUint32(),
		nudConfigs:         opts.NUDConfigs,
		useNeighborCache:   !opts.UseLinkAddrCache,
		uniqueIDGenerator:  opts.UniqueID,
		nudDisp:            opts.NUDDisp,
		randomGenerator:    mathrand.New(randSrc),
		sendBufferSize: tcpip.SendBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		receiveBufferSize: ReceiveBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		tcpInvalidRateLimit: defaultTCPInvalidRateLimit,
	}

	// Add specified network protocols.
	for _, netProtoFactory := range opts.NetworkProtocols {
		netProto := netProtoFactory(s)
		s.networkProtocols[netProto.Number()] = netProto
	}

	// Add specified transport protocols.
	for _, transProtoFactory := range opts.TransportProtocols {
		transProto := transProtoFactory(s)
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	// Add the factory for raw endpoints, if present.
	s.rawFactory = opts.RawFactory

	// Create the global transport demuxer.
	s.demux = newTransportDemuxer(s)

	return s
}

// newJob returns a tcpip.Job using the Stack clock.
func (s *Stack) newJob(l sync.Locker, f func()) *tcpip.Job {
	return tcpip.NewJob(s.clock, l, f)
}

// UniqueID returns a unique identifier.
func (s *Stack) UniqueID() uint64 {
	return s.uniqueIDGenerator.UniqueID()
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
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
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.SettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
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
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.Option(option)
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// Clock returns the Stack's clock for retrieving the current time and
// scheduling work.
func (s *Stack) Clock() tcpip.Clock {
	return s.clock
}

// Stats returns a mutable copy of the current stats.
//
// This is not generally exported via the public interface, but is available
// internally.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetForwarding enables or disables packet forwarding between NICs for the
// passed protocol.
func (s *Stack) SetForwarding(protocolNum tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	protocol, ok := s.networkProtocols[protocolNum]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	forwardingProtocol, ok := protocol.(ForwardingNetworkProtocol)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	forwardingProtocol.SetForwarding(enable)
	return nil
}

// Forwarding returns true if packet forwarding between NICs is enabled for the
// passed protocol.
func (s *Stack) Forwarding(protocolNum tcpip.NetworkProtocolNumber) bool {
	protocol, ok := s.networkProtocols[protocolNum]
	if !ok {
		return false
	}

	forwardingProtocol, ok := protocol.(ForwardingNetworkProtocol)
	if !ok {
		return false
	}

	return forwardingProtocol.Forwarding()
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
//
// This method takes ownership of the table.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.route.mu.Lock()
	defer s.route.mu.Unlock()
	s.route.mu.table = table
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.route.mu.RLock()
	defer s.route.mu.RUnlock()
	return append([]tcpip.Route(nil), s.route.mu.table...)
}

// AddRoute appends a route to the route table.
func (s *Stack) AddRoute(route tcpip.Route) {
	s.route.mu.Lock()
	defer s.route.mu.Unlock()
	s.route.mu.table = append(s.route.mu.table, route)
}

// RemoveRoutes removes matching routes from the route table.
func (s *Stack) RemoveRoutes(match func(tcpip.Route) bool) {
	s.route.mu.Lock()
	defer s.route.mu.Unlock()

	var filteredRoutes []tcpip.Route
	for _, route := range s.route.mu.table {
		if !match(route) {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	s.route.mu.table = filteredRoutes
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewEndpoint(network, waiterQueue)
}

// NewRawEndpoint creates a new raw transport layer endpoint of the given
// protocol. Raw endpoints receive all traffic for a given protocol regardless
// of address.
func (s *Stack) NewRawEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		return nil, &tcpip.ErrNotPermitted{}
	}

	if !associated {
		return s.rawFactory.NewUnassociatedEndpoint(s, network, transport, waiterQueue)
	}

	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewRawEndpoint(network, waiterQueue)
}

// NewPacketEndpoint creates a new packet endpoint listening for the given
// netProto.
func (s *Stack) NewPacketEndpoint(cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		return nil, &tcpip.ErrNotPermitted{}
	}

	return s.rawFactory.NewPacketEndpoint(s, cooked, netProto, waiterQueue)
}

// NICContext is an opaque pointer used to store client-supplied NIC metadata.
type NICContext interface{}

// NICOptions specifies the configuration of a NIC as it is being created.
// The zero value creates an enabled, unnamed NIC.
type NICOptions struct {
	// Name specifies the name of the NIC.
	Name string

	// Disabled specifies whether to avoid calling Attach on the passed
	// LinkEndpoint.
	Disabled bool

	// Context specifies user-defined data that will be returned in stack.NICInfo
	// for the NIC. Clients of this library can use it to add metadata that
	// should be tracked alongside a NIC, to avoid having to keep a
	// map[tcpip.NICID]metadata mirroring stack.Stack's nic map.
	Context NICContext
}

// CreateNICWithOptions creates a NIC with the provided id, LinkEndpoint, and
// NICOptions. See the documentation on type NICOptions for details on how
// NICs can be configured.
//
// LinkEndpoint.Attach will be called to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNICWithOptions(id tcpip.NICID, ep LinkEndpoint, opts NICOptions) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique.
	if _, ok := s.nics[id]; ok {
		return &tcpip.ErrDuplicateNICID{}
	}

	// Make sure name is unique, unless unnamed.
	if opts.Name != "" {
		for _, n := range s.nics {
			if n.Name() == opts.Name {
				return &tcpip.ErrDuplicateNICID{}
			}
		}
	}

	n := newNIC(s, id, opts.Name, ep, opts.Context)
	s.nics[id] = n
	if !opts.Disabled {
		return n.enable()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and LinkEndpoint and calls
// LinkEndpoint.Attach to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNIC(id tcpip.NICID, ep LinkEndpoint) tcpip.Error {
	return s.CreateNICWithOptions(id, ep, NICOptions{})
}

// GetLinkEndpointByName gets the link endpoint specified by name.
func (s *Stack) GetLinkEndpointByName(name string) LinkEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nic := range s.nics {
		if nic.Name() == name {
			return nic.LinkEndpoint
		}
	}
	return nil
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start
// delivering packets to it.
func (s *Stack) EnableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.enable()
}

// DisableNIC disables the given NIC.
func (s *Stack) DisableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.disable()
	return nil
}

// CheckNIC checks if a NIC is usable.
func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false
	}

	return nic.Enabled()
}

// RemoveNIC removes NIC and all related routes from the network stack.
func (s *Stack) RemoveNIC(id tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.removeNICLocked(id)
}

// removeNICLocked removes NIC and all related routes from the network stack.
//
// s.mu must be locked.
func (s *Stack) removeNICLocked(id tcpip.NICID) tcpip.Error {
	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	delete(s.nics, id)

	// Remove routes in-place. n tracks the number of routes written.
	s.route.mu.Lock()
	n := 0
	for i, r := range s.route.mu.table {
		s.route.mu.table[i] = tcpip.Route{}
		if r.NIC != id {
			// Keep this route.
			s.route.mu.table[n] = r
			n++
		}
	}
	s.route.mu.table = s.route.mu.table[:n]
	s.route.mu.Unlock()

	return nic.remove()
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

	// NetworkStats holds the stats of each NetworkEndpoint bound to the NIC.
	NetworkStats map[tcpip.NetworkProtocolNumber]NetworkEndpointStats

	// Context is user-supplied data optionally supplied in CreateNICWithOptions.
	// See type NICOptions for more details.
	Context NICContext

	// ARPHardwareType holds the ARP Hardware type of the NIC. This is the
	// value sent in haType field of an ARP Request sent by this NIC and the
	// value expected in the haType field of an ARP response.
	ARPHardwareType header.ARPHardwareType
}

// HasNIC returns true if the NICID is defined in the stack.
func (s *Stack) HasNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	_, ok := s.nics[id]
	s.mu.RUnlock()
	return ok
}

// NICInfo returns a map of NICIDs to their associated information.
func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		flags := NICStateFlags{
			Up:          true, // Netstack interfaces are always up.
			Running:     nic.Enabled(),
			Promiscuous: nic.Promiscuous(),
			Loopback:    nic.IsLoopback(),
		}

		netStats := make(map[tcpip.NetworkProtocolNumber]NetworkEndpointStats)
		for proto, netEP := range nic.networkEndpoints {
			netStats[proto] = netEP.Stats()
		}

		nics[id] = NICInfo{
			Name:              nic.name,
			LinkAddress:       nic.LinkEndpoint.LinkAddress(),
			ProtocolAddresses: nic.primaryAddresses(),
			Flags:             flags,
			MTU:               nic.LinkEndpoint.MTU(),
			Stats:             nic.stats,
			NetworkStats:      netStats,
			Context:           nic.context,
			ARPHardwareType:   nic.LinkEndpoint.ARPHardwareType(),
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
func (s *Stack) AddAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	return s.AddAddressWithOptions(id, protocol, addr, CanBePrimaryEndpoint)
}

// AddAddressWithPrefix is the same as AddAddress, but allows you to specify
// the address prefix.
func (s *Stack) AddAddressWithPrefix(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.AddressWithPrefix) tcpip.Error {
	ap := tcpip.ProtocolAddress{
		Protocol:          protocol,
		AddressWithPrefix: addr,
	}
	return s.AddProtocolAddressWithOptions(id, ap, CanBePrimaryEndpoint)
}

// AddProtocolAddress adds a new network-layer protocol address to the
// specified NIC.
func (s *Stack) AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress) tcpip.Error {
	return s.AddProtocolAddressWithOptions(id, protocolAddress, CanBePrimaryEndpoint)
}

// AddAddressWithOptions is the same as AddAddress, but allows you to specify
// whether the new endpoint can be primary or not.
func (s *Stack) AddAddressWithOptions(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, peb PrimaryEndpointBehavior) tcpip.Error {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return s.AddProtocolAddressWithOptions(id, tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: netProto.DefaultPrefixLen(),
		},
	}, peb)
}

// AddProtocolAddressWithOptions is the same as AddProtocolAddress, but allows
// you to specify whether the new endpoint can be primary or not.
func (s *Stack) AddProtocolAddressWithOptions(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addAddress(protocolAddress, peb)
}

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.removeAddress(addr)
	}

	return &tcpip.ErrUnknownNICID{}
}

// AllAddresses returns a map of NICIDs to their protocol addresses (primary
// and non-primary).
func (s *Stack) AllAddresses() map[tcpip.NICID][]tcpip.ProtocolAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID][]tcpip.ProtocolAddress)
	for id, nic := range s.nics {
		nics[id] = nic.allPermanentAddresses()
	}
	return nics
}

// GetMainNICAddress returns the first non-deprecated primary address and prefix
// for the given NIC and protocol. If no non-deprecated primary address exists,
// a deprecated primary address and prefix will be returned. Returns false if
// the NIC doesn't exist and an empty value if the NIC doesn't have a primary
// address for the given protocol.
func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.AddressWithPrefix{}, false
	}

	return nic.primaryAddress(protocol), true
}

func (s *Stack) getAddressEP(nic *NIC, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) AssignableAddressEndpoint {
	if len(localAddr) == 0 {
		return nic.primaryEndpoint(netProto, remoteAddr)
	}
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}

// findLocalRouteFromNICRLocked is like findLocalRouteRLocked but finds a route
// from the specified NIC.
//
// Precondition: s.mu must be read locked.
func (s *Stack) findLocalRouteFromNICRLocked(localAddressNIC *NIC, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, false /* createTemp */, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	var outgoingNIC *NIC
	// Prefer a local route to the same interface as the local address.
	if localAddressNIC.hasAddress(netProto, remoteAddr) {
		outgoingNIC = localAddressNIC
	}

	// If the remote address isn't owned by the local address's NIC, check all
	// NICs.
	if outgoingNIC == nil {
		for _, nic := range s.nics {
			if nic.hasAddress(netProto, remoteAddr) {
				outgoingNIC = nic
				break
			}
		}
	}

	// If the remote address is not owned by the stack, we can't return a local
	// route.
	if outgoingNIC == nil {
		localAddressEndpoint.DecRef()
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

// findLocalRouteRLocked returns a local route.
//
// A local route is a route to some remote address which the stack owns. That
// is, a local route is a route where packets never have to leave the stack.
//
// Precondition: s.mu must be read locked.
func (s *Stack) findLocalRouteRLocked(localAddressNICID tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	if len(localAddr) == 0 {
		localAddr = remoteAddr
	}

	if localAddressNICID == 0 {
		for _, localAddressNIC := range s.nics {
			if r := s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto); r != nil {
				return r
			}
		}

		return nil
	}

	if localAddressNIC, ok := s.nics[localAddressNICID]; ok {
		return s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto)
	}

	return nil
}

// FindRoute creates a route to the given destination address, leaving through
// the given NIC and local address (if provided).
//
// If a NIC is not specified, the returned route will leave through the same
// NIC as the NIC that has the local address assigned when forwarding is
// disabled. If forwarding is enabled and the NIC is unspecified, the route may
// leave through any interface unless the route is link-local.
//
// If no local address is provided, the stack will select a local address. If no
// remote address is provided, the stack wil use a remote address equal to the
// local address.
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (*Route, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	isLinkLocal := header.IsV6LinkLocalAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr)
	isLocalBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)
	isLoopback := header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr)
	needRoute := !(isLocalBroadcast || isMulticast || isLinkLocal || isLoopback)

	if s.handleLocal && !isMulticast && !isLocalBroadcast {
		if r := s.findLocalRouteRLocked(id, localAddr, remoteAddr, netProto); r != nil {
			return r, nil
		}
	}

	// If the interface is specified and we do not need a route, return a route
	// through the interface if the interface is valid and enabled.
	if id != 0 && !needRoute {
		if nic, ok := s.nics[id]; ok && nic.Enabled() {
			if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, netProto); addressEndpoint != nil {
				return makeRoute(
					netProto,
					"", /* gateway */
					localAddr,
					remoteAddr,
					nic, /* outboundNIC */
					nic, /* localAddressNIC*/
					addressEndpoint,
					s.handleLocal,
					multicastLoop,
				), nil
			}
		}

		if isLoopback {
			return nil, &tcpip.ErrBadLocalAddress{}
		}
		return nil, &tcpip.ErrNetworkUnreachable{}
	}

	canForward := s.Forwarding(netProto) && !header.IsV6LinkLocalAddress(localAddr) && !isLinkLocal

	// Find a route to the remote with the route table.
	var chosenRoute tcpip.Route
	if r := func() *Route {
		s.route.mu.RLock()
		defer s.route.mu.RUnlock()

		for _, route := range s.route.mu.table {
			if len(remoteAddr) != 0 && !route.Destination.Contains(remoteAddr) {
				continue
			}

			nic, ok := s.nics[route.NIC]
			if !ok || !nic.Enabled() {
				continue
			}

			if id == 0 || id == route.NIC {
				if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, netProto); addressEndpoint != nil {
					var gateway tcpip.Address
					if needRoute {
						gateway = route.Gateway
					}
					r := constructAndValidateRoute(netProto, addressEndpoint, nic /* outgoingNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop)
					if r == nil {
						panic(fmt.Sprintf("non-forwarding route validation failed with route table entry = %#v, id = %d, localAddr = %s, remoteAddr = %s", route, id, localAddr, remoteAddr))
					}
					return r
				}
			}

			// If the stack has forwarding enabled and we haven't found a valid route
			// to the remote address yet, keep track of the first valid route. We
			// keep iterating because we prefer routes that let us use a local
			// address that is assigned to the outgoing interface. There is no
			// requirement to do this from any RFC but simply a choice made to better
			// follow a strong host model which the netstack follows at the time of
			// writing.
			if canForward && chosenRoute == (tcpip.Route{}) {
				chosenRoute = route
			}
		}

		return nil
	}(); r != nil {
		return r, nil
	}

	if chosenRoute != (tcpip.Route{}) {
		// At this point we know the stack has forwarding enabled since chosenRoute is
		// only set when forwarding is enabled.
		nic, ok := s.nics[chosenRoute.NIC]
		if !ok {
			// If the route's NIC was invalid, we should not have chosen the route.
			panic(fmt.Sprintf("chosen route must have a valid NIC with ID = %d", chosenRoute.NIC))
		}

		var gateway tcpip.Address
		if needRoute {
			gateway = chosenRoute.Gateway
		}

		// Use the specified NIC to get the local address endpoint.
		if id != 0 {
			if aNIC, ok := s.nics[id]; ok {
				if addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, netProto); addressEndpoint != nil {
					if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop); r != nil {
						return r, nil
					}
				}
			}

			return nil, &tcpip.ErrNoRoute{}
		}

		if id == 0 {
			// If an interface is not specified, try to find a NIC that holds the local
			// address endpoint to construct a route.
			for _, aNIC := range s.nics {
				addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, netProto)
				if addressEndpoint == nil {
					continue
				}

				if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop); r != nil {
					return r, nil
				}
			}
		}
	}

	if needRoute {
		return nil, &tcpip.ErrNoRoute{}
	}
	if header.IsV6LoopbackAddress(remoteAddr) {
		return nil, &tcpip.ErrBadLocalAddress{}
	}
	return nil, &tcpip.ErrNetworkUnreachable{}
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
func (s *Stack) CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, we try to find the address there only.
	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return 0
		}

		addressEndpoint := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if addressEndpoint == nil {
			return 0
		}

		addressEndpoint.DecRef()

		return nic.id
	}

	// Go through all the NICs.
	for _, nic := range s.nics {
		if addressEndpoint := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint); addressEndpoint != nil {
			addressEndpoint.DecRef()
			return nic.id
		}
	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setPromiscuousMode(enable)

	return nil
}

// SetSpoofing enables or disables address spoofing in the given NIC, allowing
// endpoints to bind to any address in the NIC.
func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setSpoofing(enable)

	return nil
}

// LinkResolutionResult is the result of a link address resolution attempt.
type LinkResolutionResult struct {
	LinkAddress tcpip.LinkAddress
	Success     bool
}

// GetLinkAddress finds the link address corresponding to a network address.
//
// Returns ErrNotSupported if the stack is not configured with a link address
// resolver for the specified network protocol.
//
// Returns ErrWouldBlock if the link address is not readily available, along
// with a notification channel for the caller to block on. Triggers address
// resolution asynchronously.
//
// onResolve will be called either immediately, if resolution is not required,
// or when address resolution is complete, with the resolved link address and
// whether resolution succeeded.
//
// If specified, the local address must be an address local to the interface
// the neighbor cache belongs to. The local address is the source address of
// a packet prompting NUD/link address resolution.
func (s *Stack) GetLinkAddress(nicID tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, onResolve func(LinkResolutionResult)) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.getLinkAddress(addr, localAddr, protocol, onResolve)
}

// Neighbors returns all IP to MAC address associations.
func (s *Stack) Neighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) ([]NeighborEntry, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.neighbors(protocol)
}

// AddStaticNeighbor statically associates an IP address to a MAC address.
func (s *Stack) AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addStaticNeighbor(addr, protocol, linkAddr)
}

// RemoveNeighbor removes an IP to MAC address association previously created
// either automically or by AddStaticNeighbor. Returns ErrBadAddress if there
// is no association with the provided address.
func (s *Stack) RemoveNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.removeNeighbor(protocol, addr)
}

// ClearNeighbors removes all IP to MAC address associations.
func (s *Stack) ClearNeighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.clearNeighbors(protocol)
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optional, but
// nic-specific IDs have precedence over global ones.
func (s *Stack) RegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.registerEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CheckRegisterTransportEndpoint checks if an endpoint can be registered with
// the stack transport dispatcher.
func (s *Stack) CheckRegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.checkEndpoint(netProtos, protocol, id, flags, bindToDevice)
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// StartTransportEndpointCleanup removes the endpoint with the given id from
// the stack transport dispatcher. It also transitions it to the cleanup stage.
func (s *Stack) StartTransportEndpointCleanup(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.cleanupEndpointsMu.Lock()
	s.cleanupEndpoints[ep] = struct{}{}
	s.cleanupEndpointsMu.Unlock()

	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CompleteTransportEndpointCleanup removes the endpoint from the cleanup
// stage.
func (s *Stack) CompleteTransportEndpointCleanup(ep TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	delete(s.cleanupEndpoints, ep)
	s.cleanupEndpointsMu.Unlock()
}

// FindTransportEndpoint finds an endpoint that most closely matches the provided
// id. If no endpoint is found it returns nil.
func (s *Stack) FindTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, id TransportEndpointID, nicID tcpip.NICID) TransportEndpoint {
	return s.demux.findTransportEndpoint(netProto, transProto, id, nicID)
}

// RegisterRawTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided transport
// protocol will be delivered to the given endpoint.
func (s *Stack) RegisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) tcpip.Error {
	return s.demux.registerRawEndpoint(netProto, transProto, ep)
}

// UnregisterRawTransportEndpoint removes the endpoint for the transport
// protocol from the stack transport dispatcher.
func (s *Stack) UnregisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	s.demux.unregisterRawEndpoint(netProto, transProto, ep)
}

// RegisterRestoredEndpoint records e as an endpoint that has been restored on
// this stack.
func (s *Stack) RegisterRestoredEndpoint(e ResumableEndpoint) {
	s.mu.Lock()
	s.resumableEndpoints = append(s.resumableEndpoints, e)
	s.mu.Unlock()
}

// RegisteredEndpoints returns all endpoints which are currently registered.
func (s *Stack) RegisteredEndpoints() []TransportEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	var es []TransportEndpoint
	for _, e := range s.demux.protocol {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

// CleanupEndpoints returns endpoints currently in the cleanup state.
func (s *Stack) CleanupEndpoints() []TransportEndpoint {
	s.cleanupEndpointsMu.Lock()
	es := make([]TransportEndpoint, 0, len(s.cleanupEndpoints))
	for e := range s.cleanupEndpoints {
		es = append(es, e)
	}
	s.cleanupEndpointsMu.Unlock()
	return es
}

// RestoreCleanupEndpoints adds endpoints to cleanup tracking. This is useful
// for restoring a stack after a save.
func (s *Stack) RestoreCleanupEndpoints(es []TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	for _, e := range es {
		s.cleanupEndpoints[e] = struct{}{}
	}
	s.cleanupEndpointsMu.Unlock()
}

// Close closes all currently registered transport endpoints.
//
// Endpoints created or modified during this call may not get closed.
func (s *Stack) Close() {
	for _, e := range s.RegisteredEndpoints() {
		e.Abort()
	}
	for _, p := range s.transportProtocols {
		p.proto.Close()
	}
	for _, p := range s.networkProtocols {
		p.Close()
	}
}

// Wait waits for all transport and link endpoints to halt their worker
// goroutines.
//
// Endpoints created or modified during this call may not get waited on.
//
// Note that link endpoints must be stopped via an implementation specific
// mechanism.
func (s *Stack) Wait() {
	for _, e := range s.RegisteredEndpoints() {
		e.Wait()
	}
	for _, e := range s.CleanupEndpoints() {
		e.Wait()
	}
	for _, p := range s.transportProtocols {
		p.proto.Wait()
	}
	for _, p := range s.networkProtocols {
		p.Wait()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.nics {
		n.LinkEndpoint.Wait()
	}
}

// Resume restarts the stack after a restore. This must be called after the
// entire system has been restored.
func (s *Stack) Resume() {
	// ResumableEndpoint.Resume() may call other methods on s, so we can't hold
	// s.mu while resuming the endpoints.
	s.mu.Lock()
	eps := s.resumableEndpoints
	s.resumableEndpoints = nil
	s.mu.Unlock()
	for _, e := range eps {
		e.Resume(s)
	}
}

// RegisterPacketEndpoint registers ep with the stack, causing it to receive
// all traffic of the specified netProto on the given NIC. If nicID is 0, it
// receives traffic from every NIC.
func (s *Stack) RegisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If no NIC is specified, capture on all devices.
	if nicID == 0 {
		// Register with each NIC.
		for _, nic := range s.nics {
			if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
				s.unregisterPacketEndpointLocked(0, netProto, ep)
				return err
			}
		}
		return nil
	}

	// Capture on a specific device.
	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
		return err
	}

	return nil
}

// UnregisterPacketEndpoint unregisters ep for packets of the specified
// netProto from the specified NIC. If nicID is 0, ep is unregistered from all
// NICs.
func (s *Stack) UnregisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unregisterPacketEndpointLocked(nicID, netProto, ep)
}

func (s *Stack) unregisterPacketEndpointLocked(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	// If no NIC is specified, unregister on all devices.
	if nicID == 0 {
		// Unregister with each NIC.
		for _, nic := range s.nics {
			nic.unregisterPacketEndpoint(netProto, ep)
		}
		return
	}

	// Unregister in a single device.
	nic, ok := s.nics[nicID]
	if !ok {
		return
	}
	nic.unregisterPacketEndpoint(netProto, ep)
}

// WritePacketToRemote writes a payload on the specified NIC using the provided
// network protocol and remote link address.
func (s *Stack) WritePacketToRemote(nicID tcpip.NICID, remote tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.VectorisedView) tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return &tcpip.ErrUnknownDevice{}
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(nic.MaxHeaderLength()),
		Data:               payload,
	})
	return nic.WritePacketToRemote(remote, nil, netProto, pkt)
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
// TCP endpoint state before and after processing of the segment.
//
// NOTE: TCPProbe is added only to endpoints created after this call. Endpoints
// created prior to this call will not call the probe function.
//
// Further, installing two different probes back to back can result in some
// endpoints calling the first one and some the second one. There is no
// guarantee provided on which probe will be invoked. Ideally this should only
// be called once per stack.
func (s *Stack) AddTCPProbe(probe TCPProbeFunc) {
	s.tcpProbeFunc.Store(probe)
}

// GetTCPProbe returns the TCPProbeFunc if installed with AddTCPProbe, nil
// otherwise.
func (s *Stack) GetTCPProbe() TCPProbeFunc {
	p := s.tcpProbeFunc.Load()
	if p == nil {
		return nil
	}
	return p.(TCPProbeFunc)
}

// RemoveTCPProbe removes an installed TCP probe.
//
// NOTE: This only ensures that endpoints created after this call do not
// have a probe attached. Endpoints already created will continue to invoke
// TCP probe.
func (s *Stack) RemoveTCPProbe() {
	// This must be TCPProbeFunc(nil) because atomic.Value.Store(nil) panics.
	s.tcpProbeFunc.Store(TCPProbeFunc(nil))
}

// JoinGroup joins the given multicast group on the given NIC.
func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.joinGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

// LeaveGroup leaves the given multicast group on the given NIC.
func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.leaveGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

// IsInGroup returns true if the NIC with ID nicID has joined the multicast
// group multicastAddr.
func (s *Stack) IsInGroup(nicID tcpip.NICID, multicastAddr tcpip.Address) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.isInGroup(multicastAddr), nil
	}
	return false, &tcpip.ErrUnknownNICID{}
}

// IPTables returns the stack's iptables.
func (s *Stack) IPTables() *IPTables {
	return s.tables
}

// ICMPLimit returns the maximum number of ICMP messages that can be sent
// in one second.
func (s *Stack) ICMPLimit() rate.Limit {
	return s.icmpRateLimiter.Limit()
}

// SetICMPLimit sets the maximum number of ICMP messages that be sent
// in one second.
func (s *Stack) SetICMPLimit(newLimit rate.Limit) {
	s.icmpRateLimiter.SetLimit(newLimit)
}

// ICMPBurst returns the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) ICMPBurst() int {
	return s.icmpRateLimiter.Burst()
}

// SetICMPBurst sets the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) SetICMPBurst(burst int) {
	s.icmpRateLimiter.SetBurst(burst)
}

// AllowICMPMessage returns true if we the rate limiter allows at least one
// ICMP message to be sent at this instant.
func (s *Stack) AllowICMPMessage() bool {
	return s.icmpRateLimiter.Allow()
}

// GetNetworkEndpoint returns the NetworkEndpoint with the specified protocol
// number installed on the specified NIC.
func (s *Stack) GetNetworkEndpoint(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NetworkEndpoint, tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.getNetworkEndpoint(proto), nil
}

// NUDConfigurations gets the per-interface NUD configurations.
func (s *Stack) NUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NUDConfigurations, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return NUDConfigurations{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.nudConfigs(proto)
}

// SetNUDConfigurations sets the per-interface NUD configurations.
//
// Note, if c contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (s *Stack) SetNUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber, c NUDConfigurations) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.setNUDConfigs(proto, c)
}

// Seed returns a 32 bit value that can be used as a seed value for port
// picking, ISN generation etc.
//
// NOTE: The seed is generated once during stack initialization only.
func (s *Stack) Seed() uint32 {
	return s.seed
}

// Rand returns a reference to a pseudo random generator that can be used
// to generate random numbers as required.
func (s *Stack) Rand() *mathrand.Rand {
	return s.randomGenerator
}

func generateRandUint32() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(b)
}

func generateRandInt64() int64 {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	buf := bytes.NewReader(b)
	var v int64
	if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
		panic(err)
	}
	return v
}

// FindNetworkEndpoint returns the network endpoint for the given address.
func (s *Stack) FindNetworkEndpoint(netProto tcpip.NetworkProtocolNumber, address tcpip.Address) (NetworkEndpoint, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, nic := range s.nics {
		addressEndpoint := nic.getAddressOrCreateTempInner(netProto, address, false /* createTemp */, NeverPrimaryEndpoint)
		if addressEndpoint == nil {
			continue
		}
		addressEndpoint.DecRef()
		return nic.getNetworkEndpoint(netProto), nil
	}
	return nil, &tcpip.ErrBadAddress{}
}

// FindNICNameFromID returns the name of the NIC for the given NICID.
func (s *Stack) FindNICNameFromID(id tcpip.NICID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return ""
	}

	return nic.Name()
}

// NewJob returns a new tcpip.Job using the stack's clock.
func (s *Stack) NewJob(l sync.Locker, f func()) *tcpip.Job {
	return tcpip.NewJob(s.clock, l, f)
}

// ParseResult indicates the result of a parsing attempt.
type ParseResult int

const (
	// ParsedOK indicates that a packet was successfully parsed.
	ParsedOK ParseResult = iota

	// UnknownNetworkProtocol indicates that the network protocol is unknown.
	UnknownNetworkProtocol

	// NetworkLayerParseError indicates that the network packet was not
	// successfully parsed.
	NetworkLayerParseError

	// UnknownTransportProtocol indicates that the transport protocol is unknown.
	UnknownTransportProtocol

	// TransportLayerParseError indicates that the transport packet was not
	// successfully parsed.
	TransportLayerParseError
)

// ParsePacketBuffer parses the provided packet buffer.
func (s *Stack) ParsePacketBuffer(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) ParseResult {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return UnknownNetworkProtocol
	}

	transProtoNum, hasTransportHdr, ok := netProto.Parse(pkt)
	if !ok {
		return NetworkLayerParseError
	}
	if !hasTransportHdr {
		return ParsedOK
	}

	// TODO(gvisor.dev/issue/170): ICMP packets don't have their TransportHeader
	// fields set yet, parse it here. See icmp/protocol.go:protocol.Parse for a
	// full explanation.
	if transProtoNum == header.ICMPv4ProtocolNumber || transProtoNum == header.ICMPv6ProtocolNumber {
		return ParsedOK
	}

	pkt.TransportProtocolNumber = transProtoNum
	// Parse the transport header if present.
	state, ok := s.transportProtocols[transProtoNum]
	if !ok {
		return UnknownTransportProtocol
	}

	if !state.proto.Parse(pkt) {
		return TransportLayerParseError
	}

	return ParsedOK
}

// networkProtocolNumbers returns the network protocol numbers the stack is
// configured with.
func (s *Stack) networkProtocolNumbers() []tcpip.NetworkProtocolNumber {
	protos := make([]tcpip.NetworkProtocolNumber, 0, len(s.networkProtocols))
	for p := range s.networkProtocols {
		protos = append(protos, p)
	}
	return protos
}

func isSubnetBroadcastOnNIC(nic *NIC, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	addressEndpoint := nic.getAddressOrCreateTempInner(protocol, addr, false /* createTemp */, NeverPrimaryEndpoint)
	if addressEndpoint == nil {
		return false
	}

	subnet := addressEndpoint.Subnet()
	addressEndpoint.DecRef()
	return subnet.IsBroadcast(addr)
}

// IsSubnetBroadcast returns true if the provided address is a subnet-local
// broadcast address on the specified NIC and protocol.
//
// Returns false if the NIC is unknown or if the protocol is unknown or does
// not support addressing.
//
// If the NIC is not specified, the stack will check all NICs.
func (s *Stack) IsSubnetBroadcast(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return false
		}

		return isSubnetBroadcastOnNIC(nic, protocol, addr)
	}

	for _, nic := range s.nics {
		if isSubnetBroadcastOnNIC(nic, protocol, addr) {
			return true
		}
	}

	return false
}
