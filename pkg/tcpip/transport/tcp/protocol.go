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

// Package tcp contains the implementation of the TCP transport protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing tcp.NewProtocol() as one of the
// transport protocols when calling stack.New(). Then endpoints can be created
// by passing tcp.ProtocolNumber as the transport protocol number when calling
// Stack.NewEndpoint().
package tcp

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ProtocolNumber is the tcp protocol number.
	ProtocolNumber = header.TCPProtocolNumber

	// MinBufferSize is the smallest size of a receive or send buffer.
	MinBufferSize = 4 << 10 // 4096 bytes.

	// DefaultSendBufferSize is the default size of the send buffer for
	// an endpoint.
	DefaultSendBufferSize = 1 << 20 // 1MB

	// DefaultReceiveBufferSize is the default size of the receive buffer
	// for an endpoint.
	DefaultReceiveBufferSize = 1 << 20 // 1MB

	// MaxBufferSize is the largest size a receive/send buffer can grow to.
	MaxBufferSize = 4 << 20 // 4MB

	// MaxUnprocessedSegments is the maximum number of unprocessed segments
	// that can be queued for a given endpoint.
	MaxUnprocessedSegments = 300

	// DefaultTCPLingerTimeout is the amount of time that sockets linger in
	// FIN_WAIT_2 state before being marked closed.
	DefaultTCPLingerTimeout = 60 * time.Second

	// DefaultTCPTimeWaitTimeout is the amount of time that sockets linger
	// in TIME_WAIT state before being marked closed.
	DefaultTCPTimeWaitTimeout = 60 * time.Second

	// DefaultSynRetries is the default value for the number of SYN retransmits
	// before a connect is aborted.
	DefaultSynRetries = 6
)

const (
	ccReno  = "reno"
	ccCubic = "cubic"
)

// SACKEnabled is used by stack.(*Stack).TransportProtocolOption to
// enable/disable SACK support in TCP. See: https://tools.ietf.org/html/rfc2018.
type SACKEnabled bool

// DelayEnabled is used by stack.(Stack*).TransportProtocolOption to
// enable/disable Nagle's algorithm in TCP.
type DelayEnabled bool

// SendBufferSizeOption is used by stack.(Stack*).TransportProtocolOption
// to get/set the default, min and max TCP send buffer sizes.
type SendBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// ReceiveBufferSizeOption is used by
// stack.(Stack*).TransportProtocolOption to get/set the default, min and max
// TCP receive buffer sizes.
type ReceiveBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// syncRcvdCounter tracks the number of endpoints in the SYN-RCVD state. The
// value is protected by a mutex so that we can increment only when it's
// guaranteed not to go above a threshold.
type synRcvdCounter struct {
	sync.Mutex
	value     uint64
	pending   sync.WaitGroup
	threshold uint64
}

// inc tries to increment the global number of endpoints in SYN-RCVD state. It
// succeeds if the increment doesn't make the count go beyond the threshold, and
// fails otherwise.
func (s *synRcvdCounter) inc() bool {
	s.Lock()
	defer s.Unlock()
	if s.value >= s.threshold {
		return false
	}

	s.pending.Add(1)
	s.value++

	return true
}

// dec atomically decrements the global number of endpoints in SYN-RCVD
// state. It must only be called if a previous call to inc succeeded.
func (s *synRcvdCounter) dec() {
	s.Lock()
	defer s.Unlock()
	s.value--
	s.pending.Done()
}

// synCookiesInUse returns true if the synRcvdCount is greater than
// SynRcvdCountThreshold.
func (s *synRcvdCounter) synCookiesInUse() bool {
	s.Lock()
	defer s.Unlock()
	return s.value >= s.threshold
}

// SetThreshold sets synRcvdCounter.Threshold to ths new threshold.
func (s *synRcvdCounter) SetThreshold(threshold uint64) {
	s.Lock()
	defer s.Unlock()
	s.threshold = threshold
}

// Threshold returns the current value of synRcvdCounter.Threhsold.
func (s *synRcvdCounter) Threshold() uint64 {
	s.Lock()
	defer s.Unlock()
	return s.threshold
}

type protocol struct {
	mu                         sync.RWMutex
	sackEnabled                bool
	delayEnabled               bool
	sendBufferSize             SendBufferSizeOption
	recvBufferSize             ReceiveBufferSizeOption
	congestionControl          string
	availableCongestionControl []string
	moderateReceiveBuffer      bool
	tcpLingerTimeout           time.Duration
	tcpTimeWaitTimeout         time.Duration
	minRTO                     time.Duration
	maxRTO                     time.Duration
	maxRetries                 uint32
	synRcvdCount               synRcvdCounter
	synRetries                 uint8
	dispatcher                 dispatcher
}

// Number returns the tcp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new tcp endpoint.
func (p *protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

// NewRawEndpoint creates a new raw TCP endpoint. Raw TCP sockets are currently
// unsupported. It implements stack.TransportProtocol.NewRawEndpoint.
func (p *protocol) NewRawEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return raw.NewEndpoint(stack, netProto, header.TCPProtocolNumber, waiterQueue)
}

// MinimumPacketSize returns the minimum valid tcp packet size.
func (*protocol) MinimumPacketSize() int {
	return header.TCPMinimumSize
}

// ParsePorts returns the source and destination ports stored in the given tcp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	h := header.TCP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// QueuePacket queues packets targeted at an endpoint after hashing the packet
// to a specific processing queue. Each queue is serviced by its own processor
// goroutine which is responsible for dequeuing and doing full TCP dispatch of
// the packet.
func (p *protocol) QueuePacket(r *stack.Route, ep stack.TransportEndpoint, id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	p.dispatcher.queuePacket(r, ep, id, pkt)
}

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint.
//
// RFC 793, page 36, states that "If the connection does not exist (CLOSED) then
// a reset is sent in response to any incoming segment except another reset. In
// particular, SYNs addressed to a non-existent connection are rejected by this
// means."
func (*protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	s := newSegment(r, id, pkt)
	defer s.decRef()

	if !s.parse() || !s.csumValid {
		return false
	}

	// There's nothing to do if this is already a reset packet.
	if s.flagIsSet(header.TCPFlagRst) {
		return true
	}

	replyWithReset(s, stack.DefaultTOS, s.route.DefaultTTL())
	return true
}

// replyWithReset replies to the given segment with a reset segment.
func replyWithReset(s *segment, tos, ttl uint8) {
	// Get the seqnum from the packet if the ack flag is set.
	seq := seqnum.Value(0)
	ack := seqnum.Value(0)
	flags := byte(header.TCPFlagRst)
	// As per RFC 793 page 35 (Reset Generation)
	//   1.  If the connection does not exist (CLOSED) then a reset is sent
	//   in response to any incoming segment except another reset.  In
	//   particular, SYNs addressed to a non-existent connection are rejected
	//   by this means.

	//   If the incoming segment has an ACK field, the reset takes its
	//   sequence number from the ACK field of the segment, otherwise the
	//   reset has sequence number zero and the ACK field is set to the sum
	//   of the sequence number and segment length of the incoming segment.
	//   The connection remains in the CLOSED state.
	if s.flagIsSet(header.TCPFlagAck) {
		seq = s.ackNumber
	} else {
		flags |= header.TCPFlagAck
		ack = s.sequenceNumber.Add(s.logicalLen())
	}
	sendTCP(&s.route, tcpFields{
		id:     s.id,
		ttl:    ttl,
		tos:    tos,
		flags:  flags,
		seq:    seq,
		ack:    ack,
		rcvWnd: 0,
	}, buffer.VectorisedView{}, nil /* gso */, nil /* PacketOwner */)
}

// SetOption implements stack.TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case SACKEnabled:
		p.mu.Lock()
		p.sackEnabled = bool(v)
		p.mu.Unlock()
		return nil

	case DelayEnabled:
		p.mu.Lock()
		p.delayEnabled = bool(v)
		p.mu.Unlock()
		return nil

	case SendBufferSizeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}
		p.mu.Lock()
		p.sendBufferSize = v
		p.mu.Unlock()
		return nil

	case ReceiveBufferSizeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}
		p.mu.Lock()
		p.recvBufferSize = v
		p.mu.Unlock()
		return nil

	case tcpip.CongestionControlOption:
		for _, c := range p.availableCongestionControl {
			if string(v) == c {
				p.mu.Lock()
				p.congestionControl = string(v)
				p.mu.Unlock()
				return nil
			}
		}
		// linux returns ENOENT when an invalid congestion control
		// is specified.
		return tcpip.ErrNoSuchFile

	case tcpip.ModerateReceiveBufferOption:
		p.mu.Lock()
		p.moderateReceiveBuffer = bool(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPLingerTimeoutOption:
		if v < 0 {
			v = 0
		}
		p.mu.Lock()
		p.tcpLingerTimeout = time.Duration(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPTimeWaitTimeoutOption:
		if v < 0 {
			v = 0
		}
		p.mu.Lock()
		p.tcpTimeWaitTimeout = time.Duration(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPMinRTOOption:
		if v < 0 {
			v = tcpip.TCPMinRTOOption(MinRTO)
		}
		p.mu.Lock()
		p.minRTO = time.Duration(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPMaxRTOOption:
		if v < 0 {
			v = tcpip.TCPMaxRTOOption(MaxRTO)
		}
		p.mu.Lock()
		p.maxRTO = time.Duration(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPMaxRetriesOption:
		p.mu.Lock()
		p.maxRetries = uint32(v)
		p.mu.Unlock()
		return nil

	case tcpip.TCPSynRcvdCountThresholdOption:
		p.mu.Lock()
		p.synRcvdCount.SetThreshold(uint64(v))
		p.mu.Unlock()
		return nil

	case tcpip.TCPSynRetriesOption:
		if v < 1 || v > 255 {
			return tcpip.ErrInvalidOptionValue
		}
		p.mu.Lock()
		p.synRetries = uint8(v)
		p.mu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements stack.TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *SACKEnabled:
		p.mu.RLock()
		*v = SACKEnabled(p.sackEnabled)
		p.mu.RUnlock()
		return nil

	case *DelayEnabled:
		p.mu.RLock()
		*v = DelayEnabled(p.delayEnabled)
		p.mu.RUnlock()
		return nil

	case *SendBufferSizeOption:
		p.mu.RLock()
		*v = p.sendBufferSize
		p.mu.RUnlock()
		return nil

	case *ReceiveBufferSizeOption:
		p.mu.RLock()
		*v = p.recvBufferSize
		p.mu.RUnlock()
		return nil

	case *tcpip.CongestionControlOption:
		p.mu.RLock()
		*v = tcpip.CongestionControlOption(p.congestionControl)
		p.mu.RUnlock()
		return nil

	case *tcpip.AvailableCongestionControlOption:
		p.mu.RLock()
		*v = tcpip.AvailableCongestionControlOption(strings.Join(p.availableCongestionControl, " "))
		p.mu.RUnlock()
		return nil

	case *tcpip.ModerateReceiveBufferOption:
		p.mu.RLock()
		*v = tcpip.ModerateReceiveBufferOption(p.moderateReceiveBuffer)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPLingerTimeoutOption:
		p.mu.RLock()
		*v = tcpip.TCPLingerTimeoutOption(p.tcpLingerTimeout)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPTimeWaitTimeoutOption:
		p.mu.RLock()
		*v = tcpip.TCPTimeWaitTimeoutOption(p.tcpTimeWaitTimeout)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMinRTOOption:
		p.mu.RLock()
		*v = tcpip.TCPMinRTOOption(p.minRTO)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMaxRTOOption:
		p.mu.RLock()
		*v = tcpip.TCPMaxRTOOption(p.maxRTO)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMaxRetriesOption:
		p.mu.RLock()
		*v = tcpip.TCPMaxRetriesOption(p.maxRetries)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPSynRcvdCountThresholdOption:
		p.mu.RLock()
		*v = tcpip.TCPSynRcvdCountThresholdOption(p.synRcvdCount.Threshold())
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPSynRetriesOption:
		p.mu.RLock()
		*v = tcpip.TCPSynRetriesOption(p.synRetries)
		p.mu.RUnlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Close implements stack.TransportProtocol.Close.
func (p *protocol) Close() {
	p.dispatcher.close()
}

// Wait implements stack.TransportProtocol.Wait.
func (p *protocol) Wait() {
	p.dispatcher.wait()
}

// SynRcvdCounter returns a reference to the synRcvdCount for this protocol
// instance.
func (p *protocol) SynRcvdCounter() *synRcvdCounter {
	return &p.synRcvdCount
}

// Parse implements stack.TransportProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	hdr, ok := pkt.Data.PullUp(header.TCPMinimumSize)
	if !ok {
		return false
	}

	// If the header has options, pull those up as well.
	if offset := int(header.TCP(hdr).DataOffset()); offset > header.TCPMinimumSize && offset <= pkt.Data.Size() {
		hdr, ok = pkt.Data.PullUp(offset)
		if !ok {
			panic(fmt.Sprintf("There should be at least %d bytes in pkt.Data.", offset))
		}
	}

	pkt.TransportHeader = hdr
	pkt.Data.TrimFront(len(hdr))
	return true
}

// NewProtocol returns a TCP transport protocol.
func NewProtocol() stack.TransportProtocol {
	p := protocol{
		sendBufferSize: SendBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultSendBufferSize,
			Max:     MaxBufferSize,
		},
		recvBufferSize: ReceiveBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultReceiveBufferSize,
			Max:     MaxBufferSize,
		},
		congestionControl:          ccReno,
		availableCongestionControl: []string{ccReno, ccCubic},
		tcpLingerTimeout:           DefaultTCPLingerTimeout,
		tcpTimeWaitTimeout:         DefaultTCPTimeWaitTimeout,
		synRcvdCount:               synRcvdCounter{threshold: SynRcvdCountThreshold},
		synRetries:                 DefaultSynRetries,
		minRTO:                     MinRTO,
		maxRTO:                     MaxRTO,
		maxRetries:                 MaxRetries,
	}
	p.dispatcher.init(runtime.GOMAXPROCS(0))
	return &p
}
