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
	"strings"
	"sync"

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
)

// SACKEnabled option can be used to enable SACK support in the TCP
// protocol. See: https://tools.ietf.org/html/rfc2018.
type SACKEnabled bool

// SendBufferSizeOption allows the default, min and max send buffer sizes for
// TCP endpoints to be queried or configured.
type SendBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// ReceiveBufferSizeOption allows the default, min and max receive buffer size
// for TCP endpoints to be queried or configured.
type ReceiveBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

const (
	ccReno  = "reno"
	ccCubic = "cubic"
)

type protocol struct {
	mu                         sync.Mutex
	sackEnabled                bool
	sendBufferSize             SendBufferSizeOption
	recvBufferSize             ReceiveBufferSizeOption
	congestionControl          string
	availableCongestionControl []string
	moderateReceiveBuffer      bool
}

// Number returns the tcp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new tcp endpoint.
func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
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

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint.
//
// RFC 793, page 36, states that "If the connection does not exist (CLOSED) then
// a reset is sent in response to any incoming segment except another reset. In
// particular, SYNs addressed to a non-existent connection are rejected by this
// means."
func (*protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) bool {
	s := newSegment(r, id, pkt)
	defer s.decRef()

	if !s.parse() || !s.csumValid {
		return false
	}

	// There's nothing to do if this is already a reset packet.
	if s.flagIsSet(header.TCPFlagRst) {
		return true
	}

	replyWithReset(s)
	return true
}

// replyWithReset replies to the given segment with a reset segment.
func replyWithReset(s *segment) {
	// Get the seqnum from the packet if the ack flag is set.
	seq := seqnum.Value(0)
	if s.flagIsSet(header.TCPFlagAck) {
		seq = s.ackNumber
	}

	ack := s.sequenceNumber.Add(s.logicalLen())

	sendTCP(&s.route, s.id, buffer.VectorisedView{}, s.route.DefaultTTL(), stack.DefaultTOS, header.TCPFlagRst|header.TCPFlagAck, seq, ack, 0 /* rcvWnd */, nil /* options */, nil /* gso */)
}

// SetOption implements TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case SACKEnabled:
		p.mu.Lock()
		p.sackEnabled = bool(v)
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

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *SACKEnabled:
		p.mu.Lock()
		*v = SACKEnabled(p.sackEnabled)
		p.mu.Unlock()
		return nil

	case *SendBufferSizeOption:
		p.mu.Lock()
		*v = p.sendBufferSize
		p.mu.Unlock()
		return nil

	case *ReceiveBufferSizeOption:
		p.mu.Lock()
		*v = p.recvBufferSize
		p.mu.Unlock()
		return nil

	case *tcpip.CongestionControlOption:
		p.mu.Lock()
		*v = tcpip.CongestionControlOption(p.congestionControl)
		p.mu.Unlock()
		return nil

	case *tcpip.AvailableCongestionControlOption:
		p.mu.Lock()
		*v = tcpip.AvailableCongestionControlOption(strings.Join(p.availableCongestionControl, " "))
		p.mu.Unlock()
		return nil

	case *tcpip.ModerateReceiveBufferOption:
		p.mu.Lock()
		*v = tcpip.ModerateReceiveBufferOption(p.moderateReceiveBuffer)
		p.mu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// NewProtocol returns a TCP transport protocol.
func NewProtocol() stack.TransportProtocol {
	return &protocol{
		sendBufferSize:             SendBufferSizeOption{MinBufferSize, DefaultSendBufferSize, MaxBufferSize},
		recvBufferSize:             ReceiveBufferSizeOption{MinBufferSize, DefaultReceiveBufferSize, MaxBufferSize},
		congestionControl:          ccReno,
		availableCongestionControl: []string{ccReno, ccCubic},
	}
}
