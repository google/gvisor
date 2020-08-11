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

// Package udp contains the implementation of the UDP transport protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing udp.NewProtocol() as one of the
// transport protocols when calling stack.New(). Then endpoints can be created
// by passing udp.ProtocolNumber as the transport protocol number when calling
// Stack.NewEndpoint().
package udp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ProtocolNumber is the udp protocol number.
	ProtocolNumber = header.UDPProtocolNumber

	// MinBufferSize is the smallest size of a receive or send buffer.
	MinBufferSize = 4 << 10 // 4KiB bytes.

	// DefaultSendBufferSize is the default size of the send buffer for
	// an endpoint.
	DefaultSendBufferSize = 32 << 10 // 32KiB

	// DefaultReceiveBufferSize is the default size of the receive buffer
	// for an endpoint.
	DefaultReceiveBufferSize = 32 << 10 // 32KiB

	// MaxBufferSize is the largest size a receive/send buffer can grow to.
	MaxBufferSize = 4 << 20 // 4MiB
)

type protocol struct {
}

// Number returns the udp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new udp endpoint.
func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

// NewRawEndpoint creates a new raw UDP endpoint. It implements
// stack.TransportProtocol.NewRawEndpoint.
func (p *protocol) NewRawEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return raw.NewEndpoint(stack, netProto, header.UDPProtocolNumber, waiterQueue)
}

// MinimumPacketSize returns the minimum valid udp packet size.
func (*protocol) MinimumPacketSize() int {
	return header.UDPMinimumSize
}

// ParsePorts returns the source and destination ports stored in the given udp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	h := header.UDP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint. We return False as we don't actually
// do anything but leave it to the default handler. If we could have a null
// method that may be even better, but it's not critical path so it may not
// matter.
//   Returns:
//     A boolean telling us whether the packet was malformed
//     A boolean  telling the caller (nic.go) whether it handled the error,
//     or whether to try use the default error handling code, which will
//     result in an ICMP response.
func (p *protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, pkt *stack.PacketBuffer) (bool, bool) {
	_, ok := pkt.Data.PullUp(header.UDPMinimumSize)
	if !ok {
		// Packet is too small
		r.Stats().UDP.MalformedPacketsReceived.Increment()
		return false, false
	}
	r.Stats().UDP.UnknownPortErrors.Increment()
	return true, false
}

// SetOption implements stack.TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements stack.TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.TransportProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	h, ok := pkt.Data.PullUp(header.UDPMinimumSize)
	if !ok {
		// Packet is too small. Where to report it?
		// ?.Stats().UDP.MalformedPacketsReceived.Increment()
		return false
	}
	pkt.TransportHeader = h
	pkt.Data.TrimFront(header.UDPMinimumSize)
	return true
}

// NewProtocol returns a UDP transport protocol.
func NewProtocol() stack.TransportProtocol {
	return &protocol{}
}
