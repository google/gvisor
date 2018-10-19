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

// Package udp contains the implementation of the UDP transport protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing udp.ProtocolName (or "udp") as one of the
// transport protocols when calling stack.New(). Then endpoints can be created
// by passing udp.ProtocolNumber as the transport protocol number when calling
// Stack.NewEndpoint().
package udp

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	// ProtocolName is the string representation of the udp protocol name.
	ProtocolName = "udp"

	// ProtocolNumber is the udp protocol number.
	ProtocolNumber = header.UDPProtocolNumber
)

type protocol struct{}

// Number returns the udp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new udp endpoint.
func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
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
// that don't match any existing endpoint.
func (p *protocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, buffer.VectorisedView) bool {
	return true
}

// SetOption implements TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func init() {
	stack.RegisterTransportProtocolFactory(ProtocolName, func() stack.TransportProtocol {
		return &protocol{}
	})
}
