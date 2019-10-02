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

// Package icmp contains the implementation of the ICMP and IPv6-ICMP transport
// protocols for use in ping. To use it in the networking stack, this package
// must be added to the project, and activated on the stack by passing
// icmp.NewProtocol4() and/or icmp.NewProtocol6() as one of the transport
// protocols when calling stack.New(). Then endpoints can be created by passing
// icmp.ProtocolNumber or icmp.ProtocolNumber6 as the transport protocol number
// when calling Stack.NewEndpoint().
package icmp

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ProtocolNumber4 is the ICMP protocol number.
	ProtocolNumber4 = header.ICMPv4ProtocolNumber

	// ProtocolNumber6 is the IPv6-ICMP protocol number.
	ProtocolNumber6 = header.ICMPv6ProtocolNumber
)

// protocol implements stack.TransportProtocol.
type protocol struct {
	number tcpip.TransportProtocolNumber
}

// Number returns the ICMP protocol number.
func (p *protocol) Number() tcpip.TransportProtocolNumber {
	return p.number
}

func (p *protocol) netProto() tcpip.NetworkProtocolNumber {
	switch p.number {
	case ProtocolNumber4:
		return header.IPv4ProtocolNumber
	case ProtocolNumber6:
		return header.IPv6ProtocolNumber
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

// NewEndpoint creates a new icmp endpoint. It implements
// stack.TransportProtocol.NewEndpoint.
func (p *protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if netProto != p.netProto() {
		return nil, tcpip.ErrUnknownProtocol
	}
	return newEndpoint(stack, netProto, p.number, waiterQueue)
}

// NewRawEndpoint creates a new raw icmp endpoint. It implements
// stack.TransportProtocol.NewRawEndpoint.
func (p *protocol) NewRawEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if netProto != p.netProto() {
		return nil, tcpip.ErrUnknownProtocol
	}
	return raw.NewEndpoint(stack, netProto, p.number, waiterQueue)
}

// MinimumPacketSize returns the minimum valid icmp packet size.
func (p *protocol) MinimumPacketSize() int {
	switch p.number {
	case ProtocolNumber4:
		return header.ICMPv4MinimumSize
	case ProtocolNumber6:
		return header.ICMPv6MinimumSize
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

// ParsePorts in case of ICMP sets src to 0, dst to ICMP ID, and err to nil.
func (p *protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	switch p.number {
	case ProtocolNumber4:
		hdr := header.ICMPv4(v)
		return 0, hdr.Ident(), nil
	case ProtocolNumber6:
		hdr := header.ICMPv6(v)
		return 0, hdr.Ident(), nil
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint.
func (p *protocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, buffer.View, buffer.VectorisedView) bool {
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

// NewProtocol4 returns an ICMPv4 transport protocol.
func NewProtocol4() stack.TransportProtocol {
	return &protocol{ProtocolNumber4}
}

// NewProtocol6 returns an ICMPv6 transport protocol.
func NewProtocol6() stack.TransportProtocol {
	return &protocol{ProtocolNumber6}
}
