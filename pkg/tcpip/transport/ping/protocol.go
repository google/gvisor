// Copyright 2018 Google Inc.
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

// Package ping contains the implementation of the ICMP and IPv6-ICMP transport
// protocols for use in ping. To use it in the networking stack, this package
// must be added to the project, and
// activated on the stack by passing ping.ProtocolName (or "ping") and/or
// ping.ProtocolName6 (or "ping6") as one of the transport protocols when
// calling stack.New(). Then endpoints can be created by passing
// ping.ProtocolNumber or ping.ProtocolNumber6 as the transport protocol number
// when calling Stack.NewEndpoint().
package ping

import (
	"encoding/binary"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	// ProtocolName4 is the string representation of the ping protocol name.
	ProtocolName4 = "ping4"

	// ProtocolNumber4 is the ICMP protocol number.
	ProtocolNumber4 = header.ICMPv4ProtocolNumber

	// ProtocolName6 is the string representation of the ping protocol name.
	ProtocolName6 = "ping6"

	// ProtocolNumber6 is the IPv6-ICMP protocol number.
	ProtocolNumber6 = header.ICMPv6ProtocolNumber
)

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

// NewEndpoint creates a new ping endpoint.
func (p *protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if netProto != p.netProto() {
		return nil, tcpip.ErrUnknownProtocol
	}
	return newEndpoint(stack, netProto, waiterQueue), nil
}

// MinimumPacketSize returns the minimum valid ping packet size.
func (p *protocol) MinimumPacketSize() int {
	switch p.number {
	case ProtocolNumber4:
		return header.ICMPv4EchoMinimumSize
	case ProtocolNumber6:
		return header.ICMPv6EchoMinimumSize
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

// ParsePorts returns the source and destination ports stored in the given udp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	return 0, binary.BigEndian.Uint16(v[header.ICMPv4MinimumSize:]), nil
}

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint.
func (p *protocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, *buffer.VectorisedView) bool {
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
	stack.RegisterTransportProtocolFactory(ProtocolName4, func() stack.TransportProtocol {
		return &protocol{ProtocolNumber4}
	})

	// TODO: Support IPv6.
}
