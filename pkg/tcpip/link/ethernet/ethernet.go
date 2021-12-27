// Copyright 2020 The gVisor Authors.
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

// Package ethernet provides an implementation of an ethernet link endpoint that
// wraps an inner link endpoint.
package ethernet

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)

// New returns an ethernet link endpoint that wraps an inner link endpoint.
func New(ep stack.LinkEndpoint) *Endpoint {
	var e Endpoint
	e.Endpoint.Init(ep, &e)
	return &e
}

// Endpoint is an ethernet endpoint.
//
// It adds an ethernet header to packets before sending them out through its
// inner link endpoint and consumes an ethernet header before sending the
// packet to the stack.
type Endpoint struct {
	nested.Endpoint
}

// LinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	if l := e.Endpoint.LinkAddress(); len(l) != 0 {
		return l
	}
	return header.UnspecifiedEthernetAddress
}

// MTU implements stack.LinkEndpoint.
func (e *Endpoint) MTU() uint32 {
	if mtu := e.Endpoint.MTU(); mtu > header.EthernetMinimumSize {
		return mtu - header.EthernetMinimumSize
	}
	return 0
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *Endpoint) DeliverNetworkPacket(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	hdr, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	if !ok {
		return
	}

	// Note, there is no need to check the destination link address here since
	// the ethernet hardware filters frames based on their destination addresses.
	eth := header.Ethernet(hdr)
	e.Endpoint.DeliverNetworkPacket(eth.SourceAddress() /* remote */, eth.DestinationAddress() /* local */, eth.Type() /* protocol */, pkt)
}

// Capabilities implements stack.LinkEndpoint.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	c := e.Endpoint.Capabilities()
	if c&stack.CapabilityLoopback == 0 {
		c |= stack.CapabilityResolutionRequired
	}
	return c
}

// WritePacket implements stack.LinkEndpoint.
func (e *Endpoint) WritePacket(r stack.RouteInfo, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.AddHeader(e.LinkAddress(), r.RemoteLinkAddress, proto, pkt)
	return e.Endpoint.WritePacket(r, proto, pkt)
}

// WritePackets implements stack.LinkEndpoint.
func (e *Endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, proto tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	linkAddr := e.LinkAddress()

	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		e.AddHeader(linkAddr, pkt.EgressRoute.RemoteLinkAddress, pkt.NetworkProtocolNumber, pkt)
	}

	return e.Endpoint.WritePackets(r, pkts, proto)
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (e *Endpoint) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize + e.Endpoint.MaxHeaderLength()
}

// ARPHardwareType implements stack.LinkEndpoint.
func (e *Endpoint) ARPHardwareType() header.ARPHardwareType {
	if a := e.Endpoint.ARPHardwareType(); a != header.ARPHardwareNone {
		return a
	}
	return header.ARPHardwareEther
}

// AddHeader implements stack.LinkEndpoint.
func (*Endpoint) AddHeader(local, remote tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	fields := header.EthernetFields{
		SrcAddr: local,
		DstAddr: remote,
		Type:    proto,
	}
	eth.Encode(&fields)
}

// WriteRawPacket implements stack.LinkEndpoint.
func (e *Endpoint) WriteRawPacket(pkt *stack.PacketBuffer) tcpip.Error {
	return e.Endpoint.WriteRawPacket(pkt)
}
