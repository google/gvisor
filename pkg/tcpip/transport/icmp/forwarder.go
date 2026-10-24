// Copyright 2026 The gVisor Authors.
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

package icmp

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// ForwarderHandler handles incoming ICMP packets. Returning true marks the
// packet as handled, returning false marks the packet as unhandled.
type ForwarderHandler func(*ForwarderRequest) (handled bool)

// Forwarder allows clients to decide what to do with ICMP packets delivered to
// the per-stack default handler.
//
// The canonical way of using it is to pass the Forwarder.HandlePacket function
// to stack.SetTransportProtocolHandler.
type Forwarder struct {
	handler ForwarderHandler
}

// NewForwarder allocates and initializes a new forwarder.
func NewForwarder(handler ForwarderHandler) *Forwarder {
	return &Forwarder{
		handler: handler,
	}
}

// HandlePacket handles ICMP packets.
//
// This function is expected to be passed as an argument to the
// stack.SetTransportProtocolHandler function.
func (f *Forwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	req := &ForwarderRequest{
		id:  id,
		pkt: pkt,
	}
	handled := f.handler(req)
	if req.pkt != nil {
		req.pkt.ClearICMPEchoReply()
	}
	req.pkt = nil
	return handled
}

// ForwarderRequest represents an ICMP request received by the forwarder and
// passed to the client. ForwarderRequest is only valid for the duration of the
// ForwarderHandler call; callers must not save it and call Reply after the
// handler returns.
type ForwarderRequest struct {
	id  stack.TransportEndpointID
	pkt *stack.PacketBuffer
}

// ID returns the addresses and ICMP identifier associated with the request.
func (r *ForwarderRequest) ID() stack.TransportEndpointID {
	return r.id
}

// PacketBuffer returns the packet associated with the request. The packet is
// only valid for the duration of the ForwarderHandler call and must not be
// saved to call Reply after the handler returns.
func (r *ForwarderRequest) PacketBuffer() *stack.PacketBuffer {
	return r.pkt
}

// PacketInfo returns network-layer information associated with the request.
func (r *ForwarderRequest) PacketInfo() stack.NetworkPacketInfo {
	if r.pkt == nil {
		return stack.NetworkPacketInfo{}
	}
	return r.pkt.NetworkPacketInfo
}

// Reply asks netstack to synthesize its built-in ICMP Echo Reply for the
// request. Reply is only valid for the duration of the ForwarderHandler call.
// Reply is idempotent and returns false if the packet is not an ICMP Echo
// Request with an active built-in reply path. A true return value does not
// guarantee that the reply packet was delivered.
func (r *ForwarderRequest) Reply() bool {
	return stack.ReplyICMPEcho(r.pkt)
}
