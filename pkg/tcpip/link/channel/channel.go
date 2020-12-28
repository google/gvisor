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

// Package channel provides the implemention of channel-based data-link layer
// endpoints. Such endpoints allow injection of inbound packets and store
// outbound packets in a channel.
package channel

import (
	"context"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// PacketInfo holds all the information about an outbound packet.
type PacketInfo struct {
	Pkt   *stack.PacketBuffer
	Proto tcpip.NetworkProtocolNumber
	GSO   *stack.GSO
	Route stack.RouteInfo
}

// Notification is the interface for receiving notification from the packet
// queue.
type Notification interface {
	// WriteNotify will be called when a write happens to the queue.
	WriteNotify()
}

// NotificationHandle is an opaque handle to the registered notification target.
// It can be used to unregister the notification when no longer interested.
//
// +stateify savable
type NotificationHandle struct {
	n Notification
}

type queue struct {
	// c is the outbound packet channel.
	c chan PacketInfo
	// mu protects fields below.
	mu     sync.RWMutex
	notify []*NotificationHandle
}

func (q *queue) Close() {
	close(q.c)
}

func (q *queue) Read() (PacketInfo, bool) {
	select {
	case p := <-q.c:
		return p, true
	default:
		return PacketInfo{}, false
	}
}

func (q *queue) ReadContext(ctx context.Context) (PacketInfo, bool) {
	select {
	case pkt := <-q.c:
		return pkt, true
	case <-ctx.Done():
		return PacketInfo{}, false
	}
}

func (q *queue) Write(p PacketInfo) bool {
	wrote := false
	select {
	case q.c <- p:
		wrote = true
	default:
	}
	q.mu.Lock()
	notify := q.notify
	q.mu.Unlock()

	if wrote {
		// Send notification outside of lock.
		for _, h := range notify {
			h.n.WriteNotify()
		}
	}
	return wrote
}

func (q *queue) Num() int {
	return len(q.c)
}

func (q *queue) AddNotify(notify Notification) *NotificationHandle {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := &NotificationHandle{n: notify}
	q.notify = append(q.notify, h)
	return h
}

func (q *queue) RemoveNotify(handle *NotificationHandle) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Make a copy, since we reads the array outside of lock when notifying.
	notify := make([]*NotificationHandle, 0, len(q.notify))
	for _, h := range q.notify {
		if h != handle {
			notify = append(notify, h)
		}
	}
	q.notify = notify
}

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	dispatcher         stack.NetworkDispatcher
	mtu                uint32
	linkAddr           tcpip.LinkAddress
	LinkEPCapabilities stack.LinkEndpointCapabilities

	// Outbound packet queue.
	q *queue
}

// New creates a new channel endpoint.
func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) *Endpoint {
	return &Endpoint{
		q: &queue{
			c: make(chan PacketInfo, size),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}

// Close closes e. Further packet injections will panic. Reads continue to
// succeed until all packets are read.
func (e *Endpoint) Close() {
	e.q.Close()
}

// Read does non-blocking read one packet from the outbound packet queue.
func (e *Endpoint) Read() (PacketInfo, bool) {
	return e.q.Read()
}

// ReadContext does blocking read for one packet from the outbound packet queue.
// It can be cancelled by ctx, and in this case, it returns false.
func (e *Endpoint) ReadContext(ctx context.Context) (PacketInfo, bool) {
	return e.q.ReadContext(ctx)
}

// Drain removes all outbound packets from the channel and counts them.
func (e *Endpoint) Drain() int {
	c := 0
	for {
		if _, ok := e.Read(); !ok {
			return c
		}
		c++
	}
}

// NumQueued returns the number of packet queued for outbound.
func (e *Endpoint) NumQueued() int {
	return e.q.Num()
}

// InjectInbound injects an inbound packet.
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.InjectLinkAddr(protocol, "", pkt)
}

// InjectLinkAddr injects an inbound packet with a remote link address.
func (e *Endpoint) InjectLinkAddr(protocol tcpip.NetworkProtocolNumber, remote tcpip.LinkAddress, pkt *stack.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(remote, "" /* local */, protocol, pkt)
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEPCapabilities
}

// GSOMaxSize returns the maximum GSO packet size.
func (*Endpoint) GSOMaxSize() uint32 {
	return 1 << 15
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePacket stores outbound packets into the channel.
func (e *Endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	p := PacketInfo{
		Pkt:   pkt,
		Proto: protocol,
		GSO:   gso,
		Route: r.GetFields(),
	}

	e.q.Write(p)

	return nil
}

// WritePackets stores outbound packets into the channel.
func (e *Endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		p := PacketInfo{
			Pkt:   pkt,
			Proto: protocol,
			GSO:   gso,
			Route: r.GetFields(),
		}

		if !e.q.Write(p) {
			break
		}
		n++
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*Endpoint) Wait() {}

// AddNotify adds a notification target for receiving event about outgoing
// packets.
func (e *Endpoint) AddNotify(notify Notification) *NotificationHandle {
	return e.q.AddNotify(notify)
}

// RemoveNotify removes handle from the list of notification targets.
func (e *Endpoint) RemoveNotify(handle *NotificationHandle) {
	e.q.RemoveNotify(handle)
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *Endpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
}
