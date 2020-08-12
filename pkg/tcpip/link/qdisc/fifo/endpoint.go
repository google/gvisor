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

// Package fifo provides the implementation of data-link layer endpoints that
// wrap another endpoint and queues all outbound packets and asynchronously
// dispatches them to the lower endpoint.
package fifo

import (
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// endpoint represents a LinkEndpoint which implements a FIFO queue for all
// outgoing packets. endpoint can have 1 or more underlying queueDispatchers.
// All outgoing packets are consistenly hashed to a single underlying queue
// using the PacketBuffer.Hash if set, otherwise all packets are queued to the
// first queue to avoid reordering in case of missing hash.
type endpoint struct {
	dispatcher  stack.NetworkDispatcher
	lower       stack.LinkEndpoint
	wg          sync.WaitGroup
	dispatchers []*queueDispatcher
}

// queueDispatcher is responsible for dispatching all outbound packets in its
// queue. It will also smartly batch packets when possible and write them
// through the lower LinkEndpoint.
type queueDispatcher struct {
	lower          stack.LinkEndpoint
	q              *packetBufferQueue
	newPacketWaker sleep.Waker
	closeWaker     sleep.Waker
}

// New creates a new fifo link endpoint with the n queues with maximum
// capacity of queueLen.
func New(lower stack.LinkEndpoint, n int, queueLen int) stack.LinkEndpoint {
	e := &endpoint{
		lower: lower,
	}
	// Create the required dispatchers
	for i := 0; i < n; i++ {
		qd := &queueDispatcher{
			q:     &packetBufferQueue{limit: queueLen},
			lower: lower,
		}
		e.dispatchers = append(e.dispatchers, qd)
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			qd.dispatchLoop()
		}()
	}
	return e
}

func (q *queueDispatcher) dispatchLoop() {
	const newPacketWakerID = 1
	const closeWakerID = 2
	s := sleep.Sleeper{}
	s.AddWaker(&q.newPacketWaker, newPacketWakerID)
	s.AddWaker(&q.closeWaker, closeWakerID)
	defer s.Done()

	const batchSize = 32
	var batch stack.PacketBufferList
	for {
		id, ok := s.Fetch(true)
		if ok && id == closeWakerID {
			return
		}
		for pkt := q.q.dequeue(); pkt != nil; pkt = q.q.dequeue() {
			batch.PushBack(pkt)
			if batch.Len() < batchSize && !q.q.empty() {
				continue
			}
			// We pass a protocol of zero here because each packet carries its
			// NetworkProtocol.
			q.lower.WritePackets(nil /* route */, nil /* gso */, batch, 0 /* protocol */)
			for pkt := batch.Front(); pkt != nil; pkt = pkt.Next() {
				pkt.EgressRoute.Release()
				batch.Remove(pkt)
			}
			batch.Reset()
		}
	}
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.DeliverNetworkPacket.
func (e *endpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(remote, local, protocol, pkt)
}

// DeliverOutboundPacket implements stack.NetworkDispatcher.DeliverOutboundPacket.
func (e *endpoint) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.dispatcher.DeliverOutboundPacket(remote, local, protocol, pkt)
}

// Attach implements stack.LinkEndpoint.Attach.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.lower.Attach(e)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (e *endpoint) MTU() uint32 {
	return e.lower.MTU()
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.lower.Capabilities()
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength.
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	if gso, ok := e.lower.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// WritePacket implements stack.LinkEndpoint.WritePacket.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	// WritePacket caller's do not set the following fields in PacketBuffer
	// so we populate them here.
	newRoute := r.Clone()
	pkt.EgressRoute = &newRoute
	pkt.GSOOptions = gso
	pkt.NetworkProtocolNumber = protocol
	d := e.dispatchers[int(pkt.Hash)%len(e.dispatchers)]
	if !d.q.enqueue(pkt) {
		return tcpip.ErrNoBufferSpace
	}
	d.newPacketWaker.Assert()
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
//
// Being a batch API, each packet in pkts should have the following fields
// populated:
//   - pkt.EgressRoute
//   - pkt.GSOOptions
//   - pkt.NetworkProtocolNumber
func (e *endpoint) WritePackets(_ *stack.Route, _ *stack.GSO, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	enqueued := 0
	for pkt := pkts.Front(); pkt != nil; {
		d := e.dispatchers[int(pkt.Hash)%len(e.dispatchers)]
		nxt := pkt.Next()
		// Since qdisc can hold onto a packet for long we should Clone
		// the route here to ensure it doesn't get released while the
		// packet is still in our queue.
		newRoute := pkt.EgressRoute.Clone()
		pkt.EgressRoute = &newRoute
		if !d.q.enqueue(pkt) {
			if enqueued > 0 {
				d.newPacketWaker.Assert()
			}
			return enqueued, tcpip.ErrNoBufferSpace
		}
		pkt = nxt
		enqueued++
		d.newPacketWaker.Assert()
	}
	return enqueued, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	// TODO(gvisor.dev/issue/3267): Queue these packets as well once
	// WriteRawPacket takes PacketBuffer instead of VectorisedView.
	return e.lower.WriteRawPacket(vv)
}

// Wait implements stack.LinkEndpoint.Wait.
func (e *endpoint) Wait() {
	e.lower.Wait()

	// The linkEP is gone. Teardown the outbound dispatcher goroutines.
	for i := range e.dispatchers {
		e.dispatchers[i].closeWaker.Assert()
	}

	e.wg.Wait()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return e.lower.ARPHardwareType()
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.lower.AddHeader(local, remote, protocol, pkt)
}
