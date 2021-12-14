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

// Package fifo provides the implementation of FIFO queuing discipline that
// queues all outbound packets and asynchronously dispatches them to the
// lower link endpoint in the order that they were queued.
package fifo

import (
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.QueueingDiscipline = (*discipline)(nil)

// discipline represents a QueueingDiscipline which implements a FIFO queue for
// all outgoing packets. discipline can have 1 or more underlying
// queueDispatchers. All outgoing packets are consistenly hashed to a single
// underlying queue using the PacketBuffer.Hash if set, otherwise all packets
// are queued to the first queue to avoid reordering in case of missing hash.
type discipline struct {
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

// New creates a new fifo queuing discipline  with the n queues with maximum
// capacity of queueLen.
func New(lower stack.LinkEndpoint, n int, queueLen int) stack.QueueingDiscipline {
	d := &discipline{
		lower: lower,
	}
	// Create the required dispatchers
	for i := 0; i < n; i++ {
		qd := &queueDispatcher{
			q:     &packetBufferQueue{limit: queueLen},
			lower: lower,
		}
		d.dispatchers = append(d.dispatchers, qd)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			qd.dispatchLoop()
		}()
	}
	return d
}

func (q *queueDispatcher) dispatchLoop() {
	s := sleep.Sleeper{}
	s.AddWaker(&q.newPacketWaker)
	s.AddWaker(&q.closeWaker)
	defer s.Done()

	const batchSize = 32
	var batch stack.PacketBufferList
	for {
		w := s.Fetch(true)
		if w == &q.closeWaker {
			return
		}
		// Must otherwise be the newPacketWaker.
		for pkt := q.q.dequeue(); pkt != nil; pkt = q.q.dequeue() {
			batch.PushBack(pkt)
			if batch.Len() < batchSize && !q.q.empty() {
				continue
			}
			// We pass a protocol of zero here because each packet carries its
			// NetworkProtocol.
			q.lower.WritePackets(stack.RouteInfo{}, batch, 0 /* protocol */)
			batch.DecRef()
			batch.Reset()
		}
	}
}

// WritePacket implements stack.QueueingDiscipline.WritePacket.
//
// The packet must have the following fields populated:
//  - pkt.EgressRoute
//  - pkt.GSOOptions
//  - pkt.NetworkProtocolNumber
func (d *discipline) WritePacket(_ stack.RouteInfo, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	qd := d.dispatchers[int(pkt.Hash)%len(d.dispatchers)]
	if !qd.q.enqueue(pkt) {
		return &tcpip.ErrNoBufferSpace{}
	}
	qd.newPacketWaker.Assert()
	return nil
}

// WritePackets implements stack.QueueingDiscipline.WritePackets.
//
// Each packet in the packet buffer list must have the following fields
// populated:
//  - pkt.EgressRoute
//  - pkt.GSOOptions
//  - pkt.NetworkProtocolNumber
func (d *discipline) WritePackets(_ stack.RouteInfo, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	enqueued := 0
	for pkt := pkts.Front(); pkt != nil; {
		qd := d.dispatchers[int(pkt.Hash)%len(d.dispatchers)]
		nxt := pkt.Next()
		if !qd.q.enqueue(pkt) {
			if enqueued > 0 {
				qd.newPacketWaker.Assert()
			}
			return enqueued, &tcpip.ErrNoBufferSpace{}
		}
		pkt = nxt
		enqueued++
		qd.newPacketWaker.Assert()
	}
	return enqueued, nil
}
