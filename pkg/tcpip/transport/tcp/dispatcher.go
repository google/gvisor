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

package tcp

import (
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// epQueue is a queue of endpoints.
type epQueue struct {
	mu   sync.Mutex
	list endpointList
}

// enqueue adds e to the queue if the endpoint is not already on the queue.
func (q *epQueue) enqueue(e *endpoint) {
	q.mu.Lock()
	if e.pendingProcessing {
		q.mu.Unlock()
		return
	}
	q.list.PushBack(e)
	e.pendingProcessing = true
	q.mu.Unlock()
}

// dequeue removes and returns the first element from the queue if available,
// returns nil otherwise.
func (q *epQueue) dequeue() *endpoint {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		q.list.Remove(e)
		e.pendingProcessing = false
		q.mu.Unlock()
		return e
	}
	q.mu.Unlock()
	return nil
}

// empty returns true if the queue is empty, false otherwise.
func (q *epQueue) empty() bool {
	q.mu.Lock()
	v := q.list.Empty()
	q.mu.Unlock()
	return v
}

// processor is responsible for processing packets queued to a tcp endpoint.
type processor struct {
	epQ              epQueue
	newEndpointWaker sleep.Waker
	closeWaker       sleep.Waker
	id               int
	wg               sync.WaitGroup
}

func newProcessor(id int) *processor {
	p := &processor{
		id: id,
	}
	p.wg.Add(1)
	go p.handleSegments()
	return p
}

func (p *processor) close() {
	p.closeWaker.Assert()
}

func (p *processor) wait() {
	p.wg.Wait()
}

func (p *processor) queueEndpoint(ep *endpoint) {
	// Queue an endpoint for processing by the processor goroutine.
	p.epQ.enqueue(ep)
	p.newEndpointWaker.Assert()
}

func (p *processor) handleSegments() {
	const newEndpointWaker = 1
	const closeWaker = 2
	s := sleep.Sleeper{}
	s.AddWaker(&p.newEndpointWaker, newEndpointWaker)
	s.AddWaker(&p.closeWaker, closeWaker)
	defer s.Done()
	for {
		id, ok := s.Fetch(true)
		if ok && id == closeWaker {
			p.wg.Done()
			return
		}
		for ep := p.epQ.dequeue(); ep != nil; ep = p.epQ.dequeue() {
			if ep.segmentQueue.empty() {
				continue
			}

			// If socket has transitioned out of connected state
			// then just let the worker handle the packet.
			//
			// NOTE: We read this outside of e.mu lock which means
			// that by the time we get to handleSegments the
			// endpoint may not be in ESTABLISHED. But this should
			// be fine as all normal shutdown states are handled by
			// handleSegments and if the endpoint moves to a
			// CLOSED/ERROR state then handleSegments is a noop.
			if ep.EndpointState() != StateEstablished {
				ep.newSegmentWaker.Assert()
				continue
			}

			if !ep.mu.TryLock() {
				ep.newSegmentWaker.Assert()
				continue
			}
			// If the endpoint is in a connected state then we do
			// direct delivery to ensure low latency and avoid
			// scheduler interactions.
			if err := ep.handleSegments(true /* fastPath */); err != nil || ep.EndpointState() == StateClose {
				// Send any active resets if required.
				if err != nil {
					ep.resetConnectionLocked(err)
				}
				ep.notifyProtocolGoroutine(notifyTickleWorker)
				ep.mu.Unlock()
				continue
			}

			if !ep.segmentQueue.empty() {
				p.epQ.enqueue(ep)
			}

			ep.mu.Unlock()
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. The processor is selected based on the
// hash of the endpoint id to ensure that delivery for the same endpoint happens
// in-order.
type dispatcher struct {
	processors []*processor
	seed       uint32
}

func newDispatcher(nProcessors int) *dispatcher {
	processors := []*processor{}
	for i := 0; i < nProcessors; i++ {
		processors = append(processors, newProcessor(i))
	}
	return &dispatcher{
		processors: processors,
		seed:       generateRandUint32(),
	}
}

func (d *dispatcher) close() {
	for _, p := range d.processors {
		p.close()
	}
}

func (d *dispatcher) wait() {
	for _, p := range d.processors {
		p.wait()
	}
}

func (d *dispatcher) queuePacket(r *stack.Route, stackEP stack.TransportEndpoint, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) {
	ep := stackEP.(*endpoint)
	s := newSegment(r, id, pkt)
	if !s.parse() {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		s.decRef()
		return
	}

	if !s.csumValid {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		s.decRef()
		return
	}

	// For sockets not in established state let the worker goroutine
	// handle the packets.
	if ep.EndpointState() != StateEstablished {
		ep.newSegmentWaker.Assert()
		return
	}

	d.selectProcessor(id).queueEndpoint(ep)
}

func generateRandUint32() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8)}

	h := jenkins.Sum32(d.seed)
	h.Write(payload)
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))

	return d.processors[h.Sum32()%uint32(len(d.processors))]
}
