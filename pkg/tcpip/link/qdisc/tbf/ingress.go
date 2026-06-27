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

package tbf

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Ingress is a stack.LinkEndpoint decorator that applies single-rate token
// bucket shaping to inbound traffic before it is delivered to the network
// stack. Unlike Linux, where the ingress hook can only police (drop), gVisor
// owns the receive path in userspace and can queue inbound packets until the
// bucket refills, mirroring the egress TBF's behavior. Packets that arrive
// while the backlog queue is full are dropped. All inbound traffic on the
// link is shaped, including ARP and NDP, and delivery into the stack is
// serialized on the shaper's single dispatch goroutine.
//
// Outbound traffic passes through unmodified; pair with the egress TBF qdisc
// to shape both directions. Packets delivered directly to packet endpoints
// via DeliverLinkPacket are not shaped, but no link endpoint used with this
// wrapper calls it: runsc NICs deliver to packet endpoints from within the
// NIC's (post-shaper) DeliverNetworkPacket.
//
// +stateify savable
type Ingress struct {
	nested.Endpoint

	// Immutable configuration set by NewIngress.
	clock tcpip.Clock `state:"nosave"`

	// dropped counts inbound packets dropped because the backlog queue was
	// full. Packets discarded by Close or detach are not counted.
	dropped tcpip.StatCounter

	// Shutdown state.
	wg     sync.WaitGroup `state:"nosave"`
	closed atomicbitops.Int32

	// Wakers driving dispatchLoop.
	newPacketWaker sleep.Waker `state:"nosave"`
	tokenWaker     sleep.Waker `state:"nosave"`
	closeWaker     sleep.Waker `state:"nosave"`

	mu ingressQueueMutex `state:"nosave"`
	// +checklocks:mu
	queue qdisc.PacketBufferCircularList

	// Dispatcher state: mutated only inside dispatchLoop and
	// thus not protected by mu.
	bucket   tokenBucket
	watchdog tcpip.Timer `state:"nosave"`
}

var _ stack.GSOEndpoint = (*Ingress)(nil)
var _ stack.LinkEndpoint = (*Ingress)(nil)
var _ stack.NetworkDispatcher = (*Ingress)(nil)

// NewIngress creates a new ingress TBF shaper wrapping lower. Inbound traffic
// is rate-limited to rate bytes/sec with bursts of up to burst bytes, queueing
// up to queueLen packets of backlog before dropping. As with the egress TBF,
// queueLen counts packets, not bytes. An inbound packet larger than burst
// (possible when GRO coalesces TCP segments beyond it) is not dropped; it
// passes once the bucket is completely full and drives the bucket into debt,
// preserving the sustained rate.
//
// +checklocksignore: we don't have to hold locks during initialization.
func NewIngress(lower stack.LinkEndpoint, clock tcpip.Clock, rate uint64, burst, queueLen uint32) (*Ingress, error) {
	buffer, err := validateConfig(lower, rate, burst, "ingress-qdisc=tbf", "ingress-qdisc-tbf-rate", "ingress-qdisc-tbf-burst")
	if err != nil {
		return nil, err
	}

	e := &Ingress{
		clock:  clock,
		bucket: makeTokenBucket(rate, buffer, clock.NowMonotonic()),
	}
	e.Endpoint.Init(lower, e)
	e.queue.Init(int(queueLen))
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.dispatchLoop()
	}()
	return e, nil
}

// DeliverNetworkPacket implements stack.NetworkDispatcher. The lower endpoint
// calls it for each inbound packet; the packet is queued for token-bucket
// paced delivery to the dispatcher attached above this endpoint, or dropped
// if the backlog queue is full.
func (e *Ingress) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if e.closed.Load() == qDiscClosed {
		return
	}

	e.mu.Lock()
	// Re-check closed now that we hold mu: the dispatch loop drains the queue
	// under mu when it observes the close, so a packet pushed after that
	// drain would never be released.
	if e.closed.Load() == qDiscClosed {
		e.mu.Unlock()
		return
	}
	haveSpace := e.queue.HasSpace()
	if haveSpace {
		// Some lower endpoints (e.g. xdp) carry the protocol only in the
		// argument; stash it on the packet so dispatchLoop can deliver with
		// the same protocol later.
		pkt.NetworkProtocolNumber = protocol
		e.queue.PushBack(pkt.IncRef())
	}
	e.mu.Unlock()
	if !haveSpace {
		// Backlog full: drop, as Linux's sch_tbf does when limit is exceeded.
		e.dropped.Increment()
		return
	}

	e.newPacketWaker.Assert()
}

// DroppedPackets returns the number of inbound packets dropped because the
// backlog queue was full.
func (e *Ingress) DroppedPackets() uint64 {
	return e.dropped.Value()
}

func (e *Ingress) dispatchLoop() {
	s := sleep.Sleeper{}
	s.AddWaker(&e.newPacketWaker)
	s.AddWaker(&e.tokenWaker)
	s.AddWaker(&e.closeWaker)
	defer s.Done()

	var batch stack.PacketBufferList
	for {
		switch w := s.Fetch(true); w {
		case &e.newPacketWaker, &e.tokenWaker:
		case &e.closeWaker:
			if e.watchdog != nil {
				e.watchdog.Stop()
			}
			e.mu.Lock()
			for p := e.queue.RemoveFront(); p != nil; p = e.queue.RemoveFront() {
				p.DecRef()
			}
			e.queue.DecRef()
			e.mu.Unlock()
			return
		default:
			panic("unknown waker")
		}

		e.mu.Lock()
		for pkt := e.queue.PeekFront(); pkt != nil; pkt = e.queue.PeekFront() {
			ok, wait := e.bucket.consume(e.clock.NowMonotonic(), uint32(pkt.Size()))
			if !ok {
				if e.watchdog != nil {
					e.watchdog.Stop()
				}
				e.watchdog = e.clock.AfterFunc(wait, e.tokenWaker.Assert)
				break
			}
			e.queue.RemoveFront()
			batch.PushBack(pkt)

			possiblyAnotherPacket := batch.Len() < BatchSize && !e.queue.IsEmpty()
			if possiblyAnotherPacket {
				continue
			}
			e.mu.Unlock()
			e.deliverBatch(&batch)
			e.mu.Lock()
		}
		if batch.Len() > 0 {
			e.mu.Unlock()
			e.deliverBatch(&batch)
			e.mu.Lock()
		}
		e.mu.Unlock()
	}
}

// deliverBatch hands each packet to the dispatcher attached above this
// endpoint (normally the NIC) and then drops the queue's references. Delivery
// happens outside e.mu because the dispatcher runs protocol processing
// inline. nested.Endpoint discards the packets if the endpoint was detached.
func (e *Ingress) deliverBatch(batch *stack.PacketBufferList) {
	for _, pkt := range batch.AsSlice() {
		e.Endpoint.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
	}
	batch.Reset()
}

// Attach implements stack.LinkEndpoint. Attaching a nil dispatcher (detach)
// also shuts the shaper down: new deliveries are refused and the dispatch
// goroutine is told to drop the backlog and exit, but NOT joined. Every
// detach site in the stack (nic.remove via Stack.RemoveNIC, Stack.Wait, and
// checkpoint's Stack.beforeSave) runs with the stack mutex held, while the
// dispatch goroutine may itself be blocked acquiring stack locks delivering
// a packet inline (e.g. FindRoute from ICMP processing); joining here could
// deadlock the whole stack. The goroutine is joined in Close instead, which
// nic.remove runs as a deferred action after stack locks are released. Like
// fdbased, re-attaching after a detach is not supported.
func (e *Ingress) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.signalShutdown()
	}
	e.Endpoint.Attach(dispatcher)
}

// Close implements stack.LinkEndpoint. It shuts down and joins the dispatch
// goroutine, which drops any backlog, and then closes the lower endpoint.
// The stack invokes Close without its locks held (it is a deferred action of
// nic.remove), so joining here cannot deadlock the way it could in Attach.
func (e *Ingress) Close() {
	e.signalShutdown()
	e.wg.Wait()
	e.Endpoint.Close()
}

// Wait implements stack.LinkEndpoint by waiting for the lower endpoint only.
// It deliberately does not join the shaper's dispatch goroutine: Stack.Wait
// calls Wait with the stack mutex held while the dispatch goroutine may be
// blocked acquiring stack locks to deliver a packet, so joining here could
// deadlock. Close joins the goroutine, mirroring how fdbased's processor
// goroutines are quiesced outside of Wait.
func (e *Ingress) Wait() {
	e.Endpoint.Wait()
}

// signalShutdown tells the dispatch goroutine to drop any queued packets and
// exit, and makes future deliveries no-ops. It does not wait for the
// goroutine; Close does. Idempotent.
func (e *Ingress) signalShutdown() {
	if e.closed.Swap(qDiscClosed) != qDiscClosed {
		e.closeWaker.Assert()
	}
}
