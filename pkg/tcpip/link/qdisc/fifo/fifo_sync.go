// Copyright 2023 The gVisor Authors.
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

package fifo

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.QueueingDiscipline = (*SyncDiscipline)(nil)

// SyncDiscipline represents a QueueingDiscipline which implements a FIFO queue for
// all outgoing packets. SyncDiscipline, compared to the QueueingDiscipline
// returned by New, more closely resemble's Linux's FIFO qdisc.
//   - All packets are enqueued in a single queue.
//   - Writes are synchronous by default. If multiple goroutines write
//     simultaneously, only one actually writes while the others just enqueue
//     packets and continue.
//   - Bulk data transfer is handled asynchronously.
type SyncDiscipline struct {
	// Used to close the SyncDiscipline.
	closed atomicbitops.Int32
	wg     sync.WaitGroup

	// Wakers are used by the bulkDrain goroutine.
	bulkWaker  sleep.Waker
	closeWaker sleep.Waker

	// mu protoects the packet queue.
	mu sync.Mutex
	// +checklocks:mu
	queue packetBufferCircularList

	// drainMu ensures that only one goroutines at a time is actually
	// draining the queue. It should only ever be locked via TryLock, and
	// only with mu held.
	drainMu sync.Mutex

	// The endpoint to write packets to.
	// +checklocks:drainMu
	lower stack.LinkWriter
	// batch is used to avoid allocating.
	// +checklocks:drainMu
	batch stack.PacketBufferList
}

// NewSync creates a new fifo queuing SyncDiscipline with a maximum capacity of
// queueLen.
func NewSync(lower stack.LinkWriter, queueLen int) *SyncDiscipline {
	sd := &SyncDiscipline{
		lower: lower,
	}
	sd.queue.init(queueLen)
	sd.wg.Add(1)
	go sd.bulkDrain()
	return sd
}

// WritePacket implements stack.QueueingDiscipline.WritePacket.
//
// The packet must have the following fields populated:
//   - pkt.EgressRoute
//   - pkt.GSOOptions
//   - pkt.NetworkProtocolNumber
func (sd *SyncDiscipline) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	if sd.closed.Load() == qDiscClosed {
		return &tcpip.ErrClosedForSend{}
	}

	// Acquire lock to enqueue pkt.
	sd.mu.Lock()
	defer sd.mu.Unlock()

	sd.queue.pushBack(pkt.IncRef())

	// Try to send. If another goroutine holds drainMu, we're guaranteed
	// it'll see and send the enqueued pkt.
	if pkt.NoDrain || !sd.drainMu.TryLock() {
		return nil
	}
	defer sd.drainMu.Unlock()

	sd.drain() // +checklocksforce: sd.drainMu
	return nil
}

// Kick implements stack.QueueingDiscipline.Kick.
func (sd *SyncDiscipline) Kick(pingpong bool) {
	if sd.closed.Load() == qDiscClosed {
		return
	}

	// Bulk data transfers happen asynchronously so we don't block the app
	// thread from queueing more data.
	if !pingpong {
		sd.bulkWaker.Assert()
		return
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	// Try to send. If another goroutine holds drainMu, we're guaranteed
	// it'll see and send any enqueued pkts.
	if !sd.drainMu.TryLock() {
		return
	}
	defer sd.drainMu.Unlock()

	sd.drain() // +checklocksforce: sd.drainMu
}

// +checklocks:sd.mu
// +checklocks:sd.drainMu
func (sd *SyncDiscipline) drain() {
	for pkt := sd.queue.removeFront(); pkt != nil; pkt = sd.queue.removeFront() {
		sd.batch.PushBack(pkt)
		if sd.batch.Len() >= BatchSize || sd.queue.isEmpty() {
			sd.mu.Unlock()
			_, _ = sd.lower.WritePackets(sd.batch)
			sd.batch.Reset()
			sd.mu.Lock()
		}
	}
}

func (sd *SyncDiscipline) bulkDrain() {
	defer sd.wg.Done()
	sleeper := sleep.Sleeper{}
	sleeper.AddWaker(&sd.bulkWaker)
	sleeper.AddWaker(&sd.closeWaker)
	defer sleeper.Done()

	for {
		switch sleeper.Fetch(true /* block */) {
		case &sd.closeWaker:
			sd.mu.Lock()
			for pkt := sd.queue.removeFront(); pkt != nil; pkt = sd.queue.removeFront() {
				pkt.DecRef()
			}
			sd.mu.Unlock()
			return
		case &sd.bulkWaker:
			// If we can't get the lock, then another goroutine is
			// guaranteed to send the packets that caused this
			// wakeup.
			sd.mu.Lock()
			if sd.drainMu.TryLock() {
				sd.drain() // +checklocksforce: sd.drainMu
				sd.drainMu.Unlock()
			}
			sd.mu.Unlock()
		}
	}
}

// Close implements stack.QueueingDiscipline.Close.
func (sd *SyncDiscipline) Close() {
	sd.closed.Store(qDiscClosed)
	sd.closeWaker.Assert()
	sd.wg.Wait()
}
