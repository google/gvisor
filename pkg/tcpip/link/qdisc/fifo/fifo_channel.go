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

package fifo

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// +stateify savable
type disciplineCh struct {
	wg          sync.WaitGroup `state:"nosave"`
	dispatchers []queueDispatcherCh

	closed atomicbitops.Int32
}

// +stateify savable
type queueDispatcherCh struct {
	lower stack.LinkWriter
	queue chan *stack.PacketBuffer
}

// NewCh creates a new fifo queuing discipline with the n queues with maximum
// capacity of queueLen.
//
// +checklocksignore: we don't have to hold locks during initialization.
func NewCh(lower stack.LinkWriter, n int, queueLen int) stack.QueueingDiscipline {
	d := &disciplineCh{
		dispatchers: make([]queueDispatcherCh, n),
	}
	// Create the required dispatchers
	for i := range d.dispatchers {
		qd := &d.dispatchers[i]
		qd.lower = lower
		qd.queue = make(chan *stack.PacketBuffer, queueLen)

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			qd.dispatchLoop()
		}()
	}
	return d
}

func (qd *queueDispatcherCh) dispatchLoop() {
	var batch stack.PacketBufferList
	for {
		// Block until a packet arrives or the channel closes.
		pkt, ok := <-qd.queue
		if !ok {
			return
		}
		batch.PushBack(pkt)

		// We got a packet. Grab as many as possible.
		for batch.Len() < BatchSize {
			select {
			case pkt := <-qd.queue:
				batch.PushBack(pkt)
				continue
			default:
			}
			break
		}
		_, _ = qd.lower.WritePackets(batch)
		batch.Reset()
	}
}

// WritePacket implements stack.QueueingDiscipline.WritePacket.
//
// The packet must have the following fields populated:
//   - pkt.EgressRoute
//   - pkt.GSOOptions
//   - pkt.NetworkProtocolNumber
func (d *disciplineCh) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	if d.closed.Load() == qDiscClosed {
		return &tcpip.ErrClosedForSend{}
	}
	d.dispatchers[int(pkt.Hash)%len(d.dispatchers)].queue <- pkt.IncRef()
	return nil
}

func (d *disciplineCh) Close() {
	d.closed.Store(qDiscClosed)
	for i := range d.dispatchers {
		close(d.dispatchers[i].queue)
	}
	d.wg.Wait()
}
