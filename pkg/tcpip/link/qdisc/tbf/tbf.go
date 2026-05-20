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

// Package tbf provides a simplified Token Bucket Filter queueing discipline
// modeled on Linux's net/sched/sch_tbf.c. Only the single-rate bucket is
// implemented; peakrate/peakburst (Linux's second bucket) is not.
package tbf

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// BatchSize is the number of packets to write in each syscall. It is 47
	// because when GVisorGSO is in use then a single 65KB TCP segment can get
	// split into 46 segments of 1420 bytes and a single 216 byte segment.
	BatchSize = 47

	qDiscClosed = 1
)

var _ stack.QueueingDiscipline = (*discipline)(nil)

// +stateify savable
type discipline struct {
	// Immutable configuration set by New.
	lower  stack.LinkWriter
	clock  tcpip.Clock `state:"nosave"`
	rate   uint64      // max sustained throughput, bytes/sec
	burst  uint32      // largest packet this TBF will pass, bytes
	buffer int64       // nanoseconds needed to transmit burst bytes at rate

	// Shutdown state.
	wg     sync.WaitGroup `state:"nosave"`
	closed atomicbitops.Int32

	// Wakers driving dispatchLoop.
	newPacketWaker sleep.Waker `state:"nosave"`
	tokenWaker     sleep.Waker `state:"nosave"`
	closeWaker     sleep.Waker `state:"nosave"`

	mu queueMutex `state:"nosave"`
	// +checklocks:mu
	queue qdisc.PacketBufferCircularList

	// Dispatcher state: mutated only inside dispatchLoop and
	// thus not protected by mu.
	tokens         int64 // current bucket level, ns
	timeCheckpoint tcpip.MonotonicTime
	watchdog       tcpip.Timer `state:"nosave"`
}

// len2TimeNS returns the number of ns to transmit len bytes at rate bytes/sec.
// Linux's psched_l2t_ns avoids the divide via a precomputed mult/shift; see
// psched_ratecfg_precompute__ in net/sched/sch_generic.c.
func len2TimeNS(rate uint64, len uint32) uint64 {
	const nsecPerSec = 1000000000
	return uint64(len) * nsecPerSec / rate
}

func (d *discipline) dispatchLoop() {
	s := sleep.Sleeper{}
	s.AddWaker(&d.newPacketWaker)
	s.AddWaker(&d.tokenWaker)
	s.AddWaker(&d.closeWaker)
	defer s.Done()

	var batch stack.PacketBufferList
	for {
		switch w := s.Fetch(true); w {
		case &d.newPacketWaker, &d.tokenWaker:
		case &d.closeWaker:
			if d.watchdog != nil {
				d.watchdog.Stop()
			}
			d.mu.Lock()
			for p := d.queue.RemoveFront(); p != nil; p = d.queue.RemoveFront() {
				p.DecRef()
			}
			d.queue.DecRef()
			d.mu.Unlock()
			return
		default:
			panic("unknown waker")
		}

		d.mu.Lock()
		for pkt := d.queue.PeekFront(); pkt != nil; pkt = d.queue.PeekFront() {
			pktLen := pkt.Size()
			now := d.clock.NowMonotonic()
			toks := min(now.Sub(d.timeCheckpoint).Nanoseconds(), d.buffer)
			toks += d.tokens
			if toks > d.buffer {
				toks = d.buffer
			}
			toks -= int64(len2TimeNS(d.rate, uint32(pktLen)))
			sufficientTokens := toks >= 0
			if !sufficientTokens {
				// -toks is the deficit in ns: how long until enough tokens accumulate.
				if d.watchdog != nil {
					d.watchdog.Stop()
				}
				d.watchdog = d.clock.AfterFunc(time.Duration(-toks), d.tokenWaker.Assert)
				break
			}
			d.queue.RemoveFront()
			d.timeCheckpoint = now
			d.tokens = toks
			batch.PushBack(pkt)

			possiblyAnotherPacket := batch.Len() < BatchSize && !d.queue.IsEmpty()
			if possiblyAnotherPacket {
				continue
			}
			d.mu.Unlock()
			_, _ = d.lower.WritePackets(batch)
			batch.Reset()
			d.mu.Lock()
		}
		if batch.Len() > 0 {
			d.mu.Unlock()
			_, _ = d.lower.WritePackets(batch)
			batch.Reset()
			d.mu.Lock()
		}
		d.mu.Unlock()
	}
}

// New creates a new TBF queueing discipline that will rate-limit lower to
// rate bytes/sec with bursts of up to burst bytes, queueing up to queueLen
// packets of backlog before dropping. Note that queueLen counts packets,
// not bytes as in Linux's sch_tbf.c, for consistency with the fifo qdisc.
//
// +checklocksignore: we don't have to hold locks during initialization.
func New(lower stack.LinkEndpoint, clock tcpip.Clock, rate uint64, burst, queueLen uint32) (stack.QueueingDiscipline, error) {
	if rate == 0 {
		return nil, fmt.Errorf("qdisc=tbf requires setting qdisc-tbf-rate")
	}

	if burst == 0 {
		return nil, fmt.Errorf("qdisc=tbf requires setting qdisc-tbf-burst")
	}

	if gsoEP, ok := lower.(stack.GSOEndpoint); ok {
		// HostGSOSupported endpoints can hand WritePacket a single GSO
		// super-packet up to GSOMaxSize+MaxHeaderLength bytes, so the bucket
		// must be able to hold one. GVisorGSOSupported segments above the
		// qdisc and GSONotSupported never produces packets above the link
		// MTU, both covered by the next check.
		maxGSOPktLen := gsoEP.GSOMaxSize() + uint32(lower.MaxHeaderLength())
		if gsoEP.SupportedGSO() == stack.HostGSOSupported && burst < uint32(maxGSOPktLen) {
			return nil, fmt.Errorf("burst (%d bytes) is smaller than link's max GSO packet size (%d bytes); either increase burst or disable host GSO via --gso=false", burst, maxGSOPktLen)
		}
	}

	maxPktLen := lower.MTU() + uint32(lower.MaxHeaderLength())
	if burst < maxPktLen {
		return nil, fmt.Errorf("burst (%d bytes) is smaller than max packet length (%d bytes)", burst, maxPktLen)
	}

	buffer := int64(len2TimeNS(rate, burst))
	if buffer == 0 {
		return nil, fmt.Errorf("rate (%d bytes/sec) is too high relative to burst (%d bytes); reduce qdisc-tbf-rate or increase qdisc-tbf-burst", rate, burst)
	}

	d := &discipline{
		lower:          lower,
		clock:          clock,
		rate:           rate,
		burst:          burst,
		buffer:         buffer,
		tokens:         buffer,
		timeCheckpoint: clock.NowMonotonic(),
	}
	d.queue.Init(int(queueLen))
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.dispatchLoop()
	}()
	return d, nil
}

// WritePacket implements stack.QueueingDiscipline.WritePacket.
func (d *discipline) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	if d.closed.Load() == qDiscClosed {
		return &tcpip.ErrClosedForSend{}
	}

	if uint32(pkt.Size()) > d.burst {
		// if the burst parameter is not smaller than the expected packet size,
		// oversize packets should be impossible with New's GSO check
		return &tcpip.ErrMessageTooLong{}
	}

	d.mu.Lock()
	haveSpace := d.queue.HasSpace()
	if haveSpace {
		d.queue.PushBack(pkt.IncRef())
	}
	d.mu.Unlock()
	if !haveSpace {
		return &tcpip.ErrNoBufferSpace{}
	}

	d.newPacketWaker.Assert()
	return nil
}

// Close implements stack.QueueingDiscipline.Close.
func (d *discipline) Close() {
	d.closed.Store(qDiscClosed)
	d.closeWaker.Assert()
	d.wg.Wait()
}
