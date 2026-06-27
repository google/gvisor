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

// Package tbf provides a simplified Token Bucket Filter modeled on Linux's
// net/sched/sch_tbf.c. Only the single-rate bucket is implemented;
// peakrate/peakburst (Linux's second bucket) is not.
//
// New constructs an egress queueing discipline that shapes traffic written
// out a link endpoint. NewIngress constructs a link endpoint decorator that
// shapes inbound traffic before it is delivered to the network stack.
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
	lower stack.LinkWriter
	clock tcpip.Clock `state:"nosave"`
	burst uint32      // largest packet this TBF will pass, bytes

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
	bucket   tokenBucket
	watchdog tcpip.Timer `state:"nosave"`
}

// len2TimeNS returns the number of ns to transmit len bytes at rate bytes/sec.
// Linux's psched_l2t_ns avoids the divide via a precomputed mult/shift; see
// psched_ratecfg_precompute__ in net/sched/sch_generic.c.
func len2TimeNS(rate uint64, len uint32) uint64 {
	const nsecPerSec = 1000000000
	return uint64(len) * nsecPerSec / rate
}

// tokenBucket implements the single-rate token accounting shared by the
// egress discipline and the ingress shaper. Tokens are measured in
// nanoseconds of transmission time at rate, as in Linux's sch_tbf. It is not
// thread-safe: only the owning dispatch goroutine may call consume.
//
// +stateify savable
type tokenBucket struct {
	rate           uint64 // max sustained throughput, bytes/sec
	buffer         int64  // bucket capacity: ns needed to transmit burst bytes at rate
	tokens         int64  // current bucket level, ns
	timeCheckpoint tcpip.MonotonicTime
}

func makeTokenBucket(rate uint64, buffer int64, now tcpip.MonotonicTime) tokenBucket {
	return tokenBucket{
		rate:           rate,
		buffer:         buffer,
		tokens:         buffer,
		timeCheckpoint: now,
	}
}

// consume attempts to take pktLen bytes worth of tokens from the bucket at
// time now. On success it commits the spend and returns (true, 0). Otherwise
// the bucket is left unchanged and it returns (false, wait), where wait is
// how long until the packet can pass.
//
// A packet whose cost exceeds the bucket capacity passes only once the
// bucket is completely full, driving the balance negative; the debt then
// repays at rate before anything else passes. This keeps the sustained rate
// exact without permanently blackholing packets that could never accumulate
// enough tokens. It only happens on the ingress side, where GRO can coalesce
// inbound TCP segments beyond the configured burst; Linux's sch_tbf handles
// the equivalent case by segmenting oversized GSO packets, while netstack
// delivers the packet whole and charges its true cost. The egress qdisc
// rejects oversized packets in WritePacket, so its balance never goes
// negative.
func (tb *tokenBucket) consume(now tcpip.MonotonicTime, pktLen uint32) (bool, time.Duration) {
	// Elapsed credit is deliberately not capped before the clamp below
	// (unlike Linux's psched min_t): for a non-negative balance the clamp
	// alone yields the same result, and capping elapsed credit at one
	// bucket's worth would prevent a debt larger than the bucket from ever
	// repaying.
	toks := now.Sub(tb.timeCheckpoint).Nanoseconds() + tb.tokens
	if toks > tb.buffer {
		toks = tb.buffer
	}
	cost := int64(len2TimeNS(tb.rate, pktLen))
	floor := int64(0)
	if cost > tb.buffer {
		floor = tb.buffer - cost
	}
	toks -= cost
	if toks < floor {
		// floor-toks is the deficit in ns: how long until the packet can pass.
		return false, time.Duration(floor - toks)
	}
	tb.timeCheckpoint = now
	tb.tokens = toks
	return true, 0
}

// validateConfig checks that rate and burst form a usable single-rate token
// bucket for lower and returns the bucket capacity ("buffer") in nanoseconds.
// kind, rateFlag and burstFlag name the configuration surface (egress or
// ingress) so errors point the operator at the right flags.
func validateConfig(lower stack.LinkEndpoint, rate uint64, burst uint32, kind, rateFlag, burstFlag string) (int64, error) {
	if rate == 0 {
		return 0, fmt.Errorf("%s requires setting %s", kind, rateFlag)
	}

	if burst == 0 {
		return 0, fmt.Errorf("%s requires setting %s", kind, burstFlag)
	}

	if gsoEP, ok := lower.(stack.GSOEndpoint); ok {
		// HostGSOSupported endpoints can hand WritePacket a single GSO
		// super-packet up to GSOMaxSize+MaxHeaderLength bytes (and, on the
		// ingress side, deliver host-GRO-coalesced packets of the same
		// scale), so the bucket must be able to hold one. GVisorGSOSupported
		// segments above the qdisc and GSONotSupported never produces packets
		// above the link MTU, both covered by the next check.
		maxGSOPktLen := gsoEP.GSOMaxSize() + uint32(lower.MaxHeaderLength())
		if gsoEP.SupportedGSO() == stack.HostGSOSupported && burst < uint32(maxGSOPktLen) {
			return 0, fmt.Errorf("burst (%d bytes) is smaller than link's max GSO packet size (%d bytes); either increase burst or disable host GSO via --gso=false", burst, maxGSOPktLen)
		}
	}

	maxPktLen := lower.MTU() + uint32(lower.MaxHeaderLength())
	if burst < maxPktLen {
		return 0, fmt.Errorf("burst (%d bytes) is smaller than max packet length (%d bytes)", burst, maxPktLen)
	}

	buffer := int64(len2TimeNS(rate, burst))
	if buffer == 0 {
		return 0, fmt.Errorf("rate (%d bytes/sec) is too high relative to burst (%d bytes); reduce %s or increase %s", rate, burst, rateFlag, burstFlag)
	}
	return buffer, nil
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
			ok, wait := d.bucket.consume(d.clock.NowMonotonic(), uint32(pkt.Size()))
			if !ok {
				if d.watchdog != nil {
					d.watchdog.Stop()
				}
				d.watchdog = d.clock.AfterFunc(wait, d.tokenWaker.Assert)
				break
			}
			d.queue.RemoveFront()
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
	buffer, err := validateConfig(lower, rate, burst, "qdisc=tbf", "qdisc-tbf-rate", "qdisc-tbf-burst")
	if err != nil {
		return nil, err
	}

	d := &discipline{
		lower:  lower,
		clock:  clock,
		burst:  burst,
		bucket: makeTokenBucket(rate, buffer, clock.NowMonotonic()),
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
	if d.closed.Load() == qDiscClosed {
		d.mu.Unlock()
		return &tcpip.ErrClosedForSend{}
	}
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
