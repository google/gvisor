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

package tbf_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/tbf"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeEndpoint is a minimal stack.LinkEndpoint and stack.GSOEndpoint that
// records writes from the dispatcher. The caller (not the LinkWriter) DecRefs
// the batch via batch.Reset() after WritePackets returns, matching fifo and
// channel.Endpoint. WritePackets here must therefore not DecRef.
type fakeEndpoint struct {
	mtu             uint32
	maxHeaderLength uint16
	gsoMaxSize      uint32
	supportedGSO    stack.SupportedGSO

	mu             sync.Mutex
	batchSizes     []int
	bytesWritten   int
	packetsWritten int
	packetsWanted  int // 0 disables the done signal
	done           chan struct{}
}

func (e *fakeEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	bytes := 0
	for _, pkt := range pkts.AsSlice() {
		bytes += pkt.Size()
		n++
	}
	e.mu.Lock()
	e.batchSizes = append(e.batchSizes, n)
	e.bytesWritten += bytes
	e.packetsWritten += n
	if e.packetsWanted > 0 && e.packetsWritten >= e.packetsWanted && e.done != nil {
		select {
		case <-e.done:
		default:
			close(e.done)
		}
	}
	e.mu.Unlock()
	return n, nil
}

func (e *fakeEndpoint) MTU() uint32                                  { return e.mtu }
func (e *fakeEndpoint) SetMTU(mtu uint32)                            { e.mtu = mtu }
func (e *fakeEndpoint) MaxHeaderLength() uint16                      { return e.maxHeaderLength }
func (e *fakeEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *fakeEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *fakeEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *fakeEndpoint) Attach(stack.NetworkDispatcher)               {}
func (e *fakeEndpoint) IsAttached() bool                             { return false }
func (e *fakeEndpoint) Wait()                                        {}
func (e *fakeEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *fakeEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *fakeEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *fakeEndpoint) Close()                                       {}
func (e *fakeEndpoint) SetOnCloseAction(func())                      {}
func (e *fakeEndpoint) GSOMaxSize() uint32                           { return e.gsoMaxSize }
func (e *fakeEndpoint) SupportedGSO() stack.SupportedGSO             { return e.supportedGSO }

// snapshot returns a copy of stats taken under lock.
func (e *fakeEndpoint) snapshot() (packets, bytes int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.packetsWritten, e.bytesWritten
}

// maxBatchSize returns the largest batch ever written to the endpoint, or 0
// if no writes have been observed.
func (e *fakeEndpoint) maxBatchSize() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	max := 0
	for _, n := range e.batchSizes {
		if n > max {
			max = n
		}
	}
	return max
}

// newPkt constructs a PacketBuffer with size bytes of payload. The caller
// owns one reference and must DecRef when done.
func newPkt(size int) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(make([]byte, size)),
	})
}

// waitForPackets returns true if ep observed at least n packets within d.
// Polls instead of relying on the done channel so callers can poll for
// arbitrary thresholds without re-instrumenting the endpoint.
func waitForPackets(t *testing.T, ep *fakeEndpoint, n int, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		got, _ := ep.snapshot()
		if got >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// pollMax polls ep over d, returning early as soon as the packet count
// exceeds limit (the test would fail anyway), otherwise returning the
// final observed count. Used to assert "no more than `limit` drained".
func pollMax(t *testing.T, ep *fakeEndpoint, limit int, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		got, _ := ep.snapshot()
		if got > limit {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := ep.snapshot()
	return got
}

// TestNewValidation covers the rejected-configuration paths in tbf.New.
// These mirror what the runsc boot layer would reject before sandbox start.
func TestNewValidation(t *testing.T) {
	const mtu = 1500
	const hdr = 14
	tests := []struct {
		name      string
		ep        *fakeEndpoint
		rate      uint64
		burst     uint32
		queueLen  uint32
		errSubstr string
	}{
		{
			name:      "rate zero rejected",
			ep:        &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr},
			rate:      0,
			burst:     1 << 16,
			queueLen:  10,
			errSubstr: "qdisc=tbf requires setting qdisc-tbf-rate",
		},
		{
			name:      "burst zero rejected",
			ep:        &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr},
			rate:      1 << 20,
			burst:     0,
			queueLen:  10,
			errSubstr: "qdisc=tbf requires setting qdisc-tbf-burst",
		},
		{
			name:      "burst smaller than MTU+hdr rejected",
			ep:        &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr},
			rate:      1 << 20,
			burst:     mtu, // missing the header
			queueLen:  10,
			errSubstr: "smaller than max packet length",
		},
		{
			name: "burst smaller than host GSO max rejected",
			ep: &fakeEndpoint{
				mtu: mtu, maxHeaderLength: hdr,
				gsoMaxSize:   1 << 16,
				supportedGSO: stack.HostGSOSupported,
			},
			rate:      1 << 20,
			burst:     mtu + hdr, // big enough for non-GSO, too small for host GSO
			queueLen:  10,
			errSubstr: "smaller than link's max GSO",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := tbf.New(tt.ep, &faketime.NullClock{}, tt.rate, tt.burst, tt.queueLen)
			if err == nil {
				d.Close()
				t.Fatalf("tbf.New succeeded unexpectedly")
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("tbf.New err = %q, want substring %q", err, tt.errSubstr)
			}
		})
	}
}

// TestNewSucceeds confirms valid configurations construct cleanly with each
// SupportedGSO mode the qdisc has to handle, and Close() shuts down the
// dispatch goroutine without leaking refs. The "gvisor GSO" case uses a
// burst that would be rejected under host GSO; this catches a regression
// where the host-GSO-only burst guard is broadened to all GSO modes.
func TestNewSucceeds(t *testing.T) {
	const mtu = 1500
	const hdr = 14
	tests := []struct {
		name  string
		ep    *fakeEndpoint
		burst uint32
	}{
		{
			name:  "no GSO",
			ep:    &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr},
			burst: mtu + hdr,
		},
		{
			name:  "gvisor GSO with burst smaller than GSO max",
			ep:    &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr, gsoMaxSize: 1 << 16, supportedGSO: stack.GVisorGSOSupported},
			burst: mtu + hdr,
		},
		{
			name:  "host GSO with sufficient burst",
			ep:    &fakeEndpoint{mtu: mtu, maxHeaderLength: hdr, gsoMaxSize: 1 << 16, supportedGSO: stack.HostGSOSupported},
			burst: 1 << 17,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := tbf.New(tt.ep, &faketime.NullClock{}, 1<<20, tt.burst, 10)
			if err != nil {
				t.Fatalf("tbf.New: %v", err)
			}
			d.Close()
		})
	}
}

// TestWriteRefusedAfterClosed mirrors the FIFO test of the same name: once
// Close is called, WritePacket must surface ErrClosedForSend so callers can
// distinguish shutdown from transient backpressure.
func TestWriteRefusedAfterClosed(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	d, err := tbf.New(ep, &faketime.NullClock{}, 1<<20, 1<<17, 10)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	d.Close()

	pkt := newPkt(64)
	defer pkt.DecRef()
	gotErr := d.WritePacket(pkt)
	if _, ok := gotErr.(*tcpip.ErrClosedForSend); !ok {
		t.Errorf("WritePacket after Close: err = %v, want ErrClosedForSend", gotErr)
	}
}

// TestPacketLargerThanBurstRejected confirms WritePacket fast-paths an
// oversized packet to ErrMessageTooLong rather than silently queueing
// something that could never drain. With host GSO this is unreachable
// because New() guards burst >= GSOMax, but with no GSO a packet sized
// beyond burst is plausible.
func TestPacketLargerThanBurstRejected(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	const burst = 2000
	d, err := tbf.New(ep, &faketime.NullClock{}, 1<<20, burst, 10)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	pkt := newPkt(burst + 1)
	defer pkt.DecRef()
	gotErr := d.WritePacket(pkt)
	if _, ok := gotErr.(*tcpip.ErrMessageTooLong); !ok {
		t.Errorf("WritePacket of oversized packet: err = %v, want ErrMessageTooLong", gotErr)
	}
}

// TestQueueFullReturnsNoBufferSpace stalls the dispatcher with a NullClock
// (tokens never replenish) and a one-packet bucket, then floods more
// packets than the queue can hold. After the dispatcher consumes the
// initial bucket-worth, every subsequent push has to land in the queue,
// and we expect at least one push to overflow with ErrNoBufferSpace.
func TestQueueFullReturnsNoBufferSpace(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	const pktSize = 1514
	const burst = pktSize // exactly one packet of capacity
	const queueLen = 8
	d, err := tbf.New(ep, &faketime.NullClock{}, 1<<10 /* very low rate */, burst, queueLen)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	// Push significantly more than the queue can hold. With NullClock at
	// most one packet ever drains, so timing of the dispatcher is irrelevant.
	const total = queueLen + 100
	pkts := make([]*stack.PacketBuffer, total)
	for i := range pkts {
		pkts[i] = newPkt(pktSize)
	}
	defer func() {
		for _, p := range pkts {
			p.DecRef()
		}
	}()

	overflow := 0
	for _, p := range pkts {
		err := d.WritePacket(p)
		if err == nil {
			continue
		}
		if _, ok := err.(*tcpip.ErrNoBufferSpace); ok {
			overflow++
			continue
		}
		t.Fatalf("unexpected WritePacket error: %v", err)
	}
	if overflow == 0 {
		t.Errorf("expected at least one ErrNoBufferSpace among %d writes, got zero", total)
	}
	// Sanity: drained packets cannot exceed bucket-worth (1) plus what fit
	// in the queue (queueLen). Anything above that means tokens replenished
	// or counting is wrong.
	if got := total - overflow; got > queueLen+1 {
		t.Errorf("admitted %d packets, expected at most %d (bucket+queue)", got, queueLen+1)
	}
}

// TestUnshapedPassesAllPackets sets a rate so high relative to the workload
// that the bucket is effectively unbounded; every packet should pass
// through to the lower endpoint.
func TestUnshapedPassesAllPackets(t *testing.T) {
	const want = 200
	ep := &fakeEndpoint{
		mtu: 1500, maxHeaderLength: 14,
		done:          make(chan struct{}),
		packetsWanted: want,
	}
	d, err := tbf.New(ep, &faketime.NullClock{}, 1<<40 /* 1 TB/s */, 1<<20, uint32(want)+10)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	// pktSize=1500 ensures len2TimeNS doesn't truncate to zero (which it
	// would for tiny packets at this rate), so the token math is actually
	// exercised, not just the dispatch path.
	for i := 0; i < want; i++ {
		pkt := newPkt(1500)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}
	select {
	case <-ep.done:
	case <-time.After(2 * time.Second):
		got, _ := ep.snapshot()
		t.Fatalf("only %d/%d packets reached lower endpoint", got, want)
	}
}

// TestWriteMorePacketsThanBatchSize mirrors the FIFO test of the same name.
// It is a smoke test that a workload larger than BatchSize eventually drains
// and that the lower endpoint never observes a batch larger than BatchSize.
// Since writes race with the dispatcher, the test does not require a full
// BatchSize batch to form.
func TestWriteMorePacketsThanBatchSize(t *testing.T) {
	for _, want := range []int{tbf.BatchSize + 1, tbf.BatchSize*2 + 1} {
		t.Run("", func(t *testing.T) {
			ep := &fakeEndpoint{
				mtu: 1500, maxHeaderLength: 14,
				done:          make(chan struct{}),
				packetsWanted: want,
			}
			d, err := tbf.New(ep, &faketime.NullClock{}, 1<<40, 1<<20, uint32(want)+10)
			if err != nil {
				t.Fatalf("tbf.New: %v", err)
			}
			defer d.Close()

			for i := 0; i < want; i++ {
				pkt := newPkt(1)
				if err := d.WritePacket(pkt); err != nil {
					t.Fatalf("WritePacket %d: %v", i, err)
				}
				pkt.DecRef()
			}
			select {
			case <-ep.done:
			case <-time.After(time.Second):
				got, _ := ep.snapshot()
				t.Fatalf("expected %d packets, got %d", want, got)
			}
			if got := ep.maxBatchSize(); got > tbf.BatchSize {
				t.Errorf("max batch size = %d, want <= %d", got, tbf.BatchSize)
			}
		})
	}
}

// TestBurstAbsorption verifies that with a full bucket, a burst worth of
// bytes drains immediately. NullClock freezes token replenishment so any
// drain must come from the initial bucket. With burst == N * pktSize,
// exactly N packets pass.
//
// The "exactly N" property (the bucket does not overflow into a 5th
// packet's worth of credit) is exercised by TestBucketCapNotExceeded.
func TestBurstAbsorption(t *testing.T) {
	const pktSize = 1514
	const allowed = 4
	const burst = pktSize * allowed
	ep := &fakeEndpoint{
		mtu: 1500, maxHeaderLength: 14,
		done:          make(chan struct{}),
		packetsWanted: allowed,
	}
	d, err := tbf.New(ep, &faketime.NullClock{}, 1 /* 1 byte/sec */, burst, 32)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	for i := 0; i < allowed; i++ {
		pkt := newPkt(pktSize)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}
	select {
	case <-ep.done:
	case <-time.After(2 * time.Second):
		got, _ := ep.snapshot()
		t.Fatalf("burst absorption: got %d/%d packets out", got, allowed)
	}
}

// TestBucketCapNotExceeded checks that even after the qdisc has been idle
// for far longer than the bucket-fill time, a single burst cannot exceed
// burst bytes. Without a cap, a long idle period would let tokens
// accumulate without bound and a sudden flood would all drain at once.
func TestBucketCapNotExceeded(t *testing.T) {
	const pktSize = 1514
	const allowed = 4
	const burst = pktSize * allowed
	ep := &fakeEndpoint{
		mtu: 1500, maxHeaderLength: 14,
		done:          make(chan struct{}),
		packetsWanted: allowed,
	}
	clk := faketime.NewManualClock()
	d, err := tbf.New(ep, clk, 1 /* 1 byte/sec */, burst, 32)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	// Idle for far longer than it would take to refill the bucket. With a
	// correct cap, tokens stay at `buffer`; without one, tokens grow and a
	// burst of N+ packets would all drain.
	clk.Advance(time.Hour)

	const flood = allowed + 10
	for i := 0; i < flood; i++ {
		pkt := newPkt(pktSize)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}
	select {
	case <-ep.done:
	case <-time.After(2 * time.Second):
		got, _ := ep.snapshot()
		t.Fatalf("expected at least %d drained, got %d", allowed, got)
	}
	// The dispatcher has caught up to "exactly allowed". With a correct
	// cap, the bucket is now empty and the remaining packets will park
	// against the watchdog. Without a cap, more packets would already have
	// drained. Poll briefly to give any extra dispatch turns time to run.
	if got := pollMax(t, ep, allowed, 100*time.Millisecond); got > allowed {
		t.Errorf("bucket cap violated: %d packets drained, want %d", got, allowed)
	}
}

// TestSustainedRate exercises the watchdog refill path (clock.AfterFunc
// fires tokenWaker, which wakes dispatchLoop) and pins down per-advance
// pacing. All packets are queued up front: pkt 1 drains via the initial
// bucket, pkts 2..N park. Each one-second advance must release exactly
// one packet. A bug that drained packets early or failed to advance the
// token counter would cause either too many or too few drains per
// advance, and the exact-count assertion catches both.
func TestSustainedRate(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	const pktSize = 1514
	const burst = pktSize
	const rate = uint64(pktSize)
	const queued = 4

	clk := faketime.NewManualClock()
	d, err := tbf.New(ep, clk, rate, burst, 32)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	for i := 0; i < queued; i++ {
		pkt := newPkt(pktSize)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}
	if !waitForPackets(t, ep, 1, time.Second) {
		t.Fatalf("initial packet did not drain")
	}
	if got := pollMax(t, ep, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("before any advance: got %d packets, want 1", got)
	}

	for i := 2; i <= queued; i++ {
		clk.Advance(time.Second)
		if !waitForPackets(t, ep, i, time.Second) {
			got, _ := ep.snapshot()
			t.Fatalf("after advance %d: got %d packets, want %d", i-1, got, i)
		}
		if got := pollMax(t, ep, i, 100*time.Millisecond); got > i {
			t.Errorf("after advance %d: got %d packets, want %d (extra drained)", i-1, got, i)
		}
	}
}

// TestNewPacketArrivingMidWaitPreservesOrder verifies that a packet enqueued
// while the dispatcher is parked on the watchdog cannot jump ahead of the
// already-parked head packet, and that its arrival does not shorten the head
// packet's wait. This exercises the watchdog-rearm branch of dispatchLoop with
// queue mutation between the rearm and the watchdog firing.
func TestNewPacketArrivingMidWaitPreservesOrder(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	const pktSize = 1514
	const burst = pktSize
	const rate = uint64(pktSize) // 1 packet per second

	clk := faketime.NewManualClock()
	d, err := tbf.New(ep, clk, rate, burst, 32)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	// pkt1 drains via the initial bucket.
	pkt1 := newPkt(pktSize)
	if err := d.WritePacket(pkt1); err != nil {
		t.Fatalf("WritePacket pkt1: %v", err)
	}
	pkt1.DecRef()
	if !waitForPackets(t, ep, 1, time.Second) {
		t.Fatalf("pkt1 did not drain")
	}

	// pkt2 parks on the watchdog: bucket is empty, refill takes 1s.
	pkt2 := newPkt(pktSize)
	if err := d.WritePacket(pkt2); err != nil {
		t.Fatalf("WritePacket pkt2: %v", err)
	}
	pkt2.DecRef()

	// Half-advance the wait; pkt2 must not drain.
	clk.Advance(500 * time.Millisecond)
	if got := pollMax(t, ep, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("pkt2 drained early: got %d, want 1", got)
	}

	// pkt3 arrives mid-wait. It must not jump ahead of pkt2 and must not
	// shorten pkt2's wait.
	pkt3 := newPkt(pktSize)
	if err := d.WritePacket(pkt3); err != nil {
		t.Fatalf("WritePacket pkt3: %v", err)
	}
	pkt3.DecRef()
	if got := pollMax(t, ep, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("a packet drained out of order during mid-wait push: got %d, want 1", got)
	}

	// Complete pkt2's wait; pkt2 drains, pkt3 still waits.
	clk.Advance(500 * time.Millisecond)
	if !waitForPackets(t, ep, 2, time.Second) {
		t.Fatalf("pkt2 did not drain after full advance")
	}
	if got := pollMax(t, ep, 2, 100*time.Millisecond); got > 2 {
		t.Errorf("pkt3 drained early: got %d, want 2", got)
	}

	// Advance for pkt3.
	clk.Advance(time.Second)
	if !waitForPackets(t, ep, 3, time.Second) {
		t.Fatalf("pkt3 did not drain")
	}
}

// TestShapedPathBatchesAfterRefill verifies that when the dispatcher is parked
// on the watchdog with packets queued behind the head, a refill of multiple
// packets' worth of tokens drains them as a single multi-packet batch rather
// than one packet per dispatcher iteration. This pins down that batching is
// not exclusive to the unshaped path.
func TestShapedPathBatchesAfterRefill(t *testing.T) {
	const pktSize = 1514
	const groupSize = 5
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}

	clk := faketime.NewManualClock()
	rate := uint64(pktSize)              // 1 packet per second sustained
	burst := uint32(pktSize * groupSize) // bucket holds groupSize packets

	d, err := tbf.New(ep, clk, rate, burst, 64)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	// Drain the initial bucket so subsequent pushes park on the watchdog.
	for i := 0; i < groupSize; i++ {
		pkt := newPkt(pktSize)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}
	if !waitForPackets(t, ep, groupSize, time.Second) {
		got, _ := ep.snapshot()
		t.Fatalf("initial drain: got %d/%d", got, groupSize)
	}

	// Bucket empty. Queue another group; the dispatcher will park on the
	// watchdog after peeking the head.
	for i := 0; i < groupSize; i++ {
		pkt := newPkt(pktSize)
		if err := d.WritePacket(pkt); err != nil {
			t.Fatalf("post-drain WritePacket %d: %v", i, err)
		}
		pkt.DecRef()
	}

	// Refill enough for the whole group at once. The watchdog fires, the
	// dispatcher wakes, and the inner loop should drain all groupSize as a
	// single batch since the queue is fully populated when the loop starts.
	clk.Advance(time.Duration(groupSize) * time.Second)
	if !waitForPackets(t, ep, 2*groupSize, 2*time.Second) {
		got, _ := ep.snapshot()
		t.Fatalf("after refill: got %d/%d", got, 2*groupSize)
	}

	if got := ep.maxBatchSize(); got < 2 {
		t.Errorf("max batch size under shaping = %d, want >= 2 (batching not happening)", got)
	}
}

// TestFastSimultaneousWrites mirrors the FIFO test of the same name. Many
// goroutines hammering WritePacket at once must not panic, deadlock, or
// leak refs. Run with --config=race for data-race coverage on the queue
// and watchdog paths.
func TestFastSimultaneousWrites(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	d, err := tbf.New(ep, &faketime.NullClock{}, 1<<40, 1<<20, 10000)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}

	const nWriters = 100
	const nWrites = 100
	var wg sync.WaitGroup
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nWrites; j++ {
				pkt := newPkt(64)
				// WritePacket errors (e.g. ErrNoBufferSpace if the
				// queue ever fills) are not fatal; the goal is to
				// exercise concurrent paths, not enforce throughput.
				_ = d.WritePacket(pkt)
				pkt.DecRef()
			}
		}()
	}
	wg.Wait()
	d.Close()
}

// TestCloseDrainsQueuedPackets fills the queue with packets that the
// dispatcher cannot send and then closes the qdisc. The leak check in
// TestMain catches any packet whose ref was not dropped. ManualClock
// is used (not NullClock) so any watchdog the dispatcher arms before
// Close is a real pending timer; whether Close races ahead of the arm
// is timing-dependent, but the leak check covers both orderings.
func TestCloseDrainsQueuedPackets(t *testing.T) {
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	clk := faketime.NewManualClock()
	const queueLen = 32
	d, err := tbf.New(ep, clk, 1<<10, 1514, queueLen)
	if err != nil {
		t.Fatalf("tbf.New: %v", err)
	}

	for i := 0; i < queueLen*2; i++ {
		pkt := newPkt(1514)
		_ = d.WritePacket(pkt) // ignore overflows
		pkt.DecRef()
	}
	d.Close()
}

// TestCloseConcurrentWithWritePacket fires many WritePackets concurrently
// with Close. It exercises the race where WritePacket loads closed=false,
// Close stores closed=true and asserts closeWaker, the dispatcher drains
// the queue and exits, and then WritePacket pushes a packet that nothing
// will drain. The leak check in TestMain catches the surviving ref.
//
// Distinct from TestFastSimultaneousWrites, which closes only after all
// writers have completed.
func TestCloseConcurrentWithWritePacket(t *testing.T) {
	const trials = 50
	const nWriters = 16
	const nWrites = 200
	for trial := 0; trial < trials; trial++ {
		ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
		d, err := tbf.New(ep, &faketime.NullClock{}, 1<<40, 1<<20, 1024)
		if err != nil {
			t.Fatalf("trial %d: tbf.New: %v", trial, err)
		}
		var wg sync.WaitGroup
		for i := 0; i < nWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < nWrites; j++ {
					pkt := newPkt(64)
					_ = d.WritePacket(pkt)
					pkt.DecRef()
				}
			}()
		}
		d.Close()
		wg.Wait()
	}
}

func benchmarkWritePacket(b *testing.B, rate uint64) {
	b.Helper()
	ep := &fakeEndpoint{mtu: 1500, maxHeaderLength: 14}
	d, err := tbf.New(ep, &faketime.NullClock{}, rate, 1<<24, 1<<16)
	if err != nil {
		b.Fatalf("tbf.New: %v", err)
	}
	defer d.Close()

	pkts := make([]*stack.PacketBuffer, b.N)
	for i := range pkts {
		pkts[i] = newPkt(1500)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.WritePacket(pkts[i])
	}
	b.StopTimer()
	for _, p := range pkts {
		p.DecRef()
	}
}

// BenchmarkWritePacketUnshaped measures the per-call overhead of TBF when
// the bucket never empties: the fast path through WritePacket plus the
// cost of waking the dispatcher.
func BenchmarkWritePacketUnshaped(b *testing.B) {
	benchmarkWritePacket(b, 1<<40)
}

// BenchmarkWritePacketShaped measures the same path under a low rate, where
// most calls take the queue-and-park branch. NullClock keeps the watchdog
// from firing so we measure the WritePacket cost in isolation.
func BenchmarkWritePacketShaped(b *testing.B) {
	benchmarkWritePacket(b, 1<<10)
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
