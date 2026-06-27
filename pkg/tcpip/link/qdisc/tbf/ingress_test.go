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
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/tbf"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeLower is a minimal stack.LinkEndpoint and stack.GSOEndpoint sitting
// below the ingress shaper. It records the dispatcher it was attached with
// (which is the shaper itself) and counts egress writes passed through.
//
// It deliberately does not share tbf_test.go's fakeEndpoint: the ingress
// decorator drives Attach/Close on its child and these tests assert on that
// lifecycle, while the egress fake stubs those methods out (its Attach is a
// no-op and IsAttached is hardwired to false) because the egress qdisc never
// calls them.
type fakeLower struct {
	mtu             uint32
	maxHeaderLength uint16
	gsoMaxSize      uint32
	supportedGSO    stack.SupportedGSO

	mu             sync.Mutex
	dispatcher     stack.NetworkDispatcher
	packetsWritten int
	closed         bool
}

func (e *fakeLower) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.Lock()
	e.packetsWritten += pkts.Len()
	e.mu.Unlock()
	return pkts.Len(), nil
}

func (e *fakeLower) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
}

func (e *fakeLower) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}

func (e *fakeLower) Close() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

func (e *fakeLower) MTU() uint32                                  { return e.mtu }
func (e *fakeLower) SetMTU(mtu uint32)                            { e.mtu = mtu }
func (e *fakeLower) MaxHeaderLength() uint16                      { return e.maxHeaderLength }
func (e *fakeLower) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *fakeLower) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *fakeLower) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *fakeLower) Wait()                                        {}
func (e *fakeLower) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *fakeLower) AddHeader(*stack.PacketBuffer)                {}
func (e *fakeLower) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *fakeLower) SetOnCloseAction(func())                      {}
func (e *fakeLower) GSOMaxSize() uint32                           { return e.gsoMaxSize }
func (e *fakeLower) SupportedGSO() stack.SupportedGSO             { return e.supportedGSO }

// countDispatcher is a fake stack.NetworkDispatcher above the shaper. It
// records every delivered packet's protocol argument, the packet's
// NetworkProtocolNumber field, and its size.
type countDispatcher struct {
	mu         sync.Mutex
	count      int
	protocols  []tcpip.NetworkProtocolNumber
	fieldProto []tcpip.NetworkProtocolNumber
	sizes      []int

	packetsWanted int // 0 disables the done signal
	done          chan struct{}
}

func (d *countDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.mu.Lock()
	d.count++
	d.protocols = append(d.protocols, protocol)
	d.fieldProto = append(d.fieldProto, pkt.NetworkProtocolNumber)
	d.sizes = append(d.sizes, pkt.Size())
	if d.packetsWanted > 0 && d.count >= d.packetsWanted && d.done != nil {
		select {
		case <-d.done:
		default:
			close(d.done)
		}
	}
	d.mu.Unlock()
}

func (d *countDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	panic("DeliverLinkPacket is never called on the shaped ingress path")
}

func (d *countDispatcher) delivered() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}

// waitForDelivered returns true if d observed at least n deliveries within
// timeout.
func waitForDelivered(t *testing.T, d *countDispatcher, n int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if d.delivered() >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// pollMaxDelivered polls d over timeout, returning early as soon as the
// delivery count exceeds limit (the test would fail anyway), otherwise
// returning the final observed count. Used to assert "no more than `limit`
// delivered".
func pollMaxDelivered(t *testing.T, d *countDispatcher, limit int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := d.delivered(); got > limit {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	return d.delivered()
}

// newIngress builds an attached shaper around a plain non-GSO lower endpoint.
func newIngress(t *testing.T, clock tcpip.Clock, rate uint64, burst, queueLen uint32) (*tbf.Ingress, *fakeLower, *countDispatcher) {
	t.Helper()
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	ing, err := tbf.NewIngress(lower, clock, rate, burst, queueLen)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	d := &countDispatcher{}
	ing.Attach(d)
	return ing, lower, d
}

// TestIngressNewValidation covers the rejected-configuration paths in
// tbf.NewIngress, mirroring TestNewValidation for the egress qdisc. Error
// messages must name the ingress flags.
func TestIngressNewValidation(t *testing.T) {
	const mtu = 1500
	const hdr = 14
	tests := []struct {
		name      string
		ep        *fakeLower
		rate      uint64
		burst     uint32
		errSubstr string
	}{
		{
			name:      "rate zero rejected",
			ep:        &fakeLower{mtu: mtu, maxHeaderLength: hdr},
			rate:      0,
			burst:     1 << 16,
			errSubstr: "ingress-qdisc=tbf requires setting ingress-qdisc-tbf-rate",
		},
		{
			name:      "burst zero rejected",
			ep:        &fakeLower{mtu: mtu, maxHeaderLength: hdr},
			rate:      1 << 20,
			burst:     0,
			errSubstr: "ingress-qdisc=tbf requires setting ingress-qdisc-tbf-burst",
		},
		{
			name:      "burst smaller than MTU+hdr rejected",
			ep:        &fakeLower{mtu: mtu, maxHeaderLength: hdr},
			rate:      1 << 20,
			burst:     mtu, // missing the header
			errSubstr: "smaller than max packet length",
		},
		{
			name: "burst smaller than host GSO max rejected",
			ep: &fakeLower{
				mtu: mtu, maxHeaderLength: hdr,
				gsoMaxSize:   1 << 16,
				supportedGSO: stack.HostGSOSupported,
			},
			rate:      1 << 20,
			burst:     mtu + hdr, // big enough for non-GSO, too small for host GSO
			errSubstr: "smaller than link's max GSO",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ing, err := tbf.NewIngress(tt.ep, &faketime.NullClock{}, tt.rate, tt.burst, 10)
			if err == nil {
				ing.Close()
				t.Fatalf("tbf.NewIngress succeeded unexpectedly")
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("tbf.NewIngress err = %q, want substring %q", err, tt.errSubstr)
			}
		})
	}
}

// TestIngressNewSucceeds confirms valid configurations construct cleanly with
// each SupportedGSO mode, and Close() shuts down the dispatch goroutine
// without leaking refs.
func TestIngressNewSucceeds(t *testing.T) {
	const mtu = 1500
	const hdr = 14
	tests := []struct {
		name  string
		ep    *fakeLower
		burst uint32
	}{
		{
			name:  "no GSO",
			ep:    &fakeLower{mtu: mtu, maxHeaderLength: hdr},
			burst: mtu + hdr,
		},
		{
			name:  "gvisor GSO with burst smaller than GSO max",
			ep:    &fakeLower{mtu: mtu, maxHeaderLength: hdr, gsoMaxSize: 1 << 16, supportedGSO: stack.GVisorGSOSupported},
			burst: mtu + hdr,
		},
		{
			name:  "host GSO with sufficient burst",
			ep:    &fakeLower{mtu: mtu, maxHeaderLength: hdr, gsoMaxSize: 1 << 16, supportedGSO: stack.HostGSOSupported},
			burst: 1 << 17,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ing, err := tbf.NewIngress(tt.ep, &faketime.NullClock{}, 1<<20, tt.burst, 10)
			if err != nil {
				t.Fatalf("tbf.NewIngress: %v", err)
			}
			ing.Close()
		})
	}
}

// TestIngressPassthroughAndForwarding checks the decorator surface: link
// properties and GSO capabilities are forwarded from the lower endpoint,
// egress writes pass through unshaped, and Close propagates to the child.
func TestIngressPassthroughAndForwarding(t *testing.T) {
	lower := &fakeLower{
		mtu: 1500, maxHeaderLength: 14,
		gsoMaxSize: 1 << 16, supportedGSO: stack.HostGSOSupported,
	}
	ing, err := tbf.NewIngress(lower, &faketime.NullClock{}, 1<<20, 1<<17, 10)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}

	if got, want := ing.MTU(), lower.mtu; got != want {
		t.Errorf("MTU() = %d, want %d", got, want)
	}
	if got, want := ing.MaxHeaderLength(), lower.maxHeaderLength; got != want {
		t.Errorf("MaxHeaderLength() = %d, want %d", got, want)
	}
	if got, want := ing.GSOMaxSize(), lower.gsoMaxSize; got != want {
		t.Errorf("GSOMaxSize() = %d, want %d", got, want)
	}
	if got, want := ing.SupportedGSO(), lower.supportedGSO; got != want {
		t.Errorf("SupportedGSO() = %d, want %d", got, want)
	}

	// Attach propagates to the child with the shaper as the dispatcher.
	d := &countDispatcher{}
	ing.Attach(d)
	if !ing.IsAttached() {
		t.Errorf("IsAttached() = false after Attach")
	}
	if !lower.IsAttached() {
		t.Errorf("lower endpoint not attached after Attach")
	}

	// Egress writes pass straight through.
	var pkts stack.PacketBufferList
	pkts.PushBack(newPkt(64))
	if _, err := ing.WritePackets(pkts); err != nil {
		t.Errorf("WritePackets: %v", err)
	}
	pkts.Reset()
	lower.mu.Lock()
	written := lower.packetsWritten
	lower.mu.Unlock()
	if written != 1 {
		t.Errorf("lower endpoint saw %d written packets, want 1", written)
	}

	ing.Close()
	lower.mu.Lock()
	closed := lower.closed
	lower.mu.Unlock()
	if !closed {
		t.Errorf("lower endpoint not closed after Close")
	}
}

// TestIngressDeliverAfterCloseDropped confirms inbound packets delivered
// after Close are dropped without panicking or leaking. The leak check in
// TestMain (tbf_test.go) catches a surviving ref.
func TestIngressDeliverAfterCloseDropped(t *testing.T) {
	ing, _, d := newIngress(t, &faketime.NullClock{}, 1<<20, 1<<17, 10)
	ing.Close()

	pkt := newPkt(64)
	defer pkt.DecRef()
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
	if got := d.delivered(); got != 0 {
		t.Errorf("delivered %d packets after Close, want 0", got)
	}
}

// TestIngressOversizePacketDeliveredWithDebt verifies that an inbound packet
// larger than burst (as GRO coalescing can produce) is neither dropped nor
// wedges the queue: it passes once the bucket is completely full, drives the
// bucket into debt, and the next packet waits for the debt to repay plus its
// own cost.
func TestIngressOversizePacketDeliveredWithDebt(t *testing.T) {
	const pktSize = 1514
	const burst = pktSize        // bucket capacity: one packet, one second
	const rate = uint64(pktSize) // 1 packet per second

	clk := faketime.NewManualClock()
	ing, _, d := newIngress(t, clk, rate, burst, 32)
	defer ing.Close()

	// 2x burst: a 2s cost against a 1s bucket. The full initial bucket lets
	// it pass immediately, leaving 1s of debt.
	big := newPkt(2 * pktSize)
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, big)
	big.DecRef()
	if !waitForDelivered(t, d, 1, time.Second) {
		t.Fatalf("oversize packet was not delivered")
	}

	// A normal packet now needs the 1s debt repaid plus its own 1s cost.
	pkt := newPkt(pktSize)
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	clk.Advance(time.Second)
	if got := pollMaxDelivered(t, d, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("packet delivered before the oversize debt repaid: got %d, want 1", got)
	}
	clk.Advance(time.Second)
	if !waitForDelivered(t, d, 2, time.Second) {
		t.Fatalf("packet did not deliver after the debt repaid")
	}
	if got := ing.DroppedPackets(); got != 0 {
		t.Errorf("DroppedPackets() = %d, want 0", got)
	}
}

// TestIngressUnshapedPassesAllPackets sets a rate so high relative to the
// workload that the bucket is effectively unbounded; every packet should
// reach the dispatcher.
func TestIngressUnshapedPassesAllPackets(t *testing.T) {
	const want = 200
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	ing, err := tbf.NewIngress(lower, &faketime.NullClock{}, 1<<40 /* 1 TB/s */, 1<<20, want+10)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	defer ing.Close()
	d := &countDispatcher{done: make(chan struct{}), packetsWanted: want}
	ing.Attach(d)

	// pktSize=1500 ensures len2TimeNS doesn't truncate to zero, so the token
	// math is actually exercised, not just the dispatch path.
	for i := 0; i < want; i++ {
		pkt := newPkt(1500)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("only %d/%d packets reached the dispatcher", d.delivered(), want)
	}
}

// TestIngressOrderAndProtocolPreserved injects packets with distinct sizes
// and alternating protocols, without pre-setting NetworkProtocolNumber (as
// the xdp endpoint does not), and verifies the dispatcher sees the same
// order, the same protocol arguments, and a matching NetworkProtocolNumber
// field on each packet.
func TestIngressOrderAndProtocolPreserved(t *testing.T) {
	const want = 8
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	ing, err := tbf.NewIngress(lower, &faketime.NullClock{}, 1<<40, 1<<20, want+2)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	defer ing.Close()
	d := &countDispatcher{done: make(chan struct{}), packetsWanted: want}
	ing.Attach(d)

	protos := []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
	for i := 0; i < want; i++ {
		pkt := newPkt(100 + i) // distinct sizes encode the injection order
		ing.DeliverNetworkPacket(protos[i%2], pkt)
		pkt.DecRef()
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("only %d/%d packets delivered", d.delivered(), want)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < want; i++ {
		if got, want := d.sizes[i], 100+i; got != want {
			t.Errorf("packet %d: size = %d, want %d (order not preserved)", i, got, want)
		}
		if got, want := d.protocols[i], protos[i%2]; got != want {
			t.Errorf("packet %d: protocol argument = %d, want %d", i, got, want)
		}
		if got, want := d.fieldProto[i], protos[i%2]; got != want {
			t.Errorf("packet %d: pkt.NetworkProtocolNumber = %d, want %d", i, got, want)
		}
	}
}

// TestIngressBurstAbsorption verifies that with a full bucket, a burst worth
// of bytes is delivered immediately. NullClock freezes token replenishment so
// any delivery must come from the initial bucket.
func TestIngressBurstAbsorption(t *testing.T) {
	const pktSize = 1514
	const allowed = 4
	const burst = pktSize * allowed
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	ing, err := tbf.NewIngress(lower, &faketime.NullClock{}, 1 /* 1 byte/sec */, burst, 32)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	defer ing.Close()
	d := &countDispatcher{done: make(chan struct{}), packetsWanted: allowed}
	ing.Attach(d)

	for i := 0; i < allowed; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("burst absorption: got %d/%d packets delivered", d.delivered(), allowed)
	}
}

// TestIngressBucketCapNotExceeded checks that even after the shaper has been
// idle far longer than the bucket-fill time, a single burst cannot exceed
// burst bytes.
func TestIngressBucketCapNotExceeded(t *testing.T) {
	const pktSize = 1514
	const allowed = 4
	const burst = pktSize * allowed
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	clk := faketime.NewManualClock()
	ing, err := tbf.NewIngress(lower, clk, 1 /* 1 byte/sec */, burst, 32)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	defer ing.Close()
	d := &countDispatcher{done: make(chan struct{}), packetsWanted: allowed}
	ing.Attach(d)

	// Idle for far longer than it would take to refill the bucket. With a
	// correct cap, tokens stay at `buffer`; without one, tokens grow and a
	// flood of allowed+ packets would all drain.
	clk.Advance(time.Hour)

	const flood = allowed + 10
	for i := 0; i < flood; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected at least %d delivered, got %d", allowed, d.delivered())
	}
	if got := pollMaxDelivered(t, d, allowed, 100*time.Millisecond); got > allowed {
		t.Errorf("bucket cap violated: %d packets delivered, want %d", got, allowed)
	}
}

// TestIngressSustainedRate exercises the watchdog refill path and pins down
// per-advance pacing, mirroring the egress TestSustainedRate: all packets are
// queued up front, packet 1 drains via the initial bucket, and each
// one-second advance must release exactly one more packet.
func TestIngressSustainedRate(t *testing.T) {
	const pktSize = 1514
	const burst = pktSize
	const rate = uint64(pktSize)
	const queued = 4

	clk := faketime.NewManualClock()
	ing, _, d := newIngress(t, clk, rate, burst, 32)
	defer ing.Close()

	for i := 0; i < queued; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	if !waitForDelivered(t, d, 1, time.Second) {
		t.Fatalf("initial packet did not drain")
	}
	if got := pollMaxDelivered(t, d, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("before any advance: got %d packets, want 1", got)
	}

	for i := 2; i <= queued; i++ {
		clk.Advance(time.Second)
		if !waitForDelivered(t, d, i, time.Second) {
			t.Fatalf("after advance %d: got %d packets, want %d", i-1, d.delivered(), i)
		}
		if got := pollMaxDelivered(t, d, i, 100*time.Millisecond); got > i {
			t.Errorf("after advance %d: got %d packets, want %d (extra drained)", i-1, got, i)
		}
	}
}

// TestIngressQueueOverflowDrops floods more packets than the bucket plus the
// backlog queue can hold and verifies the overflow is dropped: after fully
// draining, the dispatcher must have seen at most bucket(1)+queueLen packets.
// The leak check in TestMain verifies the dropped packets' refs were
// released.
func TestIngressQueueOverflowDrops(t *testing.T) {
	const pktSize = 1514
	const burst = pktSize // exactly one packet of bucket capacity
	const rate = uint64(pktSize)
	const queueLen = 4
	const flood = 20

	clk := faketime.NewManualClock()
	ing, _, d := newIngress(t, clk, rate, burst, queueLen)
	defer ing.Close()

	for i := 0; i < flood; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	// The head packet always drains via the initial bucket.
	if !waitForDelivered(t, d, 1, time.Second) {
		t.Fatalf("initial packet did not drain")
	}

	// Drain whatever was accepted, one packet per one-second advance. The
	// queue held at most queueLen packets; depending on whether the dispatch
	// loop dequeued the head packet before or after the flood filled the
	// queue, total accepted is queueLen or queueLen+1.
	for i := 0; i < queueLen+2; i++ {
		clk.Advance(time.Second)
		waitForDelivered(t, d, d.delivered()+1, 200*time.Millisecond)
	}
	got := d.delivered()
	if got < queueLen || got > queueLen+1 {
		t.Errorf("delivered %d packets, want %d or %d (bucket+queue)", got, queueLen, queueLen+1)
	}
	if got >= flood {
		t.Errorf("delivered all %d flooded packets; expected overflow drops", flood)
	}
	// Every flooded packet was either delivered or counted as dropped.
	if dropped := ing.DroppedPackets(); dropped != uint64(flood-got) {
		t.Errorf("DroppedPackets() = %d, want %d (flood %d - delivered %d)", dropped, flood-got, flood, got)
	}
}

// TestIngressShapedRefillReleasesGroup mirrors the egress
// TestShapedPathBatchesAfterRefill: with several packets parked behind an
// empty bucket, a refill worth the whole group must release all of them.
func TestIngressShapedRefillReleasesGroup(t *testing.T) {
	const pktSize = 1514
	const groupSize = 5
	clk := faketime.NewManualClock()
	rate := uint64(pktSize)              // 1 packet per second sustained
	burst := uint32(pktSize * groupSize) // bucket holds groupSize packets

	ing, _, d := newIngress(t, clk, rate, burst, 64)
	defer ing.Close()

	// Drain the initial bucket so subsequent packets park on the watchdog.
	for i := 0; i < groupSize; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	if !waitForDelivered(t, d, groupSize, time.Second) {
		t.Fatalf("initial drain: got %d/%d", d.delivered(), groupSize)
	}

	// Bucket empty. Queue another group; the dispatcher parks on the
	// watchdog after peeking the head.
	for i := 0; i < groupSize; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	if got := pollMaxDelivered(t, d, groupSize, 100*time.Millisecond); got > groupSize {
		t.Fatalf("parked packets delivered early: got %d, want %d", got, groupSize)
	}

	// Refill enough for the whole group at once.
	clk.Advance(time.Duration(groupSize) * time.Second)
	if !waitForDelivered(t, d, 2*groupSize, 2*time.Second) {
		t.Fatalf("after refill: got %d/%d", d.delivered(), 2*groupSize)
	}
	if got := pollMaxDelivered(t, d, 2*groupSize, 100*time.Millisecond); got > 2*groupSize {
		t.Errorf("delivered %d packets, want %d", got, 2*groupSize)
	}
}

// TestIngressShapedOrderPreservedMidWait mirrors the egress
// TestNewPacketArrivingMidWaitPreservesOrder on the shaped path: a packet
// arriving while the head packet is parked on the watchdog must not jump
// ahead of it or shorten its wait. Protocols are used as order markers since
// they do not affect token cost.
func TestIngressShapedOrderPreservedMidWait(t *testing.T) {
	const pktSize = 1514
	clk := faketime.NewManualClock()
	ing, _, d := newIngress(t, clk, uint64(pktSize) /* 1 packet per second */, pktSize, 32)
	defer ing.Close()

	// pkt1 drains via the initial bucket.
	pkt1 := newPkt(pktSize)
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt1)
	pkt1.DecRef()
	if !waitForDelivered(t, d, 1, time.Second) {
		t.Fatalf("pkt1 did not drain")
	}

	// pkt2 parks on the watchdog: bucket is empty, refill takes 1s.
	pkt2 := newPkt(pktSize)
	ing.DeliverNetworkPacket(header.IPv6ProtocolNumber, pkt2)
	pkt2.DecRef()

	// Half-advance the wait; pkt2 must not deliver.
	clk.Advance(500 * time.Millisecond)
	if got := pollMaxDelivered(t, d, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("pkt2 delivered early: got %d, want 1", got)
	}

	// pkt3 arrives mid-wait. It must not jump ahead of pkt2 and must not
	// shorten pkt2's wait.
	pkt3 := newPkt(pktSize)
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt3)
	pkt3.DecRef()
	if got := pollMaxDelivered(t, d, 1, 100*time.Millisecond); got > 1 {
		t.Errorf("a packet delivered out of order during mid-wait push: got %d, want 1", got)
	}

	// Complete pkt2's wait; pkt2 delivers, pkt3 still waits.
	clk.Advance(500 * time.Millisecond)
	if !waitForDelivered(t, d, 2, time.Second) {
		t.Fatalf("pkt2 did not deliver after full advance")
	}
	if got := pollMaxDelivered(t, d, 2, 100*time.Millisecond); got > 2 {
		t.Errorf("pkt3 delivered early: got %d, want 2", got)
	}

	// Advance for pkt3.
	clk.Advance(time.Second)
	if !waitForDelivered(t, d, 3, time.Second) {
		t.Fatalf("pkt3 did not deliver")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	want := []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber, header.IPv4ProtocolNumber}
	for i, p := range want {
		if d.protocols[i] != p {
			t.Errorf("delivery %d: protocol = %d, want %d (order violated)", i, d.protocols[i], p)
		}
	}
}

// TestIngressWaitDoesNotJoinDispatcher pins down the lifecycle contract that
// avoids deadlocking against the stack: Wait only waits for the lower
// endpoint and must return while the shaper's dispatch goroutine is still
// running (Stack.Wait invokes Wait with the stack mutex held; the goroutine
// is joined by Close instead). Double Close and Wait-after-Close must be
// safe.
func TestIngressWaitDoesNotJoinDispatcher(t *testing.T) {
	ing, _, _ := newIngress(t, &faketime.NullClock{}, 1<<20, 1<<17, 10)

	done := make(chan struct{})
	go func() {
		ing.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Wait() blocked while the shaper is running; it must only wait for the child")
	}

	ing.Close()
	ing.Close() // double Close must be idempotent
	ing.Wait()  // Wait after Close must not block
}

// TestIngressDetachDropsBacklogAndStops verifies that Attach(nil) shuts the
// shaper down: queued packets are dropped (leak check catches missed refs),
// and later deliveries are ignored.
func TestIngressDetachDropsBacklogAndStops(t *testing.T) {
	const pktSize = 1514
	clk := faketime.NewManualClock()
	// rate=1 byte/sec parks everything after the first packet.
	lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
	ing, err := tbf.NewIngress(lower, clk, 1, pktSize, 32)
	if err != nil {
		t.Fatalf("tbf.NewIngress: %v", err)
	}
	d := &countDispatcher{}
	ing.Attach(d)

	for i := 0; i < 8; i++ {
		pkt := newPkt(pktSize)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	if !waitForDelivered(t, d, 1, time.Second) {
		t.Fatalf("initial packet did not drain")
	}

	ing.Attach(nil)
	if ing.IsAttached() {
		t.Errorf("IsAttached() = true after Attach(nil)")
	}
	if lower.IsAttached() {
		t.Errorf("lower endpoint still attached after Attach(nil)")
	}

	before := d.delivered()
	pkt := newPkt(64)
	ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
	if got := pollMaxDelivered(t, d, before, 100*time.Millisecond); got > before {
		t.Errorf("delivered %d packets after detach, want %d", got, before)
	}

	// Close after detach must be safe.
	ing.Close()
}

// TestIngressCloseDrainsQueuedPackets fills the queue with packets the
// dispatcher cannot deliver and then closes the shaper. The leak check in
// TestMain catches any packet whose ref was not dropped.
func TestIngressCloseDrainsQueuedPackets(t *testing.T) {
	clk := faketime.NewManualClock()
	const queueLen = 32
	ing, _, _ := newIngress(t, clk, 1<<10, 1514, queueLen)

	for i := 0; i < queueLen*2; i++ {
		pkt := newPkt(1514)
		ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt) // overflow drops are fine
		pkt.DecRef()
	}
	ing.Close()
}

// TestIngressFastConcurrentDeliveries hammers DeliverNetworkPacket from many
// goroutines at once, mirroring the link endpoints' concurrent inbound
// delivery (fdbased runs NumChannels x ProcessorsPerChannel goroutines). Must
// not panic, deadlock, or leak refs. Run with --config=race for data-race
// coverage.
func TestIngressFastConcurrentDeliveries(t *testing.T) {
	ing, _, _ := newIngress(t, &faketime.NullClock{}, 1<<40, 1<<20, 10000)

	const nWriters = 100
	const nWrites = 100
	var wg sync.WaitGroup
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nWrites; j++ {
				pkt := newPkt(64)
				ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}()
	}
	wg.Wait()
	ing.Close()
}

// TestIngressCloseConcurrentWithDeliver races Close against deliveries,
// mirroring the egress TestCloseConcurrentWithWritePacket: a delivery that
// loads closed=false before Close must not push onto a queue nothing will
// drain. The leak check in TestMain catches the surviving ref.
func TestIngressCloseConcurrentWithDeliver(t *testing.T) {
	const trials = 50
	const nWriters = 16
	const nWrites = 200
	for trial := 0; trial < trials; trial++ {
		lower := &fakeLower{mtu: 1500, maxHeaderLength: 14}
		ing, err := tbf.NewIngress(lower, &faketime.NullClock{}, 1<<40, 1<<20, 1024)
		if err != nil {
			t.Fatalf("trial %d: tbf.NewIngress: %v", trial, err)
		}
		d := &countDispatcher{}
		ing.Attach(d)
		var wg sync.WaitGroup
		for i := 0; i < nWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < nWrites; j++ {
					pkt := newPkt(64)
					ing.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
					pkt.DecRef()
				}
			}()
		}
		ing.Close()
		wg.Wait()
	}
}
