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

package tcp

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const testClockResolution = 500 * time.Microsecond

type quantizedClock struct {
	*faketime.ManualClock
	resolution time.Duration
}

func (c *quantizedClock) NowMonotonic() tcpip.MonotonicTime {
	now := c.ManualClock.NowMonotonic().Sub(tcpip.MonotonicTime{})
	return tcpip.MonotonicTime{}.Add(now.Truncate(c.resolution))
}

type rackTestContext struct {
	clock tcpip.Clock
	snd   sender
	segs  []*segment
}

func newRACKTestContext(clock tcpip.Clock, resolution time.Duration) *rackTestContext {
	ctx := &rackTestContext{clock: clock}
	st := stack.New(stack.Options{Clock: clock, ClockResolution: resolution})
	ctx.snd.ep = &Endpoint{
		stack:      st,
		scoreboard: NewSACKScoreboard(1, 0),
	}
	ctx.snd.writeList.set = make(map[*segment]struct{})
	ctx.snd.reorderTimer.init(clock, func() {})
	ctx.snd.rc.init(&ctx.snd, 0)
	return ctx
}

// +checklocks:ctx.snd.ep.mu
func (ctx *rackTestContext) addSegment(seq seqnum.Value, xmitTime tcpip.MonotonicTime) *segment {
	seg := newOutgoingSegment(
		stack.TransportEndpointID{},
		ctx.clock,
		buffer.MakeWithView(buffer.NewViewSize(1)),
		0,
	)
	seg.sequenceNumber = seq
	seg.xmitCount = 1
	seg.xmitTime = xmitTime
	ctx.snd.writeList.PushBack(seg)
	ctx.segs = append(ctx.segs, seg)
	return seg
}

func (ctx *rackTestContext) cleanup() {
	ctx.snd.reorderTimer.cleanup()
	for _, seg := range ctx.segs {
		seg.DecRef()
	}
}

func TestRACKQuantizedClockPreventsPrematureLossAndSchedulesRecheck(t *testing.T) {
	clock := &quantizedClock{
		ManualClock: faketime.NewManualClock(),
		resolution:  testClockResolution,
	}
	ctx := newRACKTestContext(clock, testClockResolution)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()

	// Send the older packet just before a quantization boundary.
	clock.Advance(testClockResolution - time.Microsecond)
	older := ctx.addSegment(0, clock.NowMonotonic())

	// Send the newer packet just after the boundary, then receive its ACK
	// within the same clock bucket.
	clock.Advance(2 * time.Microsecond)
	newer := ctx.addSegment(1, clock.NowMonotonic())
	clock.Advance(49 * time.Microsecond)
	ack := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.Buffer{}, 0)
	defer ack.DecRef()

	ctx.snd.rc.update(newer, ack)
	if got := ctx.snd.rc.RTT; got != 0 {
		t.Fatalf("RACK RTT = %v, want 0", got)
	}
	wantXmitTime := (tcpip.MonotonicTime{}).Add(testClockResolution)
	if got := ctx.snd.rc.XmitTime; got != wantXmitTime {
		t.Fatalf("RACK transmit time = %v, want %v", got, wantXmitTime)
	}
	if got := ctx.snd.rc.EndSequence; got != 2 {
		t.Fatalf("RACK end sequence = %d, want 2", got)
	}

	var timerFired bool
	ctx.snd.reorderTimer.cleanup()
	ctx.snd.reorderTimer.init(clock, func() { timerFired = true })
	if got := ctx.snd.rc.detectLoss(ack.rcvdTime); got != 0 {
		t.Fatalf("detectLoss at ACK got %d losses, want 0", got)
	}
	if older.lost {
		t.Fatal("older packet marked lost from quantization alone")
	}
	wantTimerTarget := (tcpip.MonotonicTime{}).Add(2 * testClockResolution)
	if got := ctx.snd.reorderTimer.target; got != wantTimerTarget {
		t.Fatalf("reorder timer target = %v, want %v", got, wantTimerTarget)
	}

	clock.Advance(testClockResolution - time.Nanosecond)
	if timerFired {
		t.Fatal("reorder timer fired before its target")
	}
	clock.Advance(time.Nanosecond)
	if !timerFired {
		t.Fatal("reorder timer did not fire at its target")
	}
	if older.lost {
		t.Fatal("timer callback marked packet lost before endpoint processing")
	}

	// Delay endpoint processing by another tick. The production expiry path
	// evaluates loss at the timer target, where the packet is now beyond the
	// uncertainty boundary, rather than adding callback delay to its age.
	clock.Advance(testClockResolution)
	ctx.snd.FastRecovery.Active = true
	ctx.snd.SndNxt = 1
	ctx.snd.SndCwnd = 0
	if err := ctx.snd.rc.reorderTimerExpired(); err != nil {
		t.Fatalf("reorderTimerExpired failed: %v", err)
	}
	if !older.lost {
		t.Fatal("reorderTimerExpired did not mark older packet lost at timer target")
	}
}

func TestRACKClockResolutionPreventsPrematureLoss(t *testing.T) {
	for _, test := range []struct {
		name       string
		resolution time.Duration
		wantLost   bool
	}{
		{name: "unspecified resolution", wantLost: true},
		{name: "quantization allowance", resolution: testClockResolution},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, test.resolution)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()

			ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(testClockResolution)
			ctx.snd.rc.EndSequence = 2
			seg := ctx.addSegment(0, tcpip.MonotonicTime{})

			gotLost := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}.Add(testClockResolution)) != 0
			if gotLost != test.wantLost || seg.lost != test.wantLost {
				t.Errorf("detectLoss=%t, segment lost=%t; want %t", gotLost, seg.lost, test.wantLost)
			}
		})
	}
}

func TestRACKClockResolutionLossBoundaryIsExclusive(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, testClockResolution)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(time.Nanosecond)
	ctx.snd.rc.EndSequence = 2
	seg := ctx.addSegment(0, tcpip.MonotonicTime{})

	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}.Add(testClockResolution)); got != 0 {
		t.Fatalf("detectLoss at uncertainty boundary got %d losses, want 0", got)
	}
	if seg.lost {
		t.Fatal("segment marked lost at uncertainty boundary")
	}
	if !ctx.snd.reorderTimer.enabled() {
		t.Fatal("reorder timer not enabled at uncertainty boundary")
	}
	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}.Add(2 * testClockResolution)); got != 1 {
		t.Fatalf("detectLoss after uncertainty boundary got %d losses, want 1", got)
	}
}

// TestRACKReorderTimerDeclaresLossOnFirstExpiry verifies that a reorder timer
// armed on a quantized clock expires exactly once, at the loss deadline
// including timestamp uncertainty, and that its first expiry declares loss.
// Arming only to the pre-uncertainty deadline makes every expiry a no-op that
// re-arms a second timer before any loss is declared.
func TestRACKReorderTimerDeclaresLossOnFirstExpiry(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, testClockResolution)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()

	// A newer packet was transmitted one tick after the older packet below,
	// and its ACK was received in the same clock bucket, so RACK.RTT and
	// RACK.ReoWnd are zero. The older packet's loss deadline is therefore
	// exactly one clock resolution past the ACK processing time.
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(testClockResolution)
	ctx.snd.rc.EndSequence = 2
	older := ctx.addSegment(0, tcpip.MonotonicTime{})

	var timerFired bool
	ctx.snd.reorderTimer.cleanup()
	ctx.snd.reorderTimer.init(clock, func() { timerFired = true })

	// detectLoss must not declare loss while the uncertainty boundary has
	// not elapsed, and must arm the timer through that boundary so that the
	// first expiry observes a negative timeRemaining.
	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}); got != 0 {
		t.Fatalf("detectLoss got %d losses, want 0", got)
	}
	if older.lost {
		t.Fatal("segment marked lost before the uncertainty boundary elapsed")
	}
	if !ctx.snd.reorderTimer.enabled() {
		t.Fatal("reorder timer not armed")
	}
	if got, want := ctx.snd.reorderTimer.target, (tcpip.MonotonicTime{}).Add(2*testClockResolution); got != want {
		t.Fatalf("reorder timer target = %v, want %v", got, want)
	}

	// A single expiry at the target must be sufficient to declare loss.
	clock.Advance(2 * testClockResolution)
	if !timerFired {
		t.Fatal("reorder timer did not fire at its target")
	}
	ctx.snd.FastRecovery.Active = true
	ctx.snd.SndNxt = 1
	ctx.snd.SndCwnd = 0
	if err := ctx.snd.rc.reorderTimerExpired(); err != nil {
		t.Fatalf("reorderTimerExpired failed: %v", err)
	}
	if !older.lost {
		t.Fatal("reorderTimerExpired did not declare loss on the first timer expiry")
	}
}

// TestRACKInitialDeliverySequence starts transmissions at the clock origin.
// An unset delivery timestamp must not compare their sequence numbers with zero.
func TestRACKInitialDeliverySequence(t *testing.T) {
	for _, test := range []struct {
		name string
		iss  seqnum.Value
	}{
		{name: "low_isn", iss: 1234},
		{name: "high_isn", iss: 1 << 31},
		{name: "sequence_wrap", iss: ^seqnum.Value(0) - 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			// Initialize the same connection-relative state as initSender.
			ctx.snd.rc.init(&ctx.snd, test.iss)
			ctx.addSegment(test.iss.Add(1), clock.NowMonotonic())
			later := ctx.addSegment(test.iss.Add(2), clock.NowMonotonic())

			clock.Advance(time.Millisecond)
			if got, want := ctx.snd.rc.detectLoss(clock.NowMonotonic()), 0; got != want {
				t.Errorf("losses before any delivery = %d, want %d", got, want)
			}

			// The first delivered segment also has transmission timestamp zero.
			// It must advance the marker, including when its end wraps to zero.
			ack := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.Buffer{}, 0)
			defer ack.DecRef()
			ctx.snd.rc.update(later, ack)
			if got, want := ctx.snd.rc.EndSequence, test.iss.Add(3); got != want {
				t.Errorf("first delivery end = %d, want %d", got, want)
			}
		})
	}
}

func TestRACKInitialDSACKWindow(t *testing.T) {
	for _, test := range []struct {
		name string
		iss  seqnum.Value
	}{
		{name: "low_isn", iss: 1234},
		{name: "high_isn", iss: 1 << 31},
		{name: "sequence_wrap", iss: ^seqnum.Value(0) - 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newRACKTestContext(faketime.NewManualClock(), 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			ctx.snd.rc.init(&ctx.snd, test.iss)
			ctx.snd.SndUna = test.iss.Add(1)
			ctx.snd.SndNxt = test.iss.Add(4)
			ctx.snd.rc.minRTT = 100 * time.Millisecond
			ctx.snd.rtt.Lock()
			ctx.snd.rtt.TCPRTTState.SRTT = 100 * time.Millisecond
			ctx.snd.rtt.Unlock()

			// The first DSACK must expand the reordering window regardless
			// of where the connection starts in sequence space.
			ctx.snd.rc.DSACKSeen = true
			ctx.snd.rc.updateRACKReorderWindow()
			if got, want := ctx.snd.rc.ReoWnd, 50*time.Millisecond; got != want {
				t.Errorf("first DSACK window = %s, want %s", got, want)
			}
			if got, want := ctx.snd.rc.RTTSeq, ctx.snd.SndNxt; got != want {
				t.Errorf("DSACK round boundary = %d, want %d", got, want)
			}

			// Another DSACK in the same round cannot expand it again.
			ctx.snd.rc.DSACKSeen = true
			ctx.snd.rc.updateRACKReorderWindow()
			if got, want := ctx.snd.rc.ReoWnd, 50*time.Millisecond; got != want {
				t.Errorf("same-round DSACK window = %s, want %s", got, want)
			}

			// Acknowledging the round boundary allows a new expansion,
			// including when that boundary wraps through zero.
			ctx.snd.SndUna = ctx.snd.SndNxt
			ctx.snd.rc.DSACKSeen = true
			ctx.snd.rc.updateRACKReorderWindow()
			if got, want := ctx.snd.rc.ReoWnd, 75*time.Millisecond; got != want {
				t.Errorf("next-round DSACK window = %s, want %s", got, want)
			}
		})
	}
}

func TestRACKRetransmissionTimestampWrap(t *testing.T) {
	const wrap = 1 << 32 * time.Millisecond
	const rtt = 5 * time.Millisecond
	for _, test := range []struct {
		name       string
		retransmit time.Duration
		echo       time.Duration
		wantRTT    time.Duration
	}{
		// An echo from before the wrap belongs to the original transmission.
		{"original", wrap + time.Millisecond, wrap - time.Millisecond, 0},
		// A later echo can acknowledge a retransmission from before the wrap.
		{"retransmission", wrap - time.Millisecond, wrap + time.Millisecond, rtt},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()

			clock.Advance(test.retransmit)
			seg := ctx.addSegment(1, clock.NowMonotonic())
			seg.xmitCount = 2
			clock.Advance(rtt)
			ack := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.Buffer{}, 0)
			defer ack.DecRef()
			ack.parsedOptions.TS = true
			ack.parsedOptions.TSEcr = ctx.snd.ep.tsVal(tcpip.MonotonicTime{}.Add(test.echo))
			ctx.snd.rc.update(seg, ack)
			if got, want := ctx.snd.rc.RTT, test.wantRTT; got != want {
				t.Errorf("RACK RTT = %s, want %s", got, want)
			}
		})
	}
}

func TestRACKEqualTransmitTimeOrdersByEndSequence(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, 0)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()
	ctx.snd.rc.EndSequence = 2
	for seq := seqnum.Value(0); seq < 3; seq++ {
		ctx.addSegment(seq, tcpip.MonotonicTime{})
	}

	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}); got != 1 {
		t.Fatalf("detectLoss got %d losses, want 1", got)
	}
	for seg := ctx.snd.writeList.Front(); seg != nil; seg = seg.Next() {
		wantLost := seg.sequenceNumber == 0
		if seg.lost != wantLost {
			t.Errorf("segment ending at %d lost=%t, want %t", seg.sequenceNumber.Add(1), seg.lost, wantLost)
		}
	}
}

// TestRACKDetectLossStopsAfterRACKSegment checks that loss detection does not
// look past the first segment that was sent once and not before the RACK
// segment. Segments are first sent in sequence order, so no segment after it
// can have been sent before the RACK segment.
func TestRACKDetectLossStopsAfterRACKSegment(t *testing.T) {
	rackXmitTime := tcpip.MonotonicTime{}.Add(time.Millisecond)
	for _, test := range []struct {
		name     string
		xmitTime tcpip.MonotonicTime
	}{
		{"later", rackXmitTime.Add(time.Millisecond)},
		// The RACK segment ends at 2, as does the segment below.
		{"same time", rackXmitTime},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			ctx.snd.rc.XmitTime = rackXmitTime
			ctx.snd.rc.EndSequence = 2

			before := ctx.addSegment(0, tcpip.MonotonicTime{})
			ctx.addSegment(1, test.xmitTime)
			// No sender produces this segment: it follows a segment that was
			// sent once, and claims to have been sent before it. It shows
			// whether the walk went past that segment.
			beyond := ctx.addSegment(2, tcpip.MonotonicTime{})

			if got := ctx.snd.rc.detectLoss(rackXmitTime.Add(2 * time.Millisecond)); got != 1 {
				t.Errorf("detectLoss got %d losses, want 1", got)
			}
			if !before.lost {
				t.Error("segment sent before the RACK segment not marked lost")
			}
			if beyond.lost {
				t.Error("detectLoss examined a segment past the first one sent after the RACK segment")
			}
		})
	}
}

// TestRACKDetectLossWalksPastRetransmissions checks that a retransmission,
// which says nothing about when the segments after it were sent, does not end
// loss detection.
func TestRACKDetectLossWalksPastRetransmissions(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, 0)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(time.Millisecond)
	ctx.snd.rc.EndSequence = 3

	// The first segment was retransmitted after the RACK segment was sent.
	retransmitted := ctx.addSegment(0, tcpip.MonotonicTime{}.Add(2*time.Millisecond))
	retransmitted.xmitCount = 2
	// A segment marked lost earlier and not yet retransmitted still counts.
	marked := ctx.addSegment(1, tcpip.MonotonicTime{})
	marked.lost = true
	original := ctx.addSegment(2, tcpip.MonotonicTime{})

	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}.Add(3 * time.Millisecond)); got != 2 {
		t.Errorf("detectLoss got %d losses, want 2", got)
	}
	if retransmitted.lost {
		t.Error("retransmission sent after the RACK segment marked lost")
	}
	if !marked.lost {
		t.Error("segment marked lost earlier no longer marked lost")
	}
	if !original.lost {
		t.Error("segment sent before the RACK segment not marked lost")
	}
}

// fullWalk reports what detectLoss has to find at rcvTime: the segments it
// has to mark lost, its result, and the longest wait for a segment that is
// not lost yet. It looks at every transmitted segment and changes nothing.
//
// +checklocks:ctx.snd.ep.mu
func (ctx *rackTestContext) fullWalk(rcvTime tcpip.MonotonicTime) (map[*segment]bool, int, time.Duration) {
	rc := &ctx.snd.rc
	lost := make(map[*segment]bool)
	numLost := 0
	var timeout time.Duration
	for seg := ctx.snd.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		if ctx.snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			lost[seg] = seg.lost
			continue
		}
		if seg.lost && seg.xmitCount == 1 {
			lost[seg] = true
			numLost++
			continue
		}
		lost[seg] = seg.lost
		endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
		if !seg.xmitTime.Before(rc.XmitTime) && (seg.xmitTime != rc.XmitTime || !endSeq.LessThan(rc.EndSequence)) {
			continue
		}
		if timeRemaining := seg.xmitTime.Sub(rcvTime) + rc.RTT + rc.ReoWnd; timeRemaining <= 0 {
			lost[seg] = true
			numLost++
		} else if timeRemaining > timeout {
			timeout = timeRemaining
		}
	}
	return lost, numLost, timeout
}

// TestRACKDetectLossMatchesFullWalk drives a sender's write list through
// random transmissions, retransmissions, splits, acknowledgments and
// scoreboard resets, and checks after each step that detectLoss finds what a
// walk over every transmitted segment finds.
func TestRACKDetectLossMatchesFullWalk(t *testing.T) {
	const (
		seeds = 200
		steps = 300
		tick  = 100 * time.Microsecond
	)
	for seed := int64(0); seed < seeds; seed++ {
		func() {
			rng := rand.New(rand.NewSource(seed))
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			ctx.snd.rc.ReoWnd = time.Duration(rng.Intn(4)) * tick

			// live holds the segments in the write list, in order.
			var live []*segment
			pick := func() *segment {
				if len(live) == 0 {
					return nil
				}
				return live[rng.Intn(len(live))]
			}
			deliver := func(seg *segment) {
				ack := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.Buffer{}, 0)
				defer ack.DecRef()
				ctx.snd.rc.update(seg, ack)
			}

			// Sequence numbers advance by two, which leaves room for the
			// second half of a split segment.
			var next seqnum.Value
			for step := 0; step < steps; step++ {
				switch op := rng.Intn(12); {
				case op < 4:
					// Send new data.
					live = append(live, ctx.addSegment(next, clock.NowMonotonic()))
					next += 2
				case op < 6:
					clock.Advance(time.Duration(1+rng.Intn(3)) * tick)
				case op == 10:
					// Split a segment, as splitSeg does: the second half
					// inherits when and how often the segment was sent.
					if len(live) == 0 {
						break
					}
					i := rng.Intn(len(live))
					seg := live[i]
					if seg.sequenceNumber%2 != 0 || (i+1 < len(live) && live[i+1].sequenceNumber == seg.sequenceNumber+1) {
						break
					}
					half := seg.clone()
					half.sequenceNumber++
					ctx.snd.writeList.InsertAfter(seg, half)
					ctx.segs = append(ctx.segs, half)
					live = append(live[:i+1], append([]*segment{half}, live[i+1:]...)...)
				case op == 11:
					// A retransmission timeout forgets what was selectively
					// acknowledged.
					ctx.snd.ep.scoreboard.Reset()
				case op < 7:
					// Retransmit, as sendSegment does.
					if seg := pick(); seg != nil {
						seg.xmitTime = clock.NowMonotonic()
						seg.xmitCount++
						seg.lost = false
					}
				case op < 9:
					// Selective acknowledgment.
					if seg := pick(); seg != nil && !ctx.snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
						deliver(seg)
						ctx.snd.ep.scoreboard.Insert(seg.sackBlock())
					}
				default:
					// Cumulative acknowledgment.
					for n := rng.Intn(3); n >= 0 && len(live) != 0; n-- {
						seg := live[0]
						if !ctx.snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
							deliver(seg)
						}
						ctx.snd.writeList.Remove(seg)
						live = live[1:]
					}
				}

				now := clock.NowMonotonic()
				wantLost, wantNumLost, wantTimeout := ctx.fullWalk(now)
				ctx.snd.reorderTimer.disable()
				if got := ctx.snd.rc.detectLoss(now); got != wantNumLost {
					t.Fatalf("seed %d step %d: detectLoss got %d losses, want %d", seed, step, got, wantNumLost)
				}
				for seg := ctx.snd.writeList.Front(); seg != nil; seg = seg.Next() {
					if seg.lost != wantLost[seg] {
						t.Fatalf("seed %d step %d: segment %d lost=%t, want %t", seed, step, seg.sequenceNumber, seg.lost, wantLost[seg])
					}
				}
				if got, want := ctx.snd.reorderTimer.enabled(), wantTimeout != 0; got != want {
					t.Fatalf("seed %d step %d: reorder timer enabled=%t, want %t", seed, step, got, want)
				}
				if got, want := ctx.snd.reorderTimer.target, now.Add(wantTimeout); wantTimeout != 0 && got != want {
					t.Fatalf("seed %d step %d: reorder timer target = %v, want %v", seed, step, got, want)
				}
			}
		}()
	}
}

// BenchmarkRACKDetectLoss measures loss detection on an ACK that finds no
// loss: the RACK segment has been acknowledged cumulatively, and everything in
// flight was sent after it.
func BenchmarkRACKDetectLoss(b *testing.B) {
	for _, inFlight := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("inFlight=%d", inFlight), func(b *testing.B) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(time.Millisecond)
			ctx.snd.rc.EndSequence = 1
			xmitTime := ctx.snd.rc.XmitTime
			for seq := 1; seq <= inFlight; seq++ {
				xmitTime = xmitTime.Add(time.Microsecond)
				ctx.addSegment(seqnum.Value(seq), xmitTime)
			}
			now := xmitTime.Add(time.Millisecond)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if got := ctx.snd.rc.detectLoss(now); got != 0 {
					b.Fatalf("detectLoss got %d losses, want 0", got)
				}
			}
		})
	}
}

func TestRACKDetectLossSteadyStateDoesNotAllocate(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, testClockResolution)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(testClockResolution)
	ctx.snd.rc.EndSequence = 2
	ctx.addSegment(0, tcpip.MonotonicTime{})
	ctx.snd.ep.mu.Unlock()

	// Exclude the existing timer facility's one-time initialization.
	ctx.snd.reorderTimer.enable(testClockResolution)
	allocs := testing.AllocsPerRun(1000, func() {
		ctx.snd.ep.mu.Lock()
		defer ctx.snd.ep.mu.Unlock()
		if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}.Add(testClockResolution)); got != 0 {
			panic("detectLoss unexpectedly reported loss")
		}
	})
	if allocs != 0 {
		t.Errorf("detectLoss allocated %v objects per call, want 0", allocs)
	}
}

func TestRACKZeroClockResolutionPreservesLossBoundary(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, 0)
	defer ctx.cleanup()
	ctx.snd.ep.mu.Lock()
	defer ctx.snd.ep.mu.Unlock()
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(time.Nanosecond)
	ctx.snd.rc.EndSequence = 2
	ctx.addSegment(0, tcpip.MonotonicTime{})

	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}); got != 1 {
		t.Fatalf("detectLoss at zero-resolution boundary got %d losses, want 1", got)
	}
}

// TestRACKPTODuration checks the PTO allowance for single- and multi-segment
// flights. It also checks the fallback before an RTT sample and the RTO cap.
func TestRACKPTODuration(t *testing.T) {
	for _, test := range []struct {
		name        string
		outstanding int
		srtt        time.Duration
		inited      bool
		rto         time.Duration
		want        time.Duration
	}{
		{"one-min-rtt", 1, time.Millisecond, true, 0, 202 * time.Millisecond},
		{"two-min-rtt", 2, time.Millisecond, true, 0, 4 * time.Millisecond},
		{"many-min-rtt", 42, time.Millisecond, true, 0, 4 * time.Millisecond},
		{"two-larger-rtt", 2, 5 * time.Millisecond, true, 0, 12 * time.Millisecond},
		{"two-wan-rtt", 2, 250 * time.Millisecond, true, 0, 502 * time.Millisecond},
		{"uninitialized-rtt", 2, 5 * time.Millisecond, false, 0, time.Second},
		{"zero-rtt", 2, 0, true, 0, time.Second},
		{"rto-before-pto", 2, time.Millisecond, true, 3 * time.Millisecond, 3 * time.Millisecond},
		{"rto-equals-pto", 2, time.Millisecond, true, 4 * time.Millisecond, 4 * time.Millisecond},
		{"rto-after-pto", 2, time.Millisecond, true, 5 * time.Millisecond, 4 * time.Millisecond},
		{"one-rto-cap", 1, time.Millisecond, true, 20 * time.Millisecond, 20 * time.Millisecond},
		{"fallback-rto-cap", 2, 0, false, 200 * time.Millisecond, 200 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			ctx := newRACKTestContext(clock, 0 /* resolution */)
			defer ctx.cleanup()
			ctx.snd.ep.mu.Lock()
			defer ctx.snd.ep.mu.Unlock()
			ctx.snd.Outstanding = test.outstanding
			ctx.snd.rtt.Lock()
			ctx.snd.rtt.TCPRTTState.SRTTInited = test.inited
			ctx.snd.rtt.TCPRTTState.SRTT = test.srtt
			ctx.snd.rtt.Unlock()
			var expirations int
			ctx.snd.probeTimer.init(clock, func() {
				if ctx.snd.probeTimer.checkExpiration() {
					expirations++
				}
			})
			defer ctx.snd.probeTimer.cleanup()
			ctx.snd.resendTimer.init(clock, func() {})
			defer ctx.snd.resendTimer.cleanup()
			if test.rto != 0 {
				// Some of the RTO has already elapsed. Bound the PTO by the
				// remaining time, not the RTO's original duration.
				ctx.snd.resendTimer.enable(test.rto + time.Millisecond)
			}
			clock.Advance(time.Millisecond)
			now := clock.NowMonotonic()
			ctx.snd.schedulePTO()
			if !ctx.snd.probeTimer.enabled() {
				t.Fatal("probe timer is not enabled")
			}
			if got := ctx.snd.probeTimer.target.Sub(now); got != test.want {
				t.Fatalf("PTO = %v, want %v", got, test.want)
			}
			if ctx.snd.resendTimer.enabled() {
				t.Error("RTO timer is still enabled alongside the probe timer")
			}
			clock.Advance(test.want - time.Nanosecond)
			if expirations != 0 {
				t.Fatalf("probe expired before PTO: %d expirations", expirations)
			}
			clock.Advance(time.Nanosecond)
			if expirations != 1 {
				t.Fatalf("probe expirations at PTO = %d, want 1", expirations)
			}
		})
	}
}
