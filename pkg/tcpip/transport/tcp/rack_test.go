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

func TestRACKEqualTransmitTimeOrdersByEndSequence(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, 0)
	defer ctx.cleanup()
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

func TestRACKDetectLossSteadyStateDoesNotAllocate(t *testing.T) {
	clock := faketime.NewManualClock()
	ctx := newRACKTestContext(clock, testClockResolution)
	defer ctx.cleanup()
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(testClockResolution)
	ctx.snd.rc.EndSequence = 2
	ctx.addSegment(0, tcpip.MonotonicTime{})

	// Exclude the existing timer facility's one-time initialization.
	ctx.snd.reorderTimer.enable(testClockResolution)
	allocs := testing.AllocsPerRun(1000, func() {
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
	ctx.snd.rc.XmitTime = tcpip.MonotonicTime{}.Add(time.Nanosecond)
	ctx.snd.rc.EndSequence = 2
	ctx.addSegment(0, tcpip.MonotonicTime{})

	if got := ctx.snd.rc.detectLoss(tcpip.MonotonicTime{}); got != 1 {
		t.Fatalf("detectLoss at zero-resolution boundary got %d losses, want 1", got)
	}
}
