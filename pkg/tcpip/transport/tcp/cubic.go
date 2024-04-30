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
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// effectivelyInfinity is an initialization value used for round-trip times
// that are then set using min.  It is equal to approximately 100 years: large
// enough that it will always be greater than a real TCP round-trip time, and
// small enough that it fits in time.Duration.
const effectivelyInfinity = time.Duration(math.MaxInt64)

const (
	// RTT = round-trip time.

	// The delay increase sensitivity is determined by minRTTThresh and
	// maxRTTThresh. Smaller values of minRTTThresh may cause spurious exits
	// from slow start. Larger values of maxRTTThresh may result in slow start
	// not exiting until loss is encountered for connections on large RTT paths.
	minRTTThresh = 4 * time.Millisecond
	maxRTTThresh = 16 * time.Millisecond

	// minRTTDivisor is a fraction of RTT to compute the delay threshold. A
	// smaller value would mean a larger threshold and thus less sensitivity to
	// delay increase, and vice versa.
	minRTTDivisor = 8

	// nRTTSample is the minimum number of RTT samples in the round before
	// considering whether to exit the round due to increased RTT.
	nRTTSample = 8

	// ackDelta is the maximum time between ACKs for them to be considered part
	// of the same ACK Train during HyStart
	ackDelta = 2 * time.Millisecond
)

// cubicState stores the variables related to TCP CUBIC congestion
// control algorithm state.
//
// See: https://tools.ietf.org/html/rfc8312.
// +stateify savable
type cubicState struct {
	stack.TCPCubicState

	// numCongestionEvents tracks the number of congestion events since last
	// RTO.
	numCongestionEvents int

	s *sender
}

// newCubicCC returns a partially initialized cubic state with the constants
// beta and c set and t set to current time.
func newCubicCC(s *sender) *cubicState {
	now := s.ep.stack.Clock().NowMonotonic()
	return &cubicState{
		TCPCubicState: stack.TCPCubicState{
			T:    now,
			Beta: 0.7,
			C:    0.4,
			// By this point, the sender has initialized it's initial sequence
			// number.
			EndSeq:     s.SndNxt,
			LastRTT:    effectivelyInfinity,
			CurrRTT:    effectivelyInfinity,
			LastAck:    now,
			RoundStart: now,
		},
		s: s,
	}
}

// enterCongestionAvoidance is used to initialize cubic in cases where we exit
// SlowStart without a real congestion event taking place. This can happen when
// a connection goes back to slow start due to a retransmit and we exceed the
// previously lowered ssThresh without experiencing packet loss.
//
// Refer: https://tools.ietf.org/html/rfc8312#section-4.8
func (c *cubicState) enterCongestionAvoidance() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.7 &
	// https://tools.ietf.org/html/rfc8312#section-4.8
	if c.numCongestionEvents == 0 {
		c.K = 0
		c.T = c.s.ep.stack.Clock().NowMonotonic()
		c.WLastMax = c.WMax
		c.WMax = float64(c.s.SndCwnd)
	}
}

// updateHyStart tracks packet round-trip time (rtt) to find a safe threshold
// to exit slow start without triggering packet loss.  It updates the SSThresh
// when it does.
//
// Implementation of HyStart follows the algorithm from the Linux kernel, rather
// than RFC 9406 (https://www.rfc-editor.org/rfc/rfc9406.html). Briefly, the
// Linux kernel algorithm is based directly on the original HyStart paper
// (https://doi.org/10.1016/j.comnet.2011.01.014), and differs from the RFC in
// that two detection algorithms run in parallel ('ACK train' and 'Delay
// increase').  The RFC version includes only the latter algorithm and adds an
// intermediate phase called Conservative Slow Start, which is not implemented
// here.
func (c *cubicState) updateHyStart(rtt time.Duration) {
	if rtt < 0 {
		// negative indicates unknown
		return
	}
	now := c.s.ep.stack.Clock().NowMonotonic()
	if c.EndSeq.LessThan(c.s.SndUna) {
		c.beginHyStartRound(now)
	}
	// ACK train
	if now.Sub(c.LastAck) < ackDelta && // ensures acks are part of the same "train"
		c.LastRTT < effectivelyInfinity {
		c.LastAck = now
		if thresh := c.LastRTT / 2; now.Sub(c.RoundStart) > thresh {
			c.s.Ssthresh = c.s.SndCwnd
		}
	}

	// Delay increase
	c.CurrRTT = min(c.CurrRTT, rtt)
	c.SampleCount++

	if c.SampleCount >= nRTTSample && c.LastRTT < effectivelyInfinity {
		// i.e. LastRTT/minRTTDivisor, but clamped to minRTTThresh & maxRTTThresh
		thresh := max(
			minRTTThresh,
			min(maxRTTThresh, c.LastRTT/minRTTDivisor),
		)
		if c.CurrRTT >= (c.LastRTT + thresh) {
			// Triggered HyStart safe exit threshold
			c.s.Ssthresh = c.s.SndCwnd
		}
	}
}

func (c *cubicState) beginHyStartRound(now tcpip.MonotonicTime) {
	c.EndSeq = c.s.SndNxt
	c.SampleCount = 0
	c.LastRTT = c.CurrRTT
	c.CurrRTT = effectivelyInfinity
	c.LastAck = now
	c.RoundStart = now
}

// updateSlowStart will update the congestion window as per the slow-start
// algorithm used by NewReno. If after adjusting the congestion window we cross
// the ssThresh then it will return the number of packets that must be consumed
// in congestion avoidance mode.
func (c *cubicState) updateSlowStart(packetsAcked int) int {
	// Don't let the congestion window cross into the congestion
	// avoidance range.
	newcwnd := c.s.SndCwnd + packetsAcked
	enterCA := false
	if newcwnd >= c.s.Ssthresh {
		newcwnd = c.s.Ssthresh
		c.s.SndCAAckCount = 0
		enterCA = true
	}

	packetsAcked -= newcwnd - c.s.SndCwnd
	c.s.SndCwnd = newcwnd
	if enterCA {
		c.enterCongestionAvoidance()
	}
	return packetsAcked
}

// Update updates cubic's internal state variables. It must be called on every
// ACK received.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) Update(packetsAcked int, rtt time.Duration) {
	if c.s.Ssthresh == InitialSsthresh && c.s.SndCwnd < c.s.Ssthresh {
		c.updateHyStart(rtt)
	}
	if c.s.SndCwnd < c.s.Ssthresh {
		packetsAcked = c.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	} else {
		c.s.rtt.Lock()
		srtt := c.s.rtt.TCPRTTState.SRTT
		c.s.rtt.Unlock()
		c.s.SndCwnd = c.getCwnd(packetsAcked, c.s.SndCwnd, srtt)
	}
}

// cubicCwnd computes the CUBIC congestion window after t seconds from last
// congestion event.
func (c *cubicState) cubicCwnd(t float64) float64 {
	return c.C*math.Pow(t, 3.0) + c.WMax
}

// getCwnd returns the current congestion window as computed by CUBIC.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) getCwnd(packetsAcked, sndCwnd int, srtt time.Duration) int {
	elapsed := c.s.ep.stack.Clock().NowMonotonic().Sub(c.T)
	elapsedSeconds := elapsed.Seconds()

	// Compute the window as per Cubic after 'elapsed' time
	// since last congestion event.
	c.WC = c.cubicCwnd(elapsedSeconds - c.K)

	// Compute the TCP friendly estimate of the congestion window.
	c.WEst = c.WMax*c.Beta + (3.0*((1.0-c.Beta)/(1.0+c.Beta)))*(elapsedSeconds/srtt.Seconds())

	// Make sure in the TCP friendly region CUBIC performs at least
	// as well as Reno.
	if c.WC < c.WEst && float64(sndCwnd) < c.WEst {
		// TCP Friendly region of cubic.
		return int(c.WEst)
	}

	// In Concave/Convex region of CUBIC, calculate what CUBIC window
	// will be after 1 RTT and use that to grow congestion window
	// for every ack.
	tEst := (elapsed + srtt).Seconds()
	wtRtt := c.cubicCwnd(tEst - c.K)
	// As per 4.3 for each received ACK cwnd must be incremented
	// by (w_cubic(t+RTT) - cwnd/cwnd.
	cwnd := float64(sndCwnd)
	for i := 0; i < packetsAcked; i++ {
		// Concave/Convex regions of cubic have the same formulas.
		// See: https://tools.ietf.org/html/rfc8312#section-4.3
		cwnd += (wtRtt - cwnd) / cwnd
	}
	return int(cwnd)
}

// HandleLossDetected implements congestionControl.HandleLossDetected.
func (c *cubicState) HandleLossDetected() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.5
	c.numCongestionEvents++
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()
	c.reduceSlowStartThreshold()
}

// HandleRTOExpired implements congestionContrl.HandleRTOExpired.
func (c *cubicState) HandleRTOExpired() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.6
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.numCongestionEvents = 0
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()

	// We lost a packet, so reduce ssthresh.
	c.reduceSlowStartThreshold()

	// Reduce the congestion window to 1, i.e., enter slow-start. Per
	// RFC 5681, page 7, we must use 1 regardless of the value of the
	// initial congestion window.
	c.s.SndCwnd = 1
}

// fastConvergence implements the logic for Fast Convergence algorithm as
// described in https://tools.ietf.org/html/rfc8312#section-4.6.
func (c *cubicState) fastConvergence() {
	if c.WMax < c.WLastMax {
		c.WLastMax = c.WMax
		c.WMax = c.WMax * (1.0 + c.Beta) / 2.0
	} else {
		c.WLastMax = c.WMax
	}
	// Recompute k as wMax may have changed.
	c.K = math.Cbrt(c.WMax * (1 - c.Beta) / c.C)
}

// PostRecovery implements congestionControl.PostRecovery.
func (c *cubicState) PostRecovery() {
	c.T = c.s.ep.stack.Clock().NowMonotonic()
}

// reduceSlowStartThreshold returns new SsThresh as described in
// https://tools.ietf.org/html/rfc8312#section-4.7.
func (c *cubicState) reduceSlowStartThreshold() {
	c.s.Ssthresh = int(math.Max(float64(c.s.SndCwnd)*c.Beta, 2.0))
}
