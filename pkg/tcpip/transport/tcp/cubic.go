// Copyright 2018 Google LLC
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
)

// cubicState stores the variables related to TCP CUBIC congestion
// control algorithm state.
//
// See: https://tools.ietf.org/html/rfc8312.
type cubicState struct {
	// wLastMax is the previous wMax value.
	wLastMax float64

	// wMax is the value of the congestion window at the
	// time of last congestion event.
	wMax float64

	// t denotes the time when the current congestion avoidance
	// was entered.
	t time.Time

	// numCongestionEvents tracks the number of congestion events since last
	// RTO.
	numCongestionEvents int

	// c is the cubic constant as specified in RFC8312. It's fixed at 0.4 as
	// per RFC.
	c float64

	// k is the time period that the above function takes to increase the
	// current window size to W_max if there are no further congestion
	// events and is calculated using the following equation:
	//
	// K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
	k float64

	// beta is the CUBIC multiplication decrease factor. that is, when a
	// congestion event is detected, CUBIC reduces its cwnd to
	// W_cubic(0)=W_max*beta_cubic.
	beta float64

	// wC is window computed by CUBIC at time t. It's calculated using the
	// formula:
	//
	//  W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
	wC float64

	// wEst is the window computed by CUBIC at time t+RTT i.e
	// W_cubic(t+RTT).
	wEst float64

	s *sender
}

// newCubicCC returns a partially initialized cubic state with the constants
// beta and c set and t set to current time.
func newCubicCC(s *sender) *cubicState {
	return &cubicState{
		t:    time.Now(),
		beta: 0.7,
		c:    0.4,
		s:    s,
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
		c.k = 0
		c.t = time.Now()
		c.wLastMax = c.wMax
		c.wMax = float64(c.s.sndCwnd)
	}
}

// updateSlowStart will update the congestion window as per the slow-start
// algorithm used by NewReno. If after adjusting the congestion window we cross
// the ssThresh then it will return the number of packets that must be consumed
// in congestion avoidance mode.
func (c *cubicState) updateSlowStart(packetsAcked int) int {
	// Don't let the congestion window cross into the congestion
	// avoidance range.
	newcwnd := c.s.sndCwnd + packetsAcked
	enterCA := false
	if newcwnd >= c.s.sndSsthresh {
		newcwnd = c.s.sndSsthresh
		c.s.sndCAAckCount = 0
		enterCA = true
	}

	packetsAcked -= newcwnd - c.s.sndCwnd
	c.s.sndCwnd = newcwnd
	if enterCA {
		c.enterCongestionAvoidance()
	}
	return packetsAcked
}

// Update updates cubic's internal state variables. It must be called on every
// ACK received.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) Update(packetsAcked int) {
	if c.s.sndCwnd < c.s.sndSsthresh {
		packetsAcked = c.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	} else {
		c.s.rtt.Lock()
		srtt := c.s.rtt.srtt
		c.s.rtt.Unlock()
		c.s.sndCwnd = c.getCwnd(packetsAcked, c.s.sndCwnd, srtt)
	}
}

// cubicCwnd computes the CUBIC congestion window after t seconds from last
// congestion event.
func (c *cubicState) cubicCwnd(t float64) float64 {
	return c.c*math.Pow(t, 3.0) + c.wMax
}

// getCwnd returns the current congestion window as computed by CUBIC.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) getCwnd(packetsAcked, sndCwnd int, srtt time.Duration) int {
	elapsed := time.Since(c.t).Seconds()

	// Compute the window as per Cubic after 'elapsed' time
	// since last congestion event.
	c.wC = c.cubicCwnd(elapsed - c.k)

	// Compute the TCP friendly estimate of the congestion window.
	c.wEst = c.wMax*c.beta + (3.0*((1.0-c.beta)/(1.0+c.beta)))*(elapsed/srtt.Seconds())

	// Make sure in the TCP friendly region CUBIC performs at least
	// as well as Reno.
	if c.wC < c.wEst && float64(sndCwnd) < c.wEst {
		// TCP Friendly region of cubic.
		return int(c.wEst)
	}

	// In Concave/Convex region of CUBIC, calculate what CUBIC window
	// will be after 1 RTT and use that to grow congestion window
	// for every ack.
	tEst := (time.Since(c.t) + srtt).Seconds()
	wtRtt := c.cubicCwnd(tEst - c.k)
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

// HandleNDupAcks implements congestionControl.HandleNDupAcks.
func (c *cubicState) HandleNDupAcks() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.5
	c.numCongestionEvents++
	c.t = time.Now()
	c.wLastMax = c.wMax
	c.wMax = float64(c.s.sndCwnd)

	c.fastConvergence()
	c.reduceSlowStartThreshold()
}

// HandleRTOExpired implements congestionContrl.HandleRTOExpired.
func (c *cubicState) HandleRTOExpired() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.6
	c.t = time.Now()
	c.numCongestionEvents = 0
	c.wLastMax = c.wMax
	c.wMax = float64(c.s.sndCwnd)

	c.fastConvergence()

	// We lost a packet, so reduce ssthresh.
	c.reduceSlowStartThreshold()

	// Reduce the congestion window to 1, i.e., enter slow-start. Per
	// RFC 5681, page 7, we must use 1 regardless of the value of the
	// initial congestion window.
	c.s.sndCwnd = 1
}

// fastConvergence implements the logic for Fast Convergence algorithm as
// described in https://tools.ietf.org/html/rfc8312#section-4.6.
func (c *cubicState) fastConvergence() {
	if c.wMax < c.wLastMax {
		c.wLastMax = c.wMax
		c.wMax = c.wMax * (1.0 + c.beta) / 2.0
	} else {
		c.wLastMax = c.wMax
	}
	// Recompute k as wMax may have changed.
	c.k = math.Cbrt(c.wMax * (1 - c.beta) / c.c)
}

// PostRecovery implemements congestionControl.PostRecovery.
func (c *cubicState) PostRecovery() {
	c.t = time.Now()
}

// reduceSlowStartThreshold returns new SsThresh as described in
// https://tools.ietf.org/html/rfc8312#section-4.7.
func (c *cubicState) reduceSlowStartThreshold() {
	c.s.sndSsthresh = int(math.Max(float64(c.s.sndCwnd)*c.beta, 2.0))
}
