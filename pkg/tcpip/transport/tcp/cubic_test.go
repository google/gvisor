// Copyright 2024 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestHyStartAckTrainOK tests that HyStart triggers early exit from slow start
// if ACKs come in the same round for longer than RTT/2.
func TestHyStartAckTrainOK(t *testing.T) {
	fClock := faketime.NewManualClock()
	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              fClock,
	}
	s := stack.New(stackOpts)
	ep := &Endpoint{
		stack: s,
		cc:    tcpip.CongestionControlOption("cubic"),
	}
	iss := seqnum.Value(0)
	snd := &sender{
		ep: ep,
		TCPSenderState: TCPSenderState{
			SndUna:   iss + 1,
			SndNxt:   iss + 1,
			Ssthresh: InitialSsthresh,
		},
	}
	snd.ep.mu.Lock()
	uut := newCubicCC(snd)
	snd.ep.mu.Unlock()
	snd.cc = uut

	if uut.LastRTT != effectivelyInfinity {
		t.Fatal()
	}
	if uut.CurrRTT != effectivelyInfinity {
		t.Fatal()
	}

	d0 := 4 * time.Millisecond
	uut.s.ep.mu.Lock()
	defer uut.s.ep.mu.Unlock()
	uut.updateHyStart(d0)
	if uut.CurrRTT != d0 {
		t.Fatal()
	}
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("HyStart should not be triggered")
	}

	// Move SndNext and SndUna to advance to a new round.
	snd.SndNxt = snd.SndNxt.Add(2000)
	snd.SndUna = snd.SndUna.Add(1000)
	fClock.Advance(d0)
	r1ExpectedStart := fClock.NowMonotonic()

	d1 := 5 * time.Millisecond
	uut.updateHyStart(d1)
	if uut.LastRTT != d0 {
		t.Fatal()
	}
	if uut.CurrRTT != d1 {
		t.Fatal()
	}
	if uut.RoundStart != r1ExpectedStart {
		t.Fatal()
	}

	// Still in round after RTT/2 (2ms) triggers HyStart.  Note that HyStart
	// will ignore ACKs spaced more than 2ms apart, so we send one per ms 3
	// times.
	for range 2 {
		fClock.Advance(time.Millisecond)
		uut.updateHyStart(d1)
		if snd.Ssthresh != InitialSsthresh {
			t.Fatal("HyStart should not be triggered")
		}
		if uut.LastAck != fClock.NowMonotonic() {
			t.Fatal()
		}
	}

	// 3 ms---triggers HyStart setting Ssthresh
	fClock.Advance(time.Millisecond)
	uut.updateHyStart(d1)
	if snd.Ssthresh == InitialSsthresh {
		t.Fatal("HyStart SHOULD be triggered")
	}
}

// TestHyStartAckTrainTooSpread tests that ACKs that are more than 2ms apart
// are ignored for purposes of triggering HyStart via the ACK train mechanism.
func TestHyStartAckTrainTooSpread(t *testing.T) {
	fClock := faketime.NewManualClock()
	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              fClock,
	}
	s := stack.New(stackOpts)
	ep := &Endpoint{
		stack: s,
		cc:    tcpip.CongestionControlOption("cubic"),
	}
	iss := seqnum.Value(0)
	snd := &sender{
		ep: ep,
		TCPSenderState: TCPSenderState{
			SndUna:   iss + 1,
			SndNxt:   iss + 1,
			Ssthresh: InitialSsthresh,
		},
	}
	snd.ep.mu.Lock()
	uut := newCubicCC(snd)
	snd.ep.mu.Unlock()
	snd.cc = uut

	if uut.LastRTT != effectivelyInfinity {
		t.Fatal()
	}
	if uut.CurrRTT != effectivelyInfinity {
		t.Fatal()
	}
	d0 := 4 * time.Millisecond
	uut.s.ep.mu.Lock()
	defer uut.s.ep.mu.Unlock()
	uut.updateHyStart(d0)
	if uut.CurrRTT != d0 {
		t.Fatal()
	}
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("HyStart should not be triggered")
	}

	// Move SndNext and SndUna to advance to a new round.
	snd.SndNxt = snd.SndNxt.Add(2000)
	snd.SndUna = snd.SndUna.Add(1000)
	fClock.Advance(d0)
	r1ExpectedStart := fClock.NowMonotonic()

	d1 := 5 * time.Millisecond
	uut.updateHyStart(d1)
	if uut.LastRTT != d0 {
		t.Fatal()
	}
	if uut.CurrRTT != d1 {
		t.Fatal()
	}
	if uut.RoundStart != r1ExpectedStart {
		t.Fatal()
	}

	// HyStart will ignore ACKs spaced more than 2ms apart
	fClock.Advance(3 * time.Millisecond)
	uut.updateHyStart(d1)
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("HyStart should not be triggered")
	}
	if uut.LastAck != r1ExpectedStart {
		t.Fatal("Should ignore ACK 3ms later")
	}
}

// TestHyStartDelayOK tests that HyStart triggers early exit from slow start
// if RTT exceeds previous round by at least minRTTThresh.
func TestHyStartDelayOK(t *testing.T) {
	fClock := faketime.NewManualClock()
	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              fClock,
	}
	s := stack.New(stackOpts)
	ep := &Endpoint{
		stack: s,
		cc:    tcpip.CongestionControlOption("cubic"),
	}
	iss := seqnum.Value(0)
	snd := &sender{
		ep: ep,
		TCPSenderState: TCPSenderState{
			SndUna:   iss + 1,
			SndNxt:   iss + 1,
			Ssthresh: InitialSsthresh,
		},
	}
	snd.ep.mu.Lock()
	uut := newCubicCC(snd)
	snd.ep.mu.Unlock()
	snd.cc = uut

	d0 := 4 * time.Millisecond
	uut.s.ep.mu.Lock()
	defer uut.s.ep.mu.Unlock()
	uut.updateHyStart(d0)

	// Move SndNext and SndUna to advance to a new round.
	snd.SndNxt = snd.SndNxt.Add(2000)
	snd.SndUna = snd.SndUna.Add(1000)
	fClock.Advance(d0)

	d1 := d0 + minRTTThresh

	// Delay detection requires at least nRTTSample measurements.
	for i := uint(1); i < nRTTSample; i++ {
		uut.updateHyStart(d1)
		if uut.SampleCount != i {
			t.Fatal()
		}
	}
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("triggered with fewer than nRTTSample measurements")
	}
	uut.updateHyStart(d1)
	if snd.Ssthresh == InitialSsthresh {
		t.Fatal("didn't trigger SS exit")
	}
}

// TestHyStartDelay_BelowThresh tests that HyStart doesn't trigger early exit
// from slow start if at least one RTT measurement is below threshold.
func TestHyStartDelay_BelowThresh(t *testing.T) {
	fClock := faketime.NewManualClock()
	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              fClock,
	}
	s := stack.New(stackOpts)
	ep := &Endpoint{
		stack: s,
		cc:    tcpip.CongestionControlOption("cubic"),
	}
	iss := seqnum.Value(0)
	snd := &sender{
		ep: ep,
		TCPSenderState: TCPSenderState{
			SndUna:   iss + 1,
			SndNxt:   iss + 1,
			Ssthresh: InitialSsthresh,
		},
	}
	snd.ep.mu.Lock()
	uut := newCubicCC(snd)
	snd.ep.mu.Unlock()
	snd.cc = uut

	d0 := 4 * time.Millisecond
	uut.s.ep.mu.Lock()
	defer uut.s.ep.mu.Unlock()
	uut.updateHyStart(d0)

	// Move SndNext and SndUna to advance to a new round.
	snd.SndNxt = snd.SndNxt.Add(2000)
	snd.SndUna = snd.SndUna.Add(1000)
	fClock.Advance(d0)

	d1 := d0 + minRTTThresh

	// Delay detection requires at least nRTTSample measurements.
	for i := uint(1); i < nRTTSample; i++ {
		uut.updateHyStart(d1)
		if uut.SampleCount != i {
			t.Fatal()
		}
	}
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("triggered with fewer than nRTTSample measurements")
	}
	uut.updateHyStart(d1 - time.Millisecond)
	if snd.Ssthresh != InitialSsthresh {
		t.Fatal("triggered with a measurement under threshold")
	}
}
