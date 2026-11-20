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

package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

// newTestTimer lets tests observe the clock wake separately from the TCP
// handler that would run after acquiring the endpoint mutex.
func newTestTimer(clock tcpip.Clock, wake func()) timer {
	return timer{clock: clock, state: timerStateDisabled, callback: wake}
}

func TestCleanup(t *testing.T) {
	clock := faketime.NewManualClock()
	for _, armed := range []bool{false, true} {
		w := sleep.Waker{}
		tmr := newTestTimer(clock, w.Assert)
		if armed {
			tmr.enable(time.Second)
		}
		tmr.cleanup()
		tmr.disable()
		if !tmr.isUninitialized() {
			t.Errorf("timer still initialized after cleanup (armed=%t)", armed)
		}
		// A callback may already be waiting for the endpoint mutex.
		if tmr.consumeClockWake() {
			t.Errorf("wake after cleanup expired the timer (armed=%t)", armed)
		}
		clock.Advance(2 * time.Second)
		if w.IsAsserted() {
			t.Errorf("clock ran the cleaned-up timer (armed=%t)", armed)
		}
	}
}

func TestPostponedTimerExpiresOnce(t *testing.T) {
	clock := faketime.NewManualClock()
	var wakes, expirations int
	var tmr timer
	tmr = newTestTimer(clock, func() {
		wakes++
		if tmr.consumeClockWake() {
			expirations++
		}
	})
	tmr.enable(time.Second)
	tmr.enable(2 * time.Second)
	clock.Advance(time.Second)
	if wakes != 1 || expirations != 0 {
		t.Fatalf("at old deadline got %d wakes and %d expirations, want 1 and 0", wakes, expirations)
	}
	clock.Advance(time.Second)
	if wakes != 2 || expirations != 1 {
		t.Fatalf("at new deadline got %d wakes and %d expirations, want 2 and 1", wakes, expirations)
	}
	if tmr.consumeClockWake() {
		t.Fatal("second wake expired a disabled timer")
	}
}
