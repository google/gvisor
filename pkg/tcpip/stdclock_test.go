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

package tcpip

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state"
)

func TestStdClockResolution(t *testing.T) {
	// TCP compares transmit times and takes RTT samples from NowMonotonic, so
	// it must move in steps much smaller than a round trip to a local peer.
	// Without a high resolution counter, it mostly moves at the system timer
	// tick on Windows before Go 1.28: every 0.5 ms at best. Up to a few
	// hundred steps a second can still be shorter, so the test needs many
	// more fine steps. From Go 1.28, it checks the time package's own clock.
	const (
		fineStep  = 50 * time.Microsecond
		wantSteps = 10000
		timeout   = time.Second
	)
	c := NewStdClock()
	prev := c.NowMonotonic()
	steps := 0
	for deadline := time.Now().Add(timeout); steps < wantSteps && time.Now().Before(deadline); {
		now := c.NowMonotonic()
		if now.Before(prev) {
			t.Fatalf("NowMonotonic went backwards: %v after %v", now, prev)
		}
		if step := now.Sub(prev); step > 0 && step < fineStep {
			steps++
		}
		prev = now
	}
	if steps < wantSteps {
		t.Errorf("NowMonotonic took %d steps under %v in %v, want %d", steps, fineStep, timeout, wantSteps)
	}
}

func TestStdClockKeepsTime(t *testing.T) {
	c := NewStdClock()
	wallBefore := time.Now()
	start := c.NowMonotonic()
	time.Sleep(500 * time.Millisecond)
	end := c.NowMonotonic()
	wallAfter := time.Now()
	// The wall reads bracket the monotonic ones, so a pause of the test
	// between them cannot fail it. time.Now can be off by a 15.6 ms timer
	// tick on Windows.
	const slack = 40 * time.Millisecond
	if elapsed, wall := end.Sub(start), wallAfter.Sub(wallBefore); elapsed < 500*time.Millisecond-slack || elapsed > wall+slack {
		t.Errorf("NowMonotonic advanced %v during a 500ms sleep that took %v by time.Now", elapsed, wall)
	}
}

func TestStdClockRestore(t *testing.T) {
	clock := NewStdClock().(*stdClock)
	// Make the clock an hour old, so that the test fails if saving does not
	// take a reading or the restored clock does not resume from it.
	clock.baseTime = clock.baseTime.Add(-time.Hour)
	clock.baseCounter -= time.Hour
	start := time.Now()
	before := clock.NowMonotonic()
	var b bytes.Buffer
	if _, err := state.Save(t.Context(), &b, clock); err != nil {
		t.Fatal(err)
	}
	var restored stdClock
	if _, err := state.Load(t.Context(), &b, &restored); err != nil {
		t.Fatal(err)
	}
	// The restored clock cannot have advanced by more than the time spent
	// saving and loading it. time.Since can be a 15.6 ms timer tick short on
	// Windows.
	got := restored.NowMonotonic().Sub(before)
	if maxElapsed := time.Since(start) + 20*time.Millisecond; got < 0 || got > maxElapsed {
		t.Errorf("restored clock advanced %v, want [0, %v]", got, maxElapsed)
	}
}
