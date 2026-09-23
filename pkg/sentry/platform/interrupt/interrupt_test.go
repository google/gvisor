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

package interrupt

import (
	"testing"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

type countingReceiver struct {
	interrupts atomicbitops.Uint64
}

// NotifyInterrupt implements Receiver.NotifyInterrupt.
func (r *countingReceiver) NotifyInterrupt() {
	r.interrupts.Add(1)
}

func TestSingleInterruptBeforeEnable(t *testing.T) {
	var r countingReceiver
	f := Forwarder{Dst: &r}
	f.NotifyInterrupt()
	// The interrupt should cause the first Enable to fail.
	if f.Enable() {
		f.Disable()
		t.Fatalf("Enable: got true, wanted false")
	}
	// The failing Enable "acknowledges" the interrupt, allowing future Enables
	// to succeed.
	if !f.Enable() {
		t.Fatalf("Enable: got false, wanted true")
	}
	f.Disable()
}

func TestMultipleInterruptsBeforeEnable(t *testing.T) {
	var r countingReceiver
	f := Forwarder{Dst: &r}
	f.NotifyInterrupt()
	f.NotifyInterrupt()
	// The interrupts should cause the first Enable to fail.
	if f.Enable() {
		f.Disable()
		t.Fatalf("Enable: got true, wanted false")
	}
	// Interrupts are deduplicated while the Forwarder is disabled, so the
	// failing Enable "acknowledges" all interrupts, allowing future Enables to
	// succeed.
	if !f.Enable() {
		t.Fatalf("Enable: got false, wanted true")
	}
	f.Disable()
}

func TestSingleInterruptAfterEnable(t *testing.T) {
	var r countingReceiver
	f := Forwarder{Dst: &r}
	if !f.Enable() {
		t.Fatalf("Enable: got false, wanted true")
	}
	defer f.Disable()
	f.NotifyInterrupt()
	if got := r.interrupts.Load(); got != 1 {
		t.Errorf("interrupts: got %d, wanted 1", got)
	}
}

func TestMultipleInterruptsAfterEnable(t *testing.T) {
	var r countingReceiver
	f := Forwarder{Dst: &r}
	if !f.Enable() {
		t.Fatalf("Enable: got false, wanted true")
	}
	defer f.Disable()
	f.NotifyInterrupt()
	f.NotifyInterrupt()
	if got := r.interrupts.Load(); got != 2 {
		t.Errorf("interrupts: got %d, wanted 2", got)
	}
}

// TestInterruptRacingWithEnable checks that an interrupt racing with
// `Enable`/`Disable` is not lost and not duplicated.
func TestInterruptRacingWithEnable(t *testing.T) {
	var r countingReceiver
	f := Forwarder{Dst: &r}
	notify := make(chan struct{})
	notified := make(chan struct{})
	done := make(chan struct{})
	defer func() {
		close(notify)
		<-done // Wait for the below goroutine to exit.
	}()
	go func() {
		defer close(done)
		for range notify {
			f.NotifyInterrupt()
			notified <- struct{}{}
		}
	}()
	for i := 0; i < 10000; i++ {
		before := r.interrupts.Load()
		// The notification races with the Enable below.
		notify <- struct{}{}
		consumed := !f.Enable()
		if !consumed {
			f.Disable()
		}
		<-notified
		// Back to stability. Check what happened.
		interruptsHandled := 0
		if r.interrupts.Load() != before {
			// Interrupt received.
			interruptsHandled++
		}
		if consumed {
			// Couldn't `Enable` earlier, which the caller of Enable is expected to handle as an interrupt.
			interruptsHandled++
		}
		if !f.Enable() {
			interruptsHandled++ // Pending interrupt left behind, consumed now.
		} else {
			f.Disable()
		}
		if interruptsHandled != 1 {
			t.Fatalf("iteration %d: interrupt had %d handling events, wanted exactly 1", i, interruptsHandled)
		}
	}
}
