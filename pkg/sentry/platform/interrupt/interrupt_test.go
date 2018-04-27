// Copyright 2018 Google Inc.
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
)

type countingReceiver struct {
	interrupts int
}

// NotifyInterrupt implements Receiver.NotifyInterrupt.
func (r *countingReceiver) NotifyInterrupt() {
	r.interrupts++
}

func TestSingleInterruptBeforeEnable(t *testing.T) {
	var (
		f Forwarder
		r countingReceiver
	)
	f.NotifyInterrupt()
	// The interrupt should cause the first Enable to fail.
	if f.Enable(&r) {
		f.Disable()
		t.Fatalf("Enable: got true, wanted false")
	}
	// The failing Enable "acknowledges" the interrupt, allowing future Enables
	// to succeed.
	if !f.Enable(&r) {
		t.Fatalf("Enable: got false, wanted true")
	}
	f.Disable()
}

func TestMultipleInterruptsBeforeEnable(t *testing.T) {
	var (
		f Forwarder
		r countingReceiver
	)
	f.NotifyInterrupt()
	f.NotifyInterrupt()
	// The interrupts should cause the first Enable to fail.
	if f.Enable(&r) {
		f.Disable()
		t.Fatalf("Enable: got true, wanted false")
	}
	// Interrupts are deduplicated while the Forwarder is disabled, so the
	// failing Enable "acknowledges" all interrupts, allowing future Enables to
	// succeed.
	if !f.Enable(&r) {
		t.Fatalf("Enable: got false, wanted true")
	}
	f.Disable()
}

func TestSingleInterruptAfterEnable(t *testing.T) {
	var (
		f Forwarder
		r countingReceiver
	)
	if !f.Enable(&r) {
		t.Fatalf("Enable: got false, wanted true")
	}
	defer f.Disable()
	f.NotifyInterrupt()
	if r.interrupts != 1 {
		t.Errorf("interrupts: got %d, wanted 1", r.interrupts)
	}
}

func TestMultipleInterruptsAfterEnable(t *testing.T) {
	var (
		f Forwarder
		r countingReceiver
	)
	if !f.Enable(&r) {
		t.Fatalf("Enable: got false, wanted true")
	}
	defer f.Disable()
	f.NotifyInterrupt()
	f.NotifyInterrupt()
	if r.interrupts != 2 {
		t.Errorf("interrupts: got %d, wanted 2", r.interrupts)
	}
}
