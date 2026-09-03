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

package transport

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestSCMSenderBeforeSaveIdempotent verifies that calling beforeSave
// on an SCMSender whose host file descriptor is already closed (fd < 0)
// is a safe no-op and does not panic in fdnotifier.RemoveFD.
func TestSCMSenderBeforeSaveIdempotent(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer unix.Close(fds[1])

	q := &waiter.Queue{}
	ep, sysErr := NewSCMSender(fds[0], q, "test-addr")
	if sysErr != nil {
		unix.Close(fds[0])
		t.Fatalf("NewSCMSender failed: %v", sysErr)
	}
	if err := ep.Init(); err != nil {
		unix.Close(fds[0])
		t.Fatalf("Init failed: %v", err)
	}

	// First beforeSave cleans up the host FD and sets ep.fd = -1.
	ep.beforeSave()
	if ep.fd != -1 {
		t.Fatalf("after beforeSave, ep.fd = %d, want -1", ep.fd)
	}

	// Second beforeSave must be idempotent and must not panic on fdnotifier.RemoveFD(-1).
	ep.beforeSave()
}

// TestHostSenderClosedHostReadiness verifies that HostReadiness reports
// hangup and readable events when the host socket is closed (fd < 0) so that pollers
// are notified of EOF / disconnection.
func TestHostSenderClosedHostReadiness(t *testing.T) {
	c := &HostSender{fd: -1}

	mask := waiter.ReadableEvents | waiter.EventHUp | waiter.EventRdHUp | waiter.WritableEvents
	got := c.HostReadiness(mask)
	want := (waiter.ReadableEvents | waiter.EventHUp | waiter.EventRdHUp) & mask
	if got != want {
		t.Fatalf("HostReadiness(%v) when fd < 0 = %v, want %v", mask, got, want)
	}

	// Non-readable/non-hangup events like EventOut must return 0.
	if gotOut := c.HostReadiness(waiter.EventOut); gotOut != 0 {
		t.Errorf("HostReadiness(EventOut) when fd < 0 = %v, want 0", gotOut)
	}

	// Querying EventHUp explicitly must return EventHUp.
	if gotHup := c.HostReadiness(waiter.EventHUp); gotHup != waiter.EventHUp {
		t.Errorf("HostReadiness(EventHUp) when fd < 0 = %v, want %v", gotHup, waiter.EventHUp)
	}

	// Querying EventIn explicitly must return EventIn.
	if gotIn := c.HostReadiness(waiter.EventIn); gotIn != waiter.EventIn {
		t.Errorf("HostReadiness(EventIn) when fd < 0 = %v, want %v", gotIn, waiter.EventIn)
	}
}

// TestConnectionedEndpointClosedHostReadiness verifies that connectionedEndpoint.Readiness
// properly propagates hangup and readable events when backed by a closed HostSender.
func TestConnectionedEndpointClosedHostReadiness(t *testing.T) {
	c := &HostSender{fd: -1}
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			receiver: c,
			peer:     c,
		},
	}

	mask := waiter.EventIn | waiter.EventHUp | waiter.EventRdHUp | waiter.EventOut
	got := ep.Readiness(mask)
	want := (waiter.ReadableEvents | waiter.EventHUp | waiter.EventRdHUp) & mask
	if got != want {
		t.Fatalf("Readiness(%v) for closed host endpoint = %v, want %v", mask, got, want)
	}
}
