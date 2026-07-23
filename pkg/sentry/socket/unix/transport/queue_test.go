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

	"gvisor.dev/gvisor/pkg/context"
)

// mockRights is a test RightsControlMessage that models refcounted FDs as a
// set of counters.
type mockRights struct {
	refs []*int
}

// Clone implements RightsControlMessage.Clone.
func (m *mockRights) Clone() RightsControlMessage {
	nrefs := append([]*int(nil), m.refs...)
	for _, r := range nrefs {
		*r++
	}
	return &mockRights{refs: nrefs}
}

// TransferRights implements RightsControlMessage.TransferRights.
func (m *mockRights) TransferRights() RightsControlMessage {
	nrefs := append([]*int(nil), m.refs...)
	m.refs = nil
	return &mockRights{refs: nrefs}
}

// Release implements RightsControlMessage.Release.
func (m *mockRights) Release(ctx context.Context) {
	for _, r := range m.refs {
		*r--
	}
	m.refs = nil
}

// TestEnqueueTransfersRightsOwnership verifies that committing a message to the
// queue moves SCM rights out of the caller's ControlMessages and into the queued
// message.
func TestEnqueueTransfersRightsOwnership(t *testing.T) {
	q := &queue{limit: 8}

	refcount := 1
	original := &mockRights{refs: []*int{&refcount}}
	caller := ControlMessages{Rights: original}

	n, notify, err := q.Enqueue(nil, [][]byte{{42, 13, 37}}, caller, Address{}, false, false)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	if n != 3 {
		t.Errorf("Enqueue wrote %d bytes, want 3", n)
	}
	if !notify {
		t.Errorf("Enqueue notify = false, want true")
	}

	// Ownership must have moved out.
	if got := len(original.refs); got != 0 {
		t.Errorf("caller still owns %d rights after enqueue, want 0", got)
	}

	// Releasing the `ControlMessages` now must be a no-op.
	caller.Release(nil)
	if refcount != 1 {
		t.Errorf("caller release dropped a queued reference: refcount = %d, want 1", refcount)
	}

	// Draining the queue is what actually releases the rights.
	e, _, err := q.Dequeue()
	if err != nil {
		t.Fatalf("Dequeue failed: %v", err)
	}
	e.Release(nil)
	if refcount != 0 {
		t.Errorf("after dequeue release, refcount = %d, want 0", refcount)
	}
}
