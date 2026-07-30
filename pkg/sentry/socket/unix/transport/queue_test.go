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
	"gvisor.dev/gvisor/pkg/syserr"
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

// TestEnqueueRightsOwnership verifies ownership of SCM rights as a function
// of the success/error paths of the Enqueue call.
func TestEnqueueRightsOwnership(t *testing.T) {
	for _, test := range []struct {
		name string

		// limit and used are the initial capacity and occupancy of the queue.
		limit int64
		used  int64
		// closed closes the queue before enqueuing.
		closed bool

		data         [][]byte
		discardEmpty bool
		truncate     bool

		wantN           int64
		wantErr         *syserr.Error
		wantQueued      bool
		wantTransferred bool
	}{
		{
			name:            "whole message enqueued",
			limit:           8,
			data:            [][]byte{{42, 13, 37}},
			wantN:           3,
			wantQueued:      true,
			wantTransferred: true,
		},
		{
			name:            "partial enqueue",
			limit:           8,
			used:            6,
			data:            [][]byte{{42, 13, 37}},
			truncate:        true,
			wantN:           2,
			wantErr:         syserr.ErrWouldBlock,
			wantQueued:      true,
			wantTransferred: true,
		},
		{
			name:            "empty message discarded",
			limit:           8,
			data:            [][]byte{{}},
			discardEmpty:    true,
			wantTransferred: true,
		},
		{
			name:    "closed for send",
			limit:   8,
			closed:  true,
			data:    [][]byte{{42, 13, 37}},
			wantErr: syserr.ErrClosedForSend,
		},
		{
			name:    "message too long",
			limit:   2,
			data:    [][]byte{{42, 13, 37}},
			wantErr: syserr.ErrMessageTooLong,
		},
		{
			name:    "queue full",
			limit:   8,
			used:    8,
			data:    [][]byte{{42, 13, 37}},
			wantErr: syserr.ErrWouldBlock,
		},
		{
			name:     "queue full while truncating",
			limit:    8,
			used:     8,
			data:     [][]byte{{42, 13, 37}},
			truncate: true,
			wantErr:  syserr.ErrWouldBlock,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := &queue{limit: test.limit, used: test.used}
			if test.closed {
				q.Close()
			}

			refcount := 1
			rights := &mockRights{refs: []*int{&refcount}}
			caller := ControlMessages{Rights: rights}

			n, notify, err := q.Enqueue(nil, test.data, caller, Address{}, test.discardEmpty, test.truncate)
			if err != test.wantErr {
				t.Fatalf("Enqueue error = %v, want %v", err, test.wantErr)
			}
			if n != test.wantN {
				t.Fatalf("Enqueue wrote %d bytes, want %d", n, test.wantN)
			}
			if notify != test.wantQueued {
				t.Fatalf("Enqueue notify = %t, want %t", notify, test.wantQueued)
			}
			if gotRetained, wantRetained := len(rights.refs) != 0, !test.wantTransferred; gotRetained != wantRetained {
				t.Errorf("caller retains rights after Enqueue = %t, want %t", gotRetained, wantRetained)
			}
			wantRefcount := 1
			if test.wantTransferred && !test.wantQueued {
				wantRefcount = 0
			}
			if refcount != wantRefcount {
				t.Errorf("after Enqueue, refcount = %d, want %d", refcount, wantRefcount)
			}

			// Callers release their `ControlMessages` on the paths where
			// Enqueue does not take them. So the refcount should always be
			// unchanged (1) if enqueued, and 0 (decref'd) if not enqueued.
			// The patterns callers follow is to always call `Release`,
			// which should be a no-op in the enqueued case. So do that now.
			caller.Release(nil)
			if test.wantQueued && refcount != 1 {
				t.Errorf("caller release dropped a queued reference: refcount = %d, want 1", refcount)
			} else if !test.wantQueued && refcount != 0 {
				t.Errorf("caller release did not free the rights: refcount = %d, want 0", refcount)
			}

			if !test.wantQueued {
				if q.dataList.Front() != nil {
					t.Errorf("queue holds a message, want none")
				}
				return
			}

			// Draining the queue should finally decref down to zero.
			// In all cases, caller release + queue drain yields 0 refcount.
			e, _, err := q.Dequeue()
			if err != nil {
				t.Fatalf("Dequeue failed: %v", err)
			}
			e.Release(nil)
			if refcount != 0 {
				t.Errorf("after dequeue release, refcount = %d, want 0", refcount)
			}
		})
	}
}
