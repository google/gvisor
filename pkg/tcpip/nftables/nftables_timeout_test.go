// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

// TestSetTimeoutBackend verifies exact-match membership and per-element expiry
// for timeout sets.
func TestSetTimeoutBackend(t *testing.T) {
	clk := faketime.NewManualClock()
	b := &setTimeoutBackend{keyLen: 4, clock: clk, m: make(map[string]setTimeoutEntry)}

	// 1.1.1.1 expires after 1000ms; 2.2.2.2 has no timeout (permanent).
	if _, err := b.Add(&nftSetElem{startKey: []byte{1, 1, 1, 1}, timeout: 1000}, 0); err != nil {
		t.Fatalf("Add timed element: %v", err)
	}
	if _, err := b.Add(&nftSetElem{startKey: []byte{2, 2, 2, 2}}, 1); err != nil {
		t.Fatalf("Add permanent element: %v", err)
	}

	if b.Find([]byte{1, 1, 1, 1}) == -1 {
		t.Error("1.1.1.1 should be a member before expiry")
	}
	clk.Advance(500 * time.Millisecond)
	if b.Find([]byte{1, 1, 1, 1}) == -1 {
		t.Error("1.1.1.1 should still be a member at 500ms (1000ms timeout)")
	}
	clk.Advance(600 * time.Millisecond) // now 1100ms > 1000ms.
	if b.Find([]byte{1, 1, 1, 1}) != -1 {
		t.Error("1.1.1.1 should have expired after its 1000ms timeout")
	}
	if b.Find([]byte{2, 2, 2, 2}) == -1 {
		t.Error("2.2.2.2 (no timeout) should remain a member")
	}
	// A non-member key is never matched.
	if b.Find([]byte{9, 9, 9, 9}) != -1 {
		t.Error("9.9.9.9 was never added and must not match")
	}
}
