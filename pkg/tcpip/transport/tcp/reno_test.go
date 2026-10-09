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

package tcp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func newRenoInCongestionAvoidance(cwnd int) *renoState {
	return newRenoCC(&sender{
		ep: &Endpoint{},
		TCPSenderState: TCPSenderState{
			SndCwnd:  cwnd,
			Ssthresh: cwnd,
		},
	})
}

func TestRenoCongestionAvoidanceConsumesACKCredit(t *testing.T) {
	// Two segments are enough to distinguish credit for the old window from
	// credit for the larger window. There is no slow start in this test.
	r := newRenoInCongestionAvoidance(2)
	r.s.ep.mu.Lock()
	defer r.s.ep.mu.Unlock()

	// Acknowledge the entire two-segment window: grow to three, spending both
	// segment credits. Neither credit may count toward the next increase.
	r.Update(2, 0, tcpip.MonotonicTime{})
	if got, want := r.s.SndCwnd, 3; got != want {
		t.Fatalf("cwnd after ACKing the two-segment window = %d, want %d", got, want)
	}
	r.Update(1, 0, tcpip.MonotonicTime{})
	if got, want := r.s.SndCwnd, 3; got != want {
		t.Fatalf("one ACK for the new three-segment window grew cwnd to %d, want %d", got, want)
	}
}

func TestRenoCongestionAvoidanceCarriesExcessACKCredit(t *testing.T) {
	r := newRenoInCongestionAvoidance(2)
	r.s.ep.mu.Lock()
	defer r.s.ep.mu.Unlock()

	// One acknowledged segment cannot grow the two-segment window. An ACK for two
	// more segments then spends two credits on growth and leaves one over.
	r.Update(1, 0, tcpip.MonotonicTime{})
	if got, want := r.s.SndCwnd, 2; got != want {
		t.Fatalf("cwnd after ACKing half the window = %d, want %d", got, want)
	}
	r.Update(2, 0, tcpip.MonotonicTime{})
	if got, want := r.s.SndCwnd, 3; got != want {
		t.Fatalf("cwnd after crossing the two-segment threshold = %d, want %d", got, want)
	}

	// The carried credit plus two newly acknowledged segments complete the next
	// three-segment window. Discarding the credit would leave cwnd at three.
	r.Update(2, 0, tcpip.MonotonicTime{})
	if got, want := r.s.SndCwnd, 4; got != want {
		t.Fatalf("cwnd after one carried credit and two acknowledged segments = %d, want %d", got, want)
	}
}
