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

package time

import (
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

func TestReferenceClocks(t *testing.T) {
	for _, rawEnabled := range []bool{false, true} {
		clocks := NewReferenceClocks(rawEnabled)
		if got, want := clocks.MonotonicRawEnabled(), rawEnabled; got != want {
			t.Errorf("MonotonicRawEnabled() = %t, want %t", got, want)
		}
		for _, parked := range []bool{false, true, false} {
			if got, want := clocks.Update(parked), (UpdateResult{}); got != want {
				t.Errorf("Update(%t) = %+v, want %+v", parked, got, want)
			}
		}
		for _, id := range []ClockID{Monotonic, Realtime, MonotonicRaw, -1} {
			if id == -1 || (id == MonotonicRaw && !rawEnabled) {
				if _, err := clocks.GetTime(id); err != linuxerr.EINVAL {
					t.Errorf("GetTime(%v) error = %v, want %v", id, err, linuxerr.EINVAL)
				}
				continue
			}
			// Realtime may be stepped by the host between reads.
			if id == Realtime {
				if _, err := clocks.GetTime(id); err != nil {
					t.Fatal(err)
				}
				continue
			}
			before, err := clockGettime(id)
			if err != nil {
				t.Fatal(err)
			}
			got, err := clocks.GetTime(id)
			if err != nil {
				t.Fatal(err)
			}
			after, err := clockGettime(id)
			if err != nil {
				t.Fatal(err)
			}
			if got < int64(before) || got > int64(after) {
				t.Errorf("GetTime(%v) = %d, want in [%d, %d]", id, got, before, after)
			}
		}
	}
}
