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
)

// TestSetTSCOffset tests SetTSCOffset and the host-mode TSC domains. It must
// run in a single test, since the aliased pages are allocated once per process.
func TestSetTSCOffset(t *testing.T) {
	defer SetTSCOffset(0)

	if err := SetTSCOffset(0); err != nil {
		t.Fatalf("SetTSCOffset(0) got err %v, want nil", err)
	}
	if modeOffset.Load() != nil {
		t.Errorf("modeOffset is non-nil with a zero offset")
	}

	const offset = 1_000_000_000
	if err := SetTSCOffset(offset); err == nil {
		t.Errorf("SetTSCOffset(%d) before EnableGuestAliasedOffset got nil err, want error", offset)
	}
	if modeOffset.Load() != nil {
		t.Errorf("modeOffset is non-nil after a failed SetTSCOffset")
	}
	if got := TSCOffset(); got != 0 {
		t.Errorf("TSCOffset() after a failed SetTSCOffset got %d, want 0", got)
	}

	hostVA, guestVA, err := EnableGuestAliasedOffset()
	if err != nil {
		t.Fatalf("EnableGuestAliasedOffset() failed: %v", err)
	}
	if hostVA == 0 || guestVA == 0 || hostVA == guestVA {
		t.Fatalf("EnableGuestAliasedOffset() got (%#x, %#x), want distinct non-zero addresses", hostVA, guestVA)
	}
	if err := SetTSCOffset(offset); err != nil {
		t.Fatalf("SetTSCOffset(%d) got err %v, want nil", offset, err)
	}
	if got := TSCOffset(); got != offset {
		t.Errorf("TSCOffset() got %d, want %d", got, offset)
	}

	// In host mode, TSC is the raw counter plus the offset, and rawHostRdtsc
	// is the raw counter.
	before := Rdtsc()
	tsc := TSC()
	raw := rawHostRdtsc()
	after := Rdtsc()
	if tsc < before+offset || tsc > after+offset {
		t.Errorf("TSC() got %d, want in [%d, %d]", tsc, before+offset, after+offset)
	}
	if raw < before || raw > after {
		t.Errorf("rawHostRdtsc() got %d, want in [%d, %d]", raw, before, after)
	}

	if err := SetTSCOffset(0); err != nil {
		t.Fatalf("SetTSCOffset(0) got err %v, want nil", err)
	}
	if modeOffset.Load() != nil {
		t.Errorf("modeOffset is non-nil after resetting the offset")
	}
}

var benchSink TSCValue

func BenchmarkCycles(b *testing.B) {
	if _, _, err := EnableGuestAliasedOffset(); err != nil {
		b.Fatalf("EnableGuestAliasedOffset() failed: %v", err)
	}
	for _, bc := range []struct {
		name   string
		offset int64
	}{
		{"NoOffset", 0},
		{"Offset", 1_000_000_000},
	} {
		b.Run(bc.name, func(b *testing.B) {
			if err := SetTSCOffset(bc.offset); err != nil {
				b.Fatalf("SetTSCOffset(%d) failed: %v", bc.offset, err)
			}
			defer SetTSCOffset(0)
			var c tscCycleClock
			for i := 0; i < b.N; i++ {
				benchSink = c.Cycles()
			}
		})
	}
}
