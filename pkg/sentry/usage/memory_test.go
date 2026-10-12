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

package usage

import "testing"

func TestPeakPerCg(t *testing.T) {
	m := &MemoryLocked{
		RTMemoryStats:     &RTMemoryStats{},
		MemCgIDToMemStats: make(map[uint32]*memoryStats),
	}
	const cg = 1
	const mib = 1 << 20

	if got := m.PeakPerCg(cg); got != 0 {
		t.Errorf("PeakPerCg(%d) with no usage = %d, want 0", cg, got)
	}

	m.Inc(3*mib, Anonymous, cg)
	if got, want := m.PeakPerCg(cg), uint64(3*mib); got != want {
		t.Errorf("PeakPerCg(%d) after committing anonymous memory = %d, want %d", cg, got, want)
	}

	m.Inc(1*mib, Mapped, cg)
	if got, want := m.PeakPerCg(cg), uint64(4*mib); got != want {
		t.Errorf("PeakPerCg(%d) after mapping host memory = %d, want %d", cg, got, want)
	}

	// Freed pages become System waste until released; the peak is retained.
	m.Move(3*mib, System, Anonymous, cg)
	if got, want := m.PeakPerCg(cg), uint64(4*mib); got != want {
		t.Errorf("PeakPerCg(%d) after freeing anonymous memory = %d, want %d", cg, got, want)
	}

	// Waste does not count towards the peak.
	m.Inc(2*mib, Tmpfs, cg)
	if got, want := m.PeakPerCg(cg), uint64(4*mib); got != want {
		t.Errorf("PeakPerCg(%d) after committing tmpfs memory while waste is pending = %d, want %d", cg, got, want)
	}

	m.Inc(2*mib, PageCache, cg)
	if got, want := m.PeakPerCg(cg), uint64(5*mib); got != want {
		t.Errorf("PeakPerCg(%d) after committing page cache memory = %d, want %d", cg, got, want)
	}
}
