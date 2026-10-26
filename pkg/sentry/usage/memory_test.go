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

import (
	"sync"
	"testing"
)

const (
	oneGB = uint64(1) << 30
	twoGB = uint64(2) << 30
)

// setBoundsForTest sets the two bounds and restores them when the test ends,
// since they are package-level state.
func setBoundsForTest(t *testing.T, minTotal, maxTotal uint64) {
	t.Helper()
	oldMin, oldMax := MinimumTotalMemoryBytes.Load(), MaximumTotalMemoryBytes.Load()
	t.Cleanup(func() {
		MinimumTotalMemoryBytes.Store(oldMin)
		MaximumTotalMemoryBytes.Store(oldMax)
	})
	MinimumTotalMemoryBytes.Store(minTotal)
	MaximumTotalMemoryBytes.Store(maxTotal)
}

// setTotalMemoryForTest pins both bounds together, the way boot does.
func setTotalMemoryForTest(t *testing.T, total uint64) {
	t.Helper()
	setBoundsForTest(t, total, total)
}

func TestSetTotalMemoryBytesGrows(t *testing.T) {
	setTotalMemoryForTest(t, oneGB)

	if err := SetTotalMemoryBytes(twoGB); err != nil {
		t.Fatalf("SetTotalMemoryBytes(%d) failed: %v", twoGB, err)
	}
	// The reported total must follow immediately, before the application has
	// allocated anything, so both bounds have to move.
	if got := TotalMemory(0, 0); got != twoGB {
		t.Errorf("TotalMemory(0, 0) = %d, want %d", got, twoGB)
	}
	if got := MinimumTotalMemoryBytes.Load(); got != twoGB {
		t.Errorf("MinimumTotalMemoryBytes = %d, want %d", got, twoGB)
	}
	if got := MaximumTotalMemoryBytes.Load(); got != twoGB {
		t.Errorf("MaximumTotalMemoryBytes = %d, want %d", got, twoGB)
	}
}

func TestSetTotalMemoryBytesNoOp(t *testing.T) {
	setTotalMemoryForTest(t, oneGB)

	if err := SetTotalMemoryBytes(oneGB); err != nil {
		t.Errorf("SetTotalMemoryBytes(%d) (no-op) failed: %v", oneGB, err)
	}
	if got := TotalMemory(0, 0); got != oneGB {
		t.Errorf("TotalMemory(0, 0) = %d after no-op, want unchanged %d", got, oneGB)
	}
}

func TestSetTotalMemoryBytesRejects(t *testing.T) {
	for _, test := range []struct {
		name               string
		minTotal, maxTotal uint64
		n                  uint64
	}{
		{name: "shrink", minTotal: twoGB, maxTotal: twoGB, n: oneGB},
		{name: "zero", minTotal: oneGB, maxTotal: oneGB, n: 0},
		// Without --total-memory the maximum stays 0 and the minimum keeps its
		// package default, so there is no limit to raise.
		{name: "no boot-time maximum", minTotal: twoGB, maxTotal: 0, n: twoGB * 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			setBoundsForTest(t, test.minTotal, test.maxTotal)
			if err := SetTotalMemoryBytes(test.n); err == nil {
				t.Errorf("SetTotalMemoryBytes(%d) succeeded, want error", test.n)
			}
			// A rejected call must leave both bounds untouched.
			if got := MinimumTotalMemoryBytes.Load(); got != test.minTotal {
				t.Errorf("MinimumTotalMemoryBytes = %d, want unchanged %d", got, test.minTotal)
			}
			if got := MaximumTotalMemoryBytes.Load(); got != test.maxTotal {
				t.Errorf("MaximumTotalMemoryBytes = %d, want unchanged %d", got, test.maxTotal)
			}
		})
	}
}

// TestSetTotalMemoryBytesConcurrent checks that racing raises settle on the
// largest requested value with both bounds in step: a slower caller raising to
// a smaller value must not undo a larger one that already landed.
func TestSetTotalMemoryBytesConcurrent(t *testing.T) {
	const goroutines = 16
	setTotalMemoryForTest(t, oneGB)

	var wg sync.WaitGroup
	for i := 1; i <= goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Shrinks are expected to be rejected here; only the bounds matter.
			SetTotalMemoryBytes(oneGB * uint64(i))
		}(i)
	}
	wg.Wait()

	want := oneGB * goroutines
	if got := MaximumTotalMemoryBytes.Load(); got != want {
		t.Errorf("MaximumTotalMemoryBytes = %d, want %d", got, want)
	}
	if got := MinimumTotalMemoryBytes.Load(); got != want {
		t.Errorf("MinimumTotalMemoryBytes = %d, want %d", got, want)
	}
	if got := TotalMemory(0, 0); got != want {
		t.Errorf("TotalMemory(0, 0) = %d, want %d", got, want)
	}
}

func TestTotalMemoryFollowsBounds(t *testing.T) {
	setTotalMemoryForTest(t, oneGB)

	// While the bounds are pinned together, the reported total is exactly the
	// limit regardless of how much the MemoryFile has grown.
	for _, memSize := range []uint64{0, oneGB / 2, twoGB} {
		if got := TotalMemory(memSize, 0); got != oneGB {
			t.Errorf("TotalMemory(%d, 0) = %d, want %d", memSize, got, oneGB)
		}
	}
	if err := SetTotalMemoryBytes(twoGB); err != nil {
		t.Fatalf("SetTotalMemoryBytes(%d) failed: %v", twoGB, err)
	}
	for _, memSize := range []uint64{0, oneGB / 2, twoGB} {
		if got := TotalMemory(memSize, 0); got != twoGB {
			t.Errorf("TotalMemory(%d, 0) = %d after grow, want %d", memSize, got, twoGB)
		}
	}
}
