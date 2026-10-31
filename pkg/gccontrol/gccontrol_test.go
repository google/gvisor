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

package gccontrol

import (
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

const gcDisabled = -1

func gcSettings() (percent int, limit int64) {
	mu.Lock()
	defer mu.Unlock()
	percent = debug.SetGCPercent(gcDisabled)
	debug.SetGCPercent(percent)
	return percent, debug.SetMemoryLimit(-1 /* limit */)
}

func assertGCSettings(t *testing.T, wantPercent int, wantLimit int64) {
	t.Helper()
	gotPercent, gotLimit := gcSettings()
	if gotPercent != wantPercent || gotLimit != wantLimit {
		t.Fatalf("gcSettings() = (%d, %d), want (%d, %d)", gotPercent, gotLimit, wantPercent, wantLimit)
	}
}

func maybeFreeOSMemoryRanGC() bool {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	MaybeFreeOSMemory()
	runtime.ReadMemStats(&after)
	return after.NumGC > before.NumGC
}

func triggerEarlyResume(t *testing.T) {
	t.Helper()
	runtime.GC()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := gcSettings(); p != gcDisabled {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("GC remained disabled after forced collection")
}

func TestMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name         string
		totalMem     uint64
		untrackedMem uint64
		want         uint64
	}{
		{name: "unlimited", totalMem: NoMemoryLimit, untrackedMem: 512 << 20, want: maxMemoryLimit},
		{name: "cappedAtMax", totalMem: 4 << 30, want: maxMemoryLimit},
		{name: "halfOfTotal", totalMem: 200 << 20, want: 100 << 20},
		{name: "subtractsUntracked", totalMem: 200 << 20, untrackedMem: 140 << 20, want: 30 << 20},
		{name: "exhaustedBudget", totalMem: 100 << 20, untrackedMem: 120 << 20, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := memoryLimit(tc.totalMem, tc.untrackedMem); got != tc.want {
				t.Fatalf("memoryLimit(%d, %d) = %d, want %d", tc.totalMem, tc.untrackedMem, got, tc.want)
			}
		})
	}
}

func TestSuspend(t *testing.T) {
	const (
		origPercent   = 500
		origLimit     = int64(2 << 30)
		highTotalMem  = 1 << 30
		wantHighLimit = highTotalMem / 2
		lowTotalMem   = 512 << 20
		wantLowLimit  = lowTotalMem / 2
	)

	for _, tc := range []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "nestedLimitsAndEnd",
			fn: func(t *testing.T) {
				var nilSusp *Suspension
				nilSusp.End()

				s1 := Suspend(highTotalMem, 0)
				defer s1.End()
				assertGCSettings(t, gcDisabled, wantHighLimit)

				s2 := Suspend(lowTotalMem, 0)
				defer s2.End()
				assertGCSettings(t, gcDisabled, wantLowLimit)

				s3 := Suspend(NoMemoryLimit, 0)
				defer s3.End()
				assertGCSettings(t, gcDisabled, wantLowLimit)

				s3.End()
				s2.End()
				assertGCSettings(t, gcDisabled, wantLowLimit)

				s1.End()
				s1.End() // Idempotent.
				assertGCSettings(t, origPercent, origLimit)
			},
		},
		{
			name: "insufficientHeadroom",
			fn: func(t *testing.T) {
				if s := Suspend(100<<20, 100<<20); s != nil {
					s.End()
					t.Fatalf("Suspend with exhausted budget = %v, want nil", s)
				}
				if s := Suspend(4, 0); s != nil {
					s.End()
					t.Fatalf("Suspend already past limit = %v, want nil", s)
				}
				assertGCSettings(t, origPercent, origLimit)
			},
		},
		{
			name: "earlyResume",
			fn: func(t *testing.T) {
				s := Suspend(highTotalMem, 0)
				defer s.End()
				triggerEarlyResume(t)
				assertGCSettings(t, origPercent, origLimit)
				s.End()

				s2 := Suspend(highTotalMem, 0)
				defer s2.End()
				assertGCSettings(t, gcDisabled, wantHighLimit)
			},
		},
		{
			name: "maybeFreeOSMemory",
			fn: func(t *testing.T) {
				s := Suspend(highTotalMem, 0)
				defer s.End()
				if maybeFreeOSMemoryRanGC() {
					t.Fatal("MaybeFreeOSMemory ran GC while suspended")
				}
				triggerEarlyResume(t)
				if maybeFreeOSMemoryRanGC() {
					t.Fatal("MaybeFreeOSMemory ran GC before End")
				}
				s.End()
				if !maybeFreeOSMemoryRanGC() {
					t.Fatal("MaybeFreeOSMemory did not run GC after End")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			prevP := debug.SetGCPercent(origPercent)
			prevL := debug.SetMemoryLimit(origLimit)
			t.Cleanup(func() {
				debug.SetGCPercent(prevP)
				debug.SetMemoryLimit(prevL)
			})
			tc.fn(t)
		})
	}
}
