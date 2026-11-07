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
	"math"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func gcSettings() (int, int64) {
	mu.Lock()
	defer mu.Unlock()
	percent := debug.SetGCPercent(gcDisabled)
	debug.SetGCPercent(percent)
	return percent, debug.SetMemoryLimit(queryMemoryLimit)
}

func assertGCSettings(t *testing.T, wantPercent int, wantLimit int64) {
	t.Helper()
	gotPercent, gotLimit := gcSettings()
	if gotPercent != wantPercent || gotLimit != wantLimit {
		t.Fatalf("gcSettings() = (%d, %d), want (%d, %d)", gotPercent, gotLimit, wantPercent, wantLimit)
	}
}

func waitForGCSettings(t *testing.T, wantPercent int, wantLimit int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gotPercent, gotLimit := gcSettings(); gotPercent == wantPercent && gotLimit == wantLimit {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	assertGCSettings(t, wantPercent, wantLimit)
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

func TestMemoryLimits(t *testing.T) {
	for _, tc := range []struct {
		name         string
		totalMem     uint64
		untrackedMem uint64
		want         uint64
	}{
		{name: "unlimited", totalMem: NoMemoryLimit, untrackedMem: 512 << 20, want: math.MaxInt64},
		{name: "halfOfLargeTotal", totalMem: 4 << 30, want: 2 << 30},
		{name: "halfOfTotal", totalMem: 200 << 20, want: 100 << 20},
		{name: "subtractsUntracked", totalMem: 200 << 20, untrackedMem: 140 << 20, want: 30 << 20},
		{name: "exhaustedBudget", totalMem: 100 << 20, untrackedMem: 120 << 20, want: 0},
	} {
		t.Run("host/"+tc.name, func(t *testing.T) {
			if got := hostMemoryLimit(tc.totalMem, tc.untrackedMem); got != tc.want {
				t.Fatalf("hostMemoryLimit(%d, %d) = %d, want %d", tc.totalMem, tc.untrackedMem, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name        string
		used        uint64
		minHeadroom uint64
		want        uint64
	}{
		{name: "usesMinHeadroom", used: 20 << 20, minHeadroom: 128 << 20, want: 148 << 20},
		{name: "atMinHeadroom", used: 128 << 20, minHeadroom: 128 << 20, want: 256 << 20},
		{name: "doublesAboveMinHeadroom", used: 215 << 20, minHeadroom: 128 << 20, want: 430 << 20},
		{name: "saturatesUsedOverflow", used: math.MaxUint64, minHeadroom: 128 << 20, want: math.MaxInt64},
		{name: "saturatesHeadroomOverflow", used: 0, minHeadroom: math.MaxUint64, want: math.MaxInt64},
	} {
		t.Run("growth/"+tc.name, func(t *testing.T) {
			if got := growthMemoryLimit(tc.used, tc.minHeadroom); got != tc.want {
				t.Fatalf("growthMemoryLimit(%d, %d) = %d, want %d", tc.used, tc.minHeadroom, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name           string
		used           uint64
		effectiveLimit uint64
		want           bool
	}{
		{name: "zeroLimit", used: 0, effectiveLimit: 0, want: false},
		{name: "exactDoubleAllowed", used: 215 << 20, effectiveLimit: 430 << 20, want: true},
		{name: "oneByteShortOfDoubleRejected", used: 215 << 20, effectiveLimit: 430<<20 - 1, want: false},
		{name: "usedExceedsLimit", used: 300 << 20, effectiveLimit: 256 << 20, want: false},
	} {
		t.Run("headroom/"+tc.name, func(t *testing.T) {
			if got := hasHeadroom(tc.used, tc.effectiveLimit); got != tc.want {
				t.Fatalf("hasHeadroom(%d, %d) = %v, want %v", tc.used, tc.effectiveLimit, got, tc.want)
			}
		})
	}
}

func TestSuspend(t *testing.T) {
	const (
		origPercent   = 500
		origLimit     = int64(2 << 30)
		highTotalMem  = 400 << 20
		wantHighLimit = highTotalMem / 2
		lowTotalMem   = 256 << 20
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

				// Zero totalMem while idle leaves GC enabled.
				if sZero := Suspend(0, 0); sZero != nil {
					sZero.End()
					t.Fatalf("Suspend(0, 0) = %v, want nil", sZero)
				}
				assertGCSettings(t, origPercent, origLimit)

				// Pre-disabled GC leaves caller settings
				// untouched.
				debug.SetGCPercent(gcDisabled)
				if sOff := Suspend(highTotalMem, 0); sOff != nil {
					sOff.End()
					t.Fatalf("Suspend with GOGC=off = %v, want nil", sOff)
				}
				assertGCSettings(t, gcDisabled, origLimit)
				debug.SetGCPercent(origPercent)
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

				// Zero totalMem while active resumes GC early.
				sZeroActive := Suspend(highTotalMem, 0)
				defer sZeroActive.End()
				if sZero := Suspend(0, 0); sZero != nil {
					sZero.End()
					t.Fatalf("Suspend(0, 0) while active = %v, want nil", sZero)
				}
				assertGCSettings(t, origPercent, origLimit)
				sZeroActive.End()

				// Exhausting budget while active resumes GC
				// early.
				sActive := Suspend(highTotalMem, 0)
				defer sActive.End()
				if s := Suspend(100<<20, 100<<20); s != nil {
					s.End()
					t.Fatalf("Suspend with exhausted budget while active = %v, want nil", s)
				}
				assertGCSettings(t, origPercent, origLimit)
				sActive.End()

				// Exhausting budget during an EndAfter grace
				// window ends the session.
				sGrace := Suspend(highTotalMem, 0)
				defer sGrace.End()
				sGrace.EndAfter(time.Hour)
				if s := Suspend(100<<20, 100<<20); s != nil {
					s.End()
					t.Fatalf("Suspend with exhausted budget during grace = %v, want nil", s)
				}
				assertGCSettings(t, origPercent, origLimit)
				sNext := Suspend(highTotalMem, 0)
				defer sNext.End()
				assertGCSettings(t, gcDisabled, wantHighLimit)
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

				// Early GC during an EndAfter grace window
				// clears the session.
				sGrace := Suspend(highTotalMem, 0)
				defer sGrace.End()
				sGrace.EndAfter(time.Hour)
				triggerEarlyResume(t)
				assertGCSettings(t, origPercent, origLimit)

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

				// MaybeFreeOSMemory ends a grace-only session
				// and runs GC unless another handle is active.
				sGrace := Suspend(highTotalMem, 0)
				defer sGrace.End()
				sGrace.EndAfter(time.Hour)
				sActive := Suspend(lowTotalMem, 0)
				defer sActive.End()
				if maybeFreeOSMemoryRanGC() {
					t.Fatal("MaybeFreeOSMemory ran GC while active handle open")
				}
				sActive.EndAfter(time.Hour)
				if !maybeFreeOSMemoryRanGC() {
					t.Fatal("MaybeFreeOSMemory did not end grace window and run GC")
				}
				assertGCSettings(t, origPercent, origLimit)
			},
		},
		{
			name: "endAfter",
			fn: func(t *testing.T) {
				var nilSusp *Suspension
				nilSusp.EndAfter(time.Millisecond)

				// End cancels any pending EndAfter deadline and
				// makes later EndAfter calls a no-op.
				s1 := Suspend(highTotalMem, 0)
				s1.EndAfter(time.Hour)
				s1.End()
				s1.EndAfter(time.Millisecond)
				assertGCSettings(t, origPercent, origLimit)

				// A shorter EndAfter does not shorten an
				// existing longer deadline.
				sLong := Suspend(highTotalMem, 0)
				defer sLong.End()
				sLong.EndAfter(time.Hour)
				sShort := Suspend(lowTotalMem, 0)
				defer sShort.End()
				sShort.EndAfter(15 * time.Millisecond)
				time.Sleep(40 * time.Millisecond)
				assertGCSettings(t, gcDisabled, wantLowLimit)
				sLong.End()
				assertGCSettings(t, origPercent, origLimit)

				// A longer EndAfter extends a shorter deadline.
				sFirst := Suspend(highTotalMem, 0)
				defer sFirst.End()
				sFirst.EndAfter(15 * time.Millisecond)
				sExtend := Suspend(lowTotalMem, 0)
				defer sExtend.End()
				sExtend.EndAfter(80 * time.Millisecond)
				time.Sleep(35 * time.Millisecond)
				assertGCSettings(t, gcDisabled, wantLowLimit)
				waitForGCSettings(t, origPercent, origLimit)

				// An active handle keeps the session suspended
				// past an earlier EndAfter deadline.
				sBoot := Suspend(highTotalMem, 0)
				defer sBoot.End()
				sBoot.EndAfter(15 * time.Millisecond)
				sRestore := Suspend(lowTotalMem, 0)
				defer sRestore.End()
				time.Sleep(40 * time.Millisecond)
				assertGCSettings(t, gcDisabled, wantLowLimit)
				sRestore.End()
				assertGCSettings(t, origPercent, origLimit)

				// Zero totalMem during an EndAfter grace period
				// resumes GC immediately.
				sGrace := Suspend(highTotalMem, 0)
				defer sGrace.End()
				sGrace.EndAfter(time.Hour)
				if sZero := Suspend(0, 0); sZero != nil {
					sZero.End()
					t.Fatal("Suspend(0, 0) returned non-nil")
				}
				assertGCSettings(t, origPercent, origLimit)
			},
		},
		{
			name: "suspendWithHeadroom",
			fn: func(t *testing.T) {
				// When used exceeds minHeadroom, limit is
				// 2*used and still suspends cleanly.
				sDouble := SuspendWithHeadroom(NoMemoryLimit, 0, 1)
				if sDouble == nil {
					t.Fatal("SuspendWithHeadroom(NoMemoryLimit, 0, 1) = nil")
				}
				defer sDouble.End()
				if gotP, _ := gcSettings(); gotP != gcDisabled {
					t.Fatalf("GCPercent = %d, want %d", gotP, gcDisabled)
				}
				sDouble.End()
				assertGCSettings(t, origPercent, origLimit)

				// During a grace-only session with ample host
				// budget, SuspendWithHeadroom can raise the
				// soft limit above defaultMemoryLimit.
				sBoot := Suspend(NoMemoryLimit, 0)
				if sBoot == nil {
					t.Fatal("Suspend(NoMemoryLimit, 0) = nil")
				}
				defer sBoot.End()
				assertGCSettings(t, gcDisabled, int64(defaultMemoryLimit))
				sBoot.EndAfter(time.Hour)
				sSave := SuspendWithHeadroom(NoMemoryLimit, 0, 300<<20)
				if sSave == nil {
					t.Fatal("SuspendWithHeadroom during grace = nil")
				}
				defer sSave.End()
				if _, gotL := gcSettings(); gotL <= int64(defaultMemoryLimit) {
					t.Fatalf("MemoryLimit = %d, want > %d", gotL, defaultMemoryLimit)
				}
				sSave.End()
				assertGCSettings(t, origPercent, origLimit)

				// Host budget from an earlier grace handle
				// still caps SuspendWithHeadroom.
				sTightBoot := Suspend(highTotalMem, 0)
				if sTightBoot == nil {
					t.Fatal("Suspend(highTotalMem, 0) = nil")
				}
				defer sTightBoot.End()
				sTightBoot.EndAfter(time.Hour)
				sCappedSave := SuspendWithHeadroom(NoMemoryLimit, 0, 300<<20)
				if sCappedSave == nil {
					t.Fatal("SuspendWithHeadroom under host cap = nil")
				}
				defer sCappedSave.End()
				assertGCSettings(t, gcDisabled, wantHighLimit)
				sCappedSave.End()
				assertGCSettings(t, origPercent, origLimit)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			MaybeFreeOSMemory()
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
