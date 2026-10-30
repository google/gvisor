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

package maxprocs

import (
	"math"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/gohacks"
)

func saveAndRestoreState(t *testing.T) {
	t.Helper()
	origLowered := lowered
	origNeedReset := needReset.Load()
	origPrevGC := prevGCPercent
	origAppliedGC := appliedGCPercent
	origProcs := runtime.GOMAXPROCS(0)
	origGC := debug.SetGCPercent(100)
	t.Cleanup(func() {
		debug.SetGCPercent(origGC)
		runtime.GOMAXPROCS(origProcs)
		lowered = origLowered
		prevGCPercent = origPrevGC
		appliedGCPercent = origAppliedGC
		needReset.Store(origNeedReset)
	})
}

func TestBound(t *testing.T) {
	for _, tc := range []struct {
		cur    int
		envSet bool
		want   int
	}{
		{cur: 1, want: 0},
		{cur: 2, want: 0},
		{cur: maxProcs, want: 0},
		{cur: maxProcs + 1, want: 0},
		{cur: 96, want: 0},
		{cur: threshold, want: 0},
		{cur: threshold + 1, want: maxProcs},
		{cur: 160, want: maxProcs},
		{cur: 192, want: maxProcs},
		{cur: 256, want: maxProcs},
		{cur: 192, envSet: true, want: 0},
		{cur: 2, envSet: true, want: 0},
	} {
		if got := bound(tc.cur, tc.envSet); got != tc.want {
			t.Errorf("bound(%d, %t) = %d, want %d", tc.cur, tc.envSet, got, tc.want)
		}
	}
}

func TestGCPercent(t *testing.T) {
	for _, tc := range []struct {
		initial int
		want    int32
	}{
		{initial: -1, want: 100},
		{initial: 0, want: 100},
		{initial: 1, want: 100},
		{initial: threshold, want: 100},
		{initial: threshold + 1, want: 150},
		{initial: 160, want: 163},
		{initial: 192, want: 176},
		{initial: 249, want: 199},
		{initial: 250, want: maxGCPercent},
		{initial: 256, want: maxGCPercent},
		{initial: 384, want: maxGCPercent},
		{initial: 512, want: maxGCPercent},
		{initial: math.MaxInt, want: maxGCPercent},
	} {
		if got := gcPercent(tc.initial); got != tc.want {
			t.Errorf("gcPercent(%d) = %d, want %d", tc.initial, got, tc.want)
		}
	}
}

func TestEnvParsersMatchRuntime(t *testing.T) {
	inputs := []string{
		"",
		"0",
		"+0",
		"-0",
		"1",
		"+19",
		"-1",
		"100",
		"off",
		"OFF",
		"128MiB",
		"2147483647",
		"2147483648",
		"-2147483648",
		"-2147483649",
		"+",
		"-",
		" 8",
		"8 ",
		"1_000",
		"invalid",
	}
	for _, s := range inputs {
		gotN, gotOK := parseInt32(s)
		wantN64, err := strconv.ParseInt(s, 10, 32)
		wantOK := err == nil
		if gotOK != wantOK || (gotOK && gotN != int32(wantN64)) {
			t.Errorf("parseInt32(%q) = (%d, %t), want (%d, %t)", s, gotN, gotOK, wantN64, wantOK)
		}

		wantMaxProcs := wantOK && wantN64 > 0
		if got := gomaxprocsEnvSet(s); got != wantMaxProcs {
			t.Errorf("gomaxprocsEnvSet(%q) = %t, want %t", s, got, wantMaxProcs)
		}

		wantGOGC := s == "off" || wantOK
		if got := gogcEnvSet(s); got != wantGOGC {
			t.Errorf("gogcEnvSet(%q) = %t, want %t", s, got, wantGOGC)
		}
	}

	for _, tc := range []struct {
		val  string
		want bool
	}{
		{val: "", want: false},
		{val: "off", want: false},
		{val: "128MiB", want: true},
		{val: "1073741824", want: true},
	} {
		if got := gomemlimitEnvSet(tc.val); got != tc.want {
			t.Errorf("gomemlimitEnvSet(%q) = %t, want %t", tc.val, got, tc.want)
		}
	}
}

func TestInitMaxProcs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cur         int
		env         map[string]string
		numGC       uint32
		wantLowered bool
		wantProcs   int
		wantGC      int
		wantReset   bool
	}{
		{
			name:        "sub-threshold",
			cur:         64,
			wantLowered: false,
			wantProcs:   64,
			wantGC:      100,
			wantReset:   false,
		},
		{
			name:        "192-cpus-default-env",
			cur:         192,
			wantLowered: true,
			wantProcs:   maxProcs,
			wantGC:      int(gcPercent(192)),
			wantReset:   true,
		},
		{
			name:        "192-cpus-gomaxprocs-set",
			cur:         192,
			env:         map[string]string{"GOMAXPROCS": "192"},
			wantLowered: false,
			wantProcs:   192,
			wantGC:      100,
			wantReset:   false,
		},
		{
			name:        "192-cpus-gogc-set",
			cur:         192,
			env:         map[string]string{"GOGC": "120"},
			wantLowered: true,
			wantProcs:   maxProcs,
			wantGC:      100,
			wantReset:   false,
		},
		{
			name:        "192-cpus-gomemlimit-set",
			cur:         192,
			env:         map[string]string{"GOMEMLIMIT": "128MiB"},
			wantLowered: true,
			wantProcs:   maxProcs,
			wantGC:      100,
			wantReset:   false,
		},
		{
			name:        "256-cpus-after-bootstrap-gc",
			cur:         256,
			numGC:       1,
			wantLowered: true,
			wantProcs:   maxProcs,
			wantGC:      100,
			wantReset:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveAndRestoreState(t)
			lowered = false
			needReset.Store(false)
			prevGCPercent = 0
			appliedGCPercent = 0
			runtime.GOMAXPROCS(tc.cur)
			debug.SetGCPercent(100)

			lookup := func(k string) (string, bool) {
				v, ok := tc.env[k]
				return v, ok
			}
			initMaxProcs(tc.cur, lookup, func() uint32 { return tc.numGC })

			if lowered != tc.wantLowered {
				t.Errorf("lowered = %t, want %t", lowered, tc.wantLowered)
			}
			if got := runtime.GOMAXPROCS(0); got != tc.wantProcs {
				t.Errorf("GOMAXPROCS = %d, want %d", got, tc.wantProcs)
			}
			if got := needReset.Load(); got != tc.wantReset {
				t.Errorf("needReset = %t, want %t", got, tc.wantReset)
			}
			if got := int(gohacks.SetGCPercent(int32(tc.wantGC))); got != tc.wantGC {
				t.Errorf("GCPercent = %d, want %d", got, tc.wantGC)
			}

			ResetGCPercent()
			if needReset.Load() {
				t.Errorf("needReset = true after ResetGCPercent")
			}
			if got := debug.SetGCPercent(100); got != 100 {
				t.Errorf("GCPercent after ResetGCPercent = %d, want 100", got)
			}
		})
	}
}

func TestSetGCPercentAndReset(t *testing.T) {
	saveAndRestoreState(t)

	target := gcPercent(192)
	prev := gohacks.SetGCPercent(target)
	if prev != 100 {
		t.Fatalf("prev = %d, want 100", prev)
	}
	prevGCPercent = prev
	appliedGCPercent = target
	needReset.Store(true)

	// Concurrent ResetGCPercent calls must all observe the restored GOGC upon return.
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ResetGCPercent()
			if needReset.Load() {
				t.Errorf("needReset = true after ResetGCPercent returned")
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := debug.SetGCPercent(100); got != 100 {
		t.Errorf("GCPercent after concurrent ResetGCPercent = %d, want 100", got)
	}

	for _, override := range []int{50, -1} {
		gohacks.SetGCPercent(target)
		prevGCPercent = 100
		appliedGCPercent = target
		needReset.Store(true)
		debug.SetGCPercent(override)

		ResetGCPercent()
		if got := debug.SetGCPercent(100); got != override {
			t.Errorf("GCPercent after ResetGCPercent with override %d = %d, want %d", override, got, override)
		}
	}
}

func TestInitAndResetGCPercent(t *testing.T) {
	saveAndRestoreState(t)

	if lowered {
		if got := runtime.GOMAXPROCS(0); got != maxProcs {
			t.Errorf("GOMAXPROCS after init = %d, want %d", got, maxProcs)
		}
	}
	ResetGCPercent()
	if lowered {
		if got := runtime.GOMAXPROCS(0); got != maxProcs {
			t.Errorf("GOMAXPROCS after ResetGCPercent = %d, want %d", got, maxProcs)
		}
	}
}

func TestGOMAXPROCSEnvRespected(t *testing.T) {
	switch os.Getenv("TEST_MAXPROCS_SUBPROC") {
	case "env-set":
		if lowered {
			t.Fatalf("lowered = true when GOMAXPROCS=19 env var is set")
		}
		if got := runtime.GOMAXPROCS(0); got != 19 {
			t.Fatalf("GOMAXPROCS = %d, want 19", got)
		}
		return
	case "unset-136":
		if got := gohacks.NumGC(); got != 0 {
			t.Fatalf("NumGC() before initMaxProcs = %d, want 0", got)
		}
		initMaxProcs(runtime.GOMAXPROCS(0), func(string) (string, bool) { return "", false }, gohacks.NumGC)
		if !lowered {
			t.Fatalf("lowered = false on 136-P subprocess")
		}
		if got := runtime.GOMAXPROCS(0); got != maxProcs {
			t.Fatalf("GOMAXPROCS = %d, want %d", got, maxProcs)
		}
		wantGC := gcPercent(136)
		if got := gohacks.SetGCPercent(wantGC); got != wantGC {
			t.Fatalf("GCPercent = %d, want %d", got, wantGC)
		}
		if got := gohacks.NumGC(); got != 0 {
			t.Fatalf("NumGC() = %d, want 0", got)
		}
		return
	case "unset-256":
		if got := gohacks.NumGC(); got == 0 {
			t.Fatalf("NumGC() before initMaxProcs = 0 on 256-P subprocess, want > 0")
		}
		initMaxProcs(runtime.GOMAXPROCS(0), func(string) (string, bool) { return "", false }, gohacks.NumGC)
		if !lowered {
			t.Fatalf("lowered = false on 256-P subprocess")
		}
		if got := runtime.GOMAXPROCS(0); got != maxProcs {
			t.Fatalf("GOMAXPROCS = %d, want %d", got, maxProcs)
		}
		if got := gohacks.SetGCPercent(100); got != 100 {
			t.Fatalf("GCPercent = %d after bootstrap GC, want 100", got)
		}
		return
	}

	for _, tc := range []struct {
		mode      string
		gomaxproc string
	}{
		{mode: "env-set", gomaxproc: "GOMAXPROCS=19"},
		{mode: "unset-136", gomaxproc: "GOMAXPROCS=136"},
		{mode: "unset-256", gomaxproc: "GOMAXPROCS=256"},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGOMAXPROCSEnvRespected$")
		cmd.Env = []string{tc.gomaxproc, "TEST_MAXPROCS_SUBPROC=" + tc.mode}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s (%v) failed: %v\noutput:\n%s", tc.mode, cmd, err, out)
		}
	}
}
