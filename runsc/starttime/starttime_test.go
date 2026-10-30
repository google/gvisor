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

package starttime

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetState() {
	setOnce = sync.Once{}
	processStart = time.Time{}
	goStartTime = time.Time{}
	envStartTime = time.Time{}
	reexecTime = time.Time{}
}

// envTime returns the time held by the environment variable key in env.
func envTime(t *testing.T, env []string, key string) time.Time {
	t.Helper()
	for _, e := range env {
		if value, ok := strings.CutPrefix(e, key+"="); ok {
			nanos, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				t.Fatalf("invalid %s in %v: %v", key, env, err)
			}
			return time.Unix(0, nanos)
		}
	}
	t.Fatalf("%s not found in %v", key, env)
	return time.Time{}
}

// TestSpawnEnviron checks that SpawnEnviron returns a copy of env in which any
// existing start and re-exec times are replaced by a start time of now.
func TestSpawnEnviron(t *testing.T) {
	orig := []string{"FOO=bar", "RUNSC_START_TIME_NANOS=1", "RUNSC_REEXEC_TIME_NANOS=2"}
	origCopy := slices.Clone(orig)
	before := time.Now()
	env := SpawnEnviron(orig)
	after := time.Now()

	if len(env) != 2 || env[0] != "FOO=bar" {
		t.Fatalf("SpawnEnviron(%v) = %v, want FOO=bar followed by the start time", orig, env)
	}
	if got := envTime(t, env, envStartTimeKey); got.Before(before) || got.After(after) {
		t.Errorf("SpawnEnviron set the start time to %v, want the current time (between %v and %v)", got, before, after)
	}
	if slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, envReexecTimeKey+"=") }) {
		t.Errorf("SpawnEnviron(%v) = %v, want no re-exec time", orig, env)
	}
	if !slices.Equal(orig, origCopy) {
		t.Errorf("SpawnEnviron modified its input: got %v, want %v", orig, origCopy)
	}
}

// TestReexecEnviron checks that ReexecEnviron returns a copy of env that
// carries over the start time, and in which any existing re-exec time is
// replaced by the current time.
func TestReexecEnviron(t *testing.T) {
	t.Cleanup(resetState)
	start := time.Unix(1700000005, 987654321)
	t.Setenv(envStartTimeKey, strconv.FormatInt(start.UnixNano(), 10))
	orig := []string{"FOO=bar", "RUNSC_REEXEC_TIME_NANOS=1"}
	origCopy := slices.Clone(orig)
	before := time.Now()
	env := ReexecEnviron(orig)
	after := time.Now()

	if len(env) != 3 || env[0] != "FOO=bar" {
		t.Fatalf("ReexecEnviron(%v) = %v, want FOO=bar followed by the start and re-exec times", orig, env)
	}
	if got := envTime(t, env, envStartTimeKey); !got.Equal(start) {
		t.Errorf("ReexecEnviron set the start time to %v, want %v", got, start)
	}
	if got := envTime(t, env, envReexecTimeKey); got.Before(before) || got.After(after) {
		t.Errorf("ReexecEnviron set the re-exec time to %v, want the current time (between %v and %v)", got, before, after)
	}
	if !slices.Equal(orig, origCopy) {
		t.Errorf("ReexecEnviron modified its input: got %v, want %v", orig, origCopy)
	}
}

// TestTimerWithoutReexec checks that the Timer of a process that was spawned
// with a start time (as `runsc create` does) but never re-exec'd starts at that
// time and has no "re-exec" midpoint.
func TestTimerWithoutReexec(t *testing.T) {
	t.Cleanup(resetState)
	start := time.Unix(1700000005, 987654321)
	t.Setenv(envStartTimeKey, strconv.FormatInt(start.UnixNano(), 10))
	tl := Timer("test").Export()
	if !tl.Start.Equal(start) {
		t.Errorf("Timer started at %v, want %v", tl.Start, start)
	}
	if when, err := tl.Reached("re-exec"); err == nil {
		t.Errorf("Timer has a re-exec midpoint at %v, want none", when)
	}
}

// TestTimerWithReexec checks that the Timer of a re-exec'd process starts at
// the original start time and has a "re-exec" midpoint at the re-exec time.
func TestTimerWithReexec(t *testing.T) {
	t.Cleanup(resetState)
	start := time.Unix(1700000005, 987654321)
	reexec := time.Unix(1700000006, 123456789)
	t.Setenv(envStartTimeKey, strconv.FormatInt(start.UnixNano(), 10))
	t.Setenv(envReexecTimeKey, strconv.FormatInt(reexec.UnixNano(), 10))
	tl := Timer("test").Export()
	if !tl.Start.Equal(start) {
		t.Errorf("Timer started at %v, want %v", tl.Start, start)
	}
	got, err := tl.Reached("re-exec")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(reexec) {
		t.Errorf("re-exec midpoint is at %v, want %v", got, reexec)
	}
}

func TestGetFromEnv(t *testing.T) {
	t.Cleanup(resetState)
	want := time.Unix(1700000005, 987654321)
	t.Setenv(envStartTimeKey, strconv.FormatInt(want.UnixNano(), 10))
	got := Get()
	if !got.Equal(want) {
		t.Errorf("Get() = %v, want %v", got, want)
	}
}

func TestGetIsCached(t *testing.T) {
	t.Cleanup(resetState)
	t.Setenv(envStartTimeKey, "1700000005987654321")
	first := Get()
	// Get() caches its result on the first call, so later changes to the
	// environment must not affect it.
	t.Setenv(envStartTimeKey, "1800000000000000000")
	second := Get()
	if !second.Equal(first) {
		t.Errorf("second Get() = %v, want the first result %v", second, first)
	}
}

func TestGetFallback(t *testing.T) {
	t.Cleanup(resetState)
	got := Get()
	if !got.Equal(processStart) {
		t.Errorf("Get() = %v, want the /proc/self/status time %v", got, processStart)
	}
}
