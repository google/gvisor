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
}

func TestPutEnviron(t *testing.T) {
	t.Cleanup(resetState)
	orig := []string{"FOO=bar", "BAZ=qux"}
	t1 := time.Unix(1700000000, 123456789)
	env1 := PutEnviron(orig, t1)

	if want := []string{"FOO=bar", "BAZ=qux"}; !slices.Equal(orig, want) {
		t.Fatalf("PutEnviron mutated input slice: got %v, want %v", orig, want)
	}
	if want := []string{"FOO=bar", "BAZ=qux", "RUNSC_START_TIME_NANOS=1700000000123456789"}; !slices.Equal(env1, want) {
		t.Fatalf("PutEnviron(orig, t1) = %v, want %v", env1, want)
	}

	t2 := time.Unix(1700000005, 987654321)
	env2 := PutEnviron(env1, t2)
	if want := []string{"FOO=bar", "BAZ=qux", "RUNSC_START_TIME_NANOS=1700000005987654321"}; !slices.Equal(env2, want) {
		t.Fatalf("PutEnviron(env1, t2) = %v, want overwritten %v", env2, want)
	}
}

func TestGetFromEnv(t *testing.T) {
	t.Cleanup(resetState)
	want := time.Unix(1700000005, 987654321)
	env := PutEnviron(nil, want)
	key, value, _ := strings.Cut(env[0], "=")
	t.Setenv(key, value)
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
