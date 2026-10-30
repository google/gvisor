// Copyright 2024 The gVisor Authors.
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

// Package starttime holds the time the `runsc` command started.
// It is useful in order to plumb this time wherever needed.
package starttime

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/timing"
)

var (
	setOnce      sync.Once
	processStart time.Time
	goStartTime  time.Time
	envStartTime time.Time
	reexecTime   time.Time
)

// envStartTimeKey is the environment variable that holds the time the `runsc`
// command started. SpawnEnviron sets it, and ReexecEnviron preserves it across
// re-execs of `runsc`.
const envStartTimeKey = "RUNSC_START_TIME_NANOS"

// envReexecTimeKey is the environment variable that holds the time `runsc`
// last re-exec'd itself. Unlike envStartTimeKey, it is only set when `runsc`
// re-execs itself (see ReexecEnviron).
const envReexecTimeKey = "RUNSC_REEXEC_TIME_NANOS"

// timeFromEnv returns the time held by the environment variable key, or the
// zero time if it is unset or invalid.
func timeFromEnv(key string) time.Time {
	nanosStr, found := os.LookupEnv(key)
	if !found {
		return time.Time{}
	}
	nanos, err := strconv.ParseInt(nanosStr, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// Get returns the time the `runsc` command started on a best-effort basis.
// If the RUNSC_START_TIME_NANOS environment variable is set, it is used.
// Otherwise, it tries to get the time from /proc/self/status.
// If neither is available, it returns the time the function was first called.
func Get() time.Time {
	setOnce.Do(func() {
		goStartTime = time.Now()
		reexecTime = timeFromEnv(envReexecTimeKey)
		if envStartTime = timeFromEnv(envStartTimeKey); !envStartTime.IsZero() {
			return // No need to check /proc/self/status.
		}
		if st, err := os.Stat("/proc/self/status"); err == nil {
			processStart = st.ModTime()
		}
	})
	if !envStartTime.IsZero() {
		return envStartTime
	}
	if !processStart.IsZero() {
		return processStart
	}
	return goStartTime
}

// GoStartTime returns the time the `runsc` command's Go code started.
func GoStartTime() time.Time {
	Get()
	return goStartTime
}

// Timer returns a Timer object that is rooted at `runsc` execution start.
// If `runsc` was re-exec'd, this timer will have a midpoint called "re-exec"
// that corresponds to the time of the re-exec.
func Timer(name string) *timing.Timer {
	timer := timing.New(name, Get())
	if !reexecTime.IsZero() {
		timer.ReachedAt("re-exec", reexecTime)
	}
	return timer
}

// SpawnEnviron returns a copy of env to start a new `runsc` process with, such
// as the sandbox process that `runsc create` starts. The new process's start
// time (see Get) is the current time.
func SpawnEnviron(env []string) []string {
	// A newly spawned process starts now and has not re-exec'd, so drop any
	// existing start or re-exec time.
	env = slices.DeleteFunc(slices.Clone(env), func(e string) bool {
		key, _, _ := strings.Cut(e, "=")
		return key == envStartTimeKey || key == envReexecTimeKey
	})
	return append(env, fmt.Sprintf("%s=%d", envStartTimeKey, time.Now().UnixNano()))
}

// ReexecEnviron returns a copy of env for `runsc` to re-exec itself with. The
// re-exec'd process keeps this process's start time (see Get), and records the
// current time as the time of the re-exec (see Timer).
func ReexecEnviron(env []string) []string {
	env = slices.DeleteFunc(slices.Clone(env), func(e string) bool {
		key, _, _ := strings.Cut(e, "=")
		return key == envStartTimeKey || key == envReexecTimeKey
	})
	return append(env,
		fmt.Sprintf("%s=%d", envStartTimeKey, Get().UnixNano()),
		fmt.Sprintf("%s=%d", envReexecTimeKey, time.Now().UnixNano()),
	)
}
