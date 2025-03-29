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
)

// envStartTimeKey is the environment variable that holds the time the `runsc`
// command started. This is used to track the actual start time across
// re-execs of `runsc`.
const envStartTimeKey = "RUNSC_START_TIME_NANOS"

// Get returns the time the `runsc` command started on a best-effort basis.
// If the RUNSC_START_TIME_NANOS environment variable is set, it is used.
// Otherwise, it tries to get the time from /proc/self/status.
// If neither is available, it returns the time the function was first called.
func Get() time.Time {
	setOnce.Do(func() {
		goStartTime = time.Now()
		if startTimeStr, found := os.LookupEnv(envStartTimeKey); found {
			if startTime, err := strconv.ParseInt(startTimeStr, 10, 64); err == nil {
				envStartTime = time.Unix(0, startTime)
				return // No need to check /proc/self/status.
			}
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
	if !envStartTime.IsZero() {
		if !processStart.IsZero() {
			timer.ReachedAt("re-exec", processStart)
		} else {
			timer.ReachedAt("re-exec", goStartTime)
		}
	}
	return timer
}

// AppendEnviron appends the RUNSC_START_TIME_NANOS environment variable to
// the given environment, if it is not already present. Otherwise, it is
// preserved.
func AppendEnviron(env []string) []string {
	const envVarPrefix = envStartTimeKey + "="
	for _, e := range env {
		if strings.HasPrefix(e, envVarPrefix) {
			return env
		}
	}
	return append(env, fmt.Sprintf("%s=%d", envStartTimeKey, Get().UnixNano()))
}
