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
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/timing"
)

var (
	setOnce      sync.Once
	processStart time.Time
	goStartTime  time.Time
)

// Get returns the time the `runsc` command started.
// It tries to get the time from /proc/self/status if possible, otherwise it
// returns the time the function was first called.
func Get() time.Time {
	setOnce.Do(func() {
		goStartTime = time.Now()
		if st, err := os.Stat("/proc/self/status"); err == nil {
			processStart = st.ModTime()
		}
	})
	if processStart.IsZero() {
		return goStartTime
	}
	return processStart
}

// GoStartTime returns the time the `runsc` command's Go code started.
func GoStartTime() time.Time {
	Get()
	return goStartTime
}

// Timer returns a Timer object that is rooted at `runsc` execution start.
func Timer() *timing.Timer {
	return timing.New("runsc", Get())
}
