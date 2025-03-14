// Copyright 2025 The gVisor Authors.
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

// Package gomaxprocs synchronizes adjustments to GOMAXPROCS. When this package
// is active (i.e. after the first call to SetBase), it sets the value of
// GOMAXPROCS to a "base" value (which should be set by a single goroutine,
// without races) plus a non-negative "temporary" value (which may be
// concurrently increased or decreased by multiple goroutines).
//
// Note that changing GOMAXPROCS stops the world, so callers should adjust
// GOMAXPROCS infrequently.
//
// TODO: Add gomaxprocs.Get() and check that other gVisor packages don't call
// runtime.GOMAXPROCS() at all.
package gomaxprocs

import (
	"runtime"

	"gvisor.dev/gvisor/pkg/log"
)

var (
	mu gomaxprocsMutex
	// +checklocks:mu
	base int
	// +checklocks:mu
	temp int
)

// SetBase sets base GOMAXPROCS.
func SetBase(n int) {
	if n < 1 {
		log.Traceback("Invalid base GOMAXPROCS: %d", n)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	oldBase := base
	base = n
	updateRuntime(oldBase, temp)
}

// Add adds n temporary GOMAXPROCS. n may be negative; callers should call Add
// with negative n to remove temporary GOMAXPROCS when they are no longer
// needed.
func Add(n int) {
	mu.Lock()
	defer mu.Unlock()
	t := temp + n
	if t < 0 {
		log.Traceback("gomaxprocs.Add(%d) would cause temp to become %d", n, t)
		return
	}
	oldTemp := temp
	temp = t
	if base != 0 {
		updateRuntime(base, oldTemp)
	}
}

// +checklocks:mu
func updateRuntime(oldBase, oldTemp int) {
	n := base + temp
	log.Debugf("Setting GOMAXPROCS to %d", n)
	got := runtime.GOMAXPROCS(n)
	if want := oldBase + oldTemp; oldBase != 0 && got != want {
		// Something changed GOMAXPROCS outside of our control.
		log.Warningf("Previous GOMAXPROCS was %d, expected %d = %d + %d", got, want, oldBase, oldTemp)
	}
}
