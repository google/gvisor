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

package sentrycmd

import (
	"math"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestSuspendGCForBoot(t *testing.T) {
	runtime.GC()
	origGOGC := debug.SetGCPercent(100)
	origLimit := debug.SetMemoryLimit(math.MaxInt64)
	defer func() {
		debug.SetGCPercent(origGOGC)
		debug.SetMemoryLimit(origLimit)
	}()

	// Unlimited totalMem (0) caps the soft memory limit at 1 GiB.
	s := suspendGCForBoot(0)
	if s == nil {
		t.Fatal("suspendGCForBoot(0) = nil, want non-nil")
	}
	if got, want := debug.SetMemoryLimit(-1), int64(1<<30); got != want {
		t.Fatalf("memory limit = %d, want %d", got, want)
	}
	s.End()

	// Explicit totalMem uses half of totalMem.
	s = suspendGCForBoot(400 << 20)
	if s == nil {
		t.Fatal("suspendGCForBoot(400 MiB) = nil, want non-nil")
	}
	if got, want := debug.SetMemoryLimit(-1), int64(200<<20); got != want {
		t.Fatalf("memory limit = %d, want %d", got, want)
	}
	s.End()

	// Fallback timer automatically resumes GC if the sandbox has not started yet.
	origDelay := bootGCResumeDelay
	bootGCResumeDelay = 10 * time.Millisecond
	defer func() { bootGCResumeDelay = origDelay }()
	s = suspendGCForBoot(0)
	if s == nil {
		t.Fatal("suspendGCForBoot(0) = nil, want non-nil")
	}
	defer s.End()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if debug.SetMemoryLimit(-1) == math.MaxInt64 {
			if got := debug.SetGCPercent(100); got != 100 {
				t.Fatalf("GCPercent after bootGCResumeDelay = %d, want 100", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("GC remained suspended past bootGCResumeDelay")
}
