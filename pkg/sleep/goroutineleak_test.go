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

package sleep

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoroutineLeakProfile checks that a Sleeper blocked in Fetch is not
// reported by the goroutineleak profile, and that it wakes up after the
// profile is collected.
func TestGoroutineLeakProfile(t *testing.T) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		t.Skip("goroutineleak profile is not available")
	}

	var s Sleeper
	var w Waker
	s.AddWaker(&w)
	done := make(chan struct{})
	go func() {
		s.Fetch(true)
		close(done)
	}()

	// s.waitingG holds the G once the sleep is committed.
	deadline := time.Now().Add(10 * time.Second)
	for g := atomic.LoadUintptr(&s.waitingG); g == 0 || g == preparingG; g = atomic.LoadUintptr(&s.waitingG) {
		if time.Now().After(deadline) {
			t.Fatal("Sleeper did not block")
		}
		time.Sleep(time.Millisecond)
	}

	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if strings.Contains(buf.String(), "pkg/sleep.(*Sleeper).") {
		// Do not wake the goroutine: the runtime throws when it readies a
		// goroutine that it marked as leaked.
		t.Fatalf("goroutineleak profile reports the blocked Sleeper:\n%s", buf.String())
	}

	w.Assert()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Sleeper did not wake up")
	}
	s.Done()
}
