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

package syncevent

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoroutineLeakProfile checks that a Waiter blocked in WaitFor or
// WaitAndAckAll is not reported by the goroutineleak profile, and that it
// wakes up after the profile is collected.
func TestGoroutineLeakProfile(t *testing.T) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		t.Skip("goroutineleak profile is not available")
	}

	for _, test := range []struct {
		name string
		wait func(w *Waiter)
	}{
		{
			name: "WaitFor",
			wait: func(w *Waiter) { w.Ack(w.WaitFor(1)) },
		},
		{
			name: "WaitAndAckAll",
			wait: func(w *Waiter) { w.WaitAndAckAll() },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var w Waiter
			w.Init()
			done := make(chan struct{})
			go func() {
				test.wait(&w)
				close(done)
			}()

			// w.g holds the G once the sleep is committed.
			deadline := time.Now().Add(10 * time.Second)
			for g := atomic.LoadUintptr(&w.g); g == 0 || g == preparingG; g = atomic.LoadUintptr(&w.g) {
				if time.Now().After(deadline) {
					t.Fatal("Waiter did not block")
				}
				time.Sleep(time.Millisecond)
			}

			var buf bytes.Buffer
			if err := p.WriteTo(&buf, 1); err != nil {
				t.Fatalf("WriteTo failed: %v", err)
			}
			if strings.Contains(buf.String(), "pkg/syncevent.(*Waiter)."+test.name) {
				// Do not wake the goroutine: the runtime throws when it
				// readies a goroutine that it marked as leaked.
				t.Fatalf("goroutineleak profile reports the blocked Waiter:\n%s", buf.String())
			}

			w.Notify(1)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Waiter did not wake up")
			}
		})
	}
}
