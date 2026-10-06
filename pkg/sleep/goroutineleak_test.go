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

package sleep_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/syncevent"
)

func waitForPark(t testing.TB, frame string) {
	t.Helper()
	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := runtime.Stack(stack, true)
		for goroutine := range strings.SplitSeq(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, frame) &&
				(strings.Contains(goroutine, "[select]") ||
					strings.Contains(goroutine, "[semacquire]") ||
					strings.Contains(goroutine, "[chan receive]")) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not park in %s", frame)
		}
		runtime.Gosched()
	}
}

// This channel is reachable only from its own blocked goroutine.
func blockedOnUnreachableChannel() {
	ch := make(chan struct{})
	<-ch
}

func TestCustomWaiterSurvivesGoroutineLeakProfile(t *testing.T) {
	profile := pprof.Lookup("goroutineleak")
	if profile == nil {
		t.Skip("Go runtime does not provide goroutineleak profiling")
	}
	const helperEnv = "GVISOR_LEAK_PROFILE_HELPER"
	kind := os.Getenv(helperEnv)
	if kind == "" {
		for _, kind := range []string{"sleeper", "waitfor", "waitandack"} {
			t.Run(kind, func(t *testing.T) {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable,
					"-test.run=^TestCustomWaiterSurvivesGoroutineLeakProfile$")
				cmd.Env = append(os.Environ(), helperEnv+"="+kind)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("worker failed after leak profiling: %v\n%s", err, output)
				}
			})
		}
		return
	}

	var wait func() bool
	var notify, cleanup func()
	var frame string
	if kind == "sleeper" {
		var s sleep.Sleeper
		var w sleep.Waker
		s.AddWaker(&w)
		wait = func() bool { return s.Fetch(true) == &w }
		notify, cleanup = w.Assert, s.Done
		frame = "gvisor.dev/gvisor/pkg/sleep.(*Sleeper).nextWaker"
	} else {
		var w syncevent.Waiter
		w.Init()
		notify = func() { w.Notify(1) }
		cleanup = func() {}
		if kind == "waitfor" {
			wait = func() bool {
				p := w.WaitFor(1)
				w.Ack(p)
				return p == 1
			}
			frame = "gvisor.dev/gvisor/pkg/syncevent.(*Waiter).WaitFor"
		} else {
			wait = func() bool { return w.WaitAndAckAll() == 1 }
			frame = "gvisor.dev/gvisor/pkg/syncevent.(*Waiter).WaitAndAckAll"
		}
	}
	const rounds = 6
	result, done := make(chan bool, 1), make(chan struct{})
	go func() {
		defer close(done)
		for range rounds {
			result <- wait()
		}
	}()
	go blockedOnUnreachableChannel()
	waitForPark(t, ".blockedOnUnreachableChannel")
	for round := range rounds {
		waitForPark(t, frame)
		var output bytes.Buffer
		debug := round % 3
		if err := profile.WriteTo(&output, debug); err != nil {
			t.Fatal(err)
		}
		if debug == 1 {
			if strings.Contains(output.String(), frame) {
				t.Fatal("live custom waiter reported as leaked")
			}
			if !strings.Contains(output.String(), ".blockedOnUnreachableChannel") {
				t.Fatal("real channel leak no longer detected")
			}
		}
		notify()
		select {
		case correct := <-result:
			if !correct {
				t.Fatal("wrong notification")
			}
		case <-time.After(time.Second):
			t.Fatal("worker did not wake after leak profiling")
		}
	}
	<-done
	cleanup()
}

func BenchmarkSleeperAssertFetch(b *testing.B) {
	var s sleep.Sleeper
	var w sleep.Waker
	s.AddWaker(&w)
	defer s.Done()
	b.ReportAllocs()
	for b.Loop() {
		w.Assert()
		if s.Fetch(false) != &w {
			b.Fatal("wrong waker")
		}
	}
}

func BenchmarkSleeperWakeRoundTrip(b *testing.B) {
	var a, c sleep.Sleeper
	var wa, wc sleep.Waker
	a.AddWaker(&wa)
	c.AddWaker(&wc)
	defer a.Done()
	defer c.Done()
	done := make(chan struct{})
	go func() {
		for range b.N {
			c.Fetch(true)
			wa.Assert()
		}
		close(done)
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		wc.Assert()
		a.Fetch(true)
	}
	b.StopTimer()
	<-done
}
