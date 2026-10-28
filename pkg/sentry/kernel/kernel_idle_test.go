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

package kernel

import (
	"testing"
	"testing/synctest"
	"time"
)

const testIdleDelay = 100 * time.Millisecond

// newIdleTestKernel returns a Kernel with only the state that WaitForIdle
// uses, as if it had started and a task was running.
func newIdleTestKernel() *Kernel {
	k := &Kernel{tasks: &TaskSet{}}
	k.runningTasksCond.L = &k.runningTasksMu
	k.cpuClockTickerStopCond.L = &k.runningTasksMu
	k.taskActivityCh = make(chan struct{})
	k.runningTasks.Store(1)
	k.cpuClockTickerRunning = true
	return k
}

// setActive simulates a task starting to run (if active is true), or the CPU
// clock ticker stopping after all tasks stopped running (if active is false).
func (k *Kernel) setActive(active bool) {
	k.runningTasksMu.Lock()
	defer k.runningTasksMu.Unlock()
	if active {
		k.runningTasks.Store(1)
		k.cpuClockTickerRunning = true
		close(k.taskActivityCh)
		k.taskActivityCh = make(chan struct{})
		return
	}
	k.runningTasks.Store(0)
	k.cpuClockTickerRunning = false
	k.cpuClockTickerStopCond.Broadcast()
}

func (k *Kernel) setPaused(paused bool) {
	k.tasks.mu.Lock()
	defer k.tasks.mu.Unlock()
	if paused {
		k.tasks.stopCount = 1
	} else {
		k.tasks.stopCount = 0
	}
}

// waitForIdleAsync calls k.WaitForIdle(testIdleDelay) in a new goroutine. The
// returned channel receives the time at which it returns.
func waitForIdleAsync(k *Kernel) <-chan time.Time {
	done := make(chan time.Time, 1)
	go func() {
		k.WaitForIdle(testIdleDelay)
		done <- time.Now()
	}()
	return done
}

// expectNotReturned checks that WaitForIdle doesn't return for a long time.
func expectNotReturned(t *testing.T, done <-chan time.Time, when string) {
	t.Helper()
	time.Sleep(time.Hour)
	synctest.Wait()
	select {
	case <-done:
		t.Fatalf("%s: WaitForIdle returned", when)
	default:
	}
}

// expectReturnedAt checks that WaitForIdle returns at want.
func expectReturnedAt(t *testing.T, done <-chan time.Time, want time.Time) {
	t.Helper()
	if got := <-done; !got.Equal(want) {
		t.Errorf("WaitForIdle returned %v after the expected time", got.Sub(want))
	}
}

func TestWaitForIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleTestKernel()
		done := waitForIdleAsync(k)
		expectNotReturned(t, done, "while active")
		k.setActive(false)
		expectReturnedAt(t, done, time.Now().Add(testIdleDelay))
	})
}

func TestWaitForIdleAlreadyIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleTestKernel()
		k.setActive(false)
		done := waitForIdleAsync(k)
		expectReturnedAt(t, done, time.Now().Add(testIdleDelay))
	})
}

func TestWaitForIdleActivityRestartsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleTestKernel()
		done := waitForIdleAsync(k)
		for i := 0; i < 3; i++ {
			k.setActive(false)
			time.Sleep(testIdleDelay / 2)
			k.setActive(true)
			time.Sleep(time.Millisecond)
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatalf("WaitForIdle returned after short idle periods")
		default:
		}
		k.setActive(false)
		expectReturnedAt(t, done, time.Now().Add(testIdleDelay))
	})
}

func TestWaitForIdlePaused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k := newIdleTestKernel()
		done := waitForIdleAsync(k)
		k.setPaused(true)
		k.setActive(false)
		expectNotReturned(t, done, "while paused")
		// Resuming the kernel runs its tasks, at least briefly.
		k.setPaused(false)
		k.setActive(true)
		k.setActive(false)
		expectReturnedAt(t, done, time.Now().Add(testIdleDelay))
	})
}
