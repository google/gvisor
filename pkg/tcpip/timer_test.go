// Copyright 2020 The gVisor Authors.
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

package tcpip_test

import (
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	shortDuration  = 1 * time.Nanosecond
	middleDuration = 100 * time.Millisecond
	longDuration   = 1 * time.Second
)

func TestCancellableTimerReassignment(t *testing.T) {
	var timer tcpip.CancellableTimer
	var wg sync.WaitGroup
	var lock sync.Mutex

	for i := 0; i < 2; i++ {
		wg.Add(1)

		go func() {
			lock.Lock()
			// Assigning a new timer value updates the timer's locker and function.
			// This test makes sure there is no data race when reassigning a timer
			// that has an active timer (even if it has been stopped as a stopped
			// timer may be blocked on a lock before it can check if it has been
			// stopped while another goroutine holds the same lock).
			timer = *tcpip.NewCancellableTimer(&lock, func() {
				wg.Done()
			})
			timer.Reset(shortDuration)
			lock.Unlock()
		}()
	}
	wg.Wait()
}

func TestCancellableTimerFire(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	timer := tcpip.NewCancellableTimer(&lock, func() {
		ch <- struct{}{}
	})
	timer.Reset(shortDuration)

	// Wait for timer to fire.
	select {
	case <-ch:
	case <-time.After(middleDuration):
		t.Fatal("timed out waiting for timer to fire")
	}

	// The timer should have fired only once.
	select {
	case <-ch:
		t.Fatal("no other timers should have fired")
	case <-time.After(middleDuration):
	}
}

func TestCancellableTimerResetFromLongDuration(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
	timer.Reset(middleDuration)

	lock.Lock()
	timer.StopLocked()
	lock.Unlock()

	timer.Reset(shortDuration)

	// Wait for timer to fire.
	select {
	case <-ch:
	case <-time.After(middleDuration):
		t.Fatal("timed out waiting for timer to fire")
	}

	// The timer should have fired only once.
	select {
	case <-ch:
		t.Fatal("no other timers should have fired")
	case <-time.After(middleDuration):
	}
}

func TestCancellableTimerResetFromShortDuration(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	lock.Lock()
	timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
	timer.Reset(shortDuration)
	timer.StopLocked()
	lock.Unlock()

	// Wait for timer to fire if it wasn't correctly stopped.
	select {
	case <-ch:
		t.Fatal("timer fired after being stopped")
	case <-time.After(middleDuration):
	}

	timer.Reset(shortDuration)

	// Wait for timer to fire.
	select {
	case <-ch:
	case <-time.After(middleDuration):
		t.Fatal("timed out waiting for timer to fire")
	}

	// The timer should have fired only once.
	select {
	case <-ch:
		t.Fatal("no other timers should have fired")
	case <-time.After(middleDuration):
	}
}

func TestCancellableTimerImmediatelyStop(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	for i := 0; i < 1000; i++ {
		lock.Lock()
		timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
		timer.Reset(shortDuration)
		timer.StopLocked()
		lock.Unlock()
	}

	// Wait for timer to fire if it wasn't correctly stopped.
	select {
	case <-ch:
		t.Fatal("timer fired after being stopped")
	case <-time.After(middleDuration):
	}
}

func TestCancellableTimerStoppedResetWithoutLock(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	lock.Lock()
	timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
	timer.Reset(shortDuration)
	timer.StopLocked()
	lock.Unlock()

	for i := 0; i < 10; i++ {
		timer.Reset(middleDuration)

		lock.Lock()
		// Sleep until the timer fires and gets blocked trying to take the lock.
		time.Sleep(middleDuration * 2)
		timer.StopLocked()
		lock.Unlock()
	}

	// Wait for double the duration so timers that weren't correctly stopped can
	// fire.
	select {
	case <-ch:
		t.Fatal("timer fired after being stopped")
	case <-time.After(middleDuration * 2):
	}
}

func TestManyCancellableTimerResetAfterBlockedOnLock(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	lock.Lock()
	timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
	timer.Reset(shortDuration)
	for i := 0; i < 10; i++ {
		// Sleep until the timer fires and gets blocked trying to take the lock.
		time.Sleep(middleDuration)
		timer.StopLocked()
		timer.Reset(shortDuration)
	}
	lock.Unlock()

	// Wait for double the duration for the last timer to fire.
	select {
	case <-ch:
	case <-time.After(middleDuration):
		t.Fatal("timed out waiting for timer to fire")
	}

	// The timer should have fired only once.
	select {
	case <-ch:
		t.Fatal("no other timers should have fired")
	case <-time.After(middleDuration):
	}
}

func TestManyCancellableTimerResetUnderLock(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	var lock sync.Mutex

	lock.Lock()
	timer := tcpip.NewCancellableTimer(&lock, func() { ch <- struct{}{} })
	timer.Reset(shortDuration)
	for i := 0; i < 10; i++ {
		timer.StopLocked()
		timer.Reset(shortDuration)
	}
	lock.Unlock()

	// Wait for double the duration for the last timer to fire.
	select {
	case <-ch:
	case <-time.After(middleDuration):
		t.Fatal("timed out waiting for timer to fire")
	}

	// The timer should have fired only once.
	select {
	case <-ch:
		t.Fatal("no other timers should have fired")
	case <-time.After(middleDuration):
	}
}
