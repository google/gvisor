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
)

func TestJobReschedule(t *testing.T) {
	clock := tcpip.NewStdClock()
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
			job := tcpip.NewJob(clock, &lock, func() {
				wg.Done()
			})
			job.Schedule(shortDuration)
			lock.Unlock()
		}()
	}
	wg.Wait()
}

func TestJobExecution(t *testing.T) {
	t.Parallel()

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	job := tcpip.NewJob(clock, &lock, func() {
		ch <- struct{}{}
	})
	job.Schedule(shortDuration)

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

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
	job.Schedule(middleDuration)

	lock.Lock()
	job.Cancel()
	lock.Unlock()

	job.Schedule(shortDuration)

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

func TestJobRescheduleFromShortDuration(t *testing.T) {
	t.Parallel()

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	lock.Lock()
	job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
	job.Schedule(shortDuration)
	job.Cancel()
	lock.Unlock()

	// Wait for timer to fire if it wasn't correctly stopped.
	select {
	case <-ch:
		t.Fatal("timer fired after being stopped")
	case <-time.After(middleDuration):
	}

	job.Schedule(shortDuration)

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

func TestJobImmediatelyCancel(t *testing.T) {
	t.Parallel()

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	for i := 0; i < 1000; i++ {
		lock.Lock()
		job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
		job.Schedule(shortDuration)
		job.Cancel()
		lock.Unlock()
	}

	// Wait for timer to fire if it wasn't correctly stopped.
	select {
	case <-ch:
		t.Fatal("timer fired after being stopped")
	case <-time.After(middleDuration):
	}
}

func TestJobCancelledRescheduleWithoutLock(t *testing.T) {
	t.Parallel()

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	lock.Lock()
	job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
	job.Schedule(shortDuration)
	job.Cancel()
	lock.Unlock()

	for i := 0; i < 10; i++ {
		job.Schedule(middleDuration)

		lock.Lock()
		// Sleep until the timer fires and gets blocked trying to take the lock.
		time.Sleep(middleDuration * 2)
		job.Cancel()
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

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	lock.Lock()
	job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
	job.Schedule(shortDuration)
	for i := 0; i < 10; i++ {
		// Sleep until the timer fires and gets blocked trying to take the lock.
		time.Sleep(middleDuration)
		job.Cancel()
		job.Schedule(shortDuration)
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

func TestManyJobReschedulesUnderLock(t *testing.T) {
	t.Parallel()

	clock := tcpip.NewStdClock()
	var lock sync.Mutex
	ch := make(chan struct{})

	lock.Lock()
	job := tcpip.NewJob(clock, &lock, func() { ch <- struct{}{} })
	job.Schedule(shortDuration)
	for i := 0; i < 10; i++ {
		job.Cancel()
		job.Schedule(shortDuration)
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
