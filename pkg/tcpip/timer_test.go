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
	"math"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestMonotonicTimeBefore(t *testing.T) {
	var mt tcpip.MonotonicTime
	if mt.Before(mt) {
		t.Errorf("%#v.Before(%#v)", mt, mt)
	}

	one := mt.Add(1)
	if one.Before(mt) {
		t.Errorf("%#v.Before(%#v)", one, mt)
	}
	if !mt.Before(one) {
		t.Errorf("!%#v.Before(%#v)", mt, one)
	}
}

func TestMonotonicTimeAfter(t *testing.T) {
	var mt tcpip.MonotonicTime
	if mt.After(mt) {
		t.Errorf("%#v.After(%#v)", mt, mt)
	}

	one := mt.Add(1)
	if mt.After(one) {
		t.Errorf("%#v.After(%#v)", mt, one)
	}
	if !one.After(mt) {
		t.Errorf("!%#v.After(%#v)", one, mt)
	}
}

func TestMonotonicTimeAddSub(t *testing.T) {
	var mt tcpip.MonotonicTime
	if one, two := mt.Add(2), mt.Add(1).Add(1); one != two {
		t.Errorf("mt.Add(2) != mt.Add(1).Add(1) (%#v != %#v)", one, two)
	}

	min := mt.Add(math.MinInt64)
	max := mt.Add(math.MaxInt64)

	if overflow := mt.Add(1).Add(math.MaxInt64); overflow != max {
		t.Errorf("mt.Add(math.MaxInt64) != mt.Add(1).Add(math.MaxInt64) (%#v != %#v)", max, overflow)
	}
	if underflow := mt.Add(-1).Add(math.MinInt64); underflow != min {
		t.Errorf("mt.Add(math.MinInt64) != mt.Add(-1).Add(math.MinInt64) (%#v != %#v)", min, underflow)
	}

	if got, want := min.Sub(min), time.Duration(0); want != got {
		t.Errorf("got min.Sub(min) = %d, want %d", got, want)
	}
	if got, want := max.Sub(max), time.Duration(0); want != got {
		t.Errorf("got max.Sub(max) = %d, want %d", got, want)
	}

	if overflow, want := max.Sub(min), time.Duration(math.MaxInt64); overflow != want {
		t.Errorf("mt.Add(math.MaxInt64).Sub(mt.Add(math.MinInt64) != %s (%#v)", want, overflow)
	}
	if underflow, want := min.Sub(max), time.Duration(math.MinInt64); underflow != want {
		t.Errorf("mt.Add(math.MinInt64).Sub(mt.Add(math.MaxInt64) != %s (%#v)", want, underflow)
	}
}

func TestMonotonicTimeSub(t *testing.T) {
	var mt tcpip.MonotonicTime

	if one, two := mt.Add(2), mt.Add(1).Add(1); one != two {
		t.Errorf("mt.Add(2) != mt.Add(1).Add(1) (%#v != %#v)", one, two)
	}

	if max, overflow := mt.Add(math.MaxInt64), mt.Add(1).Add(math.MaxInt64); max != overflow {
		t.Errorf("mt.Add(math.MaxInt64) != mt.Add(1).Add(math.MaxInt64) (%#v != %#v)", max, overflow)
	}
	if max, underflow := mt.Add(math.MinInt64), mt.Add(-1).Add(math.MinInt64); max != underflow {
		t.Errorf("mt.Add(math.MinInt64) != mt.Add(-1).Add(math.MinInt64) (%#v != %#v)", max, underflow)
	}
}

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
