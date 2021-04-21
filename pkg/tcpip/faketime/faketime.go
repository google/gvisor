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

// Package faketime provides a fake clock that implements tcpip.Clock interface.
package faketime

import (
	"container/heap"
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// NullClock implements a clock that never advances.
type NullClock struct{}

var _ tcpip.Clock = (*NullClock)(nil)

// NowNanoseconds implements tcpip.Clock.
func (*NullClock) NowNanoseconds() int64 {
	return 0
}

// NowMonotonicNS implements tcpip.Clock.
func (*NullClock) NowMonotonicNS() int64 {
	return 0
}

// AfterFunc implements tcpip.Clock.
func (*NullClock) AfterFunc(time.Duration, func()) tcpip.Timer {
	return nil
}

type notificationChannels struct {
	mu struct {
		sync.Mutex

		ch []<-chan struct{}
	}
}

func (n *notificationChannels) add(ch <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mu.ch = append(n.mu.ch, ch)
}

// wait returns once all the notification channels are readable.
//
// Channels that are added while waiting on existing channels will be waited on
// as well.
func (n *notificationChannels) wait() {
	for {
		n.mu.Lock()
		ch := n.mu.ch
		n.mu.ch = nil
		n.mu.Unlock()

		if len(ch) == 0 {
			break
		}

		for _, c := range ch {
			<-c
		}
	}
}

// ManualClock implements tcpip.Clock and only advances manually with Advance
// method.
type ManualClock struct {
	// runningTimers tracks the completion of timer callbacks that began running
	// immediately upon their scheduling. It is used to ensure the proper ordering
	// of timer callback dispatch.
	runningTimers notificationChannels

	mu struct {
		sync.RWMutex

		// now is the current (fake) time of the clock.
		now time.Time

		// times is min-heap of times.
		times timeHeap

		// timers holds the timers scheduled for each time.
		timers map[time.Time]map[*manualTimer]struct{}
	}
}

// NewManualClock creates a new ManualClock instance.
func NewManualClock() *ManualClock {
	c := &ManualClock{}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Set the initial time to a non-zero value since the zero value is used to
	// detect inactive timers.
	c.mu.now = time.Unix(0, 0)
	c.mu.timers = make(map[time.Time]map[*manualTimer]struct{})

	return c
}

var _ tcpip.Clock = (*ManualClock)(nil)

// NowNanoseconds implements tcpip.Clock.
func (mc *ManualClock) NowNanoseconds() int64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.mu.now.UnixNano()
}

// NowMonotonicNS implements tcpip.Clock.
func (mc *ManualClock) NowMonotonicNS() int64 {
	return mc.NowNanoseconds()
}

// AfterFunc implements tcpip.Clock.
func (mc *ManualClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	mt := &manualTimer{
		clock: mc,
		f:     f,
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	mc.resetTimerLocked(mt, d)
	return mt
}

// resetTimerLocked schedules a timer to be fired after the given duration.
//
// Precondition: mc.mu and mt.mu must be locked.
func (mc *ManualClock) resetTimerLocked(mt *manualTimer, d time.Duration) {
	if !mt.mu.firesAt.IsZero() {
		panic("tried to reset an active timer")
	}

	t := mc.mu.now.Add(d)

	if !mc.mu.now.Before(t) {
		// If the timer is scheduled to fire immediately, call its callback
		// in a new goroutine immediately.
		//
		// It needs to be called in its own goroutine to escape its current
		// execution context - like an actual timer.
		ch := make(chan struct{})
		mc.runningTimers.add(ch)

		go func() {
			defer close(ch)

			mt.f()
		}()

		return
	}

	mt.mu.firesAt = t

	timers, ok := mc.mu.timers[t]
	if !ok {
		timers = make(map[*manualTimer]struct{})
		mc.mu.timers[t] = timers
		heap.Push(&mc.mu.times, t)
	}

	timers[mt] = struct{}{}
}

// stopTimerLocked stops a timer from firing.
//
// Precondition: mc.mu and mt.mu must be locked.
func (mc *ManualClock) stopTimerLocked(mt *manualTimer) {
	t := mt.mu.firesAt
	mt.mu.firesAt = time.Time{}

	if t.IsZero() {
		panic("tried to stop an inactive timer")
	}

	timers, ok := mc.mu.timers[t]
	if !ok {
		err := fmt.Sprintf("tried to stop an active timer but the clock does not have anything scheduled for the timer @ t = %s %p\nScheduled timers @:", t.UTC(), mt)
		for t := range mc.mu.timers {
			err += fmt.Sprintf("%s\n", t.UTC())
		}
		panic(err)
	}

	if _, ok := timers[mt]; !ok {
		panic(fmt.Sprintf("did not have an entry in timers for an active timer @ t = %s", t.UTC()))
	}

	delete(timers, mt)

	if len(timers) == 0 {
		delete(mc.mu.timers, t)
	}
}

// Advance executes all work that have been scheduled to execute within d from
// the current time. Blocks until all work has completed execution.
func (mc *ManualClock) Advance(d time.Duration) {
	// We spawn goroutines for timers that were scheduled to fire at the time of
	// being reset. Wait for those goroutines to complete before proceeding so
	// that timer callbacks are called in the right order.
	mc.runningTimers.wait()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	until := mc.mu.now.Add(d)
	for mc.mu.times.Len() > 0 {
		t := heap.Pop(&mc.mu.times).(time.Time)
		if t.After(until) {
			// No work to do
			heap.Push(&mc.mu.times, t)
			break
		}

		timers := mc.mu.timers[t]
		delete(mc.mu.timers, t)

		mc.mu.now = t

		// Mark the timers as inactive since they will be fired.
		//
		// This needs to be done while holding mc's lock because we remove the entry
		// in the map of timers for the current time. If an attempt to stop a
		// timer is made after mc's lock was dropped but before the timer is
		// marked inactive, we would panic since no entry exists for the time when
		// the timer was expected to fire.
		for mt := range timers {
			mt.mu.Lock()
			mt.mu.firesAt = time.Time{}
			mt.mu.Unlock()
		}

		// Release the lock before calling the timer's callback fn since the
		// callback fn might try to schedule a timer which requires obtaining
		// mc's lock.
		mc.mu.Unlock()

		for mt := range timers {
			mt.f()
		}

		// The timer callbacks may have scheduled a timer to fire immediately.
		// We spawn goroutines for these timers and need to wait for them to
		// finish before proceeding so that timer callbacks are called in the
		// right order.
		mc.runningTimers.wait()
		mc.mu.Lock()
	}

	mc.mu.now = until
}

func (mc *ManualClock) resetTimer(mt *manualTimer, d time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	if !mt.mu.firesAt.IsZero() {
		mc.stopTimerLocked(mt)
	}

	mc.resetTimerLocked(mt, d)
}

func (mc *ManualClock) stopTimer(mt *manualTimer) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	if mt.mu.firesAt.IsZero() {
		return false
	}

	mc.stopTimerLocked(mt)
	return true
}

type manualTimer struct {
	clock *ManualClock
	f     func()

	mu struct {
		sync.Mutex

		// firesAt is the time when the timer will fire.
		//
		// Zero only when the timer is not active.
		firesAt time.Time
	}
}

var _ tcpip.Timer = (*manualTimer)(nil)

// Reset implements tcpip.Timer.Reset.
func (mt *manualTimer) Reset(d time.Duration) {
	mt.clock.resetTimer(mt, d)
}

// Stop implements tcpip.Timer.Stop.
func (mt *manualTimer) Stop() bool {
	return mt.clock.stopTimer(mt)
}

type timeHeap []time.Time

var _ heap.Interface = (*timeHeap)(nil)

func (h timeHeap) Len() int {
	return len(h)
}

func (h timeHeap) Less(i, j int) bool {
	return h[i].Before(h[j])
}

func (h timeHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *timeHeap) Push(x interface{}) {
	*h = append(*h, x.(time.Time))
}

func (h *timeHeap) Pop() interface{} {
	last := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return last
}
