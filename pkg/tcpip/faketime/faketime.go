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
	"sync"
	"time"

	"github.com/dpjacques/clockwork"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// NullClock implements a clock that never advances.
type NullClock struct{}

var _ tcpip.Clock = (*NullClock)(nil)

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (*NullClock) NowNanoseconds() int64 {
	return 0
}

// NowMonotonic implements tcpip.Clock.NowMonotonic.
func (*NullClock) NowMonotonic() int64 {
	return 0
}

// AfterFunc implements tcpip.Clock.AfterFunc.
func (*NullClock) AfterFunc(time.Duration, func()) tcpip.Timer {
	return nil
}

// ManualClock implements tcpip.Clock and only advances manually with Advance
// method.
type ManualClock struct {
	clock clockwork.FakeClock

	// mu protects the fields below.
	mu sync.RWMutex

	// times is min-heap of times. A heap is used for quick retrieval of the next
	// upcoming time of scheduled work.
	times *timeHeap

	// waitGroups stores one WaitGroup for all work scheduled to execute at the
	// same time via AfterFunc. This allows parallel execution of all functions
	// passed to AfterFunc scheduled for the same time.
	waitGroups map[time.Time]*sync.WaitGroup
}

// NewManualClock creates a new ManualClock instance.
func NewManualClock() *ManualClock {
	return &ManualClock{
		clock:      clockwork.NewFakeClock(),
		times:      &timeHeap{},
		waitGroups: make(map[time.Time]*sync.WaitGroup),
	}
}

var _ tcpip.Clock = (*ManualClock)(nil)

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (mc *ManualClock) NowNanoseconds() int64 {
	return mc.clock.Now().UnixNano()
}

// NowMonotonic implements tcpip.Clock.NowMonotonic.
func (mc *ManualClock) NowMonotonic() int64 {
	return mc.NowNanoseconds()
}

// AfterFunc implements tcpip.Clock.AfterFunc.
func (mc *ManualClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	until := mc.clock.Now().Add(d)
	wg := mc.addWait(until)
	return &manualTimer{
		clock: mc,
		until: until,
		timer: mc.clock.AfterFunc(d, func() {
			defer wg.Done()
			f()
		}),
	}
}

// addWait adds an additional wait to the WaitGroup for parallel execution of
// all work scheduled for t. Returns a reference to the WaitGroup modified.
func (mc *ManualClock) addWait(t time.Time) *sync.WaitGroup {
	mc.mu.RLock()
	wg, ok := mc.waitGroups[t]
	mc.mu.RUnlock()

	if ok {
		wg.Add(1)
		return wg
	}

	mc.mu.Lock()
	heap.Push(mc.times, t)
	mc.mu.Unlock()

	wg = &sync.WaitGroup{}
	wg.Add(1)

	mc.mu.Lock()
	mc.waitGroups[t] = wg
	mc.mu.Unlock()

	return wg
}

// removeWait removes a wait from the WaitGroup for parallel execution of all
// work scheduled for t.
func (mc *ManualClock) removeWait(t time.Time) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	wg := mc.waitGroups[t]
	wg.Done()
}

// Advance executes all work that have been scheduled to execute within d from
// the current  time. Blocks until all work has completed execution.
func (mc *ManualClock) Advance(d time.Duration) {
	// Block until all the work is done
	until := mc.clock.Now().Add(d)
	for {
		mc.mu.Lock()
		if mc.times.Len() == 0 {
			mc.mu.Unlock()
			break
		}

		t := heap.Pop(mc.times).(time.Time)
		if t.After(until) {
			// No work to do
			heap.Push(mc.times, t)
			mc.mu.Unlock()
			break
		}
		mc.mu.Unlock()

		diff := t.Sub(mc.clock.Now())
		mc.clock.Advance(diff)

		mc.mu.RLock()
		wg := mc.waitGroups[t]
		mc.mu.RUnlock()

		wg.Wait()

		mc.mu.Lock()
		delete(mc.waitGroups, t)
		mc.mu.Unlock()
	}
	if now := mc.clock.Now(); until.After(now) {
		mc.clock.Advance(until.Sub(now))
	}
}

type manualTimer struct {
	clock *ManualClock
	timer clockwork.Timer

	mu    sync.RWMutex
	until time.Time
}

var _ tcpip.Timer = (*manualTimer)(nil)

// Reset implements tcpip.Timer.Reset.
func (t *manualTimer) Reset(d time.Duration) {
	if !t.timer.Reset(d) {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.clock.removeWait(t.until)
	t.until = t.clock.clock.Now().Add(d)
	t.clock.addWait(t.until)
}

// Stop implements tcpip.Timer.Stop.
func (t *manualTimer) Stop() bool {
	if !t.timer.Stop() {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	t.clock.removeWait(t.until)
	return true
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
