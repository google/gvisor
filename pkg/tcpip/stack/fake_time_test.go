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

package stack

import (
	"container/heap"
	"sync"
	"time"

	"github.com/dpjacques/clockwork"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type fakeClock struct {
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

func newFakeClock() *fakeClock {
	return &fakeClock{
		clock:      clockwork.NewFakeClock(),
		times:      &timeHeap{},
		waitGroups: make(map[time.Time]*sync.WaitGroup),
	}
}

var _ tcpip.Clock = (*fakeClock)(nil)

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (fc *fakeClock) NowNanoseconds() int64 {
	return fc.clock.Now().UnixNano()
}

// NowMonotonic implements tcpip.Clock.NowMonotonic.
func (fc *fakeClock) NowMonotonic() int64 {
	return fc.NowNanoseconds()
}

// AfterFunc implements tcpip.Clock.AfterFunc.
func (fc *fakeClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	until := fc.clock.Now().Add(d)
	wg := fc.addWait(until)
	return &fakeTimer{
		clock: fc,
		until: until,
		timer: fc.clock.AfterFunc(d, func() {
			defer wg.Done()
			f()
		}),
	}
}

// addWait adds an additional wait to the WaitGroup for parallel execution of
// all work scheduled for t. Returns a reference to the WaitGroup modified.
func (fc *fakeClock) addWait(t time.Time) *sync.WaitGroup {
	fc.mu.RLock()
	wg, ok := fc.waitGroups[t]
	fc.mu.RUnlock()

	if ok {
		wg.Add(1)
		return wg
	}

	fc.mu.Lock()
	heap.Push(fc.times, t)
	fc.mu.Unlock()

	wg = &sync.WaitGroup{}
	wg.Add(1)

	fc.mu.Lock()
	fc.waitGroups[t] = wg
	fc.mu.Unlock()

	return wg
}

// removeWait removes a wait from the WaitGroup for parallel execution of all
// work scheduled for t.
func (fc *fakeClock) removeWait(t time.Time) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	wg := fc.waitGroups[t]
	wg.Done()
}

// advance executes all work that have been scheduled to execute within d from
// the current fake time. Blocks until all work has completed execution.
func (fc *fakeClock) advance(d time.Duration) {
	// Block until all the work is done
	until := fc.clock.Now().Add(d)
	for {
		fc.mu.Lock()
		if fc.times.Len() == 0 {
			fc.mu.Unlock()
			return
		}

		t := heap.Pop(fc.times).(time.Time)
		if t.After(until) {
			// No work to do
			heap.Push(fc.times, t)
			fc.mu.Unlock()
			return
		}
		fc.mu.Unlock()

		diff := t.Sub(fc.clock.Now())
		fc.clock.Advance(diff)

		fc.mu.RLock()
		wg := fc.waitGroups[t]
		fc.mu.RUnlock()

		wg.Wait()

		fc.mu.Lock()
		delete(fc.waitGroups, t)
		fc.mu.Unlock()
	}
}

type fakeTimer struct {
	clock *fakeClock
	timer clockwork.Timer

	mu    sync.RWMutex
	until time.Time
}

var _ tcpip.Timer = (*fakeTimer)(nil)

// Reset implements tcpip.Timer.Reset.
func (ft *fakeTimer) Reset(d time.Duration) {
	if !ft.timer.Reset(d) {
		return
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	ft.clock.removeWait(ft.until)
	ft.until = ft.clock.clock.Now().Add(d)
	ft.clock.addWait(ft.until)
}

// Stop implements tcpip.Timer.Stop.
func (ft *fakeTimer) Stop() bool {
	if !ft.timer.Stop() {
		return false
	}

	ft.mu.RLock()
	defer ft.mu.RUnlock()

	ft.clock.removeWait(ft.until)
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
