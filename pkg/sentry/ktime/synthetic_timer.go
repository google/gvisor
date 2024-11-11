// Copyright 2024 The gVisor Authors.
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

package ktime

import (
	"fmt"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sync"
)

// SyntheticTimer implements Timer for SyntheticClocks.
//
// +stateify savable
type SyntheticTimer struct {
	// immutable
	clock    *SyntheticClock
	listener Listener

	// setting is the timer's current setting. setting is protected by
	// clock.mu.
	setting Setting

	// syntheticTimerEntry links the SyntheticTimer into
	// syntheticTimerQueue.timers when setting.Enabled == true.
	// syntheticTimerEntry is protected by mu.
	syntheticTimerEntry
}

// SyntheticClock is a Clock whose current time is set manually by calling
// Store or Add.
//
// +stateify savable
type SyntheticClock struct {
	mu sync.Mutex `state:"nosave"`

	// now is the Clock's current time. Writes to now require that mu is
	// locked.
	now atomicbitops.Int64

	// timers maps each timer expiration time to a list of all enabled timers
	// with that expiration time. timers is protected by mu.
	timers syntheticTimerSet
}

// syntheticTimerQueue is the value type of SyntheticClock.timers.
//
// +stateify savable
type syntheticTimerQueue struct {
	timers syntheticTimerList
}

// NewSyntheticTimer returns an initialized heap-allocated SyntheticTimer.
func NewSyntheticTimer(clock *SyntheticClock, listener Listener) *SyntheticTimer {
	t := &SyntheticTimer{}
	t.Init(clock, listener)
	return t
}

// Init makes a zero-value SyntheticTimer ready for use.
func (t *SyntheticTimer) Init(clock *SyntheticClock, listener Listener) {
	t.clock = clock
	t.listener = listener
}

// Destroy implements Timer.Destroy.
func (t *SyntheticTimer) Destroy() {
	// Just stop the timer.
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.setting.Enabled {
		t.setting.Enabled = false
		t.clock.delTimerLocked(t)
	}
}

// Pause implements Timer.Pause. Since SyntheticTimer expirations are caused by
// changes to the corresponding SyntheticClock's time, Pause is a no-op;
// clients must ensure that the SyntheticClock's time cannot advance while the
// timer is paused.
func (t *SyntheticTimer) Pause() {
}

// Resume implements Timer.Resume. Since Pause is a no-op, Resume is also a
// no-op.
func (t *SyntheticTimer) Resume() {
}

// Clock implements Timer.Clock.
func (t *SyntheticTimer) Clock() Clock {
	return t.clock
}

// Get implements Timer.Get.
func (t *SyntheticTimer) Get() (Time, Setting) {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	// SyntheticTimers are expired synchronously with SyntheticClock time
	// changes, so t.setting is always up to date.
	return t.clock.nowLocked(), t.setting
}

// Set implements Timer.Set.
func (t *SyntheticTimer) Set(s Setting, f func()) (Time, Setting) {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	// SyntheticTimers are expired synchronously with SyntheticClock time
	// changes, so t.setting is always up to date.
	now := t.clock.nowLocked()
	oldS := t.setting
	newS, newExp := s.At(now)
	if f != nil {
		f()
	}
	if oldS != newS {
		if oldS.Enabled {
			t.clock.delTimerLocked(t)
		}
		t.setting = newS
		if newS.Enabled {
			t.clock.addTimerLocked(t)
		}
	}
	if newExp > 0 {
		t.listener.NotifyTimer(newExp)
	}
	return now, oldS
}

// Now implements Clock.Now.
func (c *SyntheticClock) Now() Time {
	return FromNanoseconds(c.now.Load())
}

// Preconditions: c.mu must be locked.
func (c *SyntheticClock) nowLocked() Time {
	return FromNanoseconds(c.now.RacyLoad())
}

// NewTimer implements Clock.NewTimer.
func (c *SyntheticClock) NewTimer(listener Listener) Timer {
	return NewSyntheticTimer(c, listener)
}

// Store sets c's current time to now and notifies expired timers.
//
// Preconditions:
//   - now.Nanoseconds() >= 0.
//   - The caller must not hold locks following Timer methods in the lock order
//     (since Listener notification requires acquiring such locks).
func (c *SyntheticClock) Store(now Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTimeLocked(now.Nanoseconds())
}

// Add increases c's current time by d and notifies expired timers.
//
// Preconditions:
//   - c's resulting current time >= 0.
//   - The caller must not hold locks following Timer methods in the lock order
//     (since Listener notification requires acquiring such locks).
func (c *SyntheticClock) Add(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTimeLocked(c.now.RacyLoad() + delta.Nanoseconds())
}

// Preconditions: c.mu must be locked.
func (c *SyntheticClock) setTimeLocked(nowNS int64) {
	if nowNS < 0 {
		panic(fmt.Sprintf("invalid time %d", nowNS))
	}
	c.now.Store(nowNS)
	now := FromNanoseconds(nowNS)
	// Expire timers.
	for {
		seg := c.timers.FirstSegment()
		if !seg.Ok() || uint64(nowNS) < seg.Start() {
			break
		}
		// Make a copy of the timers list, then remove seg and iterate the
		// copy, since insertion of new segments (for periodic timers) will
		// invalidate seg.
		timers := seg.ValuePtr().timers
		c.timers.Remove(seg)
		for !timers.Empty() {
			t := timers.Front()
			timers.Remove(t)
			s, exp := t.setting.At(now)
			if exp == 0 {
				panic(fmt.Sprintf("ktime.SyntheticClock (time=%d) contains enqueued timer %p for time=%d with unexpired setting %+v", nowNS, t, seg.Start(), t.setting))
			}
			t.setting = s
			t.listener.NotifyTimer(exp)
			if t.setting.Enabled {
				c.addTimerLocked(t)
			}
		}
	}
}

// Preconditions: c.mu must be locked.
func (c *SyntheticClock) addTimerLocked(t *SyntheticTimer) {
	nextNS := uint64(t.setting.Next.Nanoseconds())
	seg, gap := c.timers.Find(nextNS)
	if gap.Ok() {
		seg = c.timers.Insert(gap, uint64Range{nextNS, nextNS + 1}, syntheticTimerQueue{})
	}
	seg.ValuePtr().timers.PushBack(t)
}

// Preconditions: c.mu must be locked.
func (c *SyntheticClock) delTimerLocked(t *SyntheticTimer) {
	nextNS := uint64(t.setting.Next.Nanoseconds())
	seg := c.timers.FindSegment(nextNS)
	if !seg.Ok() {
		panic(fmt.Sprintf("ktime.SyntheticClock (time=%d) does not contain enqueued timer %p for time=%d with setting %+v", c.now.RacyLoad(), t, nextNS, t.setting))
	}
	q := seg.ValuePtr()
	q.timers.Remove(t)
	if q.timers.Empty() {
		c.timers.Remove(seg)
	}
}

type syntheticTimerSetFunctions struct{}

func (syntheticTimerSetFunctions) MinKey() uint64 {
	return 0
}

func (syntheticTimerSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (syntheticTimerSetFunctions) ClearValue(*syntheticTimerQueue) {
}

func (syntheticTimerSetFunctions) Merge(_ uint64Range, _ syntheticTimerQueue, _ uint64Range, _ syntheticTimerQueue) (syntheticTimerQueue, bool) {
	return syntheticTimerQueue{}, false
}

func (syntheticTimerSetFunctions) Split(_ uint64Range, _ syntheticTimerQueue, _ uint64) (syntheticTimerQueue, syntheticTimerQueue) {
	panic("syntheticTimerSetFunctions.Split should never be called")
}
