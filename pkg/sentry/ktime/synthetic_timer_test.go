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
	"slices"
	"testing"
	"time"
)

func TestSyntheticClockNow(t *testing.T) {
	var c SyntheticClock
	if got := c.Now(); got.Nanoseconds() != 0 {
		t.Errorf("zero-value SyntheticClock: Now() = %v, want 0", got)
	}
	want := FromSeconds(1)
	c.Store(want)
	if got := c.Now(); got != want {
		t.Errorf("after Store: Now() = %v, want %v", got, want)
	}
	c.Add(10 * time.Second)
	if got, want := c.Now(), FromSeconds(11); got != want {
		t.Errorf("after positive Add: Now() = %v, want %v", got, want)
	}
	c.Add(-5 * time.Second)
	if got, want := c.Now(), FromSeconds(6); got != want {
		t.Errorf("after negative Add: Now() = %v, want %v", got, want)
	}
}

type testRecorder struct {
	vals []int
}

type testRecorderListener struct {
	r   *testRecorder
	val int
}

func (l *testRecorderListener) NotifyTimer(exp uint64) {
	l.r.vals = append(l.r.vals, l.val)
}

func newTestRecorderTimer(c Clock, r *testRecorder, val int, next Time, period time.Duration) Timer {
	t := c.NewTimer(&testRecorderListener{
		r:   r,
		val: val,
	})
	t.Set(Setting{
		Enabled: true,
		Next:    next,
		Period:  period,
	}, nil)
	return t
}

func checkRecordAt(t *testing.T, c *SyntheticClock, r *testRecorder, now Time, want []int) {
	c.Store(now)
	if !slices.Equal(r.vals, want) {
		t.Errorf("at time %v: got %v, want %v", now, r.vals, want)
	}
}

func TestSyntheticTimer(t *testing.T) {
	var (
		c SyntheticClock
		r testRecorder
	)

	// Set up timers.
	//
	// t0 and t1 are "far apart".
	// t1 and t2 are as close as possible. t1 is also periodic.
	// t3 and t4 expire at the same time.
	// t5 occurs between the second and third occurrences of t1.
	newTestRecorderTimer(&c, &r, 0, FromSeconds(2), 0)
	newTestRecorderTimer(&c, &r, 1, FromSeconds(4), 4*time.Second)
	newTestRecorderTimer(&c, &r, 2, FromSeconds(4).Add(time.Nanosecond), 0)
	newTestRecorderTimer(&c, &r, 3, FromSeconds(6), 0)
	newTestRecorderTimer(&c, &r, 4, FromSeconds(6), 0)
	newTestRecorderTimer(&c, &r, 5, FromSeconds(10), 0)

	// The order in which timers expire isn't specified, but is FIFO in the
	// current implementation.
	checkRecordAt(t, &c, &r, FromSeconds(1), []int{})
	checkRecordAt(t, &c, &r, FromSeconds(2), []int{0})
	checkRecordAt(t, &c, &r, FromSeconds(3), []int{0})
	checkRecordAt(t, &c, &r, FromSeconds(4).Add(-time.Nanosecond), []int{0})
	checkRecordAt(t, &c, &r, FromSeconds(4), []int{0, 1})
	checkRecordAt(t, &c, &r, FromSeconds(4).Add(time.Nanosecond), []int{0, 1, 2})
	checkRecordAt(t, &c, &r, FromSeconds(5), []int{0, 1, 2})
	checkRecordAt(t, &c, &r, FromSeconds(6), []int{0, 1, 2, 3, 4})
	checkRecordAt(t, &c, &r, FromSeconds(7), []int{0, 1, 2, 3, 4})
	checkRecordAt(t, &c, &r, FromSeconds(8).Add(-time.Nanosecond), []int{0, 1, 2, 3, 4})
	checkRecordAt(t, &c, &r, FromSeconds(8), []int{0, 1, 2, 3, 4, 1})
	checkRecordAt(t, &c, &r, FromSeconds(8), []int{0, 1, 2, 3, 4, 1})
	checkRecordAt(t, &c, &r, FromSeconds(9), []int{0, 1, 2, 3, 4, 1})
	checkRecordAt(t, &c, &r, FromSeconds(10), []int{0, 1, 2, 3, 4, 1, 5})
	checkRecordAt(t, &c, &r, FromSeconds(11), []int{0, 1, 2, 3, 4, 1, 5})
	checkRecordAt(t, &c, &r, FromSeconds(12), []int{0, 1, 2, 3, 4, 1, 5, 1})
	checkRecordAt(t, &c, &r, FromSeconds(13), []int{0, 1, 2, 3, 4, 1, 5, 1})
	checkRecordAt(t, &c, &r, FromSeconds(14), []int{0, 1, 2, 3, 4, 1, 5, 1})
	checkRecordAt(t, &c, &r, FromSeconds(15), []int{0, 1, 2, 3, 4, 1, 5, 1})
}

func TestSyntheticClockNextExpiration(t *testing.T) {
	var c SyntheticClock
	if exp, ok := c.NextExpiration(); ok {
		t.Errorf("empty SyntheticClock: NextExpiration() = (%v, %v), want (_, false)", exp, ok)
	}

	var r testRecorder
	timer1 := newTestRecorderTimer(&c, &r, 1, FromSeconds(5), 0)
	defer timer1.Destroy()

	if exp, ok := c.NextExpiration(); !ok || exp != FromSeconds(5) {
		t.Errorf("after adding timer1: NextExpiration() = (%v, %v), want (%v, true)", exp, ok, FromSeconds(5))
	}

	timer2 := newTestRecorderTimer(&c, &r, 2, FromSeconds(2), 0)
	defer timer2.Destroy()

	if exp, ok := c.NextExpiration(); !ok || exp != FromSeconds(2) {
		t.Errorf("after adding timer2: NextExpiration() = (%v, %v), want (%v, true)", exp, ok, FromSeconds(2))
	}

	timer2.Destroy()
	if exp, ok := c.NextExpiration(); !ok || exp != FromSeconds(5) {
		t.Errorf("after destroying timer2: NextExpiration() = (%v, %v), want (%v, true)", exp, ok, FromSeconds(5))
	}

	timer1.Destroy()
	if exp, ok := c.NextExpiration(); ok {
		t.Errorf("after destroying all timers: NextExpiration() = (%v, %v), want (_, false)", exp, ok)
	}
}

func TestSyntheticTimerSetBehavior(t *testing.T) {
	testCases := []struct {
		name         string
		clockTime    Time
		initialState Setting
		newSetting   Setting
		wantFired    bool
	}{
		{
			name:      "SetFutureDeadlineDoesNotFire",
			clockTime: FromSeconds(10),
			newSetting: Setting{
				Enabled: true,
				Next:    FromSeconds(15),
			},
			wantFired: false,
		},
		{
			name:      "StopActiveTimerDoesNotFire",
			clockTime: FromSeconds(10),
			initialState: Setting{
				Enabled: true,
				Next:    FromSeconds(15),
			},
			newSetting: Setting{
				Enabled: false,
			},
			wantFired: false,
		},
		{
			name:      "StopInactiveTimerDoesNotFire",
			clockTime: FromSeconds(10),
			newSetting: Setting{
				Enabled: false,
			},
			wantFired: false,
		},
		{
			name:      "SetDeadlineToCurrentTimeFiresImmediately",
			clockTime: FromSeconds(10),
			newSetting: Setting{
				Enabled: true,
				Next:    FromSeconds(10),
			},
			wantFired: true,
		},
		{
			name:      "SetDeadlineToPastTimeFiresImmediately",
			clockTime: FromSeconds(10),
			newSetting: Setting{
				Enabled: true,
				Next:    FromSeconds(5),
			},
			wantFired: true,
		},
		{
			name:      "StopExpiredTimerDoesNotFire",
			clockTime: FromSeconds(10),
			initialState: Setting{
				Enabled: true,
				Next:    FromSeconds(10), // expires immediately upon init
			},
			newSetting: Setting{
				Enabled: false,
			},
			wantFired: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				c SyntheticClock
				r testRecorder
			)
			c.Store(tc.clockTime)
			timer := c.NewTimer(&testRecorderListener{
				r:   &r,
				val: 1,
			})
			defer timer.Destroy()

			if tc.initialState.Enabled {
				timer.Set(tc.initialState, nil)
				r.vals = nil // reset recorded firings before applying newSetting
			}

			timer.Set(tc.newSetting, nil)
			gotFired := len(r.vals) > 0
			if gotFired != tc.wantFired {
				t.Errorf("got fired = %v, want %v", gotFired, tc.wantFired)
			}
		})
	}
}
