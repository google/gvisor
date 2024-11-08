// Copyright 2018 The gVisor Authors.
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

// Package ktime provides an API for clocks and timers implemented by the
// sentry.
package ktime

import (
	"fmt"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// Time represents an instant in time with nanosecond precision.
//
// Time may represent time with respect to any clock and may not have any
// meaning in the real world.
//
// +stateify savable
type Time struct {
	ns int64
}

var (
	// MinTime is the zero time instant, the lowest possible time that can
	// be represented by Time.
	MinTime = Time{ns: math.MinInt64}

	// MaxTime is the highest possible time that can be represented by
	// Time.
	MaxTime = Time{ns: math.MaxInt64}

	// ZeroTime represents the zero time in an unspecified Clock's domain.
	ZeroTime = Time{ns: 0}
)

const (
	// MinDuration is the minimum duration representable by time.Duration.
	MinDuration = time.Duration(math.MinInt64)

	// MaxDuration is the maximum duration representable by time.Duration.
	MaxDuration = time.Duration(math.MaxInt64)
)

// FromNanoseconds returns a Time representing the point ns nanoseconds after
// an unspecified Clock's zero time.
func FromNanoseconds(ns int64) Time {
	return Time{ns}
}

// FromSeconds returns a Time representing the point s seconds after an
// unspecified Clock's zero time.
func FromSeconds(s int64) Time {
	if s > math.MaxInt64/time.Second.Nanoseconds() {
		return MaxTime
	}
	return Time{s * 1e9}
}

// FromUnix converts from Unix seconds and nanoseconds to Time, assuming a real
// time Unix clock domain.
func FromUnix(s int64, ns int64) Time {
	if s > math.MaxInt64/time.Second.Nanoseconds() {
		return MaxTime
	}
	t := s * 1e9
	if t > math.MaxInt64-ns {
		return MaxTime
	}
	return Time{t + ns}
}

// FromTimespec converts from Linux Timespec to Time.
func FromTimespec(ts linux.Timespec) Time {
	return Time{ts.ToNsecCapped()}
}

// FromTimeval converts a Linux Timeval to Time.
func FromTimeval(tv linux.Timeval) Time {
	return Time{tv.ToNsecCapped()}
}

// Nanoseconds returns nanoseconds elapsed since the zero time in t's Clock
// domain. If t represents walltime, this is nanoseconds since the Unix epoch.
func (t Time) Nanoseconds() int64 {
	return t.ns
}

// Microseconds returns microseconds elapsed since the zero time in t's Clock
// domain. If t represents walltime, this is microseconds since the Unix epoch.
func (t Time) Microseconds() int64 {
	return t.ns / 1000
}

// Seconds returns seconds elapsed since the zero time in t's Clock domain. If
// t represents walltime, this is seconds since Unix epoch.
func (t Time) Seconds() int64 {
	return t.Nanoseconds() / time.Second.Nanoseconds()
}

// Timespec converts Time to a Linux timespec.
func (t Time) Timespec() linux.Timespec {
	return linux.NsecToTimespec(t.Nanoseconds())
}

// Unix returns the (seconds, nanoseconds) representation of t such that
// seconds*1e9 + nanoseconds = t.
func (t Time) Unix() (s int64, ns int64) {
	s = t.ns / 1e9
	ns = t.ns % 1e9
	return
}

// TimeT converts Time to a Linux time_t.
func (t Time) TimeT() linux.TimeT {
	return linux.NsecToTimeT(t.Nanoseconds())
}

// Timeval converts Time to a Linux timeval.
func (t Time) Timeval() linux.Timeval {
	return linux.NsecToTimeval(t.Nanoseconds())
}

// StatxTimestamp converts Time to a Linux statx_timestamp.
func (t Time) StatxTimestamp() linux.StatxTimestamp {
	return linux.NsecToStatxTimestamp(t.Nanoseconds())
}

// Add adds the duration of d to t.
func (t Time) Add(d time.Duration) Time {
	if t.ns > 0 && d.Nanoseconds() > math.MaxInt64-int64(t.ns) {
		return MaxTime
	}
	if t.ns < 0 && d.Nanoseconds() < math.MinInt64-int64(t.ns) {
		return MinTime
	}
	return Time{int64(t.ns) + d.Nanoseconds()}
}

// AddTime adds the duration of u to t.
func (t Time) AddTime(u Time) Time {
	return t.Add(time.Duration(u.ns))
}

// Equal reports whether the two times represent the same instant in time.
func (t Time) Equal(u Time) bool {
	return t.ns == u.ns
}

// Before reports whether the instant t is before the instant u.
func (t Time) Before(u Time) bool {
	return t.ns < u.ns
}

// After reports whether the instant t is after the instant u.
func (t Time) After(u Time) bool {
	return t.ns > u.ns
}

// Sub returns the duration of t - u.
//
// N.B. This measure may not make sense for every Time returned by ktime.Clock.
// Callers who need wall time duration can use ktime.Clock.WallTimeUntil to
// estimate that wall time.
func (t Time) Sub(u Time) time.Duration {
	dur := time.Duration(int64(t.ns)-int64(u.ns)) * time.Nanosecond
	switch {
	case u.Add(dur).Equal(t):
		return dur
	case t.Before(u):
		return MinDuration
	default:
		return MaxDuration
	}
}

// IsMin returns whether t represents the lowest possible time instant.
func (t Time) IsMin() bool {
	return t == MinTime
}

// IsZero returns whether t represents the zero time instant in t's Clock domain.
func (t Time) IsZero() bool {
	return t == ZeroTime
}

// String returns the time represented in nanoseconds as a string.
func (t Time) String() string {
	return fmt.Sprintf("%dns", t.Nanoseconds())
}

// A Clock is an abstract time source.
type Clock interface {
	// Now returns the current time in nanoseconds according to the Clock.
	Now() Time

	// NewTimer returns a Timer whose time source is the Clock, which sends
	// expirations to the given Listener. The Timer is initially stopped
	// and has no first expiration or period configured.
	NewTimer(Listener) Timer
}

// Timer is an optionally-periodic timer. Timer's semantics support the
// requirements of Linux's interval timers (setitimer(2), timer_create(2),
// timerfd_create(2)).
type Timer interface {
	// Destroy releases resources owned by the Timer. Pause and Resume may be
	// called on a destroyed Timer and are no-ops. No other methods may be
	// called on a destroyed Timer.
	Destroy()

	// Pause pauses the Timer, ensuring that it does not generate any further
	// expirations until Resume is called. If the Timer is already paused,
	// Pause has no effect.
	//
	// Pause and Resume are used to pause Timers during sentry checkpointing;
	// non-checkpoint/restore code should not call these functions.
	Pause()

	// Resume ends the effect of Pause. If the Timer is not paused, Resume has
	// no effect.
	Resume()

	// Clock returns the Timer's time source.
	Clock() Clock

	// Get returns a snapshot of the Timer's current Setting and the time
	// (according to the Timer's Clock) at which the snapshot was taken.
	//
	// Preconditions: The Timer must not be paused (since its Setting cannot be
	// advanced to the current time while it is paused.)
	Get() (Time, Setting)

	// Set atomically changes the Timer's Setting, calls f if it is not nil,
	// and returns the Timer's previous Setting and the time (according to the
	// Timer's Clock) at which the snapshot was taken. Setting s.Enabled to
	// true starts the Timer, while setting s.Enabled to false stops it.
	//
	// Preconditions:
	//   - The Timer must not be paused.
	//   - f cannot call any Timer methods or take any locks preceding Timer
	//     methods in the lock order.
	Set(s Setting, f func()) (Time, Setting)
}

// Listener receives expirations from a Timer.
type Listener interface {
	// NotifyTimer is called when its associated Timer expires. exp is the number
	// of expirations. setting is the next timer Setting.
	//
	// NotifyTimer cannot call any Timer methods or take any locks preceding
	// the Timer in the lock order.
	//
	// Preconditions: exp > 0.
	NotifyTimer(exp uint64)
}

// Setting contains user-controlled mutable Timer properties.
//
// +stateify savable
type Setting struct {
	// Enabled is true if the timer is running.
	Enabled bool

	// Next is the time in nanoseconds of the next expiration.
	Next Time

	// Period is the time in nanoseconds between expirations. If Period is
	// zero, the timer will not automatically restart after expiring.
	//
	// Invariant: Period >= 0.
	Period time.Duration
}

// SettingFromSpec converts a (value, interval) pair to a Setting based on a
// reading from c. value is interpreted as a time relative to c.Now().
func SettingFromSpec(value time.Duration, interval time.Duration, c Clock) (Setting, error) {
	return SettingFromSpecAt(value, interval, c.Now())
}

// SettingFromSpecAt converts a (value, interval) pair to a Setting. value is
// interpreted as a time relative to now.
func SettingFromSpecAt(value time.Duration, interval time.Duration, now Time) (Setting, error) {
	if value < 0 {
		return Setting{}, linuxerr.EINVAL
	}
	if value == 0 {
		return Setting{Period: interval}, nil
	}
	return Setting{
		Enabled: true,
		Next:    now.Add(value),
		Period:  interval,
	}, nil
}

// SettingFromAbsSpec converts a (value, interval) pair to a Setting. value is
// interpreted as an absolute time.
func SettingFromAbsSpec(value Time, interval time.Duration) (Setting, error) {
	if value.Before(ZeroTime) {
		return Setting{}, linuxerr.EINVAL
	}
	if value.IsZero() {
		return Setting{Period: interval}, nil
	}
	return Setting{
		Enabled: true,
		Next:    value,
		Period:  interval,
	}, nil
}

// SettingFromItimerspec converts a linux.Itimerspec to a Setting. If abs is
// true, its.Value is interpreted as an absolute time. Otherwise, it is
// interpreted as a time relative to c.Now().
func SettingFromItimerspec(its linux.Itimerspec, abs bool, c Clock) (Setting, error) {
	if abs {
		return SettingFromAbsSpec(FromTimespec(its.Value), its.Interval.ToDuration())
	}
	return SettingFromSpec(its.Value.ToDuration(), its.Interval.ToDuration(), c)
}

// SpecFromSetting converts a timestamp and a Setting to a (relative value,
// interval) pair, as used by most Linux syscalls that return a struct
// itimerval or struct itimerspec.
func SpecFromSetting(now Time, s Setting) (value, period time.Duration) {
	if !s.Enabled {
		return 0, s.Period
	}
	return s.Next.Sub(now), s.Period
}

// ItimerspecFromSetting converts a Setting to a linux.Itimerspec.
func ItimerspecFromSetting(now Time, s Setting) linux.Itimerspec {
	val, iv := SpecFromSetting(now, s)
	return linux.Itimerspec{
		Interval: linux.DurationToTimespec(iv),
		Value:    linux.DurationToTimespec(val),
	}
}

// At returns an updated Setting and a number of expirations after the
// associated Clock indicates a time of now.
//
// Settings may be created by successive calls to At with decreasing
// values of now (i.e. time may appear to go backward). Supporting this is
// required to support non-monotonic clocks, as well as allowing
// Timer.clock.Now() to be called without holding Timer.mu.
func (s Setting) At(now Time) (Setting, uint64) {
	if !s.Enabled {
		return s, 0
	}
	if s.Next.After(now) {
		return s, 0
	}
	if s.Period == 0 {
		s.Enabled = false
		return s, 1
	}
	exp := 1 + uint64(now.Sub(s.Next).Nanoseconds())/uint64(s.Period)
	s.Next = s.Next.Add(time.Duration(uint64(s.Period) * exp))
	return s, exp
}

// ChannelNotifier is a Listener that sends on a channel.
//
// ChannelNotifier cannot be saved or loaded.
type ChannelNotifier chan struct{}

// NewChannelNotifier creates a new channel notifier.
func NewChannelNotifier() (Listener, <-chan struct{}) {
	tchan := make(chan struct{}, 1)
	return ChannelNotifier(tchan), tchan
}

// NotifyTimer implements Listener.NotifyTimer.
func (c ChannelNotifier) NotifyTimer(uint64) {
	select {
	case c <- struct{}{}:
	default:
	}
}
