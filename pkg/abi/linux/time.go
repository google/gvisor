// Copyright 2018 Google Inc.
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

package linux

import (
	"math"
	"time"
)

const (
	// ClockTick is the length of time represented by a single clock tick, as
	// used by times(2) and /proc/[pid]/stat.
	ClockTick = time.Second / CLOCKS_PER_SEC

	// CLOCKS_PER_SEC is the number of ClockTicks per second.
	//
	// Linux defines this to be 100 on most architectures, irrespective of
	// CONFIG_HZ. Userspace obtains the value through sysconf(_SC_CLK_TCK),
	// which uses the AT_CLKTCK entry in the auxiliary vector if one is
	// provided, and assumes 100 otherwise (glibc:
	// sysdeps/posix/sysconf.c:__sysconf() =>
	// sysdeps/unix/sysv/linux/getclktck.c, elf/dl-support.c:_dl_aux_init()).
	//
	// Not to be confused with POSIX CLOCKS_PER_SEC, as used by clock(3); "XSI
	// requires that [POSIX] CLOCKS_PER_SEC equals 1000000 independent of the
	// actual resolution" - clock(3).
	CLOCKS_PER_SEC = 100
)

// CPU clock types for use with clock_gettime(2) et al.
//
// The 29 most significant bits of a 32 bit clock ID are either a PID or a FD.
//
// Bits 1 and 0 give the type: PROF=0, VIRT=1, SCHED=2, or FD=3.
//
// Bit 2 indicates whether a cpu clock refers to a thread or a process.
const (
	CPUCLOCK_PROF  = 0
	CPUCLOCK_VIRT  = 1
	CPUCLOCK_SCHED = 2
	CPUCLOCK_MAX   = 3
	CLOCKFD        = CPUCLOCK_MAX

	CPUCLOCK_CLOCK_MASK     = 3
	CPUCLOCK_PERTHREAD_MASK = 4
)

// Clock identifiers for use with clock_gettime(2), clock_getres(2),
// clock_nanosleep(2).
const (
	CLOCK_REALTIME           = 0
	CLOCK_MONOTONIC          = 1
	CLOCK_PROCESS_CPUTIME_ID = 2
	CLOCK_THREAD_CPUTIME_ID  = 3
	CLOCK_MONOTONIC_RAW      = 4
	CLOCK_REALTIME_COARSE    = 5
	CLOCK_MONOTONIC_COARSE   = 6
	CLOCK_BOOTTIME           = 7
	CLOCK_REALTIME_ALARM     = 8
	CLOCK_BOOTTIME_ALARM     = 9
)

// Flags for clock_nanosleep(2).
const (
	TIMER_ABSTIME = 1
)

// Flags for timerfd syscalls (timerfd_create(2), timerfd_settime(2)).
const (
	// TFD_CLOEXEC is a timerfd_create flag.
	TFD_CLOEXEC = O_CLOEXEC

	// TFD_NONBLOCK is a timerfd_create flag.
	TFD_NONBLOCK = O_NONBLOCK

	// TFD_TIMER_ABSTIME is a timerfd_settime flag.
	TFD_TIMER_ABSTIME = 1
)

// The safe number of seconds you can represent by int64.
const maxSecInDuration = math.MaxInt64 / int64(time.Second)

// TimeT represents time_t in <time.h>. It represents time in seconds.
type TimeT int64

// NsecToTimeT translates nanoseconds to TimeT (seconds).
func NsecToTimeT(nsec int64) TimeT {
	return TimeT(nsec / 1e9)
}

// Timespec represents struct timespec in <time.h>.
type Timespec struct {
	Sec  int64
	Nsec int64
}

// Unix returns the second and nanosecond.
func (ts Timespec) Unix() (sec int64, nsec int64) {
	return int64(ts.Sec), int64(ts.Nsec)
}

// ToTime returns the Go time.Time representation.
func (ts Timespec) ToTime() time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// ToNsec returns the nanosecond representation.
func (ts Timespec) ToNsec() int64 {
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

// ToNsecCapped returns the safe nanosecond representation.
func (ts Timespec) ToNsecCapped() int64 {
	if ts.Sec > maxSecInDuration {
		return math.MaxInt64
	}
	return ts.ToNsec()
}

// ToDuration returns the safe nanosecond representation as time.Duration.
func (ts Timespec) ToDuration() time.Duration {
	return time.Duration(ts.ToNsecCapped())
}

// Valid returns whether the timespec contains valid values.
func (ts Timespec) Valid() bool {
	return !(ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= int64(time.Second))
}

// NsecToTimespec translates nanoseconds to Timespec.
func NsecToTimespec(nsec int64) (ts Timespec) {
	ts.Sec = nsec / 1e9
	ts.Nsec = nsec % 1e9
	return
}

// DurationToTimespec translates time.Duration to Timespec.
func DurationToTimespec(dur time.Duration) Timespec {
	return NsecToTimespec(dur.Nanoseconds())
}

// SizeOfTimeval is the size of a Timeval struct in bytes.
const SizeOfTimeval = 16

// Timeval represents struct timeval in <time.h>.
type Timeval struct {
	Sec  int64
	Usec int64
}

// ToNsecCapped returns the safe nanosecond representation.
func (tv Timeval) ToNsecCapped() int64 {
	if tv.Sec > maxSecInDuration {
		return math.MaxInt64
	}
	return int64(tv.Sec)*1e9 + int64(tv.Usec)*1e3
}

// ToDuration returns the safe nanosecond representation as a time.Duration.
func (tv Timeval) ToDuration() time.Duration {
	return time.Duration(tv.ToNsecCapped())
}

// ToTime returns the Go time.Time representation.
func (tv Timeval) ToTime() time.Time {
	return time.Unix(tv.Sec, tv.Usec*1e3)
}

// NsecToTimeval translates nanosecond to Timeval.
func NsecToTimeval(nsec int64) (tv Timeval) {
	nsec += 999 // round up to microsecond
	tv.Sec = nsec / 1e9
	tv.Usec = nsec % 1e9 / 1e3
	return
}

// DurationToTimeval translates time.Duration to Timeval.
func DurationToTimeval(dur time.Duration) Timeval {
	return NsecToTimeval(dur.Nanoseconds())
}

// Itimerspec represents struct itimerspec in <time.h>.
type Itimerspec struct {
	Interval Timespec
	Value    Timespec
}

// ItimerVal mimics the following struct in <sys/time.h>
//   struct itimerval {
//     struct timeval it_interval; /* next value */
//     struct timeval it_value;    /* current value */
//   };
type ItimerVal struct {
	Interval Timeval
	Value    Timeval
}

// ClockT represents type clock_t.
type ClockT int64

// ClockTFromDuration converts time.Duration to clock_t.
func ClockTFromDuration(d time.Duration) ClockT {
	return ClockT(d / ClockTick)
}

// Tms represents struct tms, used by times(2).
type Tms struct {
	UTime  ClockT
	STime  ClockT
	CUTime ClockT
	CSTime ClockT
}

// TimerID represents type timer_t, which identifies a POSIX per-process
// interval timer.
type TimerID int32
