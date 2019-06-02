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

package linux

import (
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// The most significant 29 bits hold either a pid or a file descriptor.
func pidOfClockID(c int32) kernel.ThreadID {
	return kernel.ThreadID(^(c >> 3))
}

// whichCPUClock returns one of CPUCLOCK_PERF, CPUCLOCK_VIRT, CPUCLOCK_SCHED or
// CLOCK_FD.
func whichCPUClock(c int32) int32 {
	return c & linux.CPUCLOCK_CLOCK_MASK
}

// isCPUClockPerThread returns true if the CPUCLOCK_PERTHREAD bit is set in the
// clock id.
func isCPUClockPerThread(c int32) bool {
	return c&linux.CPUCLOCK_PERTHREAD_MASK != 0
}

// isValidCPUClock returns checks that the cpu clock id is valid.
func isValidCPUClock(c int32) bool {
	// Bits 0, 1, and 2 cannot all be set.
	if c&7 == 7 {
		return false
	}
	if whichCPUClock(c) >= linux.CPUCLOCK_MAX {
		return false
	}
	return true
}

// targetTask returns the kernel.Task for the given clock id.
func targetTask(t *kernel.Task, c int32) *kernel.Task {
	pid := pidOfClockID(c)
	if pid == 0 {
		return t
	}
	return t.PIDNamespace().TaskWithID(pid)
}

// ClockGetres implements linux syscall clock_getres(2).
func ClockGetres(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := int32(args[0].Int())
	addr := args[1].Pointer()
	r := linux.Timespec{
		Sec:  0,
		Nsec: 1,
	}

	if _, err := getClock(t, clockID); err != nil {
		return 0, nil, syserror.EINVAL
	}

	if addr == 0 {
		// Don't need to copy out.
		return 0, nil, nil
	}

	return 0, nil, copyTimespecOut(t, addr, &r)
}

type cpuClocker interface {
	UserCPUClock() ktime.Clock
	CPUClock() ktime.Clock
}

func getClock(t *kernel.Task, clockID int32) (ktime.Clock, error) {
	if clockID < 0 {
		if !isValidCPUClock(clockID) {
			return nil, syserror.EINVAL
		}

		targetTask := targetTask(t, clockID)
		if targetTask == nil {
			return nil, syserror.EINVAL
		}

		var target cpuClocker
		if isCPUClockPerThread(clockID) {
			target = targetTask
		} else {
			target = targetTask.ThreadGroup()
		}

		switch whichCPUClock(clockID) {
		case linux.CPUCLOCK_VIRT:
			return target.UserCPUClock(), nil
		case linux.CPUCLOCK_PROF, linux.CPUCLOCK_SCHED:
			// CPUCLOCK_SCHED is approximated by CPUCLOCK_PROF.
			return target.CPUClock(), nil
		default:
			return nil, syserror.EINVAL
		}
	}

	switch clockID {
	case linux.CLOCK_REALTIME, linux.CLOCK_REALTIME_COARSE:
		return t.Kernel().RealtimeClock(), nil
	case linux.CLOCK_MONOTONIC, linux.CLOCK_MONOTONIC_COARSE, linux.CLOCK_MONOTONIC_RAW:
		// CLOCK_MONOTONIC approximates CLOCK_MONOTONIC_RAW.
		return t.Kernel().MonotonicClock(), nil
	case linux.CLOCK_PROCESS_CPUTIME_ID:
		return t.ThreadGroup().CPUClock(), nil
	case linux.CLOCK_THREAD_CPUTIME_ID:
		return t.CPUClock(), nil
	default:
		return nil, syserror.EINVAL
	}
}

// ClockGettime implements linux syscall clock_gettime(2).
func ClockGettime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := int32(args[0].Int())
	addr := args[1].Pointer()

	c, err := getClock(t, clockID)
	if err != nil {
		return 0, nil, err
	}
	ts := c.Now().Timespec()
	return 0, nil, copyTimespecOut(t, addr, &ts)
}

// ClockSettime implements linux syscall clock_settime(2).
func ClockSettime(*kernel.Task, arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.EPERM
}

// Time implements linux syscall time(2).
func Time(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	r := t.Kernel().RealtimeClock().Now().TimeT()
	if addr == usermem.Addr(0) {
		return uintptr(r), nil, nil
	}

	if _, err := t.CopyOut(addr, r); err != nil {
		return 0, nil, err
	}
	return uintptr(r), nil, nil
}

// clockNanosleepRestartBlock encapsulates the state required to restart
// clock_nanosleep(2) via restart_syscall(2).
//
// +stateify savable
type clockNanosleepRestartBlock struct {
	c        ktime.Clock
	duration time.Duration
	rem      usermem.Addr
}

// Restart implements kernel.SyscallRestartBlock.Restart.
func (n *clockNanosleepRestartBlock) Restart(t *kernel.Task) (uintptr, error) {
	return 0, clockNanosleepFor(t, n.c, n.duration, n.rem)
}

// clockNanosleepUntil blocks until a specified time.
//
// If blocking is interrupted, the syscall is restarted with the original
// arguments.
func clockNanosleepUntil(t *kernel.Task, c ktime.Clock, ts linux.Timespec) error {
	notifier, tchan := ktime.NewChannelNotifier()
	timer := ktime.NewTimer(c, notifier)

	// Turn on the timer.
	timer.Swap(ktime.Setting{
		Period:  0,
		Enabled: true,
		Next:    ktime.FromTimespec(ts),
	})

	err := t.BlockWithTimer(nil, tchan)

	timer.Destroy()

	// Did we just block until the timeout happened?
	if err == syserror.ETIMEDOUT {
		return nil
	}

	return syserror.ConvertIntr(err, kernel.ERESTARTNOHAND)
}

// clockNanosleepFor blocks for a specified duration.
//
// If blocking is interrupted, the syscall is restarted with the remaining
// duration timeout.
func clockNanosleepFor(t *kernel.Task, c ktime.Clock, dur time.Duration, rem usermem.Addr) error {
	timer, start, tchan := ktime.After(c, dur)

	err := t.BlockWithTimer(nil, tchan)

	after := c.Now()

	timer.Destroy()

	var remaining time.Duration
	// Did we just block for the entire duration?
	if err == syserror.ETIMEDOUT {
		remaining = 0
	} else {
		remaining = dur - after.Sub(start)
		if remaining < 0 {
			remaining = time.Duration(0)
		}
	}

	// Copy out remaining time.
	if err != nil && rem != usermem.Addr(0) {
		timeleft := linux.NsecToTimespec(remaining.Nanoseconds())
		if err := copyTimespecOut(t, rem, &timeleft); err != nil {
			return err
		}
	}

	// Did we just block for the entire duration?
	if err == syserror.ETIMEDOUT {
		return nil
	}

	// If interrupted, arrange for a restart with the remaining duration.
	if err == syserror.ErrInterrupted {
		t.SetSyscallRestartBlock(&clockNanosleepRestartBlock{
			c:        c,
			duration: remaining,
			rem:      rem,
		})
		return kernel.ERESTART_RESTARTBLOCK
	}

	return err
}

// Nanosleep implements linux syscall Nanosleep(2).
func Nanosleep(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	rem := args[1].Pointer()

	ts, err := copyTimespecIn(t, addr)
	if err != nil {
		return 0, nil, err
	}

	if !ts.Valid() {
		return 0, nil, syserror.EINVAL
	}

	// Just like linux, we cap the timeout with the max number that int64 can
	// represent which is roughly 292 years.
	dur := time.Duration(ts.ToNsecCapped()) * time.Nanosecond
	return 0, nil, clockNanosleepFor(t, t.Kernel().MonotonicClock(), dur, rem)
}

// ClockNanosleep implements linux syscall clock_nanosleep(2).
func ClockNanosleep(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := int32(args[0].Int())
	flags := args[1].Int()
	addr := args[2].Pointer()
	rem := args[3].Pointer()

	req, err := copyTimespecIn(t, addr)
	if err != nil {
		return 0, nil, err
	}

	if !req.Valid() {
		return 0, nil, syserror.EINVAL
	}

	// Only allow clock constants also allowed by Linux.
	if clockID > 0 {
		if clockID != linux.CLOCK_REALTIME &&
			clockID != linux.CLOCK_MONOTONIC &&
			clockID != linux.CLOCK_PROCESS_CPUTIME_ID {
			return 0, nil, syserror.EINVAL
		}
	}

	c, err := getClock(t, clockID)
	if err != nil {
		return 0, nil, err
	}

	if flags&linux.TIMER_ABSTIME != 0 {
		return 0, nil, clockNanosleepUntil(t, c, req)
	}

	dur := time.Duration(req.ToNsecCapped()) * time.Nanosecond
	return 0, nil, clockNanosleepFor(t, c, dur, rem)
}

// Gettimeofday implements linux syscall gettimeofday(2).
func Gettimeofday(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tv := args[0].Pointer()
	tz := args[1].Pointer()

	if tv != usermem.Addr(0) {
		nowTv := t.Kernel().RealtimeClock().Now().Timeval()
		if err := copyTimevalOut(t, tv, &nowTv); err != nil {
			return 0, nil, err
		}
	}

	if tz != usermem.Addr(0) {
		// Ask the time package for the timezone.
		_, offset := time.Now().Zone()
		// This int32 array mimics linux's struct timezone.
		timezone := [2]int32{-int32(offset) / 60, 0}
		_, err := t.CopyOut(tz, timezone)
		return 0, nil, err
	}
	return 0, nil, nil
}
