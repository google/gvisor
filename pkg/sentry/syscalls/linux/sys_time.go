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
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
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
func ClockGetres(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := int32(args[0].Int())
	addr := args[1].Pointer()
	r := linux.Timespec{
		Sec:  0,
		Nsec: 1,
	}

	if _, err := getClock(t, clockID); err != nil {
		return 0, nil, linuxerr.EINVAL
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
			return nil, linuxerr.EINVAL
		}

		targetTask := targetTask(t, clockID)
		if targetTask == nil {
			return nil, linuxerr.EINVAL
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
			return nil, linuxerr.EINVAL
		}
	}

	switch clockID {
	case linux.CLOCK_REALTIME, linux.CLOCK_REALTIME_COARSE:
		return t.Kernel().RealtimeClock(), nil
	case linux.CLOCK_MONOTONIC, linux.CLOCK_MONOTONIC_COARSE,
		linux.CLOCK_MONOTONIC_RAW, linux.CLOCK_BOOTTIME:
		// CLOCK_MONOTONIC approximates CLOCK_MONOTONIC_RAW.
		// CLOCK_BOOTTIME is internally mapped to CLOCK_MONOTONIC, as:
		//	- CLOCK_BOOTTIME should behave as CLOCK_MONOTONIC while also
		//		including suspend time.
		//	- gVisor has no concept of suspend/resume.
		//	- CLOCK_MONOTONIC already includes save/restore time, which is
		//		the closest to suspend time.
		return t.Kernel().MonotonicClock(), nil
	case linux.CLOCK_PROCESS_CPUTIME_ID:
		return t.ThreadGroup().CPUClock(), nil
	case linux.CLOCK_THREAD_CPUTIME_ID:
		return t.CPUClock(), nil
	default:
		return nil, linuxerr.EINVAL
	}
}

// ClockGettime implements linux syscall clock_gettime(2).
func ClockGettime(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
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
func ClockSettime(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, linuxerr.EPERM
}

// Time implements linux syscall time(2).
func Time(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	r := t.Kernel().RealtimeClock().Now().TimeT()
	if addr == hostarch.Addr(0) {
		return uintptr(r), nil, nil
	}

	if _, err := r.CopyOut(t, addr); err != nil {
		return 0, nil, err
	}
	return uintptr(r), nil, nil
}

// Nanosleep implements linux syscall Nanosleep(2).
func Nanosleep(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	rem := args[1].Pointer()

	ts, err := copyTimespecIn(t, addr)
	if err != nil {
		return 0, nil, err
	}

	if !ts.Valid() {
		return 0, nil, linuxerr.EINVAL
	}

	// Just like linux, we cap the timeout with the max number that int64 can
	// represent which is roughly 292 years.
	dur := time.Duration(ts.ToNsecCapped()) * time.Nanosecond
	c := t.Kernel().MonotonicClock()
	return 0, nil, clockNanosleepUntil(t, c, c.Now().Add(dur), rem, true)
}

// ClockNanosleep implements linux syscall clock_nanosleep(2).
func ClockNanosleep(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := int32(args[0].Int())
	flags := args[1].Int()
	addr := args[2].Pointer()
	rem := args[3].Pointer()

	req, err := copyTimespecIn(t, addr)
	if err != nil {
		return 0, nil, err
	}

	if !req.Valid() {
		return 0, nil, linuxerr.EINVAL
	}

	// Only allow clock constants also allowed by Linux. (CLOCK_TAI is
	// unimplemented.)
	if clockID > 0 {
		if clockID != linux.CLOCK_REALTIME &&
			clockID != linux.CLOCK_MONOTONIC &&
			clockID != linux.CLOCK_BOOTTIME &&
			clockID != linux.CLOCK_PROCESS_CPUTIME_ID {
			return 0, nil, linuxerr.EINVAL
		}
	}

	c, err := getClock(t, clockID)
	if err != nil {
		return 0, nil, err
	}

	if flags&linux.TIMER_ABSTIME != 0 {
		return 0, nil, clockNanosleepUntil(t, c, ktime.FromTimespec(req), 0, false)
	}

	dur := time.Duration(req.ToNsecCapped()) * time.Nanosecond
	return 0, nil, clockNanosleepUntil(t, c, c.Now().Add(dur), rem, true)
}

// clockNanosleepUntil blocks until a specified time.
//
// If blocking is interrupted, the syscall is restarted with the original
// arguments.
func clockNanosleepUntil(t *kernel.Task, c ktime.Clock, end ktime.Time, rem hostarch.Addr, needRestartBlock bool) error {
	var err error
	if c == t.Kernel().MonotonicClock() {
		err = t.BlockWithDeadline(nil, true, end)
	} else {
		notifier, tchan := ktime.NewChannelNotifier()
		timer := ktime.NewTimer(c, notifier)
		timer.Swap(ktime.Setting{
			Period:  0,
			Enabled: true,
			Next:    end,
		})
		err = t.BlockWithTimer(nil, tchan)
		timer.Destroy()
	}

	switch {
	case linuxerr.Equals(linuxerr.ETIMEDOUT, err):
		// Slept for entire timeout.
		return nil
	case err == linuxerr.ErrInterrupted:
		// Interrupted.
		remaining := end.Sub(c.Now())
		if remaining <= 0 {
			return nil
		}

		// Copy out remaining time.
		if rem != 0 {
			timeleft := linux.NsecToTimespec(remaining.Nanoseconds())
			if err := copyTimespecOut(t, rem, &timeleft); err != nil {
				return err
			}
		}
		if needRestartBlock {
			// Arrange for a restart with the remaining duration.
			t.SetSyscallRestartBlock(&clockNanosleepRestartBlock{
				c:   c,
				end: end,
				rem: rem,
			})
			return linuxerr.ERESTART_RESTARTBLOCK
		}
		return linuxerr.ERESTARTNOHAND
	default:
		panic(fmt.Sprintf("Impossible BlockWithTimer error %v", err))
	}
}

// clockNanosleepRestartBlock encapsulates the state required to restart
// clock_nanosleep(2) via restart_syscall(2).
//
// +stateify savable
type clockNanosleepRestartBlock struct {
	c   ktime.Clock
	end ktime.Time
	rem hostarch.Addr
}

// Restart implements kernel.SyscallRestartBlock.Restart.
func (n *clockNanosleepRestartBlock) Restart(t *kernel.Task) (uintptr, error) {
	return 0, clockNanosleepUntil(t, n.c, n.end, n.rem, true)
}

// Gettimeofday implements linux syscall gettimeofday(2).
func Gettimeofday(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tv := args[0].Pointer()
	tz := args[1].Pointer()

	if tv != hostarch.Addr(0) {
		nowTv := t.Kernel().RealtimeClock().Now().Timeval()
		if err := copyTimevalOut(t, tv, &nowTv); err != nil {
			return 0, nil, err
		}
	}

	if tz != hostarch.Addr(0) {
		// Ask the time package for the timezone.
		_, offset := time.Now().Zone()
		// This int32 array mimics linux's struct timezone.
		timezone := []int32{-int32(offset) / 60, 0}
		_, err := primitive.CopyInt32SliceOut(t, tz, timezone)
		return 0, nil, err
	}
	return 0, nil, nil
}
