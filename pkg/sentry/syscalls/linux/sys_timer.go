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
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

const nsecPerSec = int64(time.Second)

// copyItimerValIn copies an ItimerVal from the untrusted app range to the
// kernel.  The ItimerVal may be either 32 or 64 bits.
// A NULL address is allowed because because Linux allows
// setitimer(which, NULL, &old_value) which disables the timer.
// There is a KERN_WARN message saying this misfeature will be removed.
// However, that hasn't happened as of 3.19, so we continue to support it.
func copyItimerValIn(t *kernel.Task, addr usermem.Addr) (linux.ItimerVal, error) {
	if addr == usermem.Addr(0) {
		return linux.ItimerVal{}, nil
	}

	switch t.Arch().Width() {
	case 8:
		// Native size, just copy directly.
		var itv linux.ItimerVal
		if _, err := t.CopyIn(addr, &itv); err != nil {
			return linux.ItimerVal{}, err
		}

		return itv, nil
	default:
		return linux.ItimerVal{}, syscall.ENOSYS
	}
}

// copyItimerValOut copies an ItimerVal to the untrusted app range.
// The ItimerVal may be either 32 or 64 bits.
// A NULL address is allowed, in which case no copy takes place
func copyItimerValOut(t *kernel.Task, addr usermem.Addr, itv *linux.ItimerVal) error {
	if addr == usermem.Addr(0) {
		return nil
	}

	switch t.Arch().Width() {
	case 8:
		// Native size, just copy directly.
		_, err := t.CopyOut(addr, itv)
		return err
	default:
		return syscall.ENOSYS
	}
}

// Getitimer implements linux syscall getitimer(2).
func Getitimer(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := args[0].Int()
	val := args[1].Pointer()

	olditv, err := t.Getitimer(timerID)
	if err != nil {
		return 0, nil, err
	}
	return 0, nil, copyItimerValOut(t, val, &olditv)
}

// Setitimer implements linux syscall setitimer(2).
func Setitimer(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := args[0].Int()
	newVal := args[1].Pointer()
	oldVal := args[2].Pointer()

	newitv, err := copyItimerValIn(t, newVal)
	if err != nil {
		return 0, nil, err
	}
	olditv, err := t.Setitimer(timerID, newitv)
	if err != nil {
		return 0, nil, err
	}
	return 0, nil, copyItimerValOut(t, oldVal, &olditv)
}

// Alarm implements linux syscall alarm(2).
func Alarm(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	duration := time.Duration(args[0].Uint()) * time.Second

	olditv, err := t.Setitimer(linux.ITIMER_REAL, linux.ItimerVal{
		Value: linux.DurationToTimeval(duration),
	})
	if err != nil {
		return 0, nil, err
	}
	olddur := olditv.Value.ToDuration()
	secs := olddur.Round(time.Second).Nanoseconds() / nsecPerSec
	if secs == 0 && olddur != 0 {
		// We can't return 0 if an alarm was previously scheduled.
		secs = 1
	}
	return uintptr(secs), nil, nil
}

// TimerCreate implements linux syscall timer_create(2).
func TimerCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := args[0].Int()
	sevp := args[1].Pointer()
	timerIDp := args[2].Pointer()

	c, err := getClock(t, clockID)
	if err != nil {
		return 0, nil, err
	}

	var sev *linux.Sigevent
	if sevp != 0 {
		sev = &linux.Sigevent{}
		if _, err = t.CopyIn(sevp, sev); err != nil {
			return 0, nil, err
		}
	}

	id, err := t.IntervalTimerCreate(c, sev)
	if err != nil {
		return 0, nil, err
	}

	if _, err := t.CopyOut(timerIDp, &id); err != nil {
		t.IntervalTimerDelete(id)
		return 0, nil, err
	}

	return uintptr(id), nil, nil
}

// TimerSettime implements linux syscall timer_settime(2).
func TimerSettime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := linux.TimerID(args[0].Value)
	flags := args[1].Int()
	newValAddr := args[2].Pointer()
	oldValAddr := args[3].Pointer()

	var newVal linux.Itimerspec
	if _, err := t.CopyIn(newValAddr, &newVal); err != nil {
		return 0, nil, err
	}
	oldVal, err := t.IntervalTimerSettime(timerID, newVal, flags&linux.TIMER_ABSTIME != 0)
	if err != nil {
		return 0, nil, err
	}
	if oldValAddr != 0 {
		if _, err := t.CopyOut(oldValAddr, &oldVal); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, nil
}

// TimerGettime implements linux syscall timer_gettime(2).
func TimerGettime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := linux.TimerID(args[0].Value)
	curValAddr := args[1].Pointer()

	curVal, err := t.IntervalTimerGettime(timerID)
	if err != nil {
		return 0, nil, err
	}
	_, err = t.CopyOut(curValAddr, &curVal)
	return 0, nil, err
}

// TimerGetoverrun implements linux syscall timer_getoverrun(2).
func TimerGetoverrun(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := linux.TimerID(args[0].Value)

	o, err := t.IntervalTimerGetoverrun(timerID)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(o), nil, nil
}

// TimerDelete implements linux syscall timer_delete(2).
func TimerDelete(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := linux.TimerID(args[0].Value)
	return 0, nil, t.IntervalTimerDelete(timerID)
}
