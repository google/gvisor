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
	"syscall"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// ItimerType denotes the type of interval timer.
type ItimerType int

// Interval timer types from <sys/time.h>.
const (
	// ItimerReal equals to ITIMER_REAL.
	ItimerReal ItimerType = iota
	// ItimerVirtual equals to ITIMER_VIRTUAL.
	ItimerVirtual
	// ItimerProf equals to ITIMER_PROF.
	ItimerProf
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

func findTimer(t *kernel.Task, w ItimerType) (*ktime.Timer, error) {
	switch w {
	case ItimerReal:
		return t.ThreadGroup().Timer().RealTimer, nil
	case ItimerVirtual:
		return t.ThreadGroup().Timer().VirtualTimer, nil
	case ItimerProf:
		return t.ThreadGroup().Timer().ProfTimer, nil
	default:
		return nil, syscall.EINVAL
	}
}

// Getitimer implements linux syscall getitimer(2).
func Getitimer(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := ItimerType(args[0].Int())
	val := args[1].Pointer()

	timer, err := findTimer(t, timerID)
	if err != nil {
		return 0, nil, err
	}
	value, interval := ktime.SpecFromSetting(timer.Get())
	olditv := linux.ItimerVal{
		Value:    linux.DurationToTimeval(value),
		Interval: linux.DurationToTimeval(interval),
	}

	return 0, nil, copyItimerValOut(t, val, &olditv)
}

// Setitimer implements linux syscall setitimer(2).
func Setitimer(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	timerID := ItimerType(args[0].Int())
	newVal := args[1].Pointer()
	oldVal := args[2].Pointer()

	timer, err := findTimer(t, timerID)
	if err != nil {
		return 0, nil, err
	}

	itv, err := copyItimerValIn(t, newVal)
	if err != nil {
		return 0, nil, err
	}
	// Just like linux, we cap the timer value and interval with the max
	// number that int64 can represent which is roughly 292 years.
	s, err := ktime.SettingFromSpec(itv.Value.ToDuration(),
		itv.Interval.ToDuration(), timer.Clock())
	if err != nil {
		return 0, nil, err
	}

	valueNS, intervalNS := ktime.SpecFromSetting(timer.Swap(s))
	olditv := linux.ItimerVal{
		Value:    linux.DurationToTimeval(valueNS),
		Interval: linux.DurationToTimeval(intervalNS),
	}

	return 0, nil, copyItimerValOut(t, oldVal, &olditv)
}

// Alarm implements linux syscall alarm(2).
func Alarm(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	duration := time.Duration(args[0].Uint()) * time.Second

	timer := t.ThreadGroup().Timer().RealTimer
	s, err := ktime.SettingFromSpec(duration, 0, timer.Clock())
	if err != nil {
		return 0, nil, err
	}

	value, _ := ktime.SpecFromSetting(timer.Swap(s))
	sec := int64(value) / nsecPerSec
	nsec := int64(value) % nsecPerSec
	// We can't return 0 if we have an alarm pending ...
	if (sec == 0 && nsec > 0) || nsec >= nsecPerSec/2 {
		sec++
	}

	return uintptr(sec), nil, nil
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
