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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/timerfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// TimerfdCreate implements Linux syscall timerfd_create(2).
func TimerfdCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	clockID := args[0].Int()
	flags := args[1].Int()

	if flags&^(linux.TFD_CLOEXEC|linux.TFD_NONBLOCK) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Timerfds aren't writable per se (their implementation of Write just
	// returns EINVAL), but they are "opened for writing", which is necessary
	// to actually reach said implementation of Write.
	fileFlags := uint32(linux.O_RDWR)
	if flags&linux.TFD_NONBLOCK != 0 {
		fileFlags |= linux.O_NONBLOCK
	}

	var clock ktime.Clock
	switch clockID {
	case linux.CLOCK_REALTIME:
		clock = t.Kernel().RealtimeClock()
	case linux.CLOCK_MONOTONIC, linux.CLOCK_BOOTTIME:
		clock = t.Kernel().MonotonicClock()
	default:
		return 0, nil, linuxerr.EINVAL
	}
	vfsObj := t.Kernel().VFS()
	file, err := timerfd.New(t, vfsObj, clock, fileFlags)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)
	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.TFD_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// TimerfdSettime implements Linux syscall timerfd_settime(2).
func TimerfdSettime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	flags := args[1].Int()
	newValAddr := args[2].Pointer()
	oldValAddr := args[3].Pointer()

	if flags&^(linux.TFD_TIMER_ABSTIME) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	tfd, ok := file.Impl().(*timerfd.TimerFileDescription)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}

	var newVal linux.Itimerspec
	if _, err := newVal.CopyIn(t, newValAddr); err != nil {
		return 0, nil, err
	}
	newS, err := ktime.SettingFromItimerspec(newVal, flags&linux.TFD_TIMER_ABSTIME != 0, tfd.Clock())
	if err != nil {
		return 0, nil, err
	}
	tm, oldS := tfd.SetTime(newS)
	if oldValAddr != 0 {
		oldVal := ktime.ItimerspecFromSetting(tm, oldS)
		if _, err := oldVal.CopyOut(t, oldValAddr); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, nil
}

// TimerfdGettime implements Linux syscall timerfd_gettime(2).
func TimerfdGettime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	curValAddr := args[1].Pointer()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	tfd, ok := file.Impl().(*timerfd.TimerFileDescription)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}

	tm, s := tfd.GetTime()
	curVal := ktime.ItimerspecFromSetting(tm, s)
	_, err := curVal.CopyOut(t, curValAddr)
	return 0, nil, err
}
