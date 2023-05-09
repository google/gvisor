// Copyright 2023 The gVisor Authors.
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

package sysmsg

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform/interrupt"
)

const maxFutexSleepSeconds = 60

// SleepOnState makes the caller sleep on the Msg.State futex.
func (m *Msg) SleepOnState(curState ThreadState, interruptor interrupt.Receiver) syscall.Errno {
	futexTimeout := unix.Timespec{
		Sec:  maxFutexSleepSeconds,
		Nsec: 0,
	}
	sentInterruptOnce := false
	errno := syscall.Errno(0)
	for {
		_, _, errno = unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&m.State)),
			linux.FUTEX_WAIT, uintptr(curState), uintptr(unsafe.Pointer(&futexTimeout)), 0, 0)
		if errno == unix.ETIMEDOUT {
			interruptor.NotifyInterrupt()
			if !sentInterruptOnce {
				log.Warningf("Systrap task goroutine has been waiting on Msg.State futex too long. Msg: %s", m.String())
			}
			sentInterruptOnce = true
		} else {
			break
		}
	}
	if errno == unix.EAGAIN || errno == unix.EINTR {
		errno = 0
	}
	return errno
}

// SleepOnState makes the caller sleep on the ThreadContext.State futex.
func (c *ThreadContext) SleepOnState(curState ContextState, interruptor interrupt.Receiver) syscall.Errno {
	futexTimeout := unix.Timespec{
		Sec:  maxFutexSleepSeconds,
		Nsec: 0,
	}
	sentInterruptOnce := false
	errno := syscall.Errno(0)
	for {
		_, _, errno = unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.State)),
			linux.FUTEX_WAIT, uintptr(curState), uintptr(unsafe.Pointer(&futexTimeout)), 0, 0)
		if errno == unix.ETIMEDOUT {
			interruptor.NotifyInterrupt()
			if !sentInterruptOnce {
				log.Warningf("Systrap task goroutine has been waiting on ThreadContext.State futex too long. ThreadContext: %s", c.String())
			}
			sentInterruptOnce = true
		} else {
			break
		}
	}
	if errno == unix.EAGAIN || errno == unix.EINTR {
		errno = 0
	}
	return errno
}

// WakeSysmsgThread calls futex wake on Sysmsg.State.
func (m *Msg) WakeSysmsgThread() (bool, syscall.Errno) {
	if !m.State.CompareAndSwap(ThreadStateAsleep, ThreadStatePrep) {
		return false, 0
	}
	_, _, e := unix.RawSyscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&m.State)), linux.FUTEX_WAKE, 1, 0, 0, 0)
	return true, e
}
