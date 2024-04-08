// Copyright 2021 The gVisor Authors.
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

package systrap

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func (t *syscallThread) initRequestReplyAddresses(sentryStackAddr uintptr) {
	// These are safe as these addresses are mmapped and never moved/gced.
	sentryMessage := (*syscallSentryMessage)(unsafe.Pointer(sentryStackAddr))
	stubMessage := (*syscallStubMessage)(unsafe.Pointer(sentryStackAddr + syscallStubMessageOffset))
	atomic.StoreUint32(&sentryMessage.state, 0)

	t.sentryMessage = sentryMessage
	t.stubMessage = stubMessage
}

// maskAllSignals blocks all signals.
func (t *syscallThread) maskAllSignalsAttached() {
	p := t.thread

	mask := ^uint64(0)
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, linux.PTRACE_SETSIGMASK, uintptr(p.tid), 8, uintptr(unsafe.Pointer(&mask)), 0, 0); errno != 0 {
		panic(fmt.Sprintf("unable to setmask: %v", errno))
	}
}

// unmaskAllSignals unblocks all signals.
func (t *syscallThread) unmaskAllSignalsAttached() {
	p := t.thread
	mask := uint64(0)
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, linux.PTRACE_SETSIGMASK, uintptr(p.tid), 8, uintptr(unsafe.Pointer(&mask)), 0, 0); errno != 0 {
		panic(fmt.Sprintf("unable to setmask: %v", errno))
	}
}

func futexWakeUint32(addr *uint32) error {
	if _, _, e := unix.RawSyscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), linux.FUTEX_WAKE, 1, 0, 0, 0); e != 0 {
		return fmt.Errorf("failed to FUTEX_WAKE: %v", e)
	}
	return nil
}

func futexWaitForUint32(addr *uint32, targetValue uint32) error {
	for {
		val := atomic.LoadUint32(addr)
		if val == targetValue {
			break
		}

		_, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), linux.FUTEX_WAIT, uintptr(val), 0, 0, 0)
		if e != 0 && e != unix.EAGAIN && e != unix.EINTR {
			return fmt.Errorf("failed to FUTEX_WAIT: %v", e)
		}
	}
	return nil
}

// futexWaitWake waits when other side will call FUTEX_WAKE. A value of the
// futex word has to be equal to futexValue and it must not be changed.
func futexWaitWake(futexAddr *uint32, futexValue uint32) error {
	for {
		_, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(futexAddr)), linux.FUTEX_WAIT, uintptr(futexValue), 0, 0, 0)
		if e == 0 {
			break
		}
		if e != unix.EAGAIN && e != unix.EINTR {
			return fmt.Errorf("failed to FUTEX_WAIT: %v", e)
		}
	}

	return nil
}

func (t *syscallThread) kickSeccompNotify() unix.Errno {
	_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(t.seccompNotify.Fd()),
		uintptr(linux.SECCOMP_IOCTL_NOTIF_SEND),
		uintptr(unsafe.Pointer(&t.seccompNotifyResp)))
	return errno
}

func (t *syscallThread) waitForSeccompNotify() error {
	for {
		req := linux.SeccompNotif{}
		_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(t.seccompNotify.Fd()),
			uintptr(linux.SECCOMP_IOCTL_NOTIF_RECV),
			uintptr(unsafe.Pointer(&req)))
		if errno == 0 {
			t.seccompNotifyResp.ID = req.ID
			break
		}
		if errno == unix.EINTR && t.subproc.alive() {
			continue
		}
		t.thread.kill()
		return fmt.Errorf("failed getting response from syscall thread : %w", errno)
	}
	return nil
}
