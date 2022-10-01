// Copyright 2022 The gVisor Authors.
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

package kernel

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/procid"
)

//go:norace
//go:nosplit
func (t *Task) blockPollUnsafe(pfds []linux.PollFD, timeout *linux.Timespec) (int, error) {
	for {
		runtime.LockOSThread()
		tid := int32(procid.Current())
		sigmask := interruptibleSyscallSignalMask(tid)
		t.syscallTID.Store(tid)
		gohacks.EnterSyscall()
		var (
			un    uintptr
			errno unix.Errno
		)
		if len(pfds) == 0 {
			un, _, errno = unix.RawSyscall6(unix.SYS_PPOLL, 0, 0, uintptr(unsafe.Pointer(timeout)), uintptr(unsafe.Pointer(&sigmask)), linux.SignalSetSize, 0)
		} else {
			un, _, errno = unix.RawSyscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&pfds[0])), uintptr(len(pfds)), uintptr(unsafe.Pointer(timeout)), uintptr(unsafe.Pointer(&sigmask)), linux.SignalSetSize, 0)
		}
		// Call UnlockOSThread(), which is safely nosplit and in the runtime
		// package, so that if we lost our P to sysmon and need to reschedule in
		// exitsyscall(), the Go runtime doesn't need to wake this thread to resume
		// our execution (increasing our wakeup latency).
		runtime.UnlockOSThread()
		gohacks.ExitSyscall()
		t.syscallTID.Store(0)
		if un != 0 {
			return int(un), nil
		}
		if errno == 0 {
			return 0, linuxerr.ETIMEDOUT
		}
		if errno != unix.EINTR {
			return 0, errno
		}
		if t.interrupted() {
			return 0, linuxerr.ErrInterrupted
		}
		// Spurious interrupt; retry.
	}
}
