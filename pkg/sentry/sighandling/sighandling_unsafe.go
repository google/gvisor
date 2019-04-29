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

package sighandling

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// TODO(b/34161764): Move to pkg/abi/linux along with definitions in
// pkg/sentry/arch.
type sigaction struct {
	handler  uintptr
	flags    uint64
	restorer uintptr
	mask     uint64
}

// IgnoreChildStop sets the SA_NOCLDSTOP flag, causing child processes to not
// generate SIGCHLD when they stop.
func IgnoreChildStop() error {
	var sa sigaction

	// Get the existing signal handler information, and set the flag.
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(syscall.SIGCHLD), 0, uintptr(unsafe.Pointer(&sa)), linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}
	sa.flags |= linux.SA_NOCLDSTOP
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(syscall.SIGCHLD), uintptr(unsafe.Pointer(&sa)), 0, linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}

	return nil
}

// dieFromSignal kills the current process with sig.
//
// Preconditions: The default action of sig is termination.
func dieFromSignal(sig linux.Signal) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sa := sigaction{handler: linux.SIG_DFL}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&sa)), 0, linux.SignalSetSize, 0, 0); e != 0 {
		panic(fmt.Sprintf("rt_sigaction failed: %v", e))
	}

	set := linux.MakeSignalSet(sig)
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, linux.SIG_UNBLOCK, uintptr(unsafe.Pointer(&set)), 0, linux.SignalSetSize, 0, 0); e != 0 {
		panic(fmt.Sprintf("rt_sigprocmask failed: %v", e))
	}

	if err := syscall.Tgkill(syscall.Getpid(), syscall.Gettid(), syscall.Signal(sig)); err != nil {
		panic(fmt.Sprintf("tgkill failed: %v", err))
	}

	panic("failed to die")
}
