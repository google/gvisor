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

//go:build linux
// +build linux

package sighandling

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// IgnoreChildStop sets the SA_NOCLDSTOP flag, causing child processes to not
// generate SIGCHLD when they stop.
func IgnoreChildStop() error {
	var sa linux.SigAction

	// Get the existing signal handler information, and set the flag.
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGCHLD), 0, uintptr(unsafe.Pointer(&sa)), linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}
	sa.Flags |= linux.SA_NOCLDSTOP
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGCHLD), uintptr(unsafe.Pointer(&sa)), 0, linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}

	return nil
}

// ReplaceSignalHandler replaces the existing signal handler for the provided
// signal with the function pointer at `handler`. This bypasses the Go runtime
// signal handlers, and should only be used for low-level signal handlers where
// use of signal.Notify is not appropriate.
//
// It stores the value of the previously set handler in previous.
func ReplaceSignalHandler(sig unix.Signal, handler uintptr, previous *uintptr) error {
	var sa linux.SigAction
	const maskLen = 8

	// Get the existing signal handler information, and save the current
	// handler. Once we replace it, we will use this pointer to fall back to
	// it when we receive other signals.
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), 0, uintptr(unsafe.Pointer(&sa)), maskLen, 0, 0); e != 0 {
		return e
	}

	// Fail if there isn't a previous handler.
	if sa.Handler == 0 {
		return fmt.Errorf("previous handler for signal %x isn't set", sig)
	}

	*previous = uintptr(sa.Handler)

	// Install our own handler.
	sa.Handler = uint64(handler)
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&sa)), 0, maskLen, 0, 0); e != 0 {
		return e
	}

	return nil
}

// KillItself sends SIGKILL to the current process, bypassing the init process
// restriction.
//
// The standard `kill(getpid(), SIGKILL)` syscall doesn't work when the current
// process is the init process within its PID namespace. This is a "known"
// Linux feature.
//
// This function uses the rt_tgqueueinfo syscall to send a "kernel-generated"
// SIGKILL.
func KillItself() error {
	pid := os.Getpid()
	tid, _, _ := unix.RawSyscall(unix.SYS_GETTID, 0, 0, 0)
	info := linux.SignalInfo{Code: linux.SI_KERNEL}
	// The current thread can send a fake kernel siginfo to itself.
	if _, _, e := unix.RawSyscall6(
		unix.SYS_RT_TGSIGQUEUEINFO,
		uintptr(pid), uintptr(tid),
		uintptr(linux.SIGKILL),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	); e != 0 {
		return e
	}
	panic("unreachable")
}
