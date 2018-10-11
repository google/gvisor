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

// +build amd64

package seccomp

import (
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// sockFprog is sock_fprog taken from <linux/filter.h>.
type sockFprog struct {
	Len    uint16
	pad    [6]byte
	Filter *linux.BPFInstruction
}

// SetFilter installs the given BPF program.
//
// This is safe to call from an afterFork context.
//
//go:nosplit
func SetFilter(instrs []linux.BPFInstruction) syscall.Errno {
	// SYS_SECCOMP is not available in syscall package.
	const SYS_SECCOMP = 317

	// PR_SET_NO_NEW_PRIVS is required in order to enable seccomp. See seccomp(2) for details.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, linux.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}

	// TODO: Use SECCOMP_FILTER_FLAG_KILL_PROCESS when available.
	sockProg := sockFprog{
		Len:    uint16(len(instrs)),
		Filter: (*linux.BPFInstruction)(unsafe.Pointer(&instrs[0])),
	}
	if _, _, errno := syscall.RawSyscall(SYS_SECCOMP, linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&sockProg))); errno != 0 {
		return errno
	}

	return 0
}
