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

package seccomp

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// SetFilter installs the given BPF program.
//
// This is safe to call from an afterFork context.
//
//go:nosplit
func SetFilter(instrs []linux.BPFInstruction) unix.Errno {
	// PR_SET_NO_NEW_PRIVS is required in order to enable seccomp. See seccomp(2) for details.
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, linux.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}

	sockProg := linux.SockFprog{
		Len:    uint16(len(instrs)),
		Filter: (*linux.BPFInstruction)(unsafe.Pointer(&instrs[0])),
	}
	return seccomp(linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_TSYNC, unsafe.Pointer(&sockProg))
}

func isKillProcessAvailable() (bool, error) {
	action := uint32(linux.SECCOMP_RET_KILL_PROCESS)
	if errno := seccomp(linux.SECCOMP_GET_ACTION_AVAIL, 0, unsafe.Pointer(&action)); errno != 0 {
		// EINVAL: SECCOMP_GET_ACTION_AVAIL not in this kernel yet.
		// EOPNOTSUPP: SECCOMP_RET_KILL_PROCESS not supported.
		if errno == unix.EINVAL || errno == unix.EOPNOTSUPP {
			return false, nil
		}
		return false, errno
	}
	return true, nil
}

// seccomp calls seccomp(2). This is safe to call from an afterFork context.
//
//go:nosplit
func seccomp(op, flags uint32, ptr unsafe.Pointer) unix.Errno {
	if _, _, errno := unix.RawSyscall(SYS_SECCOMP, uintptr(op), uintptr(flags), uintptr(ptr)); errno != 0 {
		return errno
	}
	return 0
}
