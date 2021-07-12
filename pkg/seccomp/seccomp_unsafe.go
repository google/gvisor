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
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// SetFilter installs the given BPF program.
func SetFilter(instrs []linux.BPFInstruction) error {
	// PR_SET_NO_NEW_PRIVS is required in order to enable seccomp. See
	// seccomp(2) for details.
	//
	// PR_SET_NO_NEW_PRIVS is specific to the calling thread, not the whole
	// thread group, so between PR_SET_NO_NEW_PRIVS and seccomp() below we must
	// remain on the same thread. no_new_privs will be propagated to other
	// threads in the thread group by seccomp(SECCOMP_FILTER_FLAG_TSYNC), in
	// kernel/seccomp.c:seccomp_sync_threads().
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, linux.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}

	sockProg := linux.SockFprog{
		Len:    uint16(len(instrs)),
		Filter: (*linux.BPFInstruction)(unsafe.Pointer(&instrs[0])),
	}
	tid, errno := seccomp(linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_TSYNC, unsafe.Pointer(&sockProg))
	if errno != 0 {
		return errno
	}
	// "On error, if SECCOMP_FILTER_FLAG_TSYNC was used, the return value is
	// the ID of the thread that caused the synchronization failure. (This ID
	// is a kernel thread ID of the type returned by clone(2) and gettid(2).)"
	// - seccomp(2)
	if tid != 0 {
		return fmt.Errorf("couldn't synchronize filter to TID %d", tid)
	}
	return nil
}

// SetFilterInChild is equivalent to SetFilter, but:
//
// - It is safe to call after runtime.syscall_runtime_AfterForkInChild.
//
// - It requires that the calling goroutine cannot be moved to another thread,
// which either requires that runtime.LockOSThread() is in effect or that the
// caller is in fact in a fork()ed child process.
//
// - Since fork()ed child processes cannot perform heap allocation, it returns
// a unix.Errno rather than an error.
//
// - The race instrumentation has to be disabled for all functions that are
// called in a forked child.
//
//go:norace
//go:nosplit
func SetFilterInChild(instrs []linux.BPFInstruction) unix.Errno {
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, linux.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}

	sockProg := linux.SockFprog{
		Len:    uint16(len(instrs)),
		Filter: (*linux.BPFInstruction)(unsafe.Pointer(&instrs[0])),
	}
	tid, errno := seccomp(linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_TSYNC, unsafe.Pointer(&sockProg))
	if errno != 0 {
		return errno
	}
	if tid != 0 {
		// Return an errno that seccomp(2) doesn't to uniquely identify this
		// case. Since this case occurs if another thread has a conflicting
		// filter set, "name not unique on network" is at least suggestive?
		return unix.ENOTUNIQ
	}
	return 0
}

func isKillProcessAvailable() (bool, error) {
	action := uint32(linux.SECCOMP_RET_KILL_PROCESS)
	if _, errno := seccomp(linux.SECCOMP_GET_ACTION_AVAIL, 0, unsafe.Pointer(&action)); errno != 0 {
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
func seccomp(op, flags uint32, ptr unsafe.Pointer) (uintptr, unix.Errno) {
	n, _, errno := unix.RawSyscall(SYS_SECCOMP, uintptr(op), uintptr(flags), uintptr(ptr))
	return n, errno
}
