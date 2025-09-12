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
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
)

// NotificationCallback is a callback which is called when a blocked syscall is triggered.
type NotificationCallback func(f *os.File, req linux.SeccompNotif, ret int)

// SetFilterAndLogNotifications installs the given BPF program and logs user
// notifications triggered by the seccomp filter. It allows the triggering
// syscalls to proceed without being blocked.
//
// This function is intended for debugging seccomp filter violations and should
// not be used in production environments.
//
// Note: It spawns a background goroutine to monitor a seccomp file descriptor
// and log any received notifications.
func SetFilterAndLogNotifications(
	instrs []bpf.Instruction,
	options ProgramOptions,
) error {
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
	flags := linux.SECCOMP_FILTER_FLAG_TSYNC |
		linux.SECCOMP_FILTER_FLAG_NEW_LISTENER |
		linux.SECCOMP_FILTER_FLAG_TSYNC_ESRCH | (1 << 5)
	fd, errno := seccomp(linux.SECCOMP_SET_MODE_FILTER, uint32(flags), unsafe.Pointer(&sockProg))
	if errno != 0 {
		return errno
	}
	if options.NotifyFDNum > 0 {
		if err := unix.Dup2(int(fd), options.NotifyFDNum); err != nil {
			panic(fmt.Sprintf("dup2 %d -> %d: %v", fd, options.NotifyFDNum, err))
		}
		unix.Close(int(fd))
		fd = uintptr(options.NotifyFDNum)
	}
	f := os.NewFile(fd, "seccomp_notify")
	go func() {
		// LockOSThread should help minimizing interactions with the scheduler.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var (
			req  linux.SeccompNotif
			resp linux.SeccompNotifResp
		)
		for {
			req = linux.SeccompNotif{}
			_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(f.Fd()),
				uintptr(linux.SECCOMP_IOCTL_NOTIF_RECV),
				uintptr(unsafe.Pointer(&req)))
			if errno != 0 {
				if errno == unix.EINTR {
					continue
				}
				panic(fmt.Sprintf("SECCOMP_IOCTL_NOTIF_RECV failed with %d", errno))
			}

			attached := true
			if errno := hostsyscall.RawSyscallErrno(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(req.Pid), 0); errno != 0 {
				log.Warningf("unable to attach: %v", errno)
				attached = false
			}
			resp = linux.SeccompNotifResp{
				ID:    req.ID,
				Flags: linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
			}
			errno = hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(f.Fd()),
				uintptr(linux.SECCOMP_IOCTL_NOTIF_SEND),
				uintptr(unsafe.Pointer(&resp)))
			if errno != 0 {
				panic(fmt.Sprintf("SECCOMP_IOCTL_NOTIF_SEND failed with %d", errno))
			}
			if !attached {
				if options.NotificationCallback != nil {
					options.NotificationCallback(f, req, 0)
				} else {
					log.Warningf("Seccomp violation: %#v", req)
				}
				continue
			}
			for {
				var info unix.Siginfo
				errno := unix.Waitid(unix.P_PID, int(req.Pid), &info, syscall.WALL|syscall.WEXITED, nil)
				if errno == syscall.EINTR {
					continue
				} else if errno != nil {
					log.Warningf("failed to wait for the child process: %v", errno)
				}
				break
			}
			ret := 0
			{
				var regs linux.PtraceRegs
				iovec := unix.Iovec{
					Base: (*byte)(unsafe.Pointer(&regs)),
					Len:  uint64(unsafe.Sizeof(regs)),
				}
				_, _, errno := unix.RawSyscall6(
					unix.SYS_PTRACE,
					unix.PTRACE_GETREGSET,
					uintptr(req.Pid),
					linux.NT_PRSTATUS,
					uintptr(unsafe.Pointer(&iovec)),
					0, 0)
				if errno != 0 {
					log.Warningf("unable to get registers: %s", errno)
				}
				ret = int(regs.SyscallRet())
			}

			if options.NotificationCallback != nil {
				options.NotificationCallback(f, req, ret)
			} else {
				log.Warningf("Seccomp violation: %#v", req)
			}
			if errno := hostsyscall.RawSyscallErrno(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(req.Pid), 0); errno != 0 {
				panic(fmt.Sprintf("unable to detach: %v", errno))
			}
		}
	}()
	return nil
}

// SetFilter installs the given BPF program.
func SetFilter(instrs []bpf.Instruction) error {
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
//   - It is safe to call after runtime.syscall_runtime_AfterForkInChild.
//
//   - It requires that the calling goroutine cannot be moved to another thread,
//     which either requires that runtime.LockOSThread() is in effect or that the
//     caller is in fact in a fork()ed child process.
//
//   - Since fork()ed child processes cannot perform heap allocation, it returns
//     a unix.Errno rather than an error.
//
//   - The race instrumentation has to be disabled for all functions that are
//     called in a forked child.
//
//go:norace
//go:nosplit
func SetFilterInChild(instrs []bpf.Instruction) unix.Errno {
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
	// Note: Usage of RawSyscall6 over RawSyscall is intentional in order to
	//       reduce stack-growth.
	n, _, errno := unix.RawSyscall6(SYS_SECCOMP, uintptr(op), uintptr(flags), uintptr(ptr), 0, 0, 0)
	return n, errno
}
