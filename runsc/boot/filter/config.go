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

package filter

import (
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/seccomp"
)

// allowedSyscalls is the set of syscalls executed by the Sentry
// to the host OS.
var allowedSyscalls = seccomp.SyscallRules{
	syscall.SYS_ACCEPT:        {},
	syscall.SYS_ARCH_PRCTL:    {},
	syscall.SYS_CLOCK_GETTIME: {},
	syscall.SYS_CLONE:         {},
	syscall.SYS_CLOSE:         {},
	syscall.SYS_DUP:           {},
	syscall.SYS_EPOLL_CREATE1: {},
	syscall.SYS_EPOLL_CTL:     {},
	syscall.SYS_EPOLL_PWAIT:   {},
	syscall.SYS_EPOLL_WAIT:    {},
	syscall.SYS_EVENTFD2:      {},
	syscall.SYS_EXIT:          {},
	syscall.SYS_EXIT_GROUP:    {},
	syscall.SYS_FALLOCATE:     {},
	syscall.SYS_FCNTL:         {},
	syscall.SYS_FSTAT:         {},
	syscall.SYS_FSYNC:         {},
	syscall.SYS_FTRUNCATE:     {},
	syscall.SYS_FUTEX:         {},
	syscall.SYS_GETDENTS64:    {},
	syscall.SYS_GETPID:        {},
	unix.SYS_GETRANDOM:        {},
	syscall.SYS_GETSOCKOPT:    {},
	syscall.SYS_GETTID:        {},
	syscall.SYS_GETTIMEOFDAY:  {},
	syscall.SYS_LISTEN:        {},
	syscall.SYS_LSEEK:         {},
	// TODO: Remove SYS_LSTAT when executable lookup moves
	// into the gofer.
	syscall.SYS_LSTAT:           {},
	syscall.SYS_MADVISE:         {},
	syscall.SYS_MINCORE:         {},
	syscall.SYS_MMAP:            {},
	syscall.SYS_MPROTECT:        {},
	syscall.SYS_MUNMAP:          {},
	syscall.SYS_POLL:            {},
	syscall.SYS_PREAD64:         {},
	syscall.SYS_PWRITE64:        {},
	syscall.SYS_READ:            {},
	syscall.SYS_READV:           {},
	syscall.SYS_RECVMSG:         {},
	syscall.SYS_RESTART_SYSCALL: {},
	syscall.SYS_RT_SIGACTION:    {},
	syscall.SYS_RT_SIGPROCMASK:  {},
	syscall.SYS_RT_SIGRETURN:    {},
	syscall.SYS_SCHED_YIELD:     {},
	syscall.SYS_SENDMSG:         {},
	syscall.SYS_SETITIMER:       {},
	syscall.SYS_SHUTDOWN:        {},
	syscall.SYS_SIGALTSTACK:     {},
	syscall.SYS_SYNC_FILE_RANGE: {},
	syscall.SYS_TGKILL:          {},
	syscall.SYS_WRITE:           {},
	syscall.SYS_WRITEV:          {},

	// SYS_IOCTL is needed for terminal support, but we only allow
	// setting/getting termios and winsize.
	syscall.SYS_IOCTL: []seccomp.Rule{
		{
			seccomp.AllowAny{}, /* fd */
			seccomp.AllowValue(linux.TCGETS),
			seccomp.AllowAny{}, /* termios struct */
		},
		{
			seccomp.AllowAny{}, /* fd */
			seccomp.AllowValue(linux.TCSETS),
			seccomp.AllowAny{}, /* termios struct */
		},
		{
			seccomp.AllowAny{}, /* fd */
			seccomp.AllowValue(linux.TCSETSW),
			seccomp.AllowAny{}, /* termios struct */
		},
		{
			seccomp.AllowAny{}, /* fd */
			seccomp.AllowValue(linux.TIOCSWINSZ),
			seccomp.AllowAny{}, /* winsize struct */
		},
		{
			seccomp.AllowAny{}, /* fd */
			seccomp.AllowValue(linux.TIOCGWINSZ),
			seccomp.AllowAny{}, /* winsize struct */
		},
	},
}

// whitelistFSFilters returns syscalls made by whitelistFS. Using WhitelistFS
// is less secure because it runs inside the Sentry and must be able to perform
// file operations that would otherwise be disabled by seccomp when a Gofer is
// used. When whitelistFS is not used, openning new FD in the Sentry is
// disallowed.
func whitelistFSFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCESS:          {},
		syscall.SYS_FCHMOD:          {},
		syscall.SYS_FSTAT:           {},
		syscall.SYS_FSYNC:           {},
		syscall.SYS_FTRUNCATE:       {},
		syscall.SYS_GETCWD:          {},
		syscall.SYS_GETDENTS:        {},
		syscall.SYS_GETDENTS64:      {},
		syscall.SYS_LSEEK:           {},
		syscall.SYS_LSTAT:           {},
		syscall.SYS_MKDIR:           {},
		syscall.SYS_MKDIRAT:         {},
		syscall.SYS_NEWFSTATAT:      {},
		syscall.SYS_OPEN:            {},
		syscall.SYS_OPENAT:          {},
		syscall.SYS_PREAD64:         {},
		syscall.SYS_PWRITE64:        {},
		syscall.SYS_READ:            {},
		syscall.SYS_READLINK:        {},
		syscall.SYS_READLINKAT:      {},
		syscall.SYS_RENAMEAT:        {},
		syscall.SYS_STAT:            {},
		syscall.SYS_SYMLINK:         {},
		syscall.SYS_SYMLINKAT:       {},
		syscall.SYS_SYNC_FILE_RANGE: {},
		syscall.SYS_UNLINK:          {},
		syscall.SYS_UNLINKAT:        {},
		syscall.SYS_UTIMENSAT:       {},
		syscall.SYS_WRITE:           {},
	}
}

// hostInetFilters contains syscalls that are needed by sentry/socket/hostinet.
func hostInetFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCEPT4:     {},
		syscall.SYS_BIND:        {},
		syscall.SYS_CONNECT:     {},
		syscall.SYS_GETPEERNAME: {},
		syscall.SYS_GETSOCKNAME: {},
		syscall.SYS_GETSOCKOPT:  {},
		syscall.SYS_IOCTL:       {},
		syscall.SYS_LISTEN:      {},
		syscall.SYS_READV:       {},
		syscall.SYS_RECVFROM:    {},
		syscall.SYS_RECVMSG:     {},
		syscall.SYS_SENDMSG:     {},
		syscall.SYS_SENDTO:      {},
		syscall.SYS_SETSOCKOPT:  {},
		syscall.SYS_SHUTDOWN:    {},
		syscall.SYS_SOCKET:      {},
		syscall.SYS_WRITEV:      {},
	}
}

// ptraceFilters returns syscalls made exclusively by the ptrace platform.
func ptraceFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_PTRACE:         {},
		syscall.SYS_WAIT4:          {},
		unix.SYS_GETCPU:            {},
		unix.SYS_SCHED_SETAFFINITY: {},
	}
}

// kvmFilters returns syscalls made exclusively by the KVM platform.
func kvmFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_IOCTL:           {},
		syscall.SYS_RT_SIGSUSPEND:   {},
		syscall.SYS_RT_SIGTIMEDWAIT: {},
		0xffffffffffffffff:          {}, // KVM uses syscall -1 to transition to host.
	}
}
