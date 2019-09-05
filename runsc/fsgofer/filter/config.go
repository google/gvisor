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

package filter

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// allowedSyscalls is the set of syscalls executed by the gofer.
var allowedSyscalls = seccomp.SyscallRules{
	syscall.SYS_ACCEPT: {},
	syscall.SYS_SOCKET: []seccomp.Rule{
		{
			seccomp.AllowValue(syscall.AF_UNIX),
		},
	},
	syscall.SYS_CONNECT: []seccomp.Rule{
		{
			seccomp.AllowAny{},
		},
	},
	syscall.SYS_ARCH_PRCTL: []seccomp.Rule{
		{seccomp.AllowValue(linux.ARCH_GET_FS)},
		{seccomp.AllowValue(linux.ARCH_SET_FS)},
	},
	syscall.SYS_CLOCK_GETTIME: {},
	syscall.SYS_CLONE: []seccomp.Rule{
		{
			seccomp.AllowValue(
				syscall.CLONE_VM |
					syscall.CLONE_FS |
					syscall.CLONE_FILES |
					syscall.CLONE_SIGHAND |
					syscall.CLONE_SYSVSEM |
					syscall.CLONE_THREAD),
		},
	},
	syscall.SYS_CLOSE:     {},
	syscall.SYS_DUP:       {},
	syscall.SYS_EPOLL_CTL: {},
	syscall.SYS_EPOLL_PWAIT: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_EVENTFD2: []seccomp.Rule{
		{
			seccomp.AllowValue(0),
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_EXIT:       {},
	syscall.SYS_EXIT_GROUP: {},
	syscall.SYS_FALLOCATE: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_FCHMOD:   {},
	syscall.SYS_FCHOWNAT: {},
	syscall.SYS_FCNTL: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.F_GETFL),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.F_SETFL),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.F_GETFD),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.F_DUPFD_CLOEXEC),
		},
	},
	syscall.SYS_FSTAT:     {},
	syscall.SYS_FSTATFS:   {},
	syscall.SYS_FSYNC:     {},
	syscall.SYS_FTRUNCATE: {},
	syscall.SYS_FUTEX: {
		seccomp.Rule{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
		seccomp.Rule{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_GETDENTS64:   {},
	syscall.SYS_GETPID:       {},
	unix.SYS_GETRANDOM:       {},
	syscall.SYS_GETTID:       {},
	syscall.SYS_GETTIMEOFDAY: {},
	syscall.SYS_LINKAT:       {},
	syscall.SYS_LSEEK:        {},
	syscall.SYS_MADVISE:      {},
	syscall.SYS_MKDIRAT:      {},
	syscall.SYS_MMAP: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MAP_SHARED),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_FIXED),
		},
	},
	syscall.SYS_MPROTECT:   {},
	syscall.SYS_MUNMAP:     {},
	syscall.SYS_NANOSLEEP:  {},
	syscall.SYS_NEWFSTATAT: {},
	syscall.SYS_OPENAT:     {},
	syscall.SYS_PPOLL:      {},
	syscall.SYS_PREAD64:    {},
	syscall.SYS_PWRITE64:   {},
	syscall.SYS_READ:       {},
	syscall.SYS_READLINKAT: {},
	syscall.SYS_RECVMSG: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MSG_DONTWAIT | syscall.MSG_TRUNC),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MSG_DONTWAIT | syscall.MSG_TRUNC | syscall.MSG_PEEK),
		},
	},
	syscall.SYS_RENAMEAT:        {},
	syscall.SYS_RESTART_SYSCALL: {},
	syscall.SYS_RT_SIGPROCMASK:  {},
	syscall.SYS_SCHED_YIELD:     {},
	syscall.SYS_SENDMSG: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL),
		},
	},
	syscall.SYS_SHUTDOWN: []seccomp.Rule{
		{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SHUT_RDWR)},
	},
	syscall.SYS_SIGALTSTACK: {},
	syscall.SYS_SYMLINKAT:   {},
	syscall.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.AllowValue(uint64(os.Getpid())),
		},
	},
	syscall.SYS_UNLINKAT:  {},
	syscall.SYS_UTIMENSAT: {},
	syscall.SYS_WRITE:     {},
}
