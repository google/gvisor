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
	syscall.SYS_ACCEPT:        {},
	syscall.SYS_CLOCK_GETTIME: {},
	syscall.SYS_CLONE: []seccomp.Rule{
		{
			seccomp.EqualTo(
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
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_EVENTFD2: []seccomp.Rule{
		{
			seccomp.EqualTo(0),
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_EXIT:       {},
	syscall.SYS_EXIT_GROUP: {},
	syscall.SYS_FALLOCATE: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_FCHMOD:   {},
	syscall.SYS_FCHOWNAT: {},
	syscall.SYS_FCNTL: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.F_GETFL),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.F_SETFL),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.F_GETFD),
		},
		// Used by flipcall.PacketWindowAllocator.Init().
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_ADD_SEALS),
		},
	},
	syscall.SYS_FSTAT:     {},
	syscall.SYS_FSTATFS:   {},
	syscall.SYS_FSYNC:     {},
	syscall.SYS_FTRUNCATE: {},
	syscall.SYS_FUTEX: {
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		// Non-private futex used for flipcall.
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
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
	unix.SYS_MEMFD_CREATE:    {}, /// Used by flipcall.PacketWindowAllocator.Init().
	syscall.SYS_MKDIRAT:      {},
	syscall.SYS_MKNODAT:      {},
	// Used by the Go runtime as a temporarily workaround for a Linux
	// 5.2-5.4 bug.
	//
	// See src/runtime/os_linux_x86.go.
	//
	// TODO(b/148688965): Remove once this is gone from Go.
	syscall.SYS_MLOCK: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(4096),
		},
	},
	syscall.SYS_MMAP: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MAP_SHARED),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_FIXED),
		},
	},
	syscall.SYS_MPROTECT:   {},
	syscall.SYS_MUNMAP:     {},
	syscall.SYS_NANOSLEEP:  {},
	syscall.SYS_OPENAT:     {},
	syscall.SYS_PPOLL:      {},
	syscall.SYS_PREAD64:    {},
	syscall.SYS_PWRITE64:   {},
	syscall.SYS_READ:       {},
	syscall.SYS_READLINKAT: {},
	syscall.SYS_RECVMSG: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MSG_DONTWAIT | syscall.MSG_TRUNC),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MSG_DONTWAIT | syscall.MSG_TRUNC | syscall.MSG_PEEK),
		},
	},
	syscall.SYS_RENAMEAT:        {},
	syscall.SYS_RESTART_SYSCALL: {},
	syscall.SYS_RT_SIGPROCMASK:  {},
	syscall.SYS_RT_SIGRETURN:    {},
	syscall.SYS_SCHED_YIELD:     {},
	syscall.SYS_SENDMSG: []seccomp.Rule{
		// Used by fdchannel.Endpoint.SendFD().
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		// Used by unet.SocketWriter.WriteVec().
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL),
		},
	},
	syscall.SYS_SHUTDOWN: []seccomp.Rule{
		{seccomp.MatchAny{}, seccomp.EqualTo(syscall.SHUT_RDWR)},
	},
	syscall.SYS_SIGALTSTACK: {},
	// Used by fdchannel.NewConnectedSockets().
	syscall.SYS_SOCKETPAIR: {
		{
			seccomp.EqualTo(syscall.AF_UNIX),
			seccomp.EqualTo(syscall.SOCK_SEQPACKET | syscall.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_SYMLINKAT: {},
	syscall.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	},
	syscall.SYS_UNLINKAT:  {},
	syscall.SYS_UTIMENSAT: {},
	syscall.SYS_WRITE:     {},
}

var udsSyscalls = seccomp.SyscallRules{
	syscall.SYS_SOCKET: []seccomp.Rule{
		{
			seccomp.EqualTo(syscall.AF_UNIX),
			seccomp.EqualTo(syscall.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(syscall.AF_UNIX),
			seccomp.EqualTo(syscall.SOCK_DGRAM),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(syscall.AF_UNIX),
			seccomp.EqualTo(syscall.SOCK_SEQPACKET),
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_CONNECT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
		},
	},
}
