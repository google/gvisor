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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// allowedSyscalls is the set of syscalls executed by the gofer.
var allowedSyscalls = seccomp.SyscallRules{
	unix.SYS_ACCEPT:        {},
	unix.SYS_CLOCK_GETTIME: {},
	unix.SYS_CLOSE:         {},
	unix.SYS_DUP:           {},
	unix.SYS_EPOLL_CTL:     {},
	unix.SYS_EPOLL_PWAIT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_EVENTFD2: []seccomp.Rule{
		{
			seccomp.EqualTo(0),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_EXIT:       {},
	unix.SYS_EXIT_GROUP: {},
	unix.SYS_FALLOCATE: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_FCHMOD:   {},
	unix.SYS_FCHOWNAT: {},
	unix.SYS_FCNTL: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_GETFL),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_SETFL),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_GETFD),
		},
		// Used by flipcall.PacketWindowAllocator.Init().
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_ADD_SEALS),
		},
	},
	unix.SYS_FSTAT:     {},
	unix.SYS_FSTATFS:   {},
	unix.SYS_FSYNC:     {},
	unix.SYS_FTRUNCATE: {},
	unix.SYS_FUTEX: {
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
	// getcpu is used by some versions of the Go runtime and by the hostcpu
	// package on arm64.
	unix.SYS_GETCPU: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_GETDENTS64:   {},
	unix.SYS_GETPID:       {},
	unix.SYS_GETRANDOM:    {},
	unix.SYS_GETTID:       {},
	unix.SYS_GETTIMEOFDAY: {},
	unix.SYS_LINKAT:       {},
	unix.SYS_LSEEK:        {},
	unix.SYS_MADVISE:      {},
	unix.SYS_MEMFD_CREATE: {}, /// Used by flipcall.PacketWindowAllocator.Init().
	unix.SYS_MKDIRAT:      {},
	unix.SYS_MKNODAT:      {},
	// Used by the Go runtime as a temporarily workaround for a Linux
	// 5.2-5.4 bug.
	//
	// See src/runtime/os_linux_x86.go.
	//
	// TODO(b/148688965): Remove once this is gone from Go.
	unix.SYS_MLOCK: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(4096),
		},
	},
	unix.SYS_MMAP: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MAP_SHARED),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
		},
	},
	unix.SYS_MPROTECT:   {},
	unix.SYS_MUNMAP:     {},
	unix.SYS_NANOSLEEP:  {},
	unix.SYS_OPENAT:     {},
	unix.SYS_PPOLL:      {},
	unix.SYS_PREAD64:    {},
	unix.SYS_PWRITE64:   {},
	unix.SYS_READ:       {},
	unix.SYS_READLINKAT: {},
	unix.SYS_RECVMSG: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_TRUNC),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_TRUNC | unix.MSG_PEEK),
		},
	},
	unix.SYS_RENAMEAT:        {},
	unix.SYS_RESTART_SYSCALL: {},
	// May be used by the runtime during panic().
	unix.SYS_RT_SIGACTION:   {},
	unix.SYS_RT_SIGPROCMASK: {},
	unix.SYS_RT_SIGRETURN:   {},
	unix.SYS_SCHED_YIELD:    {},
	unix.SYS_SENDMSG: []seccomp.Rule{
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
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL),
		},
	},
	unix.SYS_SHUTDOWN: []seccomp.Rule{
		{seccomp.MatchAny{}, seccomp.EqualTo(unix.SHUT_RDWR)},
	},
	unix.SYS_SIGALTSTACK: {},
	// Used by fdchannel.NewConnectedSockets().
	unix.SYS_SOCKETPAIR: {
		{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_SEQPACKET | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_SYMLINKAT: {},
	unix.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	},
	unix.SYS_UNLINKAT:  {},
	unix.SYS_UTIMENSAT: {},
	unix.SYS_WRITE:     {},
}

var udsSyscalls = seccomp.SyscallRules{
	unix.SYS_SOCKET: []seccomp.Rule{
		{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_DGRAM),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_SEQPACKET),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_CONNECT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
		},
	},
}

var xattrSyscalls = seccomp.SyscallRules{
	unix.SYS_FGETXATTR: {},
	unix.SYS_FSETXATTR: {},
}
