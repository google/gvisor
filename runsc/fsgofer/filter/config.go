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
var allowedSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_ACCEPT:        seccomp.MatchAll{},
	unix.SYS_CLOCK_GETTIME: seccomp.MatchAll{},
	unix.SYS_CLOSE:         seccomp.MatchAll{},
	unix.SYS_DUP:           seccomp.MatchAll{},
	unix.SYS_EPOLL_CTL:     seccomp.MatchAll{},
	unix.SYS_EPOLL_PWAIT: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	unix.SYS_EVENTFD2: seccomp.PerArg{
		seccomp.EqualTo(0),
		seccomp.EqualTo(0),
	},
	unix.SYS_EXIT:       seccomp.MatchAll{},
	unix.SYS_EXIT_GROUP: seccomp.MatchAll{},
	unix.SYS_FCHMOD:     seccomp.MatchAll{},
	unix.SYS_FCHOWNAT:   seccomp.MatchAll{},
	unix.SYS_FCNTL: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_GETFL),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_SETFL),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_GETFD),
		},
		// Used by flipcall.PacketWindowAllocator.Init().
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_ADD_SEALS),
		},
	},
	unix.SYS_FSTAT: seccomp.MatchAll{},
	unix.SYS_FSYNC: seccomp.MatchAll{},
	unix.SYS_FUTEX: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		// Non-private futex used for flipcall.
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAIT),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAKE),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
	},
	// getcpu is used by some versions of the Go runtime and by the hostcpu
	// package on arm64.
	unix.SYS_GETCPU: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
		seccomp.EqualTo(0),
	},
	unix.SYS_GETPID:       seccomp.MatchAll{},
	unix.SYS_GETRANDOM:    seccomp.MatchAll{},
	unix.SYS_GETTID:       seccomp.MatchAll{},
	unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
	unix.SYS_LSEEK:        seccomp.MatchAll{},
	unix.SYS_MADVISE:      seccomp.MatchAll{},
	unix.SYS_MEMFD_CREATE: seccomp.MatchAll{}, // Used by flipcall.PacketWindowAllocator.Init().
	unix.SYS_MMAP: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_SHARED),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
		},
	},
	unix.SYS_MPROTECT:  seccomp.MatchAll{},
	unix.SYS_MUNMAP:    seccomp.MatchAll{},
	unix.SYS_NANOSLEEP: seccomp.MatchAll{},
	unix.SYS_OPENAT:    seccomp.MatchAll{},
	unix.SYS_PPOLL:     seccomp.MatchAll{},
	unix.SYS_PREAD64:   seccomp.MatchAll{},
	unix.SYS_PWRITE64:  seccomp.MatchAll{},
	unix.SYS_READ:      seccomp.MatchAll{},
	unix.SYS_RECVMSG: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_TRUNC),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_TRUNC | unix.MSG_PEEK),
		},
	},
	unix.SYS_RESTART_SYSCALL: seccomp.MatchAll{},
	// May be used by the runtime during panic().
	unix.SYS_RT_SIGACTION:   seccomp.MatchAll{},
	unix.SYS_RT_SIGPROCMASK: seccomp.MatchAll{},
	unix.SYS_RT_SIGRETURN:   seccomp.MatchAll{},
	unix.SYS_SCHED_YIELD:    seccomp.MatchAll{},
	unix.SYS_SENDMSG: seccomp.Or{
		// Used by fdchannel.Endpoint.SendFD().
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		// Used by unet.SocketWriter.WriteVec().
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL),
		},
	},
	unix.SYS_SHUTDOWN: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.SHUT_RDWR),
	},
	unix.SYS_SIGALTSTACK: seccomp.MatchAll{},
	// Used by fdchannel.NewConnectedSockets().
	unix.SYS_SOCKETPAIR: seccomp.PerArg{
		seccomp.EqualTo(unix.AF_UNIX),
		seccomp.EqualTo(unix.SOCK_SEQPACKET | unix.SOCK_CLOEXEC),
		seccomp.EqualTo(0),
	},
	unix.SYS_TGKILL: seccomp.PerArg{
		seccomp.EqualTo(uint64(os.Getpid())),
	},
	unix.SYS_WRITE: seccomp.MatchAll{},
})

var udsCommonSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_SOCKET: seccomp.Or{
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_DGRAM),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_SEQPACKET),
			seccomp.EqualTo(0),
		},
	},
})

var udsOpenSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CONNECT: seccomp.MatchAll{},
})

var udsCreateSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_ACCEPT4: seccomp.MatchAll{},
	unix.SYS_BIND:    seccomp.MatchAll{},
	unix.SYS_LISTEN:  seccomp.MatchAll{},
})

var lisafsFilters = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_FALLOCATE: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	unix.SYS_FCHMODAT:   seccomp.MatchAll{},
	unix.SYS_FGETXATTR:  seccomp.MatchAll{},
	unix.SYS_FSTATFS:    seccomp.MatchAll{},
	unix.SYS_GETDENTS64: seccomp.MatchAll{},
	unix.SYS_LINKAT: seccomp.PerArg{
		seccomp.NonNegativeFD{},
		seccomp.AnyValue{},
		seccomp.NonNegativeFD{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	unix.SYS_MKDIRAT:    seccomp.MatchAll{},
	unix.SYS_MKNODAT:    seccomp.MatchAll{},
	unix.SYS_READLINKAT: seccomp.MatchAll{},
	unix.SYS_RENAMEAT:   seccomp.MatchAll{},
	unix.SYS_SYMLINKAT:  seccomp.MatchAll{},
	unix.SYS_FTRUNCATE:  seccomp.MatchAll{},
	unix.SYS_UNLINKAT:   seccomp.MatchAll{},
	unix.SYS_UTIMENSAT:  seccomp.MatchAll{},
})
