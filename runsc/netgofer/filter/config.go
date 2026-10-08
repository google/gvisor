// Copyright 2026 The gVisor Authors.
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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// allowedSyscalls is the set of syscalls executed by the netgofer.
var allowedSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CLOCK_GETTIME: seccomp.MatchAll{},
	unix.SYS_CLOSE:         seccomp.MatchAll{},
	// connect does not constrain the destination address since it is dynamic. Address filtering is handled in Go.
	unix.SYS_CONNECT:       seccomp.MatchAll{},
	unix.SYS_EPOLL_CREATE1: seccomp.MatchAll{},
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
	},
	unix.SYS_EXIT:       seccomp.MatchAll{},
	unix.SYS_EXIT_GROUP: seccomp.MatchAll{},
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
	},
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
	},
	// getcpu is used by some versions of the Go runtime and by the hostcpu
	// package on arm64.
	unix.SYS_GETCPU: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
		seccomp.EqualTo(0),
	},
	unix.SYS_GETPEERNAME: seccomp.MatchAll{},
	unix.SYS_GETPID:      seccomp.MatchAll{},
	unix.SYS_GETRANDOM:   seccomp.MatchAll{},
	unix.SYS_GETSOCKNAME: seccomp.MatchAll{},
	unix.SYS_GETSOCKOPT: seccomp.PerArg{
		seccomp.AnyValue{}, // fd
		seccomp.EqualTo(unix.SOL_SOCKET),
		seccomp.EqualTo(unix.SO_ERROR),
	},
	unix.SYS_GETTID:       seccomp.MatchAll{},
	unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
	unix.SYS_MADVISE:      seccomp.MatchAll{},
	unix.SYS_MMAP: seccomp.Or{
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
		seccomp.PerArg{ // Used by vdso getrandom().
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_WRITE | unix.PROT_READ),
			seccomp.EqualTo(linux.MAP_DROPPABLE | unix.MAP_ANONYMOUS),
		},
	},
	unix.SYS_MPROTECT:  seccomp.MatchAll{},
	unix.SYS_MUNMAP:    seccomp.MatchAll{},
	unix.SYS_NANOSLEEP: seccomp.MatchAll{},
	unix.SYS_PPOLL:     seccomp.MatchAll{},
	unix.SYS_PRCTL: seccomp.PerArg{
		seccomp.EqualTo(unix.PR_SET_VMA),
		seccomp.EqualTo(unix.PR_SET_VMA_ANON_NAME),
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
	},
	// Used by Go's automatic GOMAXPROCS updater to read cgroup CPU limits.
	unix.SYS_PREAD64: seccomp.MatchAll{},
	unix.SYS_READ:    seccomp.MatchAll{},
	unix.SYS_READV:   seccomp.MatchAll{},
	unix.SYS_RECVMMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.MSG_DONTWAIT),
	},
	unix.SYS_RESTART_SYSCALL: seccomp.MatchAll{},
	// May be used by the runtime during panic().
	unix.SYS_RT_SIGACTION:   seccomp.MatchAll{},
	unix.SYS_RT_SIGPROCMASK: seccomp.MatchAll{},
	unix.SYS_RT_SIGRETURN:   seccomp.MatchAll{},
	// Used by Go's automatic GOMAXPROCS updater.
	unix.SYS_SCHED_GETAFFINITY: seccomp.PerArg{
		seccomp.EqualTo(0),
	},
	unix.SYS_SCHED_YIELD: seccomp.MatchAll{},
	unix.SYS_SENDMMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.MSG_DONTWAIT),
	},
	unix.SYS_SETSOCKOPT: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_KEEPALIVE),
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.IPPROTO_IPV6),
			seccomp.EqualTo(unix.IPV6_V6ONLY),
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(unix.TCP_KEEPINTVL),
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(unix.TCP_KEEPIDLE),
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(unix.TCP_KEEPCNT),
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, // fd
			seccomp.EqualTo(unix.IPPROTO_TCP),
			seccomp.EqualTo(unix.TCP_NODELAY),
		},
	},
	unix.SYS_SHUTDOWN: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SHUT_RD),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SHUT_WR),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SHUT_RDWR),
		},
	},
	unix.SYS_SIGALTSTACK: seccomp.MatchAll{},
	unix.SYS_SOCKET: seccomp.Or{
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.IPPROTO_TCP),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.IPPROTO_TCP),
		},
	},
	unix.SYS_WRITE:  seccomp.MatchAll{},
	unix.SYS_WRITEV: seccomp.MatchAll{},
})
