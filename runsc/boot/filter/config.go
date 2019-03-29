// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/seccomp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/fdbased"
)

// allowedSyscalls is the set of syscalls executed by the Sentry to the host OS.
var allowedSyscalls = seccomp.SyscallRules{
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
	syscall.SYS_CLOSE:         {},
	syscall.SYS_DUP:           {},
	syscall.SYS_EPOLL_CREATE1: {},
	syscall.SYS_EPOLL_CTL:     {},
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
	syscall.SYS_FALLOCATE:  {},
	syscall.SYS_FCHMOD:     {},
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
	},
	syscall.SYS_FSTAT:     {},
	syscall.SYS_FSYNC:     {},
	syscall.SYS_FTRUNCATE: {},
	syscall.SYS_FUTEX: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_GETPID: {},
	unix.SYS_GETRANDOM: {},
	syscall.SYS_GETSOCKOPT: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.SOL_SOCKET),
			seccomp.AllowValue(syscall.SO_DOMAIN),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.SOL_SOCKET),
			seccomp.AllowValue(syscall.SO_TYPE),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.SOL_SOCKET),
			seccomp.AllowValue(syscall.SO_ERROR),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.SOL_SOCKET),
			seccomp.AllowValue(syscall.SO_SNDBUF),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.SOL_SOCKET),
			seccomp.AllowValue(syscall.SO_REUSEADDR),
		},
	},
	syscall.SYS_GETTID:       {},
	syscall.SYS_GETTIMEOFDAY: {},
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
			seccomp.AllowValue(linux.TCSETSF),
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
	syscall.SYS_LSEEK:   {},
	syscall.SYS_MADVISE: {},
	syscall.SYS_MINCORE: {},
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
			seccomp.AllowValue(syscall.MAP_PRIVATE),
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
			seccomp.AllowValue(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_STACK),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_NORESERVE),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.PROT_WRITE | syscall.PROT_READ),
			seccomp.AllowValue(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_FIXED),
		},
	},
	syscall.SYS_MPROTECT:  {},
	syscall.SYS_MUNMAP:    {},
	syscall.SYS_NANOSLEEP: {},
	syscall.SYS_POLL:      {},
	syscall.SYS_PREAD64:   {},
	syscall.SYS_PWRITE64:  {},
	syscall.SYS_READ:      {},
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
	syscall.SYS_RECVMMSG: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(fdbased.MaxMsgsPerRecv),
			seccomp.AllowValue(syscall.MSG_DONTWAIT),
			seccomp.AllowValue(0),
		},
	},
	syscall.SYS_RESTART_SYSCALL: {},
	syscall.SYS_RT_SIGACTION:    {},
	syscall.SYS_RT_SIGPROCMASK:  {},
	syscall.SYS_RT_SIGRETURN:    {},
	syscall.SYS_SCHED_YIELD:     {},
	syscall.SYS_SENDMSG: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL),
		},
	},
	syscall.SYS_SETITIMER: {},
	syscall.SYS_SHUTDOWN: []seccomp.Rule{
		{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SHUT_RDWR)},
	},
	syscall.SYS_SIGALTSTACK:     {},
	syscall.SYS_SYNC_FILE_RANGE: {},
	syscall.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.AllowValue(uint64(os.Getpid())),
		},
	},
	syscall.SYS_WRITE: {},
	// The only user in rawfile.NonBlockingWrite3 always passes iovcnt with
	// values 2 or 3. Three iovec-s are passed, when the PACKET_VNET_HDR
	// option is enabled for a packet socket.
	syscall.SYS_WRITEV: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(2),
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(3),
		},
	},
}

// hostInetFilters contains syscalls that are needed by sentry/socket/hostinet.
func hostInetFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCEPT4: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowAny{},
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
			},
		},
		syscall.SYS_BIND:        {},
		syscall.SYS_CONNECT:     {},
		syscall.SYS_GETPEERNAME: {},
		syscall.SYS_GETSOCKNAME: {},
		syscall.SYS_GETSOCKOPT: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_V6ONLY),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_ERROR),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_KEEPALIVE),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_SNDBUF),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_RCVBUF),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_REUSEADDR),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_TYPE),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_LINGER),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_TCP),
				seccomp.AllowValue(syscall.TCP_NODELAY),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_TCP),
				seccomp.AllowValue(syscall.TCP_INFO),
			},
		},
		syscall.SYS_IOCTL: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.TIOCOUTQ),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.TIOCINQ),
			},
		},
		syscall.SYS_LISTEN:   {},
		syscall.SYS_READV:    {},
		syscall.SYS_RECVFROM: {},
		syscall.SYS_RECVMSG:  {},
		syscall.SYS_SENDMSG:  {},
		syscall.SYS_SENDTO:   {},
		syscall.SYS_SETSOCKOPT: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_V6ONLY),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_SNDBUF),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_RCVBUF),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_REUSEADDR),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_TCP),
				seccomp.AllowValue(syscall.TCP_NODELAY),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
		},
		syscall.SYS_SHUTDOWN: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SHUT_RD),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SHUT_WR),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SHUT_RDWR),
			},
		},
		syscall.SYS_SOCKET: []seccomp.Rule{
			{
				seccomp.AllowValue(syscall.AF_INET),
				seccomp.AllowValue(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.AllowValue(0),
			},
			{
				seccomp.AllowValue(syscall.AF_INET),
				seccomp.AllowValue(syscall.SOCK_DGRAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.AllowValue(0),
			},
			{
				seccomp.AllowValue(syscall.AF_INET6),
				seccomp.AllowValue(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.AllowValue(0),
			},
			{
				seccomp.AllowValue(syscall.AF_INET6),
				seccomp.AllowValue(syscall.SOCK_DGRAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.AllowValue(0),
			},
		},
		syscall.SYS_WRITEV: {},
	}
}

// ptraceFilters returns syscalls made exclusively by the ptrace platform.
func ptraceFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		unix.SYS_GETCPU:            {},
		unix.SYS_SCHED_SETAFFINITY: {},
		syscall.SYS_PTRACE:         {},
		syscall.SYS_TGKILL:         {},
		syscall.SYS_WAIT4:          {},
	}
}

// kvmFilters returns syscalls made exclusively by the KVM platform.
func kvmFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ARCH_PRCTL:      {},
		syscall.SYS_IOCTL:           {},
		syscall.SYS_MMAP:            {},
		syscall.SYS_RT_SIGSUSPEND:   {},
		syscall.SYS_RT_SIGTIMEDWAIT: {},
		0xffffffffffffffff:          {}, // KVM uses syscall -1 to transition to host.
	}
}

func controlServerFilters(fd int) seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCEPT: []seccomp.Rule{
			{
				seccomp.AllowValue(fd),
			},
		},
		syscall.SYS_LISTEN: []seccomp.Rule{
			{
				seccomp.AllowValue(fd),
				seccomp.AllowValue(16 /* unet.backlog */),
			},
		},
		syscall.SYS_GETSOCKOPT: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_SOCKET),
				seccomp.AllowValue(syscall.SO_PEERCRED),
			},
		},
	}
}

// profileFilters returns extra syscalls made by runtime/pprof package.
func profileFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_OPENAT: []seccomp.Rule{
			{
				seccomp.AllowAny{},
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.O_RDONLY | syscall.O_LARGEFILE | syscall.O_CLOEXEC),
			},
		},
	}
}
