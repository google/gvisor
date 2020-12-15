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
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// allowedSyscalls is the set of syscalls executed by the Sentry to the host OS.
var allowedSyscalls = seccomp.SyscallRules{
	syscall.SYS_CLOCK_GETTIME: {},
	syscall.SYS_CLOSE:         {},
	syscall.SYS_DUP:           {},
	syscall.SYS_DUP3: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.O_CLOEXEC),
		},
	},
	syscall.SYS_EPOLL_CREATE1: {},
	syscall.SYS_EPOLL_CTL:     {},
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
	syscall.SYS_FALLOCATE:  {},
	syscall.SYS_FCHMOD:     {},
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
	},
	syscall.SYS_FSTAT:     {},
	syscall.SYS_FSYNC:     {},
	syscall.SYS_FTRUNCATE: {},
	syscall.SYS_FUTEX: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
		},
		// Non-private variants are included for flipcall support. They are otherwise
		// unncessary, as the sentry will use only private futexes internally.
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE),
			seccomp.MatchAny{},
		},
	},
	syscall.SYS_GETPID: {},
	unix.SYS_GETRANDOM: {},
	syscall.SYS_GETSOCKOPT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.SOL_SOCKET),
			seccomp.EqualTo(syscall.SO_DOMAIN),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.SOL_SOCKET),
			seccomp.EqualTo(syscall.SO_TYPE),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.SOL_SOCKET),
			seccomp.EqualTo(syscall.SO_ERROR),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.SOL_SOCKET),
			seccomp.EqualTo(syscall.SO_SNDBUF),
		},
	},
	syscall.SYS_GETTID:       {},
	syscall.SYS_GETTIMEOFDAY: {},
	// SYS_IOCTL is needed for terminal support, but we only allow
	// setting/getting termios and winsize.
	syscall.SYS_IOCTL: []seccomp.Rule{
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TCGETS),
			seccomp.MatchAny{}, /* termios struct */
		},
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TCSETS),
			seccomp.MatchAny{}, /* termios struct */
		},
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TCSETSF),
			seccomp.MatchAny{}, /* termios struct */
		},
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TCSETSW),
			seccomp.MatchAny{}, /* termios struct */
		},
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TIOCSWINSZ),
			seccomp.MatchAny{}, /* winsize struct */
		},
		{
			seccomp.MatchAny{}, /* fd */
			seccomp.EqualTo(linux.TIOCGWINSZ),
			seccomp.MatchAny{}, /* winsize struct */
		},
	},
	syscall.SYS_LSEEK:   {},
	syscall.SYS_MADVISE: {},
	unix.SYS_MEMBARRIER: []seccomp.Rule{
		{
			seccomp.EqualTo(linux.MEMBARRIER_CMD_GLOBAL),
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_MINCORE: {},
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
			seccomp.EqualTo(syscall.MAP_PRIVATE),
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
			seccomp.EqualTo(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_STACK),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_NORESERVE),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.PROT_WRITE | syscall.PROT_READ),
			seccomp.EqualTo(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_FIXED),
		},
	},
	syscall.SYS_MPROTECT:  {},
	syscall.SYS_MUNMAP:    {},
	syscall.SYS_NANOSLEEP: {},
	syscall.SYS_PPOLL:     {},
	syscall.SYS_PREAD64:   {},
	syscall.SYS_PREADV:    {},
	unix.SYS_PREADV2:      {},
	syscall.SYS_PWRITE64:  {},
	syscall.SYS_PWRITEV:   {},
	unix.SYS_PWRITEV2:     {},
	syscall.SYS_READ:      {},
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
	syscall.SYS_RECVMMSG: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(fdbased.MaxMsgsPerRecv),
			seccomp.EqualTo(syscall.MSG_DONTWAIT),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_SENDMMSG: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MSG_DONTWAIT),
			seccomp.EqualTo(0),
		},
	},
	syscall.SYS_RESTART_SYSCALL: {},
	syscall.SYS_RT_SIGACTION:    {},
	syscall.SYS_RT_SIGPROCMASK:  {},
	syscall.SYS_RT_SIGRETURN:    {},
	syscall.SYS_SCHED_YIELD:     {},
	syscall.SYS_SENDMSG: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL),
		},
	},
	syscall.SYS_SETITIMER: {},
	syscall.SYS_SHUTDOWN: []seccomp.Rule{
		// Used by fs/host to shutdown host sockets.
		{seccomp.MatchAny{}, seccomp.EqualTo(syscall.SHUT_RD)},
		{seccomp.MatchAny{}, seccomp.EqualTo(syscall.SHUT_WR)},
		// Used by unet to shutdown connections.
		{seccomp.MatchAny{}, seccomp.EqualTo(syscall.SHUT_RDWR)},
	},
	syscall.SYS_SIGALTSTACK:     {},
	unix.SYS_STATX:              {},
	syscall.SYS_SYNC_FILE_RANGE: {},
	syscall.SYS_TEE: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(1),                      /* len */
			seccomp.EqualTo(unix.SPLICE_F_NONBLOCK), /* flags */
		},
	},
	syscall.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	},
	syscall.SYS_UTIMENSAT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(0), /* null pathname */
			seccomp.MatchAny{},
			seccomp.EqualTo(0), /* flags */
		},
	},
	syscall.SYS_WRITE: {},
	// For rawfile.NonBlockingWriteIovec.
	syscall.SYS_WRITEV: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.GreaterThan(0),
		},
	},
}

// hostInetFilters contains syscalls that are needed by sentry/socket/hostinet.
func hostInetFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCEPT4: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.MatchAny{},
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
			},
		},
		syscall.SYS_BIND:        {},
		syscall.SYS_CONNECT:     {},
		syscall.SYS_GETPEERNAME: {},
		syscall.SYS_GETSOCKNAME: {},
		syscall.SYS_GETSOCKOPT: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_TOS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_RECVTOS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_PKTINFO),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_RECVORIGDSTADDR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_TCLASS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_RECVTCLASS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_V6ONLY),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(linux.IPV6_RECVORIGDSTADDR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_ERROR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_KEEPALIVE),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_SNDBUF),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_RCVBUF),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_REUSEADDR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_TYPE),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_LINGER),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_TIMESTAMP),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_TCP),
				seccomp.EqualTo(syscall.TCP_NODELAY),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_TCP),
				seccomp.EqualTo(syscall.TCP_INFO),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_TCP),
				seccomp.EqualTo(linux.TCP_INQ),
			},
		},
		syscall.SYS_IOCTL: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.TIOCOUTQ),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.TIOCINQ),
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
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_V6ONLY),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_SNDBUF),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_RCVBUF),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_REUSEADDR),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_TIMESTAMP),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_TCP),
				seccomp.EqualTo(syscall.TCP_NODELAY),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_TCP),
				seccomp.EqualTo(linux.TCP_INQ),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_TOS),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_RECVTOS),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_PKTINFO),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IP),
				seccomp.EqualTo(syscall.IP_RECVORIGDSTADDR),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_TCLASS),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(syscall.IPV6_RECVTCLASS),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_IPV6),
				seccomp.EqualTo(linux.IPV6_RECVORIGDSTADDR),
				seccomp.MatchAny{},
				seccomp.EqualTo(4),
			},
		},
		syscall.SYS_SHUTDOWN: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SHUT_RD),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SHUT_WR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SHUT_RDWR),
			},
		},
		syscall.SYS_SOCKET: []seccomp.Rule{
			{
				seccomp.EqualTo(syscall.AF_INET),
				seccomp.EqualTo(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.EqualTo(0),
			},
			{
				seccomp.EqualTo(syscall.AF_INET),
				seccomp.EqualTo(syscall.SOCK_DGRAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.EqualTo(0),
			},
			{
				seccomp.EqualTo(syscall.AF_INET6),
				seccomp.EqualTo(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.EqualTo(0),
			},
			{
				seccomp.EqualTo(syscall.AF_INET6),
				seccomp.EqualTo(syscall.SOCK_DGRAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC),
				seccomp.EqualTo(0),
			},
		},
		syscall.SYS_WRITEV: {},
	}
}

func controlServerFilters(fd int) seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_ACCEPT: []seccomp.Rule{
			{
				seccomp.EqualTo(fd),
			},
		},
		syscall.SYS_LISTEN: []seccomp.Rule{
			{
				seccomp.EqualTo(fd),
				seccomp.EqualTo(16 /* unet.backlog */),
			},
		},
		syscall.SYS_GETSOCKOPT: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(syscall.SOL_SOCKET),
				seccomp.EqualTo(syscall.SO_PEERCRED),
			},
		},
	}
}
