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
	syscall.SYS_CLOSE: {},
	syscall.SYS_DUP:   {},
	syscall.SYS_DUP3: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(syscall.O_CLOEXEC),
		},
	},
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
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AllowAny{},
		},
		// Non-private variants are included for flipcall support. They are otherwise
		// unncessary, as the sentry will use only private futexes internally.
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAIT),
			seccomp.AllowAny{},
			seccomp.AllowAny{},
		},
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(linux.FUTEX_WAKE),
			seccomp.AllowAny{},
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
	// Used by the Go runtime as a temporarily workaround for a Linux
	// 5.2-5.4 bug.
	//
	// See src/runtime/os_linux_x86.go.
	//
	// TODO(b/148688965): Remove once this is gone from Go.
	syscall.SYS_MLOCK: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(4096),
		},
	},
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
	unix.SYS_SENDMMSG: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowAny{},
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
		// Used by fs/host to shutdown host sockets.
		{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SHUT_RD)},
		{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SHUT_WR)},
		// Used by unet to shutdown connections.
		{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SHUT_RDWR)},
	},
	syscall.SYS_SIGALTSTACK:     {},
	unix.SYS_STATX:              {},
	syscall.SYS_SYNC_FILE_RANGE: {},
	syscall.SYS_TEE: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.AllowValue(1),                      /* len */
			seccomp.AllowValue(unix.SPLICE_F_NONBLOCK), /* flags */
		},
	},
	syscall.SYS_TGKILL: []seccomp.Rule{
		{
			seccomp.AllowValue(uint64(os.Getpid())),
		},
	},
	syscall.SYS_UTIMENSAT: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowValue(0), /* null pathname */
			seccomp.AllowAny{},
			seccomp.AllowValue(0), /* flags */
		},
	},
	syscall.SYS_WRITE: {},
	// For rawfile.NonBlockingWriteIovec.
	syscall.SYS_WRITEV: []seccomp.Rule{
		{
			seccomp.AllowAny{},
			seccomp.AllowAny{},
			seccomp.GreaterThan(0),
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
				seccomp.AllowValue(syscall.SOL_IP),
				seccomp.AllowValue(syscall.IP_TOS),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IP),
				seccomp.AllowValue(syscall.IP_RECVTOS),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_TCLASS),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_RECVTCLASS),
			},
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
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IP),
				seccomp.AllowValue(syscall.IP_TOS),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IP),
				seccomp.AllowValue(syscall.IP_RECVTOS),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_TCLASS),
				seccomp.AllowAny{},
				seccomp.AllowValue(4),
			},
			{
				seccomp.AllowAny{},
				seccomp.AllowValue(syscall.SOL_IPV6),
				seccomp.AllowValue(syscall.IPV6_RECVTCLASS),
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
