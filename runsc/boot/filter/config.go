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
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// allowedSyscalls is the set of syscalls executed by the Sentry to the host OS.
var allowedSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CLOCK_GETTIME: seccomp.MatchAll{},
	unix.SYS_CLOSE:         seccomp.MatchAll{},
	unix.SYS_DUP:           seccomp.MatchAll{},
	unix.SYS_DUP3: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.O_CLOEXEC),
	},
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
		seccomp.EqualTo(0),
	},
	unix.SYS_EXIT:       seccomp.MatchAll{},
	unix.SYS_EXIT_GROUP: seccomp.MatchAll{},
	unix.SYS_FALLOCATE:  seccomp.MatchAll{},
	unix.SYS_FCHMOD:     seccomp.MatchAll{},
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
	unix.SYS_FSTAT:     seccomp.MatchAll{},
	unix.SYS_FSYNC:     seccomp.MatchAll{},
	unix.SYS_FTRUNCATE: seccomp.MatchAll{},
	unix.SYS_FUTEX: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
		},
		// Non-private variants are included for flipcall support. They are otherwise
		// unnecessary, as the sentry will use only private futexes internally.
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
		},
	},
	// getcpu is used by some versions of the Go runtime and by the hostcpu
	// package on arm64.
	unix.SYS_GETCPU: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
		seccomp.EqualTo(0),
	},
	unix.SYS_GETPID:    seccomp.MatchAll{},
	unix.SYS_GETRANDOM: seccomp.MatchAll{},
	unix.SYS_GETSOCKOPT: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_DOMAIN),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_TYPE),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_ERROR),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_SNDBUF),
		},
	},
	unix.SYS_GETTID:       seccomp.MatchAll{},
	unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
	unix.SYS_IOCTL: seccomp.Or{
		// These commands are needed for host FD.
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.FIONREAD),
			seccomp.AnyValue{}, /* int* */
		},
		// These commands are needed for terminal support, but we only allow
		// setting/getting termios and winsize.
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TCGETS),
			seccomp.AnyValue{}, /* termios struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TCSETS),
			seccomp.AnyValue{}, /* termios struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TCSETSF),
			seccomp.AnyValue{}, /* termios struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TCSETSW),
			seccomp.AnyValue{}, /* termios struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TIOCSWINSZ),
			seccomp.AnyValue{}, /* winsize struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.TIOCGWINSZ),
			seccomp.AnyValue{}, /* winsize struct */
		},
		seccomp.PerArg{
			seccomp.AnyValue{}, /* fd */
			seccomp.EqualTo(linux.SIOCGIFTXQLEN),
			seccomp.AnyValue{}, /* ifreq struct */
		},
	},
	unix.SYS_LSEEK:   seccomp.MatchAll{},
	unix.SYS_MADVISE: seccomp.MatchAll{},
	unix.SYS_MEMBARRIER: seccomp.PerArg{
		seccomp.EqualTo(linux.MEMBARRIER_CMD_GLOBAL),
		seccomp.EqualTo(0),
	},
	unix.SYS_MINCORE: seccomp.MatchAll{},
	unix.SYS_MLOCK:   seccomp.MatchAll{},
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
			seccomp.EqualTo(unix.MAP_SHARED | unix.MAP_FIXED),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_PRIVATE),
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
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_STACK),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_NORESERVE),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_WRITE | unix.PROT_READ),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
		},
	},
	unix.SYS_MPROTECT:  seccomp.MatchAll{},
	unix.SYS_MUNLOCK:   seccomp.MatchAll{},
	unix.SYS_MUNMAP:    seccomp.MatchAll{},
	unix.SYS_NANOSLEEP: seccomp.MatchAll{},
	unix.SYS_PPOLL:     seccomp.MatchAll{},
	unix.SYS_PREAD64:   seccomp.MatchAll{},
	unix.SYS_PREADV:    seccomp.MatchAll{},
	unix.SYS_PREADV2:   seccomp.MatchAll{},
	unix.SYS_PWRITE64:  seccomp.MatchAll{},
	unix.SYS_PWRITEV:   seccomp.MatchAll{},
	unix.SYS_PWRITEV2:  seccomp.MatchAll{},
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
	unix.SYS_RECVMMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(fdbased.MaxMsgsPerRecv),
		seccomp.EqualTo(unix.MSG_DONTWAIT),
		seccomp.EqualTo(0),
	},
	unix.SYS_SENDMMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.MSG_DONTWAIT),
	},
	unix.SYS_RESTART_SYSCALL: seccomp.MatchAll{},
	unix.SYS_RT_SIGACTION:    seccomp.MatchAll{},
	unix.SYS_RT_SIGPROCMASK:  seccomp.MatchAll{},
	unix.SYS_RT_SIGRETURN:    seccomp.MatchAll{},
	unix.SYS_SCHED_YIELD:     seccomp.MatchAll{},
	unix.SYS_SENDMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL),
	},
	unix.SYS_SETITIMER: seccomp.MatchAll{},
	unix.SYS_SHUTDOWN: seccomp.Or{
		// Used by fs/host to shutdown host sockets.
		seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.SHUT_RD)},
		seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.SHUT_WR)},
		// Used by unet to shutdown connections.
		seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.SHUT_RDWR)},
	},
	unix.SYS_SIGALTSTACK:     seccomp.MatchAll{},
	unix.SYS_STATX:           seccomp.MatchAll{},
	unix.SYS_SYNC_FILE_RANGE: seccomp.MatchAll{},
	unix.SYS_TEE: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(1),                      /* len */
		seccomp.EqualTo(unix.SPLICE_F_NONBLOCK), /* flags */
	},
	unix.SYS_TIMER_CREATE: seccomp.PerArg{
		seccomp.EqualTo(unix.CLOCK_THREAD_CPUTIME_ID), /* which */
		seccomp.AnyValue{},                            /* sevp */
		seccomp.AnyValue{},                            /* timerid */
	},
	unix.SYS_TIMER_DELETE: seccomp.MatchAll{},
	unix.SYS_TIMER_SETTIME: seccomp.PerArg{
		seccomp.AnyValue{}, /* timerid */
		seccomp.EqualTo(0), /* flags */
		seccomp.AnyValue{}, /* new_value */
		seccomp.EqualTo(0), /* old_value */
	},
	unix.SYS_TGKILL: seccomp.PerArg{
		seccomp.EqualTo(uint64(os.Getpid())),
	},
	unix.SYS_UTIMENSAT: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(0), /* null pathname */
		seccomp.AnyValue{},
		seccomp.EqualTo(0), /* flags */
	},
	unix.SYS_WRITE: seccomp.MatchAll{},
	// For rawfile.NonBlockingWriteIovec.
	unix.SYS_WRITEV: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.GreaterThan(0),
	},
})

func controlServerFilters(fd int) seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_ACCEPT4: seccomp.PerArg{
			seccomp.EqualTo(fd),
		},
		unix.SYS_LISTEN: seccomp.PerArg{
			seccomp.EqualTo(fd),
			seccomp.EqualTo(16 /* unet.backlog */),
		},
		unix.SYS_GETSOCKOPT: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_PEERCRED),
		},
	})
}

// hostFilesystemFilters contains syscalls that are needed by directfs.
func hostFilesystemFilters() seccomp.SyscallRules {
	// Directfs allows FD-based filesystem syscalls. We deny these syscalls with
	// negative FD values (like AT_FDCWD or invalid FD numbers). We try to be as
	// restrictive as possible because any restriction here improves security. We
	// don't know what set of arguments will trigger a future vulnerability.
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_FCHOWNAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW),
		},
		unix.SYS_FCHMODAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_UNLINKAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_GETDENTS64: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_OPENAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.MaskedEqual(unix.O_NOFOLLOW, unix.O_NOFOLLOW),
			seccomp.AnyValue{},
		},
		unix.SYS_LINKAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		unix.SYS_MKDIRAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_MKNODAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_SYMLINKAT: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
		},
		unix.SYS_FSTATFS: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
		},
		unix.SYS_READLINKAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_UTIMENSAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_RENAMEAT: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
		},
		archFstatAtSysNo(): seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
	})
}
