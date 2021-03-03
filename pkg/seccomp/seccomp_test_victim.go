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

// Test binary used to test that seccomp filters are properly constructed and
// indeed kill the process on violation.
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func main() {
	dieFlag := flag.Bool("die", false, "trips over the filter if true")
	flag.Parse()

	syscalls := seccomp.SyscallRules{
		unix.SYS_ACCEPT:          {},
		unix.SYS_BIND:            {},
		unix.SYS_BRK:             {},
		unix.SYS_CLOCK_GETTIME:   {},
		unix.SYS_CLONE:           {},
		unix.SYS_CLOSE:           {},
		unix.SYS_DUP:             {},
		unix.SYS_DUP3:            {},
		unix.SYS_EPOLL_CREATE1:   {},
		unix.SYS_EPOLL_CTL:       {},
		unix.SYS_EPOLL_PWAIT:     {},
		unix.SYS_EXIT:            {},
		unix.SYS_EXIT_GROUP:      {},
		unix.SYS_FALLOCATE:       {},
		unix.SYS_FCHMOD:          {},
		unix.SYS_FCNTL:           {},
		unix.SYS_FSTAT:           {},
		unix.SYS_FSYNC:           {},
		unix.SYS_FTRUNCATE:       {},
		unix.SYS_FUTEX:           {},
		unix.SYS_GETDENTS64:      {},
		unix.SYS_GETPEERNAME:     {},
		unix.SYS_GETPID:          {},
		unix.SYS_GETSOCKNAME:     {},
		unix.SYS_GETSOCKOPT:      {},
		unix.SYS_GETTID:          {},
		unix.SYS_GETTIMEOFDAY:    {},
		unix.SYS_LISTEN:          {},
		unix.SYS_LSEEK:           {},
		unix.SYS_MADVISE:         {},
		unix.SYS_MINCORE:         {},
		unix.SYS_MMAP:            {},
		unix.SYS_MPROTECT:        {},
		unix.SYS_MUNLOCK:         {},
		unix.SYS_MUNMAP:          {},
		unix.SYS_NANOSLEEP:       {},
		unix.SYS_PPOLL:           {},
		unix.SYS_PREAD64:         {},
		unix.SYS_PSELECT6:        {},
		unix.SYS_PWRITE64:        {},
		unix.SYS_READ:            {},
		unix.SYS_READLINKAT:      {},
		unix.SYS_READV:           {},
		unix.SYS_RECVMSG:         {},
		unix.SYS_RENAMEAT:        {},
		unix.SYS_RESTART_SYSCALL: {},
		unix.SYS_RT_SIGACTION:    {},
		unix.SYS_RT_SIGPROCMASK:  {},
		unix.SYS_RT_SIGRETURN:    {},
		unix.SYS_SCHED_YIELD:     {},
		unix.SYS_SENDMSG:         {},
		unix.SYS_SETITIMER:       {},
		unix.SYS_SET_ROBUST_LIST: {},
		unix.SYS_SETSOCKOPT:      {},
		unix.SYS_SHUTDOWN:        {},
		unix.SYS_SIGALTSTACK:     {},
		unix.SYS_SOCKET:          {},
		unix.SYS_SYNC_FILE_RANGE: {},
		unix.SYS_TGKILL:          {},
		unix.SYS_UTIMENSAT:       {},
		unix.SYS_WRITE:           {},
		unix.SYS_WRITEV:          {},
	}

	arch_syscalls(syscalls)

	die := *dieFlag
	if !die {
		syscalls[unix.SYS_OPENAT] = []seccomp.Rule{
			{
				seccomp.EqualTo(10),
			},
		}
	}

	if err := seccomp.Install(syscalls); err != nil {
		fmt.Printf("Failed to install seccomp: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Filters installed\n")

	unix.RawSyscall(unix.SYS_OPENAT, 10, 0, 0)
	fmt.Printf("Syscall was allowed!!!\n")
}
