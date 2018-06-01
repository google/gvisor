// Copyright 2018 Google Inc.
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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/seccomp"
)

func main() {
	dieFlag := flag.Bool("die", false, "trips over the filter if true")
	flag.Parse()

	syscalls := seccomp.SyscallRules{
		syscall.SYS_ACCEPT:          {},
		syscall.SYS_ARCH_PRCTL:      {},
		syscall.SYS_BIND:            {},
		syscall.SYS_BRK:             {},
		syscall.SYS_CLOCK_GETTIME:   {},
		syscall.SYS_CLONE:           {},
		syscall.SYS_CLOSE:           {},
		syscall.SYS_DUP:             {},
		syscall.SYS_DUP2:            {},
		syscall.SYS_EPOLL_CREATE1:   {},
		syscall.SYS_EPOLL_CTL:       {},
		syscall.SYS_EPOLL_WAIT:      {},
		syscall.SYS_EPOLL_PWAIT:     {},
		syscall.SYS_EXIT:            {},
		syscall.SYS_EXIT_GROUP:      {},
		syscall.SYS_FALLOCATE:       {},
		syscall.SYS_FCHMOD:          {},
		syscall.SYS_FCNTL:           {},
		syscall.SYS_FSTAT:           {},
		syscall.SYS_FSYNC:           {},
		syscall.SYS_FTRUNCATE:       {},
		syscall.SYS_FUTEX:           {},
		syscall.SYS_GETDENTS64:      {},
		syscall.SYS_GETPEERNAME:     {},
		syscall.SYS_GETPID:          {},
		syscall.SYS_GETSOCKNAME:     {},
		syscall.SYS_GETSOCKOPT:      {},
		syscall.SYS_GETTID:          {},
		syscall.SYS_GETTIMEOFDAY:    {},
		syscall.SYS_LISTEN:          {},
		syscall.SYS_LSEEK:           {},
		syscall.SYS_MADVISE:         {},
		syscall.SYS_MINCORE:         {},
		syscall.SYS_MMAP:            {},
		syscall.SYS_MPROTECT:        {},
		syscall.SYS_MUNLOCK:         {},
		syscall.SYS_MUNMAP:          {},
		syscall.SYS_NANOSLEEP:       {},
		syscall.SYS_NEWFSTATAT:      {},
		syscall.SYS_OPEN:            {},
		syscall.SYS_POLL:            {},
		syscall.SYS_PREAD64:         {},
		syscall.SYS_PSELECT6:        {},
		syscall.SYS_PWRITE64:        {},
		syscall.SYS_READ:            {},
		syscall.SYS_READLINKAT:      {},
		syscall.SYS_READV:           {},
		syscall.SYS_RECVMSG:         {},
		syscall.SYS_RENAMEAT:        {},
		syscall.SYS_RESTART_SYSCALL: {},
		syscall.SYS_RT_SIGACTION:    {},
		syscall.SYS_RT_SIGPROCMASK:  {},
		syscall.SYS_RT_SIGRETURN:    {},
		syscall.SYS_SCHED_YIELD:     {},
		syscall.SYS_SENDMSG:         {},
		syscall.SYS_SETITIMER:       {},
		syscall.SYS_SET_ROBUST_LIST: {},
		syscall.SYS_SETSOCKOPT:      {},
		syscall.SYS_SHUTDOWN:        {},
		syscall.SYS_SIGALTSTACK:     {},
		syscall.SYS_SOCKET:          {},
		syscall.SYS_SYNC_FILE_RANGE: {},
		syscall.SYS_TGKILL:          {},
		syscall.SYS_UTIMENSAT:       {},
		syscall.SYS_WRITE:           {},
		syscall.SYS_WRITEV:          {},
	}
	die := *dieFlag
	if !die {
		syscalls[syscall.SYS_OPENAT] = []seccomp.Rule{
			{
				seccomp.AllowValue(10),
			},
		}
	}

	if err := seccomp.Install(syscalls, false); err != nil {
		fmt.Printf("Failed to install seccomp: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Filters installed\n")

	syscall.RawSyscall(syscall.SYS_OPENAT, 10, 0, 0)
	fmt.Printf("Syscall was allowed!!!\n")
}
