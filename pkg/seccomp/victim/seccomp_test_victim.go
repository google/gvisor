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

	syscalls := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_ACCEPT:          seccomp.MatchAll{},
		unix.SYS_BIND:            seccomp.MatchAll{},
		unix.SYS_BRK:             seccomp.MatchAll{},
		unix.SYS_CLOCK_GETTIME:   seccomp.MatchAll{},
		unix.SYS_CLONE:           seccomp.MatchAll{},
		unix.SYS_CLOSE:           seccomp.MatchAll{},
		unix.SYS_DUP:             seccomp.MatchAll{},
		unix.SYS_DUP3:            seccomp.MatchAll{},
		unix.SYS_EPOLL_CREATE1:   seccomp.MatchAll{},
		unix.SYS_EPOLL_CTL:       seccomp.MatchAll{},
		unix.SYS_EPOLL_PWAIT:     seccomp.MatchAll{},
		unix.SYS_EXIT:            seccomp.MatchAll{},
		unix.SYS_EXIT_GROUP:      seccomp.MatchAll{},
		unix.SYS_FALLOCATE:       seccomp.MatchAll{},
		unix.SYS_FCHMOD:          seccomp.MatchAll{},
		unix.SYS_FCNTL:           seccomp.MatchAll{},
		unix.SYS_FSTAT:           seccomp.MatchAll{},
		unix.SYS_FSYNC:           seccomp.MatchAll{},
		unix.SYS_FTRUNCATE:       seccomp.MatchAll{},
		unix.SYS_FUTEX:           seccomp.MatchAll{},
		unix.SYS_GETDENTS64:      seccomp.MatchAll{},
		unix.SYS_GETPEERNAME:     seccomp.MatchAll{},
		unix.SYS_GETPID:          seccomp.MatchAll{},
		unix.SYS_GETSOCKNAME:     seccomp.MatchAll{},
		unix.SYS_GETSOCKOPT:      seccomp.MatchAll{},
		unix.SYS_GETTID:          seccomp.MatchAll{},
		unix.SYS_GETTIMEOFDAY:    seccomp.MatchAll{},
		unix.SYS_LISTEN:          seccomp.MatchAll{},
		unix.SYS_LSEEK:           seccomp.MatchAll{},
		unix.SYS_MADVISE:         seccomp.MatchAll{},
		unix.SYS_MINCORE:         seccomp.MatchAll{},
		unix.SYS_MMAP:            seccomp.MatchAll{},
		unix.SYS_MPROTECT:        seccomp.MatchAll{},
		unix.SYS_MUNLOCK:         seccomp.MatchAll{},
		unix.SYS_MUNMAP:          seccomp.MatchAll{},
		unix.SYS_NANOSLEEP:       seccomp.MatchAll{},
		unix.SYS_OPENAT:          seccomp.MatchAll{},
		unix.SYS_PPOLL:           seccomp.MatchAll{},
		unix.SYS_PREAD64:         seccomp.MatchAll{},
		unix.SYS_PSELECT6:        seccomp.MatchAll{},
		unix.SYS_PWRITE64:        seccomp.MatchAll{},
		unix.SYS_READ:            seccomp.MatchAll{},
		unix.SYS_READLINKAT:      seccomp.MatchAll{},
		unix.SYS_READV:           seccomp.MatchAll{},
		unix.SYS_RECVMSG:         seccomp.MatchAll{},
		unix.SYS_RENAMEAT:        seccomp.MatchAll{},
		unix.SYS_RESTART_SYSCALL: seccomp.MatchAll{},
		unix.SYS_RT_SIGACTION:    seccomp.MatchAll{},
		unix.SYS_RT_SIGPROCMASK:  seccomp.MatchAll{},
		unix.SYS_RT_SIGRETURN:    seccomp.MatchAll{},
		unix.SYS_SCHED_YIELD:     seccomp.MatchAll{},
		unix.SYS_SENDMSG:         seccomp.MatchAll{},
		unix.SYS_SETITIMER:       seccomp.MatchAll{},
		unix.SYS_SET_ROBUST_LIST: seccomp.MatchAll{},
		unix.SYS_SETSOCKOPT:      seccomp.MatchAll{},
		unix.SYS_SHUTDOWN:        seccomp.MatchAll{},
		unix.SYS_SIGALTSTACK:     seccomp.MatchAll{},
		unix.SYS_SOCKET:          seccomp.MatchAll{},
		unix.SYS_SYNC_FILE_RANGE: seccomp.MatchAll{},
		unix.SYS_TGKILL:          seccomp.MatchAll{},
		unix.SYS_UTIMENSAT:       seccomp.MatchAll{},
		unix.SYS_WRITE:           seccomp.MatchAll{},
		unix.SYS_WRITEV:          seccomp.MatchAll{},
	})

	arch_syscalls(syscalls)
	// We choose a syscall that is unlikely to be called by Go runtime,
	// even with race or other instrumentation enabled.
	syscall := uintptr(unix.SYS_UMASK)

	die := *dieFlag
	if !die {
		syscalls.Set(syscall, seccomp.PerArg{
			seccomp.EqualTo(0),
		})
	}

	if err := seccomp.Install(syscalls, seccomp.NewSyscallRules(), seccomp.DefaultProgramOptions()); err != nil {
		fmt.Printf("Failed to install seccomp: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Filters installed\n")

	unix.RawSyscall(syscall, 0, 0, 0)
	fmt.Printf("Syscall was allowed!!!\n")
}
