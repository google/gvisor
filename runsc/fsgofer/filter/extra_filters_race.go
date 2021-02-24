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

// +build race

package filter

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// instrumentationFilters returns additional filters for syscalls used by TSAN.
func instrumentationFilters() seccomp.SyscallRules {
	log.Warningf("*** SECCOMP WARNING: TSAN is enabled: syscall filters less restrictive!")
	return seccomp.SyscallRules{
		syscall.SYS_BRK:             {},
		syscall.SYS_CLOCK_NANOSLEEP: {},
		syscall.SYS_CLONE:           {},
		syscall.SYS_FUTEX:           {},
		syscall.SYS_MADVISE:         {},
		syscall.SYS_MMAP:            {},
		syscall.SYS_MUNLOCK:         {},
		syscall.SYS_NANOSLEEP:       {},
		syscall.SYS_OPEN:            {},
		syscall.SYS_OPENAT:          {},
		syscall.SYS_SET_ROBUST_LIST: {},
		// Used within glibc's malloc.
		syscall.SYS_TIME: {},
	}
}
