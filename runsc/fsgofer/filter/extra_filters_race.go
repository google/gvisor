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

//go:build race
// +build race

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// instrumentationFilters returns additional filters for syscalls used by TSAN.
func instrumentationFilters() seccomp.SyscallRules {
	log.Warningf("*** SECCOMP WARNING: TSAN is enabled: syscall filters less restrictive!")
	return archInstrumentationFilters(seccomp.SyscallRules{
		unix.SYS_BRK:             {},
		unix.SYS_CLOCK_NANOSLEEP: {},
		unix.SYS_CLONE:           {},
		unix.SYS_CLONE3:          {},
		unix.SYS_FUTEX:           {},
		unix.SYS_MADVISE:         {},
		unix.SYS_MMAP:            {},
		unix.SYS_MUNLOCK:         {},
		unix.SYS_NANOSLEEP:       {},
		unix.SYS_OPENAT:          {},
		unix.SYS_RSEQ:            {},
		unix.SYS_SET_ROBUST_LIST: {},
	})
}
