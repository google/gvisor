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

package config

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// instrumentationFilters returns additional filters for syscalls used by TSAN.
func instrumentationFilters() seccomp.SyscallRules {
	log.Warningf("TSAN is enabled: syscall filters less restrictive!")
	return archInstrumentationFilters(seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_BRK:               seccomp.MatchAll{},
		unix.SYS_CLOCK_NANOSLEEP:   seccomp.MatchAll{},
		unix.SYS_CLONE:             seccomp.MatchAll{},
		unix.SYS_CLONE3:            seccomp.MatchAll{},
		unix.SYS_FUTEX:             seccomp.MatchAll{},
		unix.SYS_MMAP:              seccomp.MatchAll{},
		unix.SYS_MUNLOCK:           seccomp.MatchAll{},
		unix.SYS_NANOSLEEP:         seccomp.MatchAll{},
		unix.SYS_OPENAT:            seccomp.MatchAll{},
		unix.SYS_RSEQ:              seccomp.MatchAll{},
		unix.SYS_SET_ROBUST_LIST:   seccomp.MatchAll{},
		unix.SYS_SCHED_GETAFFINITY: seccomp.MatchAll{},
	}))
}
