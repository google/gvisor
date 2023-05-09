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

//go:build msan
// +build msan

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// instrumentationFilters returns additional filters for syscalls used by MSAN.
func instrumentationFilters() seccomp.SyscallRules {
	Report("MSAN is enabled: syscall filters less restrictive!")
	return seccomp.SyscallRules{
		unix.SYS_CLONE:             {},
		unix.SYS_MMAP:              {},
		unix.SYS_SCHED_GETAFFINITY: {},
		unix.SYS_SET_ROBUST_LIST:   {},
	}
}
