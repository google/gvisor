// Copyright 2019 The gVisor Authors.
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

// +build arm64

package filter

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/seccomp"
)

func init() {
	allowedSyscalls[syscall.SYS_CLONE] = []seccomp.Rule{
		// parent_tidptr and child_tidptr are always 0 because neither
		// CLONE_PARENT_SETTID nor CLONE_CHILD_SETTID are used.
		{
			seccomp.EqualTo(
				syscall.CLONE_VM |
					syscall.CLONE_FS |
					syscall.CLONE_FILES |
					syscall.CLONE_SIGHAND |
					syscall.CLONE_SYSVSEM |
					syscall.CLONE_THREAD),
			seccomp.MatchAny{}, // newsp
			// These arguments are left uninitialized by the Go
			// runtime, so they may be anything (and are unused by
			// the host).
			seccomp.MatchAny{}, // parent_tidptr
			seccomp.MatchAny{}, // tls
			seccomp.MatchAny{}, // child_tidptr
		},
	}

	allowedSyscalls[syscall.SYS_FSTATAT] = []seccomp.Rule{}
}
