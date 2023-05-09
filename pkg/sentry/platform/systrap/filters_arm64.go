// Copyright 2023 The gVisor Authors.
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

//go:build arm64
// +build arm64

package systrap

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// SyscallFilters returns syscalls made exclusively by the systrap platform.
func (*Systrap) archSyscallFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		unix.SYS_PTRACE: {
			{
				seccomp.EqualTo(unix.PTRACE_GETREGSET),
				seccomp.MatchAny{},
				seccomp.EqualTo(linux.NT_ARM_TLS),
			},
			{
				seccomp.EqualTo(unix.PTRACE_SETREGSET),
				seccomp.MatchAny{},
				seccomp.EqualTo(linux.NT_ARM_TLS),
			},
		},
	}
}
