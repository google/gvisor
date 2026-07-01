// Copyright 2026 The gVisor Authors.
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

package slimvm

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// SeccompInfo returns syscalls made exclusively by the SlimVM platform.
func (*SlimVM) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{
		PlatformName: "slimvm",
		Filters: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_ARCH_PRCTL: seccomp.MatchAll{},
			unix.SYS_FUTEX:      seccomp.MatchAll{},
			unix.SYS_IOCTL:      seccomp.MatchAll{},
			unix.SYS_MEMBARRIER: seccomp.PerArg{
				seccomp.EqualTo(linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED),
				seccomp.EqualTo(0),
			},
			unix.SYS_MMAP:          seccomp.MatchAll{},
			unix.SYS_RT_SIGSUSPEND: seccomp.MatchAll{},
			redpillSyscall:         seccomp.MatchAll{},
		}),
		HotSyscalls: hottestSyscalls(),
	}
}

// hottestSyscalls returns the list of hot syscalls for the SlimVM platform.
func hottestSyscalls() []uintptr {
	return []uintptr{
		unix.SYS_FUTEX,
		unix.SYS_MMAP,
	}
}

// PrecompiledSeccompInfo implements
// platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{(*SlimVM)(nil).SeccompInfo()}
}
