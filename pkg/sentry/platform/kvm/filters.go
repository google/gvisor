// Copyright 2022 The gVisor Authors.
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

package kvm

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// SyscallFilters returns syscalls made exclusively by the KVM platform.
func (k *KVM) SyscallFilters() seccomp.SyscallRules {
	return k.archSyscallFilters().Merge(seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(KVM_RUN),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(KVM_SET_USER_MEMORY_REGION),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(KVM_GET_REGS),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(KVM_SET_REGS),
			},
		},
		unix.SYS_MEMBARRIER: seccomp.PerArg{
			seccomp.EqualTo(linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED),
			seccomp.EqualTo(0),
		},
		unix.SYS_MMAP:            seccomp.MatchAll{},
		unix.SYS_RT_SIGSUSPEND:   seccomp.MatchAll{},
		unix.SYS_RT_SIGTIMEDWAIT: seccomp.MatchAll{},
		_SYS_KVM_RETURN_TO_HOST:  seccomp.MatchAll{},
	}))
}
