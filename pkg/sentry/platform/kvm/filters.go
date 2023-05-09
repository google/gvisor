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
	r := k.archSyscallFilters()
	r.Merge(seccomp.SyscallRules{
		unix.SYS_IOCTL: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_RUN),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_SET_USER_MEMORY_REGION),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_GET_REGS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_SET_REGS),
			},
		},
		unix.SYS_MEMBARRIER: []seccomp.Rule{
			{
				seccomp.EqualTo(linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED),
				seccomp.EqualTo(0),
			},
		},
		unix.SYS_MMAP:            {},
		unix.SYS_RT_SIGSUSPEND:   {},
		unix.SYS_RT_SIGTIMEDWAIT: {},
		_SYS_KVM_RETURN_TO_HOST:  {},
	})
	return r
}
