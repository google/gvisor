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

package kvm

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// archSyscallFilters returns arch-specific syscalls made exclusively by the
// KVM platform.
func (k *KVM) archSyscallFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		unix.SYS_ARCH_PRCTL: {
			{
				seccomp.EqualTo(linux.ARCH_GET_FS),
			},
			{
				seccomp.EqualTo(linux.ARCH_GET_GS),
			},
		},
		unix.SYS_IOCTL: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_INTERRUPT),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_NMI),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(_KVM_GET_REGS),
			},
		},
	}
}
