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
	"syscall"

	"gvisor.dev/gvisor/pkg/seccomp"
)

// SyscallFilters returns syscalls made exclusively by the KVM platform.
func (*KVM) SyscallFilters() seccomp.SyscallRules {
	return seccomp.SyscallRules{
		syscall.SYS_IOCTL:           {},
		syscall.SYS_MMAP:            {},
		syscall.SYS_RT_SIGSUSPEND:   {},
		syscall.SYS_RT_SIGTIMEDWAIT: {},
		0xffffffffffffffff:          {}, // KVM uses syscall -1 to transition to host.
	}
}
