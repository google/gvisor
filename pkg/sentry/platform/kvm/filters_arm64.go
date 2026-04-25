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

//go:build arm64
// +build arm64

package kvm

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/seccomp"
)

// archSyscallFilters returns arch-specific syscalls made exclusively by the
// KVM platform.
func (*KVM) archSyscallFilters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.EqualTo(KVM_SET_VCPU_EVENTS),
		},
		// PR_PAC_SET_ENABLED_KEYS is called from loadSegments to disable
		// host pointer authentication on each vCPU host thread. See
		// disableHostPAC in machine_arm64_unsafe.go for the rationale.
		unix.SYS_PRCTL: seccomp.PerArg{
			seccomp.EqualTo(unix.PR_PAC_SET_ENABLED_KEYS),
			seccomp.EqualTo(addressPACKeys),
			seccomp.EqualTo(0),
			seccomp.EqualTo(0),
			seccomp.EqualTo(0),
		},
	})
}

// hottestSyscalls returns the list of hot syscalls for the KVM platform.
func hottestSyscalls() []uintptr {
	return nil
}
