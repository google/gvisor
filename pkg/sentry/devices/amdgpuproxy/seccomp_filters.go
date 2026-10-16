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

package amdgpuproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/amdgpu"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns the host syscalls that amdgpuproxy needs beyond the base
// filter.
func Filters() seccomp.SyscallRules {
	var ioctls seccomp.Or
	for _, cmd := range []uint32{
		amdgpu.DRM_IOCTL_VERSION,
		amdgpu.DRM_IOCTL_AMDGPU_INFO,
		amdgpu.AMDKFD_IOC_GET_VERSION,
		amdgpu.AMDKFD_IOC_CREATE_QUEUE,
		amdgpu.AMDKFD_IOC_DESTROY_QUEUE,
		amdgpu.AMDKFD_IOC_SET_MEMORY_POLICY,
		amdgpu.AMDKFD_IOC_GET_CLOCK_COUNTERS,
		amdgpu.AMDKFD_IOC_CREATE_EVENT,
		amdgpu.AMDKFD_IOC_DESTROY_EVENT,
		amdgpu.AMDKFD_IOC_SET_EVENT,
		amdgpu.AMDKFD_IOC_WAIT_EVENTS,
		amdgpu.AMDKFD_IOC_SET_SCRATCH_BACKING_VA,
		amdgpu.AMDKFD_IOC_SET_TRAP_HANDLER,
		amdgpu.AMDKFD_IOC_GET_PROCESS_APERTURES_NEW,
		amdgpu.AMDKFD_IOC_ACQUIRE_VM,
		amdgpu.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU,
		amdgpu.AMDKFD_IOC_FREE_MEMORY_OF_GPU,
		amdgpu.AMDKFD_IOC_MAP_MEMORY_TO_GPU,
		amdgpu.AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU,
		amdgpu.AMDKFD_IOC_SET_XNACK_MODE,
		amdgpu.AMDKFD_IOC_AVAILABLE_MEMORY,
		amdgpu.AMDKFD_IOC_RUNTIME_ENABLE,
	} {
		ioctls = append(ioctls, seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(uintptr(cmd))})
	}
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: ioctls,
		// Each application open of /dev/kfd duplicates the sentry's FD.
		unix.SYS_DUP: seccomp.PerArg{seccomp.NonNegativeFD{}},
		// USERPTR aliases are assembled by duplicating internal mappings.
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
	})
}
