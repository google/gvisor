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

package nvproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns seccomp-bpf filters for this package.
func Filters() seccomp.SyscallRules {
	notIocSizeMask := ^(((uintptr(1) << linux.IOC_SIZEBITS) - 1) << linux.IOC_SIZESHIFT) // for ioctls taking arbitrary size
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_CARD_INFO, 0)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_CHECK_VERSION_STR, nvgpu.SizeofRMAPIVersion)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_ATTACH_GPUS_TO_FD, 0)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_REGISTER_FD, nvgpu.SizeofIoctlRegisterFD)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_ALLOC_OS_EVENT, nvgpu.SizeofIoctlAllocOSEvent)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_FREE_OS_EVENT, nvgpu.SizeofIoctlFreeOSEvent)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_SYS_PARAMS, nvgpu.SizeofIoctlSysParams)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_WAIT_OPEN_COMPLETE, nvgpu.SizeofIoctlWaitOpenComplete)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC_MEMORY, nvgpu.SizeofIoctlNVOS02ParametersWithFD)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_FREE, nvgpu.SizeofNVOS00Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, nvgpu.SizeofNVOS54Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_DUP_OBJECT, nvgpu.SizeofNVOS55Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_SHARE, nvgpu.SizeofNVOS57Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_VID_HEAP_CONTROL, nvgpu.SizeofNVOS32Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_MAP_MEMORY, nvgpu.SizeofIoctlNVOS33ParametersWithFD)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UNMAP_MEMORY, nvgpu.SizeofNVOS34Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO, nvgpu.SizeofNVOS56Parameters)),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_INITIALIZE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_MM_INITIALIZE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_DEINITIALIZE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_CREATE_RANGE_GROUP),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_DESTROY_RANGE_GROUP),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU_VASPACE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU_VASPACE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_REGISTER_CHANNEL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_CHANNEL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_ENABLE_PEER_ACCESS),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_DISABLE_PEER_ACCESS),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_SET_RANGE_GROUP),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_FREE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_PAGEABLE_MEM_ACCESS),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_SET_PREFERRED_LOCATION),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_DISABLE_READ_DUPLICATION),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_MIGRATE_RANGE_GROUP),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_UNMAP_EXTERNAL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_ALLOC_SEMAPHORE_POOL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_VALIDATE_VA_RANGE),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(nvgpu.UVM_CREATE_EXTERNAL_RANGE),
			},
		},
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0), /* old_size */
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
	})
}
