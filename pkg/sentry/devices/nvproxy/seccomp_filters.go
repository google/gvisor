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
	nonNegativeFD := seccomp.NonNegativeFDCheck()
	notIocSizeMask := ^(((uintptr(1) << linux.IOC_SIZEBITS) - 1) << linux.IOC_SIZESHIFT) // for ioctls taking arbitrary size
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_OPENAT: seccomp.PerArg{
			// All paths that we openat() are absolute, so we pass a dirfd
			// of -1 (which is invalid for relative paths, but ignored for
			// absolute paths) to hedge against bugs involving AT_FDCWD or
			// real dirfds.
			seccomp.EqualTo(^uintptr(0)),
			seccomp.AnyValue{},
			seccomp.MaskedEqual(unix.O_NOFOLLOW|unix.O_CREAT, unix.O_NOFOLLOW),
			seccomp.AnyValue{},
		},
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_CARD_INFO, 0)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_CHECK_VERSION_STR, nvgpu.SizeofRMAPIVersion)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_REGISTER_FD, nvgpu.SizeofIoctlRegisterFD)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_ALLOC_OS_EVENT, nvgpu.SizeofIoctlAllocOSEvent)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_FREE_OS_EVENT, nvgpu.SizeofIoctlFreeOSEvent)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_SYS_PARAMS, nvgpu.SizeofIoctlSysParams)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC_MEMORY, nvgpu.SizeofIoctlNVOS02ParametersWithFD)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_FREE, nvgpu.SizeofNVOS00Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, nvgpu.SizeofNVOS54Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS21Parameters)),
			},
			// Note that we don't need to add one for NVOS21ParametersV535, because
			// SizeofNVOS21ParametersV535 == SizeofNVOS21Parameters. We test this.
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64ParametersV535)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_DUP_OBJECT, nvgpu.SizeofNVOS55Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_SHARE, nvgpu.SizeofNVOS57Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_VID_HEAP_CONTROL, nvgpu.SizeofNVOS32Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_MAP_MEMORY, nvgpu.SizeofIoctlNVOS33ParametersWithFD)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UNMAP_MEMORY, nvgpu.SizeofNVOS34Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO, nvgpu.SizeofNVOS56Parameters)),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_INITIALIZE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_MM_INITIALIZE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_DEINITIALIZE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_CREATE_RANGE_GROUP),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_DESTROY_RANGE_GROUP),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU_VASPACE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU_VASPACE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_REGISTER_CHANNEL),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_CHANNEL),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_FREE),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_PAGEABLE_MEM_ACCESS),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_ALLOC_SEMAPHORE_POOL),
			},
			seccomp.PerArg{
				nonNegativeFD,
				seccomp.EqualTo(nvgpu.UVM_VALIDATE_VA_RANGE),
			},
			seccomp.PerArg{
				nonNegativeFD,
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
