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
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// Shorthands for NVIDIA driver capabilities.
const (
	// Shorthand for compute+utility capabilities.
	// This is the default set of capabilities when capabilities are not
	// explicitly specified, and using a shorthand for this makes ABI
	// definitions in `version.go` more readable.
	compUtil = nvconf.CapCompute | nvconf.CapUtility
)

func frontendIoctlFilters(enabledCaps nvconf.DriverCaps) []seccomp.SyscallRule {
	const (
		// for ioctls taking arbitrary size
		notIocSizeMask = ^(((uintptr(1) << linux.IOC_SIZEBITS) - 1) << linux.IOC_SIZESHIFT)
	)
	var ioctlRules []seccomp.SyscallRule
	for _, feIoctl := range []struct {
		arg1 seccomp.ValueMatcher
		caps nvconf.DriverCaps
	}{
		{seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_CARD_INFO, 0)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_CHECK_VERSION_STR, nvgpu.SizeofRMAPIVersion)), compUtil},
		{seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_ATTACH_GPUS_TO_FD, 0)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_REGISTER_FD, nvgpu.SizeofIoctlRegisterFD)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_ALLOC_OS_EVENT, nvgpu.SizeofIoctlAllocOSEvent)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_FREE_OS_EVENT, nvgpu.SizeofIoctlFreeOSEvent)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_SYS_PARAMS, nvgpu.SizeofIoctlSysParams)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_WAIT_OPEN_COMPLETE, nvgpu.SizeofIoctlWaitOpenComplete)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC_MEMORY, nvgpu.SizeofIoctlNVOS02ParametersWithFD)), compUtil | nvconf.CapGraphics},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_FREE, nvgpu.SizeofNVOS00Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, nvgpu.SizeofNVOS54Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_DUP_OBJECT, nvgpu.SizeofNVOS55Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_SHARE, nvgpu.SizeofNVOS57Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_IDLE_CHANNELS, nvgpu.SizeofNVOS30Parameters)), nvconf.CapGraphics},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_VID_HEAP_CONTROL, nvgpu.SizeofNVOS32Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_MAP_MEMORY, nvgpu.SizeofIoctlNVOS33ParametersWithFD)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UNMAP_MEMORY, nvgpu.SizeofNVOS34Parameters)), compUtil},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC_CONTEXT_DMA2, nvgpu.SizeofNVOS39Parameters)), nvconf.CapGraphics},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_MAP_MEMORY_DMA, nvgpu.SizeofNVOS46Parameters)), nvconf.CapGraphics},
		{seccomp.MaskedEqual(notIocSizeMask, frontendIoctlCmd(nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA, 0)), nvconf.CapGraphics},
		{seccomp.EqualTo(frontendIoctlCmd(nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO, nvgpu.SizeofNVOS56Parameters)), compUtil},
	} {
		if feIoctl.caps&enabledCaps != 0 {
			ioctlRules = append(ioctlRules, seccomp.PerArg{
				seccomp.NonNegativeFD{},
				feIoctl.arg1,
			})
		}
	}
	return ioctlRules
}

func uvmIoctlFilters(enabledCaps nvconf.DriverCaps) []seccomp.SyscallRule {
	var ioctlRules []seccomp.SyscallRule
	for _, uvmIoctl := range []struct {
		arg1 seccomp.ValueMatcher
		caps nvconf.DriverCaps
	}{
		{seccomp.EqualTo(nvgpu.UVM_INITIALIZE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_MM_INITIALIZE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_DEINITIALIZE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_CREATE_RANGE_GROUP), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_DESTROY_RANGE_GROUP), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU_VASPACE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU_VASPACE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_REGISTER_CHANNEL), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNREGISTER_CHANNEL), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_ENABLE_PEER_ACCESS), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_DISABLE_PEER_ACCESS), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_SET_RANGE_GROUP), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_FREE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_REGISTER_GPU), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNREGISTER_GPU), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_PAGEABLE_MEM_ACCESS), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_SET_PREFERRED_LOCATION), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNSET_PREFERRED_LOCATION), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_DISABLE_READ_DUPLICATION), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNSET_ACCESSED_BY), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_MIGRATE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_MIGRATE_RANGE_GROUP), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY), nvconf.ValidCapabilities},
		{seccomp.EqualTo(nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY), nvconf.ValidCapabilities},
		{seccomp.EqualTo(nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_UNMAP_EXTERNAL), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_ALLOC_SEMAPHORE_POOL), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_VALIDATE_VA_RANGE), compUtil},
		{seccomp.EqualTo(nvgpu.UVM_CREATE_EXTERNAL_RANGE), compUtil},
	} {
		if uvmIoctl.caps&enabledCaps != 0 {
			ioctlRules = append(ioctlRules, seccomp.PerArg{
				seccomp.NonNegativeFD{},
				uvmIoctl.arg1,
			})
		}
	}
	return ioctlRules
}

// Filters returns seccomp-bpf filters for this package when using the given
// set of capabilities.
func Filters(enabledCaps nvconf.DriverCaps) seccomp.SyscallRules {
	var ioctlRules []seccomp.SyscallRule
	ioctlRules = append(ioctlRules, frontendIoctlFilters(enabledCaps)...)
	ioctlRules = append(ioctlRules, uvmIoctlFilters(enabledCaps)...)
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.Or(ioctlRules),
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
