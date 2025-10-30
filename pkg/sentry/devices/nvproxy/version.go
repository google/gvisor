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
	"fmt"
	"reflect"
	"runtime"
	"sort"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// ChecksumNoDriver is a special value that indicates that the driver runfile does not exist. This
	// is mostly for ARM drivers that NVIDIA does not provide a driver installer.
	ChecksumNoDriver = "NO_DRIVER"
)

// A driverABIFunc constructs and returns a driverABI.
// This indirection exists to avoid memory usage from unused driver ABIs.
type driverABIFunc func() *driverABI

// driverABIInfoFunc returns the driverABIInfo for a given ABI version. This
// indirection exists to avoid the memory usage in production when info about
// the driver ABI is not needed.
type driverABIInfoFunc func() *DriverABIInfo

// Checksums is a struct containing the SHA256 checksum of the linux .run driver installer file from
// NVIDIA.
type Checksums struct {
	checksumX86_64 string
	checksumARM64  string
}

// NewChecksums creates a new Checksums struct.
func NewChecksums(checksumX86_64, checksumARM64 string) Checksums {
	return Checksums{
		checksumX86_64: checksumX86_64,
		checksumARM64:  checksumARM64,
	}
}

// Checksum returns the SHA256 checksum of the linux .run driver installer file from NVIDIA for the
// given architecture.
func (c Checksums) Checksum() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return c.checksumX86_64, nil
	case "arm64":
		return c.checksumARM64, nil
	default:
		return "", nil
	}
}

// X86_64 returns the SHA256 checksum of the linux .run driver installer file from NVIDIA for X86_64.
func (c Checksums) X86_64() string {
	return c.checksumX86_64
}

// Arm64 returns the SHA256 checksum of the linux .run driver installer file from NVIDIA for ARM64.
func (c Checksums) Arm64() string {
	return c.checksumARM64
}

// abiConAndChecksum couples the driver's abiConstructor to the SHA256 checksum of its linux .run
// driver installer file from NVIDIA.
type abiConAndChecksum struct {
	cons      driverABIFunc
	checksums Checksums
}

// driverABI defines the Nvidia kernel driver ABI proxied at a given version.
//
// The Nvidia driver's ioctl interface branches widely at various places in the
// kernel driver. As for now, versioning is only supported for the following
// points of branching:
//  1. frontend device ioctls (based on IOC_NR(cmd)).
//  2. uvm device ioctls (based on cmd).
//  3. control commands within NV_ESC_RM_CONTROL in frontend device (based on
//     NVOS54_PARAMETERS.Cmd). Note that commands that have RM_GSS_LEGACY_MASK
//     set are not versioned.
//  4. allocation classes within NV_ESC_RM_ALLOC in frontend device (based on
//     NVOS64_PARAMETERS.HClass).
type driverABI struct {
	frontendIoctl   map[uint32]frontendIoctlHandler
	uvmIoctl        map[uint32]uvmIoctlHandler
	controlCmd      map[uint32]controlCmdHandler
	allocationClass map[nvgpu.ClassID]allocationClassHandler

	getInfo driverABIInfoFunc
}

// DriverABIInfo defines all the structs and ioctls used by a driverABI.
// This is used to help with verifying and supporting new driver versions. This
// helps keep track of all the driver structs and ioctls that we currently
// support. We do so by mapping ioctl numbers to its name in the driver and a
// list of DriverStructs used by that ioctl.
type DriverABIInfo struct {
	FrontendInfos   map[uint32]IoctlInfo
	UvmInfos        map[uint32]IoctlInfo
	ControlInfos    map[uint32]IoctlInfo
	AllocationInfos map[nvgpu.ClassID]IoctlInfo
}

// IoctlName is the name of the constant used by the Nvidia driver to define
// the ioctl number/control command/allocation class.
type IoctlName = string

// DriverStructName is the name of a struct used by the Nvidia driver.
type DriverStructName = string

// DriverStruct ties an nvproxy struct type to its corresponding driver struct name.
type DriverStruct struct {
	Name DriverStructName
	Type reflect.Type
}

// IoctlInfo contains information about an ioctl defined by the Nvidia driver.
type IoctlInfo struct {
	Name    IoctlName
	Structs []DriverStruct
}

// abis is a global map containing all supported Nvidia driver ABIs. This is
// initialized on Init() and is immutable henceforth.
var abis map[nvconf.DriverVersion]abiConAndChecksum
var abisOnce sync.Once

// Note: runfileChecksum is the checksum of the .run file of the driver installer for linux from
// nvidia.
// To add a new version, add in support as normal and add the "addDriverABI" call for your version.
// Run `make sudo TARGETS=//tools/gpu:main ARGS="checksum --version={}"` to get checksum.
func addDriverABI(major, minor, patch int, checksumX86_64, checksumARM64 string, cons driverABIFunc) driverABIFunc {
	if abis == nil {
		abis = make(map[nvconf.DriverVersion]abiConAndChecksum)
	}
	version := nvconf.NewDriverVersion(major, minor, patch)
	abis[version] = abiConAndChecksum{
		cons:      cons,
		checksums: NewChecksums(checksumX86_64, checksumARM64),
	}
	return cons
}

// Init initializes abis global map.
func Init() {
	abisOnce.Do(func() {
		v535_104_05 := func() *driverABI {
			// Since there is no parent to inherit from, the driverABI needs to be
			// constructed with the entirety of the nvproxy functionality.
			return &driverABI{
				frontendIoctl: map[uint32]frontendIoctlHandler{
					nvgpu.NV_ESC_CARD_INFO:                     feHandler(frontendIoctlBytes, compUtil), // nv_ioctl_card_info_t array
					nvgpu.NV_ESC_CHECK_VERSION_STR:             feHandler(frontendIoctlSimpleNoStatus[nvgpu.RMAPIVersion], compUtil),
					nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             feHandler(frontendIoctlBytes, compUtil), // NvU32 array containing GPU IDs
					nvgpu.NV_ESC_SYS_PARAMS:                    feHandler(frontendIoctlSimpleNoStatus[nvgpu.IoctlSysParams], compUtil),
					nvgpu.NV_ESC_RM_DUP_OBJECT:                 feHandler(rmDupObject, compUtil),
					nvgpu.NV_ESC_RM_SHARE:                      feHandler(frontendIoctlSimple[nvgpu.NVOS57_PARAMETERS], compUtil),
					nvgpu.NV_ESC_RM_UNMAP_MEMORY:               feHandler(frontendIoctlSimple[nvgpu.NVOS34_PARAMETERS], compUtil),
					nvgpu.NV_ESC_RM_MAP_MEMORY_DMA:             feHandler(frontendIoctlSimple[nvgpu.NVOS46_PARAMETERS], nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA:           feHandler(frontendIoctlSimple[nvgpu.NVOS47_PARAMETERS], nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: feHandler(frontendIoctlSimple[nvgpu.NVOS56_PARAMETERS], compUtil),
					nvgpu.NV_ESC_REGISTER_FD:                   feHandler(frontendRegisterFD, compUtil),
					nvgpu.NV_ESC_ALLOC_OS_EVENT:                feHandler(frontendIoctlHasFD[nvgpu.IoctlAllocOSEvent], compUtil),
					nvgpu.NV_ESC_FREE_OS_EVENT:                 feHandler(frontendIoctlHasFD[nvgpu.IoctlFreeOSEvent], compUtil),
					nvgpu.NV_ESC_NUMA_INFO:                     feHandler(rmNumaInfo, compUtil),
					nvgpu.NV_ESC_RM_ALLOC_CONTEXT_DMA2:         feHandler(rmAllocContextDMA2, nvconf.CapGraphics),
					nvgpu.NV_ESC_RM_ALLOC_MEMORY:               feHandler(rmAllocMemory, compUtil|nvconf.CapGraphics),
					nvgpu.NV_ESC_RM_FREE:                       feHandler(rmFree, compUtil),
					nvgpu.NV_ESC_RM_CONTROL:                    feHandler(rmControl, compUtil),
					nvgpu.NV_ESC_RM_ALLOC:                      feHandler(rmAlloc, compUtil),
					nvgpu.NV_ESC_RM_IDLE_CHANNELS:              feHandler(rmIdleChannels, nvconf.CapGraphics),
					nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           feHandler(rmVidHeapControl, compUtil),
					nvgpu.NV_ESC_RM_MAP_MEMORY:                 feHandler(rmMapMemory, compUtil),
				},
				uvmIoctl: map[uint32]uvmIoctlHandler{
					nvgpu.UVM_INITIALIZE:                     uvmHandler(uvmInitialize, compUtil),
					nvgpu.UVM_DEINITIALIZE:                   uvmHandler(uvmIoctlNoParams, compUtil),
					nvgpu.UVM_CREATE_RANGE_GROUP:             uvmHandler(uvmIoctlSimple[nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS], compUtil),
					nvgpu.UVM_DESTROY_RANGE_GROUP:            uvmHandler(uvmIoctlSimple[nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS], compUtil),
					nvgpu.UVM_REGISTER_GPU_VASPACE:           uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS], compUtil),
					nvgpu.UVM_UNREGISTER_GPU_VASPACE:         uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS], compUtil),
					nvgpu.UVM_REGISTER_CHANNEL:               uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_CHANNEL_PARAMS], compUtil),
					nvgpu.UVM_UNREGISTER_CHANNEL:             uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS], compUtil),
					nvgpu.UVM_ENABLE_PEER_ACCESS:             uvmHandler(uvmIoctlSimple[nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS], compUtil),
					nvgpu.UVM_DISABLE_PEER_ACCESS:            uvmHandler(uvmIoctlSimple[nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS], compUtil),
					nvgpu.UVM_SET_RANGE_GROUP:                uvmHandler(uvmIoctlSimple[nvgpu.UVM_SET_RANGE_GROUP_PARAMS], compUtil),
					nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS], compUtil),
					nvgpu.UVM_FREE:                           uvmHandler(uvmIoctlSimple[nvgpu.UVM_FREE_PARAMS], compUtil),
					nvgpu.UVM_REGISTER_GPU:                   uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_GPU_PARAMS], compUtil),
					nvgpu.UVM_UNREGISTER_GPU:                 uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_PARAMS], compUtil),
					nvgpu.UVM_PAGEABLE_MEM_ACCESS:            uvmHandler(uvmIoctlSimple[nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS], compUtil),
					nvgpu.UVM_SET_PREFERRED_LOCATION:         uvmHandler(uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS], compUtil),
					nvgpu.UVM_UNSET_PREFERRED_LOCATION:       uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNSET_PREFERRED_LOCATION_PARAMS], compUtil),
					nvgpu.UVM_DISABLE_READ_DUPLICATION:       uvmHandler(uvmIoctlSimple[nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS], compUtil),
					nvgpu.UVM_UNSET_ACCESSED_BY:              uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNSET_ACCESSED_BY_PARAMS], compUtil),
					nvgpu.UVM_MIGRATE:                        uvmHandler(uvmIoctlSimple[nvgpu.UVM_MIGRATE_PARAMS], compUtil),
					nvgpu.UVM_MIGRATE_RANGE_GROUP:            uvmHandler(uvmIoctlSimple[nvgpu.UVM_MIGRATE_RANGE_GROUP_PARAMS], compUtil),
					nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: uvmHandler(uvmIoctlSimple[nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS], compUtil),
					nvgpu.UVM_UNMAP_EXTERNAL:                 uvmHandler(uvmIoctlSimple[nvgpu.UVM_UNMAP_EXTERNAL_PARAMS], compUtil),
					nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           uvmHandler(uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS], compUtil),
					nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU:     uvmHandler(uvmIoctlSimple[nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS], nvconf.CapVideo),
					nvgpu.UVM_VALIDATE_VA_RANGE:              uvmHandler(uvmIoctlSimple[nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS], compUtil),
					nvgpu.UVM_CREATE_EXTERNAL_RANGE:          uvmHandler(uvmIoctlSimple[nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS], compUtil),
					nvgpu.UVM_MM_INITIALIZE:                  uvmHandler(uvmMMInitialize, compUtil),
				},
				controlCmd: map[uint32]controlCmdHandler{
					nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS:                               ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID:                         ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:                            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GSYNC_GET_ATTACHED_IDS:                           ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO:                              ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_DMA_ADV_SCHED_GET_VA_CAPS:                        ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_DMA_GET_CAPS:                                     ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:                      ctrlHandler(rmControlSimple, compUtil),
					nvgpu.UNKNOWN_CONTROL_COMMAND_80028B:                                   ctrlHandler(rmControlSimple, compUtil), // unknown, paramsSize == 1
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_BSP_GET_CAPS_V2:                                  ctrlHandler(rmControlSimple, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_NVJPG_GET_CAPS_V2:                                ctrlHandler(rmControlSimple, nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_ENGINE_CONTEXT_PROPERTIES:               ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV_SEMAPHORE_SURFACE_CTRL_CMD_BIND_CHANNEL:                       ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO:                                     ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], nvconf.CapVideo),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_CE_GET_CE_PCE_MASK:                               ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_CE_GET_CAPS_V2:                                   ctrlHandler(rmControlSimple, compUtil|nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_GPU_CACHE_INFO:                            ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO:                            ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_FB_GET_SEMAPHORE_SURFACE_LAYOUT:                  ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ID:                                       ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST:                       ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENCODER_CAPACITY:                         ctrlHandler(rmControlSimple, nvconf.CapVideo),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_ZCULL_INFO:                                ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GR_CTXSW_ZCULL_BIND:                              ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_OS_UNIX_VIDMEM_PERSISTENCE_STATUS:                ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_TIME:                                   ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES:                                  ctrlHandler(ctrlGetNvU32List, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], compUtil),
					nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlHandler(ctrlSubdevFIFODisableChannels, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS], compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], nvconf.CapGraphics),
					nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_SIZE:                         ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_ENTRY:                        ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX:         ctrlHandler(rmControlSimple, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06F_CTRL_CMD_BIND:                                             ctrlHandler(rmControlSimple, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                                  ctrlHandler(ctrlGpuGetIDInfo, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ctrlHandler(ctrlClientSystemGetBuildVersion, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                ctrlHandler(ctrlGetNvU32List, compUtil),
					nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS:                                      ctrlHandler(ctrlDevGetCaps, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS_V2:                                   ctrlHandler(rmControlSimple, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_GR_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS:                                      ctrlHandler(ctrlDevGetCaps, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS:                                    ctrlHandler(ctrlDevGetCaps, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS_V2:                                 ctrlHandler(rmControlSimple, nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ctrlHandler(ctrlDevFIFOGetChannelList, compUtil),
					nvgpu.NV0080_CTRL_CMD_MSENC_GET_CAPS:                                   ctrlHandler(ctrlDevGetCaps, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:                              ctrlHandler(ctrlClientSystemGetP2PCaps, compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECTS_TO_FD:                     ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECTS_FROM_FD:                   ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS], compUtil),
					nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       ctrlHandler(ctrlMemoryMulticastFabricAttachGPU, compUtil),
					nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                ctrlHandler(ctrlRegisterVASpace, compUtil),
					nvgpu.NV208F_CTRL_CMD_GPU_VERIFY_INFOROM:                               ctrlHandler(rmControlSimple, compUtil),
				},
				allocationClass: map[nvgpu.ClassID]allocationClassHandler{
					nvgpu.NV01_ROOT:                  allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_ROOT_NON_PRIV:         allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_CONTEXT_DMA:           allocHandler(rmAllocContextDMA, nvconf.CapVideo),
					nvgpu.NV01_MEMORY_SYSTEM:         allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV01_MEMORY_LOCAL_USER:     allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV01_ROOT_CLIENT:           allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_EVENT_OS_EVENT:        allocHandler(rmAllocEventOSEvent, compUtil),
					nvgpu.NV01_MEMORY_VIRTUAL:        allocHandler(rmAllocMemoryVirtual, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV01_DEVICE_0:              allocHandler(rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV_SEMAPHORE_SURFACE:       allocHandler(rmAllocSimple[nvgpu.NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS], nvconf.CapGraphics),
					nvgpu.RM_USER_SHARED_DATA:        allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_FABRIC:           allocHandler(rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_MULTICAST_FABRIC: allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_MAPPER:           allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS], nvconf.CapGraphics),
					nvgpu.NV20_SUBDEVICE_0:           allocHandler(rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV2081_BINAPI:              allocHandler(rmAllocSimple[nvgpu.NV2081_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV50_MEMORY_VIRTUAL:        allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV50_P2P:                   allocHandler(rmAllocSimple[nvgpu.NV503B_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV50_THIRD_PARTY_P2P:       allocHandler(rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS], compUtil),
					nvgpu.GF100_PROFILER:             allocHandler(rmAllocNoParams, compUtil),
					nvgpu.GT200_DEBUGGER:             allocHandler(rmAllocSMDebuggerSession, compUtil),
					nvgpu.FERMI_TWOD_A:               allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.FERMI_CONTEXT_SHARE_A:      allocHandler(rmAllocContextShare, compUtil),
					nvgpu.GF100_DISP_SW:              allocHandler(rmAllocSimple[nvgpu.NV9072_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.GF100_ZBC_CLEAR:            allocHandler(rmAllocNoParams, nvconf.CapGraphics),
					nvgpu.FERMI_VASPACE_A:            allocHandler(rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.KEPLER_CHANNEL_GROUP_A:     allocHandler(rmAllocChannelGroup, compUtil),
					nvgpu.KEPLER_INLINE_TO_MEMORY_B:  allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.VOLTA_USERMODE_A:           allocHandler(rmAllocNoParams, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.TURING_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
					nvgpu.NVB8B0_VIDEO_DECODER:       allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC4B0_VIDEO_DECODER:       allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC6B0_VIDEO_DECODER:       allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC7B0_VIDEO_DECODER:       allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC9B0_VIDEO_DECODER:       allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC4B7_VIDEO_ENCODER:       allocHandler(rmAllocSimple[nvgpu.NV_MSENC_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC7B7_VIDEO_ENCODER:       allocHandler(rmAllocSimple[nvgpu.NV_MSENC_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.NVC9B7_VIDEO_ENCODER:       allocHandler(rmAllocSimple[nvgpu.NV_MSENC_ALLOCATION_PARAMETERS], nvconf.CapVideo),
					nvgpu.AMPERE_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
					nvgpu.HOPPER_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
					nvgpu.TURING_A:                   allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.AMPERE_A:                   allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.ADA_A:                      allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.HOPPER_A:                   allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics),
					nvgpu.TURING_DMA_COPY_A:          allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.AMPERE_DMA_COPY_A:          allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.AMPERE_DMA_COPY_B:          allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.HOPPER_DMA_COPY_A:          allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.TURING_COMPUTE_A:           allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.AMPERE_COMPUTE_A:           allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.AMPERE_COMPUTE_B:           allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.ADA_COMPUTE_A:              allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV_CONFIDENTIAL_COMPUTE:    allocHandler(rmAllocSimple[nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS], compUtil),
					nvgpu.HOPPER_COMPUTE_A:           allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.HOPPER_USERMODE_A:          allocHandler(rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS], compUtil),
					nvgpu.GF100_SUBDEVICE_MASTER:     allocHandler(rmAllocNoParams, compUtil),
					nvgpu.TURING_USERMODE_A:          allocHandler(rmAllocNoParams, compUtil),
					nvgpu.HOPPER_SEC2_WORK_LAUNCH_A:  allocHandler(rmAllocNoParams, compUtil),
					nvgpu.NV04_DISPLAY_COMMON:        allocHandler(rmAllocNoParams, nvconf.CapGraphics),
					nvgpu.NV20_SUBDEVICE_DIAG:        allocHandler(rmAllocNoParams, compUtil),
				},

				getInfo: func() *DriverABIInfo {
					return &DriverABIInfo{
						FrontendInfos: map[uint32]IoctlInfo{
							nvgpu.NV_ESC_CARD_INFO:                     simpleIoctlInfo("NV_ESC_CARD_INFO", "nv_ioctl_card_info_t"),
							nvgpu.NV_ESC_CHECK_VERSION_STR:             ioctlInfoWithStructName("NV_ESC_CHECK_VERSION_STR", nvgpu.RMAPIVersion{}, "nv_ioctl_rm_api_version_t"),
							nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             simpleIoctlInfo("NV_ESC_ATTACH_GPUS_TO_FD"), // No params struct, params is a NvU32 array containing GPU IDs
							nvgpu.NV_ESC_SYS_PARAMS:                    ioctlInfoWithStructName("NV_ESC_SYS_PARAMS", nvgpu.IoctlSysParams{}, "nv_ioctl_sys_params_t"),
							nvgpu.NV_ESC_RM_DUP_OBJECT:                 ioctlInfo("NV_ESC_RM_DUP_OBJECT", nvgpu.NVOS55_PARAMETERS{}),
							nvgpu.NV_ESC_RM_SHARE:                      ioctlInfo("NV_ESC_RM_SHARE", nvgpu.NVOS57_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UNMAP_MEMORY:               ioctlInfo("NV_ESC_RM_UNMAP_MEMORY", nvgpu.NVOS34_PARAMETERS{}),
							nvgpu.NV_ESC_RM_ALLOC_CONTEXT_DMA2:         ioctlInfo("NV_ESC_RM_ALLOC_CONTEXT_DMA2", nvgpu.NVOS39_PARAMETERS{}),
							nvgpu.NV_ESC_RM_MAP_MEMORY_DMA:             ioctlInfo("NV_ESC_RM_MAP_MEMORY_DMA", nvgpu.NVOS46_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA:           ioctlInfo("NV_ESC_RM_UNMAP_MEMORY_DMA", nvgpu.NVOS47_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: ioctlInfo("NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO", nvgpu.NVOS56_PARAMETERS{}),
							nvgpu.NV_ESC_REGISTER_FD:                   ioctlInfoWithStructName("NV_ESC_REGISTER_FD", nvgpu.IoctlRegisterFD{}, "nv_ioctl_register_fd_t"),
							nvgpu.NV_ESC_ALLOC_OS_EVENT:                ioctlInfoWithStructName("NV_ESC_ALLOC_OS_EVENT", nvgpu.IoctlAllocOSEvent{}, "nv_ioctl_alloc_os_event_t"),
							nvgpu.NV_ESC_FREE_OS_EVENT:                 ioctlInfoWithStructName("NV_ESC_FREE_OS_EVENT", nvgpu.IoctlFreeOSEvent{}, "nv_ioctl_free_os_event_t"),
							nvgpu.NV_ESC_NUMA_INFO:                     simpleIoctlInfo("NV_ESC_NUMA_INFO"), // No params struct because nvproxy ignores this ioctl
							nvgpu.NV_ESC_RM_ALLOC_MEMORY:               ioctlInfoWithStructName("NV_ESC_RM_ALLOC_MEMORY", nvgpu.IoctlNVOS02ParametersWithFD{}, "nv_ioctl_nvos02_parameters_with_fd"),
							nvgpu.NV_ESC_RM_FREE:                       ioctlInfo("NV_ESC_RM_FREE", nvgpu.NVOS00_PARAMETERS{}),
							nvgpu.NV_ESC_RM_CONTROL:                    ioctlInfo("NV_ESC_RM_CONTROL", nvgpu.NVOS54_PARAMETERS{}),
							nvgpu.NV_ESC_RM_ALLOC:                      ioctlInfo("NV_ESC_RM_ALLOC", nvgpu.NVOS21_PARAMETERS{}, nvgpu.NVOS64_PARAMETERS{}),
							nvgpu.NV_ESC_RM_IDLE_CHANNELS:              ioctlInfo("NV_ESC_RM_IDLE_CHANNELS", nvgpu.NVOS30_PARAMETERS{}),
							nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           ioctlInfo("NV_ESC_RM_VID_HEAP_CONTROL", nvgpu.NVOS32_PARAMETERS{}),
							nvgpu.NV_ESC_RM_MAP_MEMORY:                 ioctlInfoWithStructName("NV_ESC_RM_MAP_MEMORY", nvgpu.IoctlNVOS33ParametersWithFD{}, "nv_ioctl_nvos33_parameters_with_fd"),
						},
						UvmInfos: map[uint32]IoctlInfo{
							nvgpu.UVM_INITIALIZE:                     ioctlInfo("UVM_INITIALIZE", nvgpu.UVM_INITIALIZE_PARAMS{}),
							nvgpu.UVM_DEINITIALIZE:                   simpleIoctlInfo("UVM_DEINITIALIZE"), // Doesn't have any params
							nvgpu.UVM_CREATE_RANGE_GROUP:             ioctlInfo("UVM_CREATE_RANGE_GROUP", nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_DESTROY_RANGE_GROUP:            ioctlInfo("UVM_DESTROY_RANGE_GROUP", nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU_VASPACE:           ioctlInfo("UVM_REGISTER_GPU_VASPACE", nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU_VASPACE:         ioctlInfo("UVM_UNREGISTER_GPU_VASPACE", nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_REGISTER_CHANNEL:               ioctlInfo("UVM_REGISTER_CHANNEL", nvgpu.UVM_REGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_UNREGISTER_CHANNEL:             ioctlInfo("UVM_UNREGISTER_CHANNEL", nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_ENABLE_PEER_ACCESS:             ioctlInfo("UVM_ENABLE_PEER_ACCESS", nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_DISABLE_PEER_ACCESS:            ioctlInfo("UVM_DISABLE_PEER_ACCESS", nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_RANGE_GROUP:                ioctlInfo("UVM_SET_RANGE_GROUP", nvgpu.UVM_SET_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        ioctlInfo("UVM_MAP_EXTERNAL_ALLOCATION", nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS{}),
							nvgpu.UVM_FREE:                           ioctlInfo("UVM_FREE", nvgpu.UVM_FREE_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU:                   ioctlInfo("UVM_REGISTER_GPU", nvgpu.UVM_REGISTER_GPU_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU:                 ioctlInfo("UVM_UNREGISTER_GPU", nvgpu.UVM_UNREGISTER_GPU_PARAMS{}),
							nvgpu.UVM_PAGEABLE_MEM_ACCESS:            ioctlInfo("UVM_PAGEABLE_MEM_ACCESS", nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_PREFERRED_LOCATION:         ioctlInfo("UVM_SET_PREFERRED_LOCATION", nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_UNSET_PREFERRED_LOCATION:       ioctlInfo("UVM_UNSET_PREFERRED_LOCATION", nvgpu.UVM_UNSET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_DISABLE_READ_DUPLICATION:       ioctlInfo("UVM_DISABLE_READ_DUPLICATION", nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS{}),
							nvgpu.UVM_UNSET_ACCESSED_BY:              ioctlInfo("UVM_UNSET_ACCESSED_BY", nvgpu.UVM_UNSET_ACCESSED_BY_PARAMS{}),
							nvgpu.UVM_MIGRATE:                        ioctlInfo("UVM_MIGRATE", nvgpu.UVM_MIGRATE_PARAMS{}),
							nvgpu.UVM_MIGRATE_RANGE_GROUP:            ioctlInfo("UVM_MIGRATE_RANGE_GROUP", nvgpu.UVM_MIGRATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: ioctlInfo("UVM_MAP_DYNAMIC_PARALLELISM_REGION", nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS{}),
							nvgpu.UVM_UNMAP_EXTERNAL:                 ioctlInfo("UVM_UNMAP_EXTERNAL", nvgpu.UVM_UNMAP_EXTERNAL_PARAMS{}),
							nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           ioctlInfo("UVM_ALLOC_SEMAPHORE_POOL", nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS{}),
							nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU:     ioctlInfo("UVM_PAGEABLE_MEM_ACCESS_ON_GPU", nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS{}),
							nvgpu.UVM_VALIDATE_VA_RANGE:              ioctlInfo("UVM_VALIDATE_VA_RANGE", nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS{}),
							nvgpu.UVM_CREATE_EXTERNAL_RANGE:          ioctlInfo("UVM_CREATE_EXTERNAL_RANGE", nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS{}),
							nvgpu.UVM_MM_INITIALIZE:                  ioctlInfo("UVM_MM_INITIALIZE", nvgpu.UVM_MM_INITIALIZE_PARAMS{}),
						},
						ControlInfos: map[uint32]IoctlInfo{
							nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:                       simpleIoctlInfo("NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE", "NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY:                simpleIoctlInfo("NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY", "NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:                             simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS", "NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS:                               simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS", "NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                               simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2", "NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                               simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_PROBED_IDS", "NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                                   simpleIoctlInfo("NV0000_CTRL_CMD_GPU_ATTACH_IDS", "NV0000_CTRL_GPU_ATTACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                                   simpleIoctlInfo("NV0000_CTRL_CMD_GPU_DETACH_IDS", "NV0000_CTRL_GPU_DETACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                                 simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_PCI_INFO", "NV0000_CTRL_GPU_GET_PCI_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID:                         simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID", "NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:                            simpleIoctlInfo("NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE", "NV0000_CTRL_GPU_QUERY_DRAIN_STATE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:                             simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE", "NV0000_CTRL_GPU_GET_MEMOP_ENABLE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GSYNC_GET_ATTACHED_IDS:                           simpleIoctlInfo("NV0000_CTRL_CMD_GSYNC_GET_ATTACHED_IDS", "NV0000_CTRL_GSYNC_GET_ATTACHED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:                        simpleIoctlInfo("NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO", "NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO:                              simpleIoctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO", "NV0000_CTRL_SYSTEM_GET_CPU_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:                           simpleIoctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2", "NV0000_CTRL_SYSTEM_GET_P2P_CAPS_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:                         simpleIoctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS", "NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:                       simpleIoctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX", "NV0000_CTRL_SYSTEM_GET_P2P_CAPS_MATRIX_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:                              simpleIoctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_FEATURES", "NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_DMA_ADV_SCHED_GET_VA_CAPS:                        simpleIoctlInfo("NV0080_CTRL_CMD_DMA_ADV_SCHED_GET_VA_CAPS", "NV0080_CTRL_DMA_ADV_SCHED_GET_VA_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_DMA_GET_CAPS:                                     simpleIoctlInfo("NV0080_CTRL_CMD_DMA_GET_CAPS", "NV0080_CTRL_DMA_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                                   simpleIoctlInfo("NV0080_CTRL_CMD_FB_GET_CAPS_V2", "NV0080_CTRL_FB_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:                           simpleIoctlInfo("NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES", "NV0080_CTRL_GPU_GET_NUM_SUBDEVICES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:                   simpleIoctlInfo("NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE", "NV0080_CTRL_GPU_QUERY_SW_STATE_PERSISTENCE_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:                      simpleIoctlInfo("NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE", "NV0080_CTRL_GPU_GET_VIRTUALIZATION_MODE_PARAMS"),
							nvgpu.UNKNOWN_CONTROL_COMMAND_80028B:                                   simpleIoctlInfo(""), // unknown, paramsSize == 1
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             simpleIoctlInfo("NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2", "NV0080_CTRL_GPU_GET_CLASSLIST_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 simpleIoctlInfo("NV0080_CTRL_CMD_HOST_GET_CAPS_V2", "NV0080_CTRL_HOST_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_BSP_GET_CAPS_V2:                                  simpleIoctlInfo("NV0080_CTRL_CMD_BSP_GET_CAPS_V2", "NV0080_CTRL_BSP_GET_CAPS_PARAMS_V2"),
							nvgpu.NV0080_CTRL_CMD_NVJPG_GET_CAPS_V2:                                simpleIoctlInfo("NV0080_CTRL_CMD_NVJPG_GET_CAPS_V2", "NV0080_CTRL_NVJPG_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_ENGINE_CONTEXT_PROPERTIES:               simpleIoctlInfo("NV0080_CTRL_CMD_FIFO_GET_ENGINE_CONTEXT_PROPERTIES", "NV0080_CTRL_FIFO_GET_ENGINE_CONTEXT_PROPERTIES_PARAMS"),
							nvgpu.NV_SEMAPHORE_SURFACE_CTRL_CMD_BIND_CHANNEL:                       simpleIoctlInfo("NV_SEMAPHORE_SURFACE_CTRL_CMD_BIND_CHANNEL", "NV_SEMAPHORE_SURFACE_CTRL_BIND_CHANNEL_PARAMS"),
							nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                                       simpleIoctlInfo("NV00F8_CTRL_CMD_ATTACH_MEM", "NV00F8_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         simpleIoctlInfo("NV00FD_CTRL_CMD_GET_INFO", "NV00FD_CTRL_GET_INFO_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       simpleIoctlInfo("NV00FD_CTRL_CMD_ATTACH_MEM", "NV00FD_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       simpleIoctlInfo("NV00FD_CTRL_CMD_DETACH_MEM", "NV00FD_CTRL_DETACH_MEM_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 simpleIoctlInfo("NV2080_CTRL_CMD_BUS_GET_PCI_INFO", "NV2080_CTRL_BUS_GET_PCI_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             simpleIoctlInfo("NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO", "NV2080_CTRL_BUS_GET_PCI_BAR_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO:                                     ioctlInfoWithStructName("NV2080_CTRL_CMD_BUS_GET_INFO", nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_BUS_GET_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  simpleIoctlInfo("NV2080_CTRL_CMD_BUS_GET_INFO_V2", "NV2080_CTRL_BUS_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               simpleIoctlInfo("NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS", "NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 simpleIoctlInfo("NV2080_CTRL_CMD_BUS_GET_C2C_INFO", "NV2080_CTRL_CMD_BUS_GET_C2C_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_CE_PCE_MASK:                               simpleIoctlInfo("NV2080_CTRL_CMD_CE_GET_CE_PCE_MASK", "NV2080_CTRL_CE_GET_CE_PCE_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_CAPS_V2:                                   simpleIoctlInfo("NV2080_CTRL_CMD_CE_GET_CAPS_V2", "NV2080_CTRL_CE_GET_CAPS_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  simpleIoctlInfo("NV2080_CTRL_CMD_CE_GET_ALL_CAPS", "NV2080_CTRL_CE_GET_ALL_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           simpleIoctlInfo("NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION", "NV2080_CTRL_EVENT_SET_NOTIFICATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   simpleIoctlInfo("NV2080_CTRL_CMD_FB_GET_INFO_V2", "NV2080_CTRL_FB_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_GPU_CACHE_INFO:                            simpleIoctlInfo("NV2080_CTRL_CMD_FB_GET_GPU_CACHE_INFO", "NV2080_CTRL_FB_GET_GPU_CACHE_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO:                            simpleIoctlInfo("NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO", "NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_SEMAPHORE_SURFACE_LAYOUT:                  simpleIoctlInfo("NV2080_CTRL_CMD_FB_GET_SEMAPHORE_SURFACE_LAYOUT", "NV2080_CTRL_FB_GET_SEMAPHORE_SURFACE_LAYOUT_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_INFO_V2", "NV2080_CTRL_GPU_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         simpleIoctlInfo("NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE", "NV2080_CTRL_FLCN_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_NAME_STRING", "NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING", "NV2080_CTRL_GPU_GET_SHORT_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO", "NV2080_CTRL_GPU_GET_SIMULATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             simpleIoctlInfo("NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS", "NV2080_CTRL_GPU_QUERY_ECC_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     simpleIoctlInfo("NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES", "NV2080_CTRL_GPU_QUERY_COMPUTE_MODE_RULES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ID:                                       simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_ID", "NV2080_CTRL_GPU_GET_ID_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      simpleIoctlInfo("NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION", "NV2080_CTRL_GPU_QUERY_ECC_CONFIGURATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO", "NV2080_CTRL_GPU_GET_OEM_BOARD_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             simpleIoctlInfo(""), // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             simpleIoctlInfo(""), // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST:                       simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST", "NV2080_CTRL_GPU_GET_ENGINE_PARTNERLIST_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_GID_INFO", "NV2080_CTRL_GPU_GET_GID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION", "NV2080_CTRL_GPU_GET_INFOROM_OBJECT_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION", "NV2080_CTRL_GPU_GET_INFOROM_IMAGE_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    simpleIoctlInfo("NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT"), // No params.
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENCODER_CAPACITY:                         simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_ENCODER_CAPACITY", "NV2080_CTRL_GPU_GET_ENCODER_CAPACITY_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_ENGINES_V2", "NV2080_CTRL_GPU_GET_ENGINES_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS", "NV2080_CTRL_GPU_GET_ACTIVE_PARTITION_IDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_PIDS", "NV2080_CTRL_GPU_GET_PIDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_PID_INFO", "NV2080_CTRL_GPU_GET_PID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    simpleIoctlInfo("NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG", "NV2080_CTRL_GPU_GET_COMPUTE_POLICY_CONFIG_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        simpleIoctlInfo("NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO", "NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_ZCULL_INFO:                                simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_ZCULL_INFO", "NV2080_CTRL_GR_GET_ZCULL_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_CTXSW_ZCULL_BIND:                              simpleIoctlInfo("NV2080_CTRL_CMD_GR_CTXSW_ZCULL_BIND", "NV2080_CTRL_GR_CTXSW_ZCULL_BIND_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     simpleIoctlInfo("NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE", "NV2080_CTRL_GR_SET_CTXSW_PREEMPTION_MODE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE", "NV2080_CTRL_GR_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER", "NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_CAPS_V2", "NV2080_CTRL_GR_GET_CAPS_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_GPC_MASK", "NV2080_CTRL_GR_GET_GPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_TPC_MASK", "NV2080_CTRL_GR_GET_TPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    simpleIoctlInfo("NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER", "NV2080_CTRL_GR_GET_SM_ISSUE_RATE_MODIFIER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             simpleIoctlInfo("NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO", "NV2080_CTRL_GRMGR_GET_GR_FS_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_OS_UNIX_VIDMEM_PERSISTENCE_STATUS:                simpleIoctlInfo("NV2080_CTRL_CMD_OS_UNIX_VIDMEM_PERSISTENCE_STATUS", "NV2080_CTRL_OS_UNIX_VIDMEM_PERSISTENCE_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 simpleIoctlInfo("NV2080_CTRL_CMD_GSP_GET_FEATURES", "NV2080_CTRL_GSP_GET_FEATURES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 simpleIoctlInfo("NV2080_CTRL_CMD_MC_GET_ARCH_INFO", "NV2080_CTRL_MC_GET_ARCH_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            simpleIoctlInfo("NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS", "NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           simpleIoctlInfo("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS", "NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         simpleIoctlInfo("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS", "NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       simpleIoctlInfo("NV2080_CTRL_CMD_PERF_BOOST", "NV2080_CTRL_PERF_BOOST_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             simpleIoctlInfo("NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO", "NV2080_CTRL_RC_GET_WATCHDOG_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     simpleIoctlInfo("NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS"), // No params.
							nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         simpleIoctlInfo("NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG"),     // No params.
							nvgpu.NV2080_CTRL_CMD_TIMER_GET_TIME:                                   simpleIoctlInfo("NV2080_CTRL_CMD_TIMER_GET_TIME", "NV2080_CTRL_TIMER_GET_TIME_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          simpleIoctlInfo("NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO", "NV2080_CTRL_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                           simpleIoctlInfo("NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ", "NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES:                                  ioctlInfoWithStructName("NV2080_CTRL_CMD_GPU_GET_ENGINES", nvgpu.RmapiParamNvU32List{}, "NV2080_CTRL_GPU_GET_ENGINES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    ioctlInfoWithStructName("NV2080_CTRL_CMD_BIOS_GET_INFO", nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_BIOS_GET_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ioctlInfo("NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS", nvgpu.NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ioctlInfo("NV2080_CTRL_CMD_GR_GET_INFO", nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_FB_GET_INFO:                                      ioctlInfoWithStructName("NV2080_CTRL_CMD_FB_GET_INFO", nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_FB_GET_INFO_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  simpleIoctlInfo("NV503C_CTRL_CMD_REGISTER_VIDMEM", "NV503C_CTRL_REGISTER_VIDMEM_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                simpleIoctlInfo("NV503C_CTRL_CMD_UNREGISTER_VIDMEM", "NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         simpleIoctlInfo("NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK", "NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   simpleIoctlInfo("NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES", "NV83DE_CTRL_DEBUG_READ_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  simpleIoctlInfo("NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES", "NV83DE_CTRL_DEBUG_CLEAR_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   simpleIoctlInfo("NV906F_CTRL_GET_CLASS_ENGINEID", "NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    simpleIoctlInfo("NV906F_CTRL_CMD_RESET_CHANNEL", "NV906F_CTRL_CMD_RESET_CHANNEL_PARAMS"),
							nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_SIZE:                         simpleIoctlInfo("NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_SIZE", "NV9096_CTRL_GET_ZBC_CLEAR_TABLE_SIZE_PARAMS"),
							nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_ENTRY:                        simpleIoctlInfo("NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_ENTRY", "NV9096_CTRL_GET_ZBC_CLEAR_TABLE_ENTRY_PARAMS"),
							nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: simpleIoctlInfo("NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK", "NV90E6_CTRL_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK_PARAMS"),
							nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   simpleIoctlInfo("NVC36F_CTRL_GET_CLASS_ENGINEID", "NVC36F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     simpleIoctlInfo("NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN", "NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS"),
							nvgpu.NVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX:         simpleIoctlInfo("NVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX", "NVC36F_CTRL_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 simpleIoctlInfo("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES", "NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   simpleIoctlInfo("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE", "NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             simpleIoctlInfo("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS", "NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleIoctlInfo("NVA06C_CTRL_CMD_GPFIFO_SCHEDULE", "NVA06C_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    simpleIoctlInfo("NVA06C_CTRL_CMD_SET_TIMESLICE", "NVA06C_CTRL_SET_TIMESLICE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          simpleIoctlInfo("NVA06C_CTRL_CMD_PREEMPT", "NVA06C_CTRL_PREEMPT_PARAMS"),
							nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleIoctlInfo("NVA06F_CTRL_CMD_GPFIFO_SCHEDULE", "NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVA06F_CTRL_CMD_BIND:                                             simpleIoctlInfo("NVA06F_CTRL_CMD_BIND", "NVA06F_CTRL_BIND_PARAMS"),
							nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          simpleIoctlInfo("NVC56F_CTRL_CMD_GET_KMB", "NVC56F_CTRL_CMD_GET_KMB_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                                  ioctlInfo("NV0000_CTRL_CMD_GPU_GET_ID_INFO", nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ioctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION", nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                ioctlInfoWithStructName("NV0080_CTRL_CMD_GPU_GET_CLASSLIST", nvgpu.RmapiParamNvU32List{}, "NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS:                                      ioctlInfoWithStructName("NV0080_CTRL_CMD_GR_GET_CAPS", nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_GR_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS_V2:                                   simpleIoctlInfo("NV0080_CTRL_CMD_GR_GET_CAPS_V2", "NV0080_CTRL_GR_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_INFO:                                      ioctlInfoWithStructName("NV0080_CTRL_CMD_GR_GET_INFO", nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV0080_CTRL_GR_GET_INFO_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS:                                      ioctlInfoWithStructName("NV0080_CTRL_CMD_FB_GET_CAPS", nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_FB_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS:                                    ioctlInfoWithStructName("NV0080_CTRL_CMD_FIFO_GET_CAPS", nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_FIFO_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS_V2:                                 simpleIoctlInfo("NV0080_CTRL_CMD_FIFO_GET_CAPS_V2", "NV0080_CTRL_FIFO_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ioctlInfo("NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST", nvgpu.NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_MSENC_GET_CAPS:                                   ioctlInfoWithStructName("NV0080_CTRL_CMD_MSENC_GET_CAPS", nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_MSENC_GET_CAPS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:                              ioctlInfo("NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS", nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      ioctlInfo("NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD", nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    ioctlInfo("NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD", nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   ioctlInfo("NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO", nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECTS_TO_FD:                     ioctlInfo("NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECTS_TO_FD", nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECTS_FROM_FD:                   ioctlInfo("NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECTS_FROM_FD", nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS{}),
							nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 ioctlInfoWithStructName("NV0041_CTRL_CMD_GET_SURFACE_INFO", nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV0041_CTRL_GET_SURFACE_INFO_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       ioctlInfo("NV00FD_CTRL_CMD_ATTACH_GPU", nvgpu.NV00FD_CTRL_ATTACH_GPU_PARAMS{}),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                ioctlInfo("NV503C_CTRL_CMD_REGISTER_VA_SPACE", nvgpu.NV503C_CTRL_REGISTER_VA_SPACE_PARAMS{}),
							nvgpu.NV208F_CTRL_CMD_GPU_VERIFY_INFOROM:                               ioctlInfo("NV208F_CTRL_CMD_GPU_VERIFY_INFOROM", nvgpu.NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS{}),
						},
						AllocationInfos: map[nvgpu.ClassID]IoctlInfo{
							nvgpu.NV01_ROOT:                  ioctlInfoWithStructName("NV01_ROOT", nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_ROOT_NON_PRIV:         ioctlInfoWithStructName("NV01_ROOT_NON_PRIV", nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_CONTEXT_DMA:           ioctlInfo("NV01_CONTEXT_DMA", nvgpu.NV_CONTEXT_DMA_ALLOCATION_PARAMS{}),
							nvgpu.NV01_MEMORY_SYSTEM:         ioctlInfo("NV01_MEMORY_SYSTEM", nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_MEMORY_LOCAL_USER:     ioctlInfo("NV01_MEMORY_LOCAL_USER", nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_ROOT_CLIENT:           ioctlInfoWithStructName("NV01_ROOT_CLIENT", nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_EVENT_OS_EVENT:        ioctlInfo("NV01_EVENT_OS_EVENT", nvgpu.NV0005_ALLOC_PARAMETERS{}),
							nvgpu.NV01_MEMORY_VIRTUAL:        ioctlInfo("NV01_MEMORY_VIRTUAL", nvgpu.NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS{}),
							nvgpu.NV01_DEVICE_0:              ioctlInfo("NV01_DEVICE_0", nvgpu.NV0080_ALLOC_PARAMETERS{}),
							nvgpu.NV_SEMAPHORE_SURFACE:       ioctlInfo("NV_SEMAPHORE_SURFACE", nvgpu.NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS{}),
							nvgpu.RM_USER_SHARED_DATA:        ioctlInfo("RM_USER_SHARED_DATA", nvgpu.NV00DE_ALLOC_PARAMETERS{}),
							nvgpu.NV_MEMORY_FABRIC:           ioctlInfo("NV_MEMORY_FABRIC", nvgpu.NV00F8_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_MEMORY_MULTICAST_FABRIC: ioctlInfo("NV_MEMORY_MULTICAST_FABRIC", nvgpu.NV00FD_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_MEMORY_MAPPER:           ioctlInfo("NV_MEMORY_MAPPER", nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS{}),
							nvgpu.NV20_SUBDEVICE_0:           ioctlInfo("NV20_SUBDEVICE_0", nvgpu.NV2080_ALLOC_PARAMETERS{}),
							nvgpu.NV2081_BINAPI:              ioctlInfo("NV2081_BINAPI", nvgpu.NV2081_ALLOC_PARAMETERS{}),
							nvgpu.NV50_MEMORY_VIRTUAL:        ioctlInfo("NV50_MEMORY_VIRTUAL", nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV50_P2P:                   ioctlInfo("NV50_P2P", nvgpu.NV503B_ALLOC_PARAMETERS{}),
							nvgpu.NV50_THIRD_PARTY_P2P:       ioctlInfo("NV50_THIRD_PARTY_P2P", nvgpu.NV503C_ALLOC_PARAMETERS{}),
							nvgpu.GT200_DEBUGGER:             ioctlInfo("GT200_DEBUGGER", nvgpu.NV83DE_ALLOC_PARAMETERS{}),
							nvgpu.GF100_PROFILER:             simpleIoctlInfo("GF100_PROFILER"), // No params
							nvgpu.FERMI_TWOD_A:               ioctlInfo("FERMI_TWOD_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.FERMI_CONTEXT_SHARE_A:      ioctlInfo("FERMI_CONTEXT_SHARE_A", nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS{}),
							nvgpu.GF100_DISP_SW:              ioctlInfo("GF100_DISP_SW", nvgpu.NV9072_ALLOCATION_PARAMETERS{}),
							nvgpu.GF100_ZBC_CLEAR:            simpleIoctlInfo("GF100_ZBC_CLEAR"), // No params
							nvgpu.FERMI_VASPACE_A:            ioctlInfo("FERMI_VASPACE_A", nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS{}),
							nvgpu.KEPLER_CHANNEL_GROUP_A:     ioctlInfo("KEPLER_CHANNEL_GROUP_A", nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS{}),
							nvgpu.KEPLER_INLINE_TO_MEMORY_B:  ioctlInfo("KEPLER_INLINE_TO_MEMORY_B", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.VOLTA_USERMODE_A:           simpleIoctlInfo("VOLTA_USERMODE_A"), // No params
							nvgpu.TURING_CHANNEL_GPFIFO_A:    ioctlInfo("TURING_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.NVB8B0_VIDEO_DECODER:       ioctlInfo("NVB8B0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC4B0_VIDEO_DECODER:       ioctlInfo("NVC4B0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC6B0_VIDEO_DECODER:       ioctlInfo("NVC6B0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC7B0_VIDEO_DECODER:       ioctlInfo("NVC7B0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC9B0_VIDEO_DECODER:       ioctlInfo("NVC9B0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC4B7_VIDEO_ENCODER:       ioctlInfo("NVC4B7_VIDEO_ENCODER", nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC7B7_VIDEO_ENCODER:       ioctlInfo("NVC7B7_VIDEO_ENCODER", nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC9B7_VIDEO_ENCODER:       ioctlInfo("NVC9B7_VIDEO_ENCODER", nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_CHANNEL_GPFIFO_A:    ioctlInfo("AMPERE_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.HOPPER_CHANNEL_GPFIFO_A:    ioctlInfo("HOPPER_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.TURING_A:                   ioctlInfo("TURING_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_A:                   ioctlInfo("AMPERE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.ADA_A:                      ioctlInfo("ADA_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_A:                   ioctlInfo("HOPPER_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_DMA_COPY_A:          ioctlInfo("TURING_DMA_COPY_A", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_A:          ioctlInfo("AMPERE_DMA_COPY_A", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_B:          ioctlInfo("AMPERE_DMA_COPY_B", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_DMA_COPY_A:          ioctlInfo("HOPPER_DMA_COPY_A", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_COMPUTE_A:           ioctlInfo("TURING_COMPUTE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_A:           ioctlInfo("AMPERE_COMPUTE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_B:           ioctlInfo("AMPERE_COMPUTE_B", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.ADA_COMPUTE_A:              ioctlInfo("ADA_COMPUTE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_CONFIDENTIAL_COMPUTE:    ioctlInfo("NV_CONFIDENTIAL_COMPUTE", nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS{}),
							nvgpu.HOPPER_COMPUTE_A:           ioctlInfo("HOPPER_COMPUTE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_USERMODE_A:          ioctlInfo("HOPPER_USERMODE_A", nvgpu.NV_HOPPER_USERMODE_A_PARAMS{}),
							nvgpu.GF100_SUBDEVICE_MASTER:     simpleIoctlInfo("GF100_SUBDEVICE_MASTER"),    // No params
							nvgpu.TURING_USERMODE_A:          simpleIoctlInfo("TURING_USERMODE_A"),         // No params
							nvgpu.HOPPER_SEC2_WORK_LAUNCH_A:  simpleIoctlInfo("HOPPER_SEC2_WORK_LAUNCH_A"), // No params
							nvgpu.NV04_DISPLAY_COMMON:        simpleIoctlInfo("NV04_DISPLAY_COMMON"),       // No params
							nvgpu.NV20_SUBDEVICE_DIAG:        simpleIoctlInfo("NV20_SUBDEVICE_DIAG"),       // No params
						},
					}
				},
			}
		}

		// 535.113.01 is an intermediate unqualified version from the main branch.
		v535_113_01 := v535_104_05

		// The following exist on the "535" branch. They branched off the main
		// branch at 535.113.01.

		v535_129_03 := addDriverABI(535, 129, 03, "e6dca5626a2608c6bb2a046cfcb7c1af338b9e961a7dd90ac09bb8a126ff002e", "8ba8d961457a241bcdf91b76d6fe2f36cb473c8bbdb02fb6650a622ce2e85b33", v535_113_01) // Internal use.
		v535_183_06 := addDriverABI(535, 183, 06, "c7bb0a0569c5347845479ed4e3e4d885c6ee3b8adf068c3401cdf754d5ba3d3b", ChecksumNoDriver, v535_129_03)                                                   // Internal use.
		v535_230_02 := addDriverABI(535, 230, 02, "20cca9118083fcc8083158466e9cb2b616a7922206bcb7296b1fa5cc9af2e0fd", "ea000e6ff481f55e9bfedbea93b739368c635fe4be6156fdad560524ac7f363b", v535_183_06)
		v535_247_01 := addDriverABI(535, 247, 01, "c250e686494cb0c1b5eeea58ba2003707510b2766df05b06ba20b11b3445466b", "bd8ea5c3747a588ff1a29b4f59300d2eba69402a605cb95fce10a30f535993d0", v535_230_02)
		v535_261_03 := addDriverABI(535, 261, 03, "d74b61d11e9c9b9052f4042d6ec4437f13d1def30e964e232d47e5d659d11d68", "9a412d3ac01c99d2ca02100a7139597fce8804c52bf533d11b60437286834a93", v535_247_01)
		_ = addDriverABI(535, 274, 02, "3b4ef54f06991e6dfff7868dde797fad9a451fee68d5267df87ca2be8e7f293b", "3e01dcaea19fe04fadb67a61a3e37c48ab0c4319d99f6f5f7df1d719b780c51c", v535_261_03)

		// 545.23.06 is an intermediate unqualified version from the main branch.
		v545_23_06 := func() *driverABI {
			abi := v535_113_01()
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545], compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV00DE_CTRL_CMD_REQUEST_DATA_POLL] = ctrlHandler(rmControlSimple, compUtil)
			abi.allocationClass[nvgpu.RM_USER_SHARED_DATA] = allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_SYSTEM] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_LOCAL_USER] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV50_MEMORY_VIRTUAL] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)

			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.ControlInfos[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = ioctlInfoWithStructName("NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO", nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545{}, "NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS")
				info.ControlInfos[nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS] = simpleIoctlInfo("NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS", "NV0000_CTRL_GPU_GET_ACTIVE_DEVICE_IDS_PARAMS")
				info.ControlInfos[nvgpu.NV00DE_CTRL_CMD_REQUEST_DATA_POLL] = simpleIoctlInfo("NV00DE_CTRL_CMD_REQUEST_DATA_POLL", "NV00DE_CTRL_REQUEST_DATA_POLL_PARAMS")
				info.AllocationInfos[nvgpu.RM_USER_SHARED_DATA] = ioctlInfoWithStructName("RM_USER_SHARED_DATA", nvgpu.NV00DE_ALLOC_PARAMETERS_V545{}, "NV00DE_ALLOC_PARAMETERS")
				info.AllocationInfos[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = ioctlInfoWithStructName("NV_MEMORY_MULTICAST_FABRIC", nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545{}, "NV00FD_ALLOCATION_PARAMETERS")
				info.AllocationInfos[nvgpu.NV01_MEMORY_SYSTEM] = ioctlInfoWithStructName("NV01_MEMORY_SYSTEM", nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				info.AllocationInfos[nvgpu.NV01_MEMORY_LOCAL_USER] = ioctlInfoWithStructName("NV01_MEMORY_LOCAL_USER", nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				info.AllocationInfos[nvgpu.NV50_MEMORY_VIRTUAL] = ioctlInfoWithStructName("NV50_MEMORY_VIRTUAL", nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				return info
			}

			return abi
		}

		// 550.40.07 is an intermediate unqualified version from the main branch.
		v550_40_07 := func() *driverABI {
			abi := v545_23_06()
			abi.frontendIoctl[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = feHandler(frontendIoctlSimple[nvgpu.IoctlWaitOpenComplete], compUtil)
			abi.frontendIoctl[nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA] = feHandler(frontendIoctlSimple[nvgpu.NVOS47_PARAMETERS_V550], nvconf.CapGraphics|nvconf.CapVideo)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = ctrlHandler(ctrlClientSystemGetP2PCapsV550, compUtil)
			abi.uvmIoctl[nvgpu.UVM_SET_PREFERRED_LOCATION] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MIGRATE] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_MIGRATE_PARAMS_V550], compUtil)
			abi.allocationClass[nvgpu.NVENC_SW_SESSION] = allocHandler(rmAllocSimple[nvgpu.NVA0BC_ALLOC_PARAMETERS], nvconf.CapVideo)
			abi.allocationClass[nvgpu.NV_MEMORY_MAPPER] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550], nvconf.CapVideo)

			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.FrontendInfos[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = ioctlInfoWithStructName("NV_ESC_WAIT_OPEN_COMPLETE", nvgpu.IoctlWaitOpenComplete{}, "nv_ioctl_wait_open_complete_t")
				info.FrontendInfos[nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA] = ioctlInfoWithStructName("NV_ESC_RM_UNMAP_MEMORY_DMA", nvgpu.NVOS47_PARAMETERS_V550{}, "NVOS47_PARAMETERS")
				info.ControlInfos[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = simpleIoctlInfo("NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID", "NV0000_CTRL_GPU_ASYNC_ATTACH_ID_PARAMS")
				info.ControlInfos[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = simpleIoctlInfo("NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID", "NV0000_CTRL_GPU_WAIT_ATTACH_ID_PARAMS")
				info.ControlInfos[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = simpleIoctlInfo("NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL", "NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS")
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = simpleIoctlInfo("NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE", "NV2080_CTRL_PERF_GET_CURRENT_PSTATE_PARAMS")
				info.ControlInfos[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = ioctlInfoWithStructName("NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS", nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550{}, "NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS")
				info.UvmInfos[nvgpu.UVM_SET_PREFERRED_LOCATION] = ioctlInfoWithStructName("UVM_SET_PREFERRED_LOCATION", nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550{}, "UVM_SET_PREFERRED_LOCATION_PARAMS")
				info.UvmInfos[nvgpu.UVM_MIGRATE] = ioctlInfoWithStructName("UVM_MIGRATE", nvgpu.UVM_MIGRATE_PARAMS_V550{}, "UVM_MIGRATE_PARAMS")
				info.AllocationInfos[nvgpu.NVENC_SW_SESSION] = ioctlInfo("NVENC_SW_SESSION", nvgpu.NVA0BC_ALLOC_PARAMETERS{})
				info.AllocationInfos[nvgpu.NV_MEMORY_MAPPER] = ioctlInfoWithStructName("NV_MEMORY_MAPPER", nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550{}, "NV_MEMORY_MAPPER_ALLOCATION_PARAMS")
				return info
			}

			return abi
		}

		v550_54_14 := func() *driverABI {
			abi := v550_40_07()
			abi.uvmIoctl[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550], compUtil)

			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.UvmInfos[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = ioctlInfoWithStructName("UVM_ALLOC_SEMAPHORE_POOL", nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550{}, "UVM_ALLOC_SEMAPHORE_POOL_PARAMS")
				info.UvmInfos[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = ioctlInfoWithStructName("UVM_MAP_EXTERNAL_ALLOCATION", nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550{}, "UVM_MAP_EXTERNAL_ALLOCATION_PARAMS")
				return info
			}

			return abi
		}

		v550_90_07 := func() *driverABI {
			abi := v550_54_14()
			abi.controlCmd[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = ctrlHandler(rmControlSimple, compUtil)

			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.ControlInfos[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = simpleIoctlInfo("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE", "NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE_PARAMS")
				return info
			}

			return abi
		}

		// This version does not belong on any branch, but it is a child of 550.90.07.
		_ = addDriverABI(550, 90, 12, "391883846713b9e700af2ae87f8ac671f5527508ce3f9f60058deb363e05162a", ChecksumNoDriver, v550_90_07) // Internal use.

		// 555.42.02 is an intermediate unqualified version.
		v555_42_02 := func() *driverABI {
			abi := v550_90_07()
			abi.allocationClass[nvgpu.NV_MEMORY_MAPPER] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555], nvconf.CapVideo)
			delete(abi.controlCmd, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.AllocationInfos[nvgpu.NV_MEMORY_MAPPER] = ioctlInfoWithStructName("NV_MEMORY_MAPPER", nvgpu.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555{}, "NV_MEMORY_MAPPER_ALLOCATION_PARAMS")
				delete(info.ControlInfos, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
				return info
			}
			return abi
		}

		// 560.28.03 is an intermediate unqualified version from the main branch.
		v560_28_03 := func() *driverABI {
			abi := v555_42_02()
			abi.allocationClass[nvgpu.NVCDB0_VIDEO_DECODER] = allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo)
			abi.allocationClass[nvgpu.BLACKWELL_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannel, compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_DMA_COPY_A] = allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_A] = allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics)
			abi.allocationClass[nvgpu.BLACKWELL_COMPUTE_A] = allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_INLINE_TO_MEMORY_A] = allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics)
			abi.controlCmd[nvgpu.NV_SEMAPHORE_SURFACE_CTRL_CMD_UNBIND_CHANNEL] = ctrlHandler(rmControlSimple, nvconf.CapGraphics)
			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.AllocationInfos[nvgpu.NVCDB0_VIDEO_DECODER] = ioctlInfo("NVCDB0_VIDEO_DECODER", nvgpu.NV_BSP_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_CHANNEL_GPFIFO_A] = ioctlInfo("BLACKWELL_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS{})
				info.AllocationInfos[nvgpu.BLACKWELL_DMA_COPY_A] = ioctlInfo("BLACKWELL_DMA_COPY_A", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_A] = ioctlInfo("BLACKWELL_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_COMPUTE_A] = ioctlInfo("BLACKWELL_COMPUTE_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_INLINE_TO_MEMORY_A] = ioctlInfo("BLACKWELL_INLINE_TO_MEMORY_A", nvgpu.NV_GR_ALLOCATION_PARAMETERS{})
				info.ControlInfos[nvgpu.NV_SEMAPHORE_SURFACE_CTRL_CMD_UNBIND_CHANNEL] = simpleIoctlInfo("NV_SEMAPHORE_SURFACE_CTRL_CMD_UNBIND_CHANNEL", "NV_SEMAPHORE_SURFACE_CTRL_UNBIND_CHANNEL_PARAMS")
				return info
			}
			return abi
		}

		v570_86_15 := addDriverABI(570, 86, 15, "87709c19c7401243136bc0ec9e7f147c6803070a11449ae8f0819dee7963f76b", ChecksumNoDriver, func() *driverABI {
			abi := v560_28_03()
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS] = ctrlHandler(rmControlSimple, compUtil)
			abi.allocationClass[nvgpu.TURING_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.AMPERE_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.HOPPER_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_DMA_COPY_B] = allocHandler(rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS], compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_CHANNEL_GPFIFO_B] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_B] = allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], nvconf.CapGraphics)
			abi.allocationClass[nvgpu.BLACKWELL_COMPUTE_B] = allocHandler(rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS], compUtil)
			abi.allocationClass[nvgpu.BLACKWELL_USERMODE_A] = allocHandler(rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS], compUtil)
			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT] = simpleIoctlInfo("NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT", "NV2080_CTRL_FB_DRAM_ENCRYPTION_INFOROM_SUPPORT_PARAMS")
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS] = simpleIoctlInfo("NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS", "NV2080_CTRL_FB_QUERY_DRAM_ENCRYPTION_STATUS_PARAMS")
				info.AllocationInfos[nvgpu.TURING_CHANNEL_GPFIFO_A] = ioctlInfoWithStructName("TURING_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				info.AllocationInfos[nvgpu.AMPERE_CHANNEL_GPFIFO_A] = ioctlInfoWithStructName("AMPERE_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				info.AllocationInfos[nvgpu.HOPPER_CHANNEL_GPFIFO_A] = ioctlInfoWithStructName("HOPPER_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				info.AllocationInfos[nvgpu.BLACKWELL_DMA_COPY_B] = ioctlInfo("BLACKWELL_DMA_COPY_B", nvgpu.NVB0B5_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_CHANNEL_GPFIFO_A] = ioctlInfoWithStructName("BLACKWELL_CHANNEL_GPFIFO_A", nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				info.AllocationInfos[nvgpu.BLACKWELL_CHANNEL_GPFIFO_B] = ioctlInfoWithStructName("BLACKWELL_CHANNEL_GPFIFO_B", nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				info.AllocationInfos[nvgpu.BLACKWELL_B] = ioctlInfo("BLACKWELL_B", nvgpu.NV_GR_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_COMPUTE_B] = ioctlInfo("BLACKWELL_COMPUTE_B", nvgpu.NV_GR_ALLOCATION_PARAMETERS{})
				info.AllocationInfos[nvgpu.BLACKWELL_USERMODE_A] = ioctlInfo("BLACKWELL_USERMODE_A", nvgpu.NV_HOPPER_USERMODE_A_PARAMS{})
				return info
			}
			return abi
		})

		v570_124_06 := addDriverABI(570, 124, 06, "1818c90657d17e510de9fa032385ff7e99063e848e901cb4636ee71c8b339313", ChecksumNoDriver, v570_86_15)
		v570_133_20 := addDriverABI(570, 133, 20, "1253d17b1528e8a24bf1f34a8ac6591c924b98ad7a32344bde253aa622ac1605", ChecksumNoDriver, v570_124_06)

		// The following exist on the "570" branch. They branched off the main
		// branch at 570.133.20.
		v570_172_08 := addDriverABI(570, 172, 8, "0256867e082caf93d7b25fa7c8e69b316062a9c6c72c6e228fad7b238c6fa17d", "15547216f2b514ace7724a5ab4c3327669904a41cafb8d4d9048d3c9b60963d8", v570_133_20)
		_ = addDriverABI(570, 195, 03, "d47de81d9a513496a60adc9cfa72fe9e162c65f2722fb960c4f531bd7ac5dc1e", "a38ae007abe8f82bfdd25272c28bc8c950114464b7475e73610523f9fd67cd64", v570_172_08)

		// 575.51.02 is an intermediate unqualified version from the main branch.
		v575_51_02 := func() *driverABI {
			abi := v570_133_20()
			delete(abi.controlCmd, nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT)
			delete(abi.controlCmd, nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS)
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT_V575] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS_V575] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_THERMAL_SYSTEM_EXECUTE_V2] = ctrlHandler(rmControlSimple, compUtil)
			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				delete(info.ControlInfos, nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT)
				delete(info.ControlInfos, nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS)
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT_V575] = simpleIoctlInfo("NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_INFOROM_SUPPORT", "NV2080_CTRL_FB_DRAM_ENCRYPTION_INFOROM_SUPPORT_PARAMS")
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS_V575] = simpleIoctlInfo("NV2080_CTRL_CMD_FB_QUERY_DRAM_ENCRYPTION_STATUS", "NV2080_CTRL_FB_QUERY_DRAM_ENCRYPTION_STATUS_PARAMS")
				info.ControlInfos[nvgpu.NV2080_CTRL_CMD_THERMAL_SYSTEM_EXECUTE_V2] = simpleIoctlInfo("NV2080_CTRL_CMD_THERMAL_SYSTEM_EXECUTE_V2", "NV2080_CTRL_THERMAL_SYSTEM_EXECUTE_V2_PARAMS")
				return info
			}
			return abi
		}

		v575_57_08 := addDriverABI(575, 57, 8, "2aa701dac180a7b20a6e578cccd901ded8d44e57d60580f08f9d28dd1fffc6f2", "549e73e4f7402f66275ee665b6e3a2ae5d7bf57296b743b824d713f205203bdf", v575_51_02)

		v580_65_06 := addDriverABI(580, 65, 06, "04b10867af585e765cfbfdcf39ed5f4bd112375bebab0172eaa187c6aa5024ff", "e02acdc0d20d4a541aa5026bfddb1b9b4fc6bc64ae3b04ff9cb9c892700cf9c4", func() *driverABI {
			abi := v575_57_08()
			abi.frontendIoctl[nvgpu.NV_ESC_RM_MAP_MEMORY_DMA] = feHandler(frontendIoctlSimple[nvgpu.NVOS46_PARAMETERS_V580], nvconf.CapGraphics|nvconf.CapVideo)
			abi.allocationClass[nvgpu.FERMI_VASPACE_A] = allocHandler(rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS_V580], compUtil)

			prevGetInfo := abi.getInfo
			abi.getInfo = func() *DriverABIInfo {
				info := prevGetInfo()
				info.FrontendInfos[nvgpu.NV_ESC_RM_MAP_MEMORY_DMA] = ioctlInfoWithStructName("NV_ESC_RM_MAP_MEMORY_DMA", nvgpu.NVOS46_PARAMETERS_V580{}, "NVOS46_PARAMETERS")
				info.AllocationInfos[nvgpu.FERMI_VASPACE_A] = ioctlInfoWithStructName("FERMI_VASPACE_A", nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS_V580{}, "NV_VASPACE_ALLOCATION_PARAMETERS")
				return info
			}
			return abi
		})

		v580_82_07 := addDriverABI(580, 82, 07, "061e48e11fe552232095811d0b1cea9b718ba2540d605074ff227fce0628798c", "a2bdfffda5784d070f0e070bc4507be47fe407c9fedd1cf04ced42d996c90092", v580_65_06)
		_ = addDriverABI(580, 95, 05, "849ef0ef8e842b9806b2cde9f11c1303d54f1a9a769467e4e5d961b2fe1182a7", "ccb4426e98a29367c60daf9df34c2a577655d54d5be25463ccd409b0b2e52029", v580_82_07)
	})
}

// simpleIoctlInfo constructs IoctlInfo for simple ioctls (for whom nvproxy
// doesn't define a struct).
func simpleIoctlInfo(name string, structNames ...string) IoctlInfo {
	structs := make([]DriverStruct, 0, len(structNames))
	for _, structName := range structNames {
		structs = append(structs, DriverStruct{
			Name: structName,
			Type: nil,
		})
	}
	return IoctlInfo{
		Name:    name,
		Structs: structs,
	}
}

// ioctlInfo creates IoctlInfo using the name of the ioctl associated with
// this ioctl and instances of all nvproxy structs used in its handling.
func ioctlInfo(name string, params ...any) IoctlInfo {
	structs := make([]DriverStruct, 0, len(params))
	for _, param := range params {
		paramType := reflect.TypeOf(param)
		structs = append(structs, newDriverStruct(paramType, paramType.Name()))
	}
	return IoctlInfo{
		Name:    name,
		Structs: structs,
	}
}

// ioctlInfoWithStructName is the same as ioctlInfo, but uses the given struct
// name instead of the type name of param.
func ioctlInfoWithStructName(name string, param any, structName string) IoctlInfo {
	paramType := reflect.TypeOf(param)
	return IoctlInfo{
		Name:    name,
		Structs: []DriverStruct{newDriverStruct(paramType, structName)},
	}
}

func newDriverStruct(paramType reflect.Type, name string) DriverStruct {
	// Right now, we only expect parameter structs.
	if paramType.Kind() != reflect.Struct {
		panic(fmt.Sprintf("expected struct, got %v", paramType.Kind()))
	}
	return DriverStruct{
		Name: name,
		Type: paramType,
	}
}

// ForEachSupportDriver calls f on all supported drivers.
// Precondition: Init() must have been called.
func ForEachSupportDriver(f func(version nvconf.DriverVersion, checksums Checksums)) {
	for version, abi := range abis {
		f(version, abi.checksums)
	}
}

// LatestDriver returns the latest supported driver.
// Precondition: Init() must have been called.
func LatestDriver() nvconf.DriverVersion {
	var ret nvconf.DriverVersion
	for version := range abis {
		if version.IsGreaterThan(ret) {
			ret = version
		}
	}
	return ret
}

// SupportedDrivers returns a list of all supported drivers.
// Precondition: Init() must have been called.
func SupportedDrivers() []nvconf.DriverVersion {
	var ret []nvconf.DriverVersion
	for version := range abis {
		ret = append(ret, version)
	}
	sort.Slice(ret, func(i, j int) bool {
		return !ret[i].IsGreaterThan(ret[j])
	})
	return ret
}

// ExpectedDriverChecksum returns the expected checksum for a given version.
// Precondition: Init() must have been called.
func ExpectedDriverChecksum(version nvconf.DriverVersion) (Checksums, bool) {
	abi, ok := abis[version]
	if !ok {
		return Checksums{
			checksumX86_64: ChecksumNoDriver,
			checksumARM64:  ChecksumNoDriver,
		}, false
	}
	return abi.checksums, true
}

// SupportedIoctlsNumbers returns the ioctl numbers that are supported by
// nvproxy at a given version.
func SupportedIoctlsNumbers(version nvconf.DriverVersion) (frontendIoctls map[uint32]struct{}, uvmIoctls map[uint32]struct{}, controlCmds map[uint32]struct{}, allocClasses map[uint32]struct{}, ok bool) {
	abiCons, ok := abis[version]
	if !ok {
		return nil, nil, nil, nil, false
	}
	abi := abiCons.cons()
	frontendIoctls = make(map[uint32]struct{})
	for ioc := range abi.frontendIoctl {
		frontendIoctls[ioc] = struct{}{}
	}
	uvmIoctls = make(map[uint32]struct{})
	for ioc := range abi.uvmIoctl {
		uvmIoctls[ioc] = struct{}{}
	}
	controlCmds = make(map[uint32]struct{})
	for cmd := range abi.controlCmd {
		controlCmds[cmd] = struct{}{}
	}
	allocClasses = make(map[uint32]struct{})
	for class := range abi.allocationClass {
		allocClasses[uint32(class)] = struct{}{}
	}
	return
}

// SupportedIoctls returns the DriverABIInfo struct for the given version,
// which describes the ioctls supported in nvproxy for the given version.
func SupportedIoctls(version nvconf.DriverVersion) (*DriverABIInfo, bool) {
	abiCons, ok := abis[version]
	if !ok {
		return nil, false
	}
	abi := abiCons.cons()
	return abi.getInfo(), true
}
