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
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/sync"
)

// DriverVersion represents a NVIDIA driver version patch release.
//
// +stateify savable
type DriverVersion struct {
	major int
	minor int
	patch int
}

// NewDriverVersion returns a new driver version.
func NewDriverVersion(major, minor, patch int) DriverVersion {
	return DriverVersion{major, minor, patch}
}

// DriverVersionFrom returns a DriverVersion from a string.
func DriverVersionFrom(version string) (DriverVersion, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return DriverVersion{}, fmt.Errorf("invalid format of version string %q", version)
	}
	var (
		res DriverVersion
		err error
	)
	res.major, err = strconv.Atoi(parts[0])
	if err != nil {
		return DriverVersion{}, fmt.Errorf("invalid format for major version %q: %v", version, err)
	}
	res.minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return DriverVersion{}, fmt.Errorf("invalid format for minor version %q: %v", version, err)
	}
	res.patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return DriverVersion{}, fmt.Errorf("invalid format for patch version %q: %v", version, err)
	}
	return res, nil
}

func (v DriverVersion) String() string {
	return fmt.Sprintf("%02d.%02d.%02d", v.major, v.minor, v.patch)
}

// Equals returns true if the two driver versions are equal.
func (v DriverVersion) Equals(other DriverVersion) bool {
	return v.major == other.major && v.minor == other.minor && v.patch == other.patch
}

// isGreaterThan returns true if v is greater than other.
// isGreaterThan returns true if v is more recent than other, assuming v and other are on the same
// dev branch.
func (v DriverVersion) isGreaterThan(other DriverVersion) bool {
	switch {
	case v.major > other.major:
		return true
	case other.major > v.major:
		return false
	case v.minor > other.minor:
		return true
	case other.minor > v.minor:
		return false
	case v.patch > other.patch:
		return true
	case other.patch > v.patch:
		return false
	default:
		return true
	}
}

type frontendIoctlHandler func(fi *frontendIoctlState) (uintptr, error)
type controlCmdHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error)
type allocationClassHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error)
type uvmIoctlHandler func(ui *uvmIoctlState) (uintptr, error)

// A driverABIFunc constructs and returns a driverABI.
// This indirection exists to avoid memory usage from unused driver ABIs.
type driverABIFunc func() *driverABI

// abiConAndChecksum couples the driver's abiConstructor to the SHA256 checksum of its linux .run
// driver installer file from NVIDIA.
type abiConAndChecksum struct {
	cons     driverABIFunc
	checksum string
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
}

// abis is a global map containing all supported Nvidia driver ABIs. This is
// initialized on Init() and is immutable henceforth.
var abis map[DriverVersion]abiConAndChecksum
var abisOnce sync.Once

// Note: runfileChecksum is the checksum of the .run file of the driver installer for linux from
// nvidia.
// To add a new version, add in support as normal and add the "addDriverABI" call for your version.
// Run `make sudo TARGETS=//tools/gpu:main ARGS="checksum --version={}"` to get checksum.
func addDriverABI(major, minor, patch int, runfileChecksum string, cons driverABIFunc) driverABIFunc {
	if abis == nil {
		abis = make(map[DriverVersion]abiConAndChecksum)
	}
	version := NewDriverVersion(major, minor, patch)
	abis[version] = abiConAndChecksum{cons: cons, checksum: runfileChecksum}
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
					nvgpu.NV_ESC_CARD_INFO:                     frontendIoctlSimple, // nv_ioctl_card_info_t array
					nvgpu.NV_ESC_CHECK_VERSION_STR:             frontendIoctlSimple, // nv_rm_api_version_t
					nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             frontendIoctlSimple, // NvU32 array containing GPU IDs
					nvgpu.NV_ESC_SYS_PARAMS:                    frontendIoctlSimple, // nv_ioctl_sys_params_t
					nvgpu.NV_ESC_RM_DUP_OBJECT:                 frontendIoctlSimple, // NVOS55_PARAMETERS
					nvgpu.NV_ESC_RM_SHARE:                      frontendIoctlSimple, // NVOS57_PARAMETERS
					nvgpu.NV_ESC_RM_UNMAP_MEMORY:               frontendIoctlSimple, // NVOS34_PARAMETERS
					nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: frontendIoctlSimple, // NVOS56_PARAMETERS
					nvgpu.NV_ESC_REGISTER_FD:                   frontendRegisterFD,
					nvgpu.NV_ESC_ALLOC_OS_EVENT:                frontendIoctHasFD[nvgpu.IoctlAllocOSEvent],
					nvgpu.NV_ESC_FREE_OS_EVENT:                 frontendIoctHasFD[nvgpu.IoctlFreeOSEvent],
					nvgpu.NV_ESC_NUMA_INFO:                     rmNumaInfo,
					nvgpu.NV_ESC_RM_ALLOC_MEMORY:               rmAllocMemory,
					nvgpu.NV_ESC_RM_FREE:                       rmFree,
					nvgpu.NV_ESC_RM_CONTROL:                    rmControl,
					nvgpu.NV_ESC_RM_ALLOC:                      rmAlloc,
					nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           rmVidHeapControl,
					nvgpu.NV_ESC_RM_MAP_MEMORY:                 rmMapMemory,
				},
				uvmIoctl: map[uint32]uvmIoctlHandler{
					nvgpu.UVM_INITIALIZE:                     uvmInitialize,
					nvgpu.UVM_DEINITIALIZE:                   uvmIoctlNoParams,
					nvgpu.UVM_CREATE_RANGE_GROUP:             uvmIoctlSimple[nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS],
					nvgpu.UVM_DESTROY_RANGE_GROUP:            uvmIoctlSimple[nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS],
					nvgpu.UVM_REGISTER_GPU_VASPACE:           uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS],
					nvgpu.UVM_UNREGISTER_GPU_VASPACE:         uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS],
					nvgpu.UVM_REGISTER_CHANNEL:               uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_CHANNEL_PARAMS],
					nvgpu.UVM_UNREGISTER_CHANNEL:             uvmIoctlSimple[nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS],
					nvgpu.UVM_ENABLE_PEER_ACCESS:             uvmIoctlSimple[nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS],
					nvgpu.UVM_DISABLE_PEER_ACCESS:            uvmIoctlSimple[nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS],
					nvgpu.UVM_SET_RANGE_GROUP:                uvmIoctlSimple[nvgpu.UVM_SET_RANGE_GROUP_PARAMS],
					nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS],
					nvgpu.UVM_FREE:                           uvmIoctlSimple[nvgpu.UVM_FREE_PARAMS],
					nvgpu.UVM_REGISTER_GPU:                   uvmIoctlHasFrontendFD[nvgpu.UVM_REGISTER_GPU_PARAMS],
					nvgpu.UVM_UNREGISTER_GPU:                 uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_PARAMS],
					nvgpu.UVM_PAGEABLE_MEM_ACCESS:            uvmIoctlSimple[nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS],
					nvgpu.UVM_SET_PREFERRED_LOCATION:         uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS],
					nvgpu.UVM_DISABLE_READ_DUPLICATION:       uvmIoctlSimple[nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS],
					nvgpu.UVM_MIGRATE_RANGE_GROUP:            uvmIoctlSimple[nvgpu.UVM_MIGRATE_RANGE_GROUP_PARAMS],
					nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: uvmIoctlSimple[nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS],
					nvgpu.UVM_UNMAP_EXTERNAL:                 uvmIoctlSimple[nvgpu.UVM_UNMAP_EXTERNAL_PARAMS],
					nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS],
					nvgpu.UVM_VALIDATE_VA_RANGE:              uvmIoctlSimple[nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS],
					nvgpu.UVM_CREATE_EXTERNAL_RANGE:          uvmIoctlSimple[nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS],
					nvgpu.UVM_MM_INITIALIZE:                  uvmMMInitialize,
				},
				controlCmd: map[uint32]controlCmdHandler{
					nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                   rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:               rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:            rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:               rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       rmControlSimple,
					0x80028b: rmControlSimple, // unknown, paramsSize == 1
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 rmControlSimple,
					nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         rmControlSimple,
					nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       rmControlSimple,
					nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          rmControlSimple,
					nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  rmControlSimple,
					nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  rmControlSimple,
					nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   rmControlSimple,
					nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    rmControlSimple,
					nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: rmControlSimple,
					nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   rmControlSimple,
					nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     rmControlSimple,
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 rmControlSimple,
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   rmControlSimple,
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          rmControlSimple,
					nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  rmControlSimple,
					nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ctrlClientSystemGetBuildVersion,
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS],
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS],
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS],
					nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 ctrlIoctlHasInfoList[nvgpu.NV0041_CTRL_GET_SURFACE_INFO_PARAMS],
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ctrlDevFIFOGetChannelList,
					nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       ctrlMemoryMulticastFabricAttachGPU,
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                ctrlDevGpuGetClasslist,
					nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlSubdevFIFODisableChannels,
					nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_BIOS_GET_INFO_PARAMS],
					nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS],
					nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                ctrlRegisterVASpace,
				},
				allocationClass: map[nvgpu.ClassID]allocationClassHandler{
					nvgpu.NV01_ROOT:                  rmAllocRootClient,
					nvgpu.NV01_ROOT_NON_PRIV:         rmAllocRootClient,
					nvgpu.NV01_MEMORY_SYSTEM:         rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS],
					nvgpu.NV01_MEMORY_LOCAL_USER:     rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS],
					nvgpu.NV01_ROOT_CLIENT:           rmAllocRootClient,
					nvgpu.NV01_EVENT_OS_EVENT:        rmAllocEventOSEvent,
					nvgpu.NV2081_BINAPI:              rmAllocSimple[nvgpu.NV2081_ALLOC_PARAMETERS],
					nvgpu.NV01_DEVICE_0:              rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS],
					nvgpu.RM_USER_SHARED_DATA:        rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS],
					nvgpu.NV_MEMORY_FABRIC:           rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS],
					nvgpu.NV_MEMORY_MULTICAST_FABRIC: rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS],
					nvgpu.NV20_SUBDEVICE_0:           rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS],
					nvgpu.NV50_MEMORY_VIRTUAL:        rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS],
					nvgpu.NV50_P2P:                   rmAllocSimple[nvgpu.NV503B_ALLOC_PARAMETERS],
					nvgpu.NV50_THIRD_PARTY_P2P:       rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS],
					nvgpu.GT200_DEBUGGER:             rmAllocSMDebuggerSession,
					nvgpu.FERMI_CONTEXT_SHARE_A:      rmAllocContextShare,
					nvgpu.FERMI_VASPACE_A:            rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS],
					nvgpu.KEPLER_CHANNEL_GROUP_A:     rmAllocChannelGroup,
					nvgpu.TURING_CHANNEL_GPFIFO_A:    rmAllocChannel,
					nvgpu.AMPERE_CHANNEL_GPFIFO_A:    rmAllocChannel,
					nvgpu.HOPPER_CHANNEL_GPFIFO_A:    rmAllocChannel,
					nvgpu.TURING_DMA_COPY_A:          rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_DMA_COPY_A:          rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_DMA_COPY_B:          rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.HOPPER_DMA_COPY_A:          rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.TURING_COMPUTE_A:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_COMPUTE_A:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_COMPUTE_B:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.ADA_COMPUTE_A:              rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.NV_CONFIDENTIAL_COMPUTE:    rmAllocSimple[nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS],
					nvgpu.HOPPER_COMPUTE_A:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.HOPPER_USERMODE_A:          rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS],
					nvgpu.GF100_SUBDEVICE_MASTER:     rmAllocNoParams,
					nvgpu.TURING_USERMODE_A:          rmAllocNoParams,
					nvgpu.HOPPER_SEC2_WORK_LAUNCH_A:  rmAllocNoParams,
				},
			}
		}

		// 535.104.12 exists on the "535.104.12" branch. It branched off the main
		// branch at 535.104.05.
		_ = addDriverABI(535, 104, 12, "ffc2d89e233d2427edb1ff5f436028a94b3ef86e78f97e088e11d905c82e8001", v535_104_05)

		// 535.113.01 is an intermediate unqualified version from the main branch.
		v535_113_01 := v535_104_05

		// The following exist on the "535" branch. They branched off the main
		// branch at 535.113.01.
		v535_129_03 := addDriverABI(535, 129, 03, "e6dca5626a2608c6bb2a046cfcb7c1af338b9e961a7dd90ac09bb8a126ff002e", v535_113_01)
		v535_154_05 := addDriverABI(535, 154, 05, "7e95065caa6b82de926110f14827a61972eb12c200e863a29e9fb47866eaa898", v535_129_03)
		_ = addDriverABI(535, 161, 07, "edc527f1dcfa0212a3bf815ebf302d45ef9663834a41e11a851dd38da159a8cd", v535_154_05)

		// 545.23.06 is an intermediate unqualified version from the main branch.
		v545_23_06 := func() *driverABI {
			abi := v535_113_01()
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545]
			abi.allocationClass[nvgpu.RM_USER_SHARED_DATA] = rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS_V545]
			abi.allocationClass[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545]
			abi.allocationClass[nvgpu.NV01_MEMORY_SYSTEM] = rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545]
			abi.allocationClass[nvgpu.NV01_MEMORY_LOCAL_USER] = rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545]
			abi.allocationClass[nvgpu.NV50_MEMORY_VIRTUAL] = rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545]
			return abi
		}

		// 550.40.07 is an intermediate unqualified version from the main branch.
		v550_40_07 := func() *driverABI {
			abi := v545_23_06()
			abi.frontendIoctl[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = frontendIoctlSimple // nv_ioctl_wait_open_complete_t
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = rmControlSimple
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = rmControlSimple
			abi.controlCmd[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = rmControlSimple // NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = rmControlSimple
			// NV2081_BINAPI forwards all control commands to the GSP in
			// src/nvidia/src/kernel/rmapi/binary_api.c:binapiControl_IMPL().
			abi.controlCmd[(nvgpu.NV2081_BINAPI<<16)|0x0108] = rmControlSimple
			abi.uvmIoctl[nvgpu.UVM_SET_PREFERRED_LOCATION] = uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550]
			return abi
		}

		v550_54_14 := addDriverABI(550, 54, 14, "8c497ff1cfc7c310fb875149bc30faa4fd26d2237b2cba6cd2e8b0780157cfe3", func() *driverABI {
			abi := v550_40_07()
			abi.uvmIoctl[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550]
			abi.uvmIoctl[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550]
			return abi
		})
		v550_54_15 := addDriverABI(550, 54, 15, "2e859ae5f912a9a47aaa9b2d40a94a14f6f486b5d3b67c0ddf8b72c1c9650385", v550_54_14)
		_ = addDriverABI(550, 90, 07, "51acf579d5a9884f573a1d3f522e7fafa5e7841e22a9cec0b4bbeae31b0b9733", v550_54_15)
	})
}

// ForEachSupportDriver calls f on all supported drivers.
// Precondition: Init() must have been called.
func ForEachSupportDriver(f func(version DriverVersion, checksum string)) {
	for version, abi := range abis {
		f(version, abi.checksum)
	}
}

// LatestDriver returns the latest supported driver.
// Precondition: Init() must have been called.
func LatestDriver() DriverVersion {
	var ret DriverVersion
	for version := range abis {
		if version.isGreaterThan(ret) {
			ret = version
		}
	}
	return ret
}

// ExpectedDriverChecksum returns the expected checksum for a given version.
// Precondition: Init() must have been called.
func ExpectedDriverChecksum(version DriverVersion) (string, bool) {
	abi, ok := abis[version]
	if !ok {
		return "", false
	}
	return abi.checksum, true
}

// SupportedIoctls returns the ioctl numbers that are supported by nvproxy at
// a given version.
func SupportedIoctls(version DriverVersion) (frontendIoctls map[uint32]struct{}, uvmIoctls map[uint32]struct{}, controlCmds map[uint32]struct{}, allocClasses map[uint32]struct{}, ok bool) {
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
