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

// IsGreaterThan returns the "greater" driver version.
// IsGreaterThan returns true if v is more recent than other, assuming v and other are on the same
// dev branch.
func (v DriverVersion) IsGreaterThan(other DriverVersion) DriverVersion {
	switch {
	case v.major > other.major:
		return v
	case other.major > v.major:
		return other
	case v.minor > other.minor:
		return v
	case other.minor > v.minor:
		return other
	case v.patch > other.patch:
		return v
	case other.patch > v.patch:
		return other
	default:
		return v
	}
}

type frontendIoctlHandler func(fi *frontendIoctlState) (uintptr, error)
type controlCmdHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error)
type allocationClassHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64ParametersV535, isNVOS64 bool) (uintptr, error)
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
	allocationClass map[uint32]allocationClassHandler

	useRmAllocParamsV535 bool
}

// abis is a global map containing all supported Nvidia driver ABIs. This is
// initialized on Init() and is immutable henceforth.
var abis map[DriverVersion]abiConAndChecksum
var abisOnce sync.Once

// Note: runfileChecksum is the checksum of the .run file of the driver installer for linux from
// nvidia.
// To add a new version, add in support as normal and add the "addDriverABI" call for your version.
// Run `make sudo TARGETS=//tools/gpu:main ARGS="checksum"` and fill in mismatches.
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
		v525_60_13Checksum := "dce1c184f9f038be72237ccd29c66bb151077f6037f1c158c83d582bd2dba8ca"
		v525_60_13 := addDriverABI(525, 60, 13, v525_60_13Checksum, func() *driverABI {
			// 525.60.13 is the earliest driver version supported by nvproxy. Since
			// there is no parent to inherit from, the driverABI needs to be constructed
			// with the entirety of the nvproxy functionality at this version.
			return &driverABI{
				frontendIoctl: map[uint32]frontendIoctlHandler{
					nvgpu.NV_ESC_CARD_INFO:                     frontendIoctlSimple, // nv_ioctl_card_info_t
					nvgpu.NV_ESC_CHECK_VERSION_STR:             frontendIoctlSimple, // nv_rm_api_version_t
					nvgpu.NV_ESC_SYS_PARAMS:                    frontendIoctlSimple, // nv_ioctl_sys_params_t
					nvgpu.NV_ESC_RM_DUP_OBJECT:                 frontendIoctlSimple, // NVOS55_PARAMETERS
					nvgpu.NV_ESC_RM_SHARE:                      frontendIoctlSimple, // NVOS57_PARAMETERS
					nvgpu.NV_ESC_RM_UNMAP_MEMORY:               frontendIoctlSimple, // NVOS34_PARAMETERS
					nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: frontendIoctlSimple, // NVOS56_PARAMETERS
					nvgpu.NV_ESC_REGISTER_FD:                   frontendRegisterFD,
					nvgpu.NV_ESC_ALLOC_OS_EVENT:                rmAllocOSEvent,
					nvgpu.NV_ESC_FREE_OS_EVENT:                 rmFreeOSEvent,
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
					nvgpu.UVM_REGISTER_GPU_VASPACE:           uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS],
					nvgpu.UVM_UNREGISTER_GPU_VASPACE:         uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS],
					nvgpu.UVM_REGISTER_CHANNEL:               uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_CHANNEL_PARAMS],
					nvgpu.UVM_UNREGISTER_CHANNEL:             uvmIoctlSimple[nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS],
					nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        uvmIoctlHasRMCtrlFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS],
					nvgpu.UVM_FREE:                           uvmIoctlSimple[nvgpu.UVM_FREE_PARAMS],
					nvgpu.UVM_REGISTER_GPU:                   uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_GPU_PARAMS],
					nvgpu.UVM_UNREGISTER_GPU:                 uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_PARAMS],
					nvgpu.UVM_PAGEABLE_MEM_ACCESS:            uvmIoctlSimple[nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS],
					nvgpu.UVM_DISABLE_READ_DUPLICATION:       uvmIoctlSimple[nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS],
					nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: uvmIoctlSimple[nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS],
					nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS],
					nvgpu.UVM_VALIDATE_VA_RANGE:              uvmIoctlSimple[nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS],
					nvgpu.UVM_CREATE_EXTERNAL_RANGE:          uvmIoctlSimple[nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS],
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
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       rmControlSimple,
					0x80028b: rmControlSimple, // unknown, paramsSize == 1
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             rmControlSimple,
					nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         rmControlSimple,
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          rmControlSimple,
					nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                rmControlSimple,
					nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  rmControlSimple,
					nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   rmControlSimple,
					nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  rmControlSimple,
					nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    rmControlSimple,
					nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: rmControlSimple,
					nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   rmControlSimple,
					nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    rmControlSimple,
					nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          rmControlSimple,
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ctrlClientSystemGetBuildVersion,
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ctrlDevFIFOGetChannelList,
					nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlSubdevFIFODisableChannels,
					nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlSubdevGRGetInfo,
				},
				allocationClass: map[uint32]allocationClassHandler{
					nvgpu.NV01_ROOT:               rmAllocSimple[nvgpu.Handle],
					nvgpu.NV01_ROOT_NON_PRIV:      rmAllocSimple[nvgpu.Handle],
					nvgpu.NV01_ROOT_CLIENT:        rmAllocSimple[nvgpu.Handle],
					nvgpu.NV01_EVENT_OS_EVENT:     rmAllocEventOSEvent,
					nvgpu.NV01_DEVICE_0:           rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS],
					nvgpu.NV20_SUBDEVICE_0:        rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS],
					nvgpu.NV50_THIRD_PARTY_P2P:    rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS],
					nvgpu.GT200_DEBUGGER:          rmAllocSimple[nvgpu.NV83DE_ALLOC_PARAMETERS],
					nvgpu.FERMI_CONTEXT_SHARE_A:   rmAllocSimple[nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS],
					nvgpu.FERMI_VASPACE_A:         rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS],
					nvgpu.KEPLER_CHANNEL_GROUP_A:  rmAllocSimple[nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS],
					nvgpu.TURING_CHANNEL_GPFIFO_A: rmAllocSimple[nvgpu.NV_CHANNEL_ALLOC_PARAMS],
					nvgpu.AMPERE_CHANNEL_GPFIFO_A: rmAllocSimple[nvgpu.NV_CHANNEL_ALLOC_PARAMS],
					nvgpu.TURING_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_DMA_COPY_B:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.HOPPER_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
					nvgpu.TURING_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.AMPERE_COMPUTE_B:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.ADA_COMPUTE_A:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.HOPPER_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
					nvgpu.HOPPER_USERMODE_A:       rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS],
					nvgpu.GF100_SUBDEVICE_MASTER:  rmAllocNoParams,
					nvgpu.TURING_USERMODE_A:       rmAllocNoParams,
					nvgpu.NV_MEMORY_FABRIC:        rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS],
				},
			}
		})

		// 525.89.02 is an intermediate unqualified version from the main branch.
		v525_89_02 := v525_60_13

		// The following versions do not exist on the main branch. They branched off
		// the main branch at 525.89.02.
		v525_105_17Checksum := "c635a21a282c9b53485f19ebb64a0f4b536a968b94d4d97629e0bc547a58142a"
		v525_105_17 := addDriverABI(525, 105, 17, v525_105_17Checksum, v525_89_02)

		v525_125_06Checksum := "b5275689f4a833c37a507717ac8f0ee2f1f5cd2b7e236ffa70aad8dfb7455b9d"
		_ = addDriverABI(525, 125, 06, v525_125_06Checksum, v525_105_17)

		// v535.43.02 is an intermediate unqualified version from the main branch.
		v535_43_02 := func() *driverABI {
			abi := v525_89_02()
			abi.useRmAllocParamsV535 = true
			abi.controlCmd[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES] = rmControlSimple
			abi.allocationClass[nvgpu.NV_CONFIDENTIAL_COMPUTE] = rmAllocSimple[nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS]
			abi.allocationClass[nvgpu.NV_MEMORY_FABRIC] = rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS_V535]
			abi.uvmIoctl[nvgpu.UVM_MM_INITIALIZE] = uvmMMInitialize
			return abi
		}

		v535_54_03Checksum := "454764f57ea1b9e19166a370f78be10e71f0626438fb197f726dc3caf05b4082"
		v535_54_03 := addDriverABI(535, 54, 03, v535_54_03Checksum, v535_43_02)
		v535_104_05Checksum := "2f9d609d1da770beee757636635c46e7ed8253ade887b87c7a5482e33fcbedc9"
		_ = addDriverABI(535, 104, 05, v535_104_05Checksum, v535_54_03)
	})
}

// GetSupportedDriversAndChecksums returns supported driver ABIs.
func GetSupportedDriversAndChecksums() map[DriverVersion]string {
	versions := make(map[DriverVersion]string, len(abis))
	for version, abi := range abis {
		versions[version] = abi.checksum
	}
	return versions
}
