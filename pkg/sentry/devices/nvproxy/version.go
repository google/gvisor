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
	"sort"
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

// A driverABIFunc constructs and returns a driverABI.
// This indirection exists to avoid memory usage from unused driver ABIs.
type driverABIFunc func() *driverABI

// driverStructNamesFunc returns a mapping of struct names used by an ABI version.
// This indirection exists to avoid the memory usage from struct name maps if they are not used.
type driverStructNamesFunc func() *driverStructNames

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

	getStructNames driverStructNamesFunc
}

// To help with verifying and supporting new driver versions, we want to keep
// track of all the driver structs that we currently support. We do so by mapping ioctl
// numbers to a list of DriverStructs used by that ioctl.
type driverStructNames struct {
	frontendNames   map[uint32][]DriverStruct
	uvmNames        map[uint32][]DriverStruct
	controlNames    map[uint32][]DriverStruct
	allocationNames map[nvgpu.ClassID][]DriverStruct
}

// DriverStructName is the name of a struct used by the Nvidia driver.
type DriverStructName = string

// DriverStruct ties an nvproxy struct type to its corresponding driver struct name.
type DriverStruct struct {
	Name DriverStructName
	Type reflect.Type
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
					nvgpu.NV_ESC_CARD_INFO:                     feHandler(frontendIoctlSimple, compUtil), // nv_ioctl_card_info_t array
					nvgpu.NV_ESC_CHECK_VERSION_STR:             feHandler(frontendIoctlSimple, compUtil), // nv_rm_api_version_t
					nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             feHandler(frontendIoctlSimple, compUtil), // NvU32 array containing GPU IDs
					nvgpu.NV_ESC_SYS_PARAMS:                    feHandler(frontendIoctlSimple, compUtil), // nv_ioctl_sys_params_t
					nvgpu.NV_ESC_RM_DUP_OBJECT:                 feHandler(frontendIoctlSimple, compUtil), // NVOS55_PARAMETERS
					nvgpu.NV_ESC_RM_SHARE:                      feHandler(frontendIoctlSimple, compUtil), // NVOS57_PARAMETERS
					nvgpu.NV_ESC_RM_UNMAP_MEMORY:               feHandler(frontendIoctlSimple, compUtil), // NVOS34_PARAMETERS
					nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: feHandler(frontendIoctlSimple, compUtil), // NVOS56_PARAMETERS
					nvgpu.NV_ESC_REGISTER_FD:                   feHandler(frontendRegisterFD, compUtil),
					nvgpu.NV_ESC_ALLOC_OS_EVENT:                feHandler(frontendIoctHasFD[nvgpu.IoctlAllocOSEvent], compUtil),
					nvgpu.NV_ESC_FREE_OS_EVENT:                 feHandler(frontendIoctHasFD[nvgpu.IoctlFreeOSEvent], compUtil),
					nvgpu.NV_ESC_NUMA_INFO:                     feHandler(rmNumaInfo, compUtil),
					nvgpu.NV_ESC_RM_ALLOC_MEMORY:               feHandler(rmAllocMemory, compUtil),
					nvgpu.NV_ESC_RM_FREE:                       feHandler(rmFree, compUtil),
					nvgpu.NV_ESC_RM_CONTROL:                    feHandler(rmControl, compUtil),
					nvgpu.NV_ESC_RM_ALLOC:                      feHandler(rmAlloc, compUtil),
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
					nvgpu.UVM_VALIDATE_VA_RANGE:              uvmHandler(uvmIoctlSimple[nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS], compUtil),
					nvgpu.UVM_CREATE_EXTERNAL_RANGE:          uvmHandler(uvmIoctlSimple[nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS], compUtil),
					nvgpu.UVM_MM_INITIALIZE:                  uvmHandler(uvmMMInitialize, compUtil),
				},
				controlCmd: map[uint32]controlCmdHandler{
					nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       ctrlHandler(rmControlSimple, compUtil),
					0x80028b: ctrlHandler(rmControlSimple, compUtil), // unknown, paramsSize == 1
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                                  ctrlHandler(ctrlGpuGetIDInfo, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ctrlHandler(ctrlClientSystemGetBuildVersion, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:                              ctrlHandler(ctrlClientSystemGetP2PCaps, compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS], compUtil),
					nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS], compUtil),
					nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NV0041_CTRL_GET_SURFACE_INFO_PARAMS], compUtil),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ctrlHandler(ctrlDevFIFOGetChannelList, compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       ctrlHandler(ctrlMemoryMulticastFabricAttachGPU, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                ctrlHandler(ctrlDevGpuGetClasslist, compUtil),
					nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlHandler(ctrlSubdevFIFODisableChannels, compUtil),
					nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_BIOS_GET_INFO_PARAMS], compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS], compUtil),
					nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                ctrlHandler(ctrlRegisterVASpace, compUtil),
				},
				allocationClass: map[nvgpu.ClassID]allocationClassHandler{
					nvgpu.NV01_ROOT:                  allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_ROOT_NON_PRIV:         allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_MEMORY_SYSTEM:         allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV01_MEMORY_LOCAL_USER:     allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV01_ROOT_CLIENT:           allocHandler(rmAllocRootClient, compUtil),
					nvgpu.NV01_EVENT_OS_EVENT:        allocHandler(rmAllocEventOSEvent, compUtil),
					nvgpu.NV2081_BINAPI:              allocHandler(rmAllocSimple[nvgpu.NV2081_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV01_DEVICE_0:              allocHandler(rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS], compUtil),
					nvgpu.RM_USER_SHARED_DATA:        allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_FABRIC:           allocHandler(rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_MULTICAST_FABRIC: allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV20_SUBDEVICE_0:           allocHandler(rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV50_MEMORY_VIRTUAL:        allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS], compUtil),
					nvgpu.NV50_P2P:                   allocHandler(rmAllocSimple[nvgpu.NV503B_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV50_THIRD_PARTY_P2P:       allocHandler(rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS], compUtil),
					nvgpu.GF100_PROFILER:             allocHandler(rmAllocNoParams, compUtil),
					nvgpu.GT200_DEBUGGER:             allocHandler(rmAllocSMDebuggerSession, compUtil),
					nvgpu.FERMI_CONTEXT_SHARE_A:      allocHandler(rmAllocContextShare, compUtil),
					nvgpu.FERMI_VASPACE_A:            allocHandler(rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.KEPLER_CHANNEL_GROUP_A:     allocHandler(rmAllocChannelGroup, compUtil),
					nvgpu.TURING_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
					nvgpu.AMPERE_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
					nvgpu.HOPPER_CHANNEL_GPFIFO_A:    allocHandler(rmAllocChannel, compUtil),
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
				},

				getStructNames: func() *driverStructNames {
					return &driverStructNames{
						frontendNames: map[uint32][]DriverStruct{
							nvgpu.NV_ESC_CARD_INFO:                     simpleIoctl("nv_ioctl_card_info_t"),
							nvgpu.NV_ESC_CHECK_VERSION_STR:             getStructName(nvgpu.RMAPIVersion{}),
							nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             nil, // NvU32 array containing GPU IDs
							nvgpu.NV_ESC_SYS_PARAMS:                    getStructName(nvgpu.IoctlSysParams{}),
							nvgpu.NV_ESC_RM_DUP_OBJECT:                 getStructName(nvgpu.NVOS55Parameters{}),
							nvgpu.NV_ESC_RM_SHARE:                      getStructName(nvgpu.NVOS57Parameters{}),
							nvgpu.NV_ESC_RM_UNMAP_MEMORY:               getStructName(nvgpu.NVOS34Parameters{}),
							nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: getStructName(nvgpu.NVOS56Parameters{}),
							nvgpu.NV_ESC_REGISTER_FD:                   getStructName(nvgpu.IoctlRegisterFD{}),
							nvgpu.NV_ESC_ALLOC_OS_EVENT:                getStructName(nvgpu.IoctlAllocOSEvent{}),
							nvgpu.NV_ESC_FREE_OS_EVENT:                 getStructName(nvgpu.IoctlFreeOSEvent{}),
							nvgpu.NV_ESC_NUMA_INFO:                     nil, // nvproxy ignores this ioctl
							nvgpu.NV_ESC_RM_ALLOC_MEMORY:               getStructName(nvgpu.IoctlNVOS02ParametersWithFD{}),
							nvgpu.NV_ESC_RM_FREE:                       getStructName(nvgpu.NVOS00Parameters{}),
							nvgpu.NV_ESC_RM_CONTROL:                    getStructName(nvgpu.NVOS54Parameters{}),
							nvgpu.NV_ESC_RM_ALLOC:                      append(getStructName(nvgpu.NVOS21Parameters{}), getStructName(nvgpu.NVOS64Parameters{})...),
							nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           getStructName(nvgpu.NVOS32Parameters{}),
							nvgpu.NV_ESC_RM_MAP_MEMORY:                 getStructName(nvgpu.IoctlNVOS33ParametersWithFD{}),
						},
						uvmNames: map[uint32][]DriverStruct{
							nvgpu.UVM_INITIALIZE:                     getStructName(nvgpu.UVM_INITIALIZE_PARAMS{}),
							nvgpu.UVM_DEINITIALIZE:                   nil, // Doesn't have any params
							nvgpu.UVM_CREATE_RANGE_GROUP:             getStructName(nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_DESTROY_RANGE_GROUP:            getStructName(nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU_VASPACE:           getStructName(nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU_VASPACE:         getStructName(nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_REGISTER_CHANNEL:               getStructName(nvgpu.UVM_REGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_UNREGISTER_CHANNEL:             getStructName(nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_ENABLE_PEER_ACCESS:             getStructName(nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_DISABLE_PEER_ACCESS:            getStructName(nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_RANGE_GROUP:                getStructName(nvgpu.UVM_SET_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        getStructName(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS{}),
							nvgpu.UVM_FREE:                           getStructName(nvgpu.UVM_FREE_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU:                   getStructName(nvgpu.UVM_REGISTER_GPU_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU:                 getStructName(nvgpu.UVM_UNREGISTER_GPU_PARAMS{}),
							nvgpu.UVM_PAGEABLE_MEM_ACCESS:            getStructName(nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_PREFERRED_LOCATION:         getStructName(nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_UNSET_PREFERRED_LOCATION:       getStructName(nvgpu.UVM_UNSET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_DISABLE_READ_DUPLICATION:       getStructName(nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS{}),
							nvgpu.UVM_UNSET_ACCESSED_BY:              getStructName(nvgpu.UVM_UNSET_ACCESSED_BY_PARAMS{}),
							nvgpu.UVM_MIGRATE:                        getStructName(nvgpu.UVM_MIGRATE_PARAMS{}),
							nvgpu.UVM_MIGRATE_RANGE_GROUP:            getStructName(nvgpu.UVM_MIGRATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: getStructName(nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS{}),
							nvgpu.UVM_UNMAP_EXTERNAL:                 getStructName(nvgpu.UVM_UNMAP_EXTERNAL_PARAMS{}),
							nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           getStructName(nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS{}),
							nvgpu.UVM_VALIDATE_VA_RANGE:              getStructName(nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS{}),
							nvgpu.UVM_CREATE_EXTERNAL_RANGE:          getStructName(nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS{}),
							nvgpu.UVM_MM_INITIALIZE:                  getStructName(nvgpu.UVM_MM_INITIALIZE_PARAMS{}),
						},
						controlNames: map[uint32][]DriverStruct{
							nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        simpleIoctl("NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: simpleIoctl("NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              simpleIoctl("NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                simpleIoctl("NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                simpleIoctl("NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    simpleIoctl("NV0000_CTRL_GPU_ATTACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    simpleIoctl("NV0000_CTRL_GPU_DETACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  simpleIoctl("NV0000_CTRL_GPU_GET_PCI_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             simpleIoctl("NV0000_CTRL_GPU_QUERY_DRAIN_STATE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              simpleIoctl("NV0000_CTRL_GPU_GET_MEMOP_ENABLE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         simpleIoctl("NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:            simpleIoctl("NV0000_CTRL_SYSTEM_GET_P2P_CAPS_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          simpleIoctl("NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        simpleIoctl("NV0000_CTRL_SYSTEM_GET_P2P_CAPS_MATRIX_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:               simpleIoctl("NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    simpleIoctl("NV0080_CTRL_FB_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            simpleIoctl("NV0080_CTRL_GPU_GET_NUM_SUBDEVICES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    simpleIoctl("NV0080_CTRL_GPU_QUERY_SW_STATE_PERSISTENCE_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       simpleIoctl("NV0080_CTRL_GPU_GET_VIRTUALIZATION_MODE_PARAMS"),
							0x80028b: nil, // unknown, paramsSize == 1
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             simpleIoctl("NV0080_CTRL_GPU_GET_CLASSLIST_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 simpleIoctl("NV0080_CTRL_HOST_GET_CAPS_V2_PARAMS"),
							nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                                       simpleIoctl("NV00F8_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         simpleIoctl("NV00FD_CTRL_GET_INFO_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       simpleIoctl("NV00FD_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       simpleIoctl("NV00FD_CTRL_DETACH_MEM_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 simpleIoctl("NV2080_CTRL_BUS_GET_PCI_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             simpleIoctl("NV2080_CTRL_BUS_GET_PCI_BAR_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  simpleIoctl("NV2080_CTRL_BUS_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               simpleIoctl("NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 simpleIoctl("NV2080_CTRL_CMD_BUS_GET_C2C_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  simpleIoctl("NV2080_CTRL_CE_GET_ALL_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           simpleIoctl("NV2080_CTRL_EVENT_SET_NOTIFICATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   simpleIoctl("NV2080_CTRL_FB_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  simpleIoctl("NV2080_CTRL_GPU_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         simpleIoctl("NV2080_CTRL_FLCN_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              simpleIoctl("NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        simpleIoctl("NV2080_CTRL_GPU_GET_SHORT_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          simpleIoctl("NV2080_CTRL_GPU_GET_SIMULATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             simpleIoctl("NV2080_CTRL_GPU_QUERY_ECC_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     simpleIoctl("NV2080_CTRL_GPU_QUERY_COMPUTE_MODE_RULES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      simpleIoctl("NV2080_CTRL_GPU_QUERY_ECC_CONFIGURATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           simpleIoctl("NV2080_CTRL_GPU_GET_OEM_BOARD_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             nil, // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             nil, // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 simpleIoctl("NV2080_CTRL_GPU_GET_GID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   simpleIoctl("NV2080_CTRL_GPU_GET_INFOROM_OBJECT_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    simpleIoctl("NV2080_CTRL_GPU_GET_INFOROM_IMAGE_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    nil, // No params.
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               simpleIoctl("NV2080_CTRL_GPU_GET_ENGINES_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     simpleIoctl("NV2080_CTRL_GPU_GET_ACTIVE_PARTITION_IDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     simpleIoctl("NV2080_CTRL_GPU_GET_PIDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 simpleIoctl("NV2080_CTRL_GPU_GET_PID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    simpleIoctl("NV2080_CTRL_GPU_GET_COMPUTE_POLICY_CONFIG_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        simpleIoctl("NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     simpleIoctl("NV2080_CTRL_GR_SET_CTXSW_PREEMPTION_MODE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           simpleIoctl("NV2080_CTRL_GR_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           simpleIoctl("NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   simpleIoctl("NV2080_CTRL_GR_GET_CAPS_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  simpleIoctl("NV2080_CTRL_GR_GET_GPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  simpleIoctl("NV2080_CTRL_GR_GET_TPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    simpleIoctl("NV2080_CTRL_GR_GET_SM_ISSUE_RATE_MODIFIER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             simpleIoctl("NV2080_CTRL_GRMGR_GET_GR_FS_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 simpleIoctl("NV2080_CTRL_GSP_GET_FEATURES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 simpleIoctl("NV2080_CTRL_MC_GET_ARCH_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            simpleIoctl("NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           simpleIoctl("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         simpleIoctl("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       simpleIoctl("NV2080_CTRL_PERF_BOOST_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             simpleIoctl("NV2080_CTRL_RC_GET_WATCHDOG_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     nil, // No params.
							nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         nil, // No params.
							nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          simpleIoctl("NV2080_CTRL_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                           simpleIoctl("NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  simpleIoctl("NV503C_CTRL_REGISTER_VIDMEM_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                simpleIoctl("NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         simpleIoctl("NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   simpleIoctl("NV83DE_CTRL_DEBUG_READ_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  simpleIoctl("NV83DE_CTRL_DEBUG_CLEAR_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   simpleIoctl("NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    simpleIoctl("NV906F_CTRL_CMD_RESET_CHANNEL_PARAMS"),
							nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: simpleIoctl("NV90E6_CTRL_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK_PARAMS"),
							nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   simpleIoctl("NVC36F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     simpleIoctl("NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 simpleIoctl("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   simpleIoctl("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             simpleIoctl("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleIoctl("NVA06C_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    simpleIoctl("NVA06C_CTRL_SET_TIMESLICE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          simpleIoctl("NVA06C_CTRL_PREEMPT_PARAMS"),
							nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleIoctl("NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          simpleIoctl("NVC56F_CTRL_CMD_GET_KMB_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                                  getStructName(nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         getStructName(nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:                              getStructName(nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      getStructName(nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    getStructName(nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   getStructName(nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS{}),
							nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 getStructName(nvgpu.NV0041_CTRL_GET_SURFACE_INFO_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             getStructName(nvgpu.NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS{}),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       getStructName(nvgpu.NV00FD_CTRL_ATTACH_GPU_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                getStructName(nvgpu.NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            getStructName(nvgpu.NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    getStructName(nvgpu.NV2080_CTRL_BIOS_GET_INFO_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      getStructName(nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS{}),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                getStructName(nvgpu.NV503C_CTRL_REGISTER_VA_SPACE_PARAMS{}),
						},
						allocationNames: map[nvgpu.ClassID][]DriverStruct{
							nvgpu.NV01_ROOT:                  getStructName(nvgpu.Handle{}),
							nvgpu.NV01_ROOT_NON_PRIV:         getStructName(nvgpu.Handle{}),
							nvgpu.NV01_MEMORY_SYSTEM:         getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_MEMORY_LOCAL_USER:     getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_ROOT_CLIENT:           getStructName(nvgpu.Handle{}),
							nvgpu.NV01_EVENT_OS_EVENT:        getStructName(nvgpu.NV0005_ALLOC_PARAMETERS{}),
							nvgpu.NV2081_BINAPI:              getStructName(nvgpu.NV2081_ALLOC_PARAMETERS{}),
							nvgpu.NV01_DEVICE_0:              getStructName(nvgpu.NV0080_ALLOC_PARAMETERS{}),
							nvgpu.RM_USER_SHARED_DATA:        getStructName(nvgpu.NV00DE_ALLOC_PARAMETERS{}),
							nvgpu.NV_MEMORY_FABRIC:           getStructName(nvgpu.NV00F8_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_MEMORY_MULTICAST_FABRIC: getStructName(nvgpu.NV00FD_ALLOCATION_PARAMETERS{}),
							nvgpu.NV20_SUBDEVICE_0:           getStructName(nvgpu.NV2080_ALLOC_PARAMETERS{}),
							nvgpu.NV50_MEMORY_VIRTUAL:        getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV50_P2P:                   getStructName(nvgpu.NV503B_ALLOC_PARAMETERS{}),
							nvgpu.NV50_THIRD_PARTY_P2P:       getStructName(nvgpu.NV503C_ALLOC_PARAMETERS{}),
							nvgpu.GT200_DEBUGGER:             getStructName(nvgpu.NV83DE_ALLOC_PARAMETERS{}),
							nvgpu.GF100_PROFILER:             nil, // No params
							nvgpu.FERMI_CONTEXT_SHARE_A:      getStructName(nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS{}),
							nvgpu.FERMI_VASPACE_A:            getStructName(nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS{}),
							nvgpu.KEPLER_CHANNEL_GROUP_A:     getStructName(nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_CHANNEL_GPFIFO_A:    getStructName(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.AMPERE_CHANNEL_GPFIFO_A:    getStructName(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.HOPPER_CHANNEL_GPFIFO_A:    getStructName(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.TURING_DMA_COPY_A:          getStructName(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_A:          getStructName(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_B:          getStructName(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_DMA_COPY_A:          getStructName(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_COMPUTE_A:           getStructName(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_A:           getStructName(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_B:           getStructName(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.ADA_COMPUTE_A:              getStructName(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_CONFIDENTIAL_COMPUTE:    getStructName(nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS{}),
							nvgpu.HOPPER_COMPUTE_A:           getStructName(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_USERMODE_A:          getStructName(nvgpu.NV_HOPPER_USERMODE_A_PARAMS{}),
							nvgpu.GF100_SUBDEVICE_MASTER:     nil, // No params
							nvgpu.TURING_USERMODE_A:          nil, // No params
							nvgpu.HOPPER_SEC2_WORK_LAUNCH_A:  nil, // No params
						},
					}
				},
			}
		}

		// 535.113.01 is an intermediate unqualified version from the main branch.
		v535_113_01 := v535_104_05

		// The following exist on the "535" branch. They branched off the main
		// branch at 535.113.01.
		v535_183_01 := addDriverABI(535, 183, 01, "f6707afbdda9407e3cbc2e5128e60bcbcdbf02fae29958c72fafb5d405e8b883", v535_113_01)
		v535_183_06 := addDriverABI(535, 183, 06, "c7bb0a0569c5347845479ed4e3e4d885c6ee3b8adf068c3401cdf754d5ba3d3b", v535_183_01)
		_ = addDriverABI(535, 216, 01, "5ddea1147810012e33967c3181341bcd6624bd3d654c63f845df833b4ece6af7", v535_183_06)

		// 545.23.06 is an intermediate unqualified version from the main branch.
		v545_23_06 := func() *driverABI {
			abi := v535_113_01()
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.RM_USER_SHARED_DATA] = allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_SYSTEM] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_LOCAL_USER] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV50_MEMORY_VIRTUAL] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)

			prevNames := abi.getStructNames
			abi.getStructNames = func() *driverStructNames {
				names := prevNames()
				names.controlNames[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = getStructName(nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545{})
				names.allocationNames[nvgpu.RM_USER_SHARED_DATA] = getStructName(nvgpu.NV00DE_ALLOC_PARAMETERS_V545{})
				names.allocationNames[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = getStructName(nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545{})
				names.allocationNames[nvgpu.NV01_MEMORY_SYSTEM] = getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{})
				names.allocationNames[nvgpu.NV01_MEMORY_LOCAL_USER] = getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{})
				names.allocationNames[nvgpu.NV50_MEMORY_VIRTUAL] = getStructName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{})

				return names
			}

			return abi
		}

		// 550.40.07 is an intermediate unqualified version from the main branch.
		v550_40_07 := func() *driverABI {
			abi := v545_23_06()
			abi.frontendIoctl[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = feHandler(frontendIoctlSimple, compUtil) // nv_ioctl_wait_open_complete_t
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = ctrlHandler(rmControlSimple, compUtil) // NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = ctrlHandler(rmControlSimple, compUtil)
			// NV2081_BINAPI forwards all control commands to the GSP in
			// src/nvidia/src/kernel/rmapi/binary_api.c:binapiControl_IMPL().
			abi.controlCmd[(nvgpu.NV2081_BINAPI<<16)|0x0108] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = ctrlHandler(ctrlClientSystemGetP2PCapsV550, compUtil)
			abi.uvmIoctl[nvgpu.UVM_SET_PREFERRED_LOCATION] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MIGRATE] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_MIGRATE_PARAMS_V550], compUtil)

			prevNames := abi.getStructNames
			abi.getStructNames = func() *driverStructNames {
				names := prevNames()
				names.frontendNames[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = simpleIoctl("nv_ioctl_wait_open_complete_t")
				names.controlNames[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = simpleIoctl("NV0000_CTRL_GPU_ASYNC_ATTACH_ID_PARAMS")
				names.controlNames[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = simpleIoctl("NV0000_CTRL_GPU_WAIT_ATTACH_ID_PARAMS")
				names.controlNames[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = simpleIoctl("NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS")
				names.controlNames[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = simpleIoctl("NV2080_CTRL_PERF_GET_CURRENT_PSTATE_PARAMS")
				// NV2081_BINAPI forwards all control commands to the GSP in
				// src/nvidia/src/kernel/rmapi/binary_api.c:binapiControl_IMPL().
				// As such, there are no structs defined in the driver for this.
				names.controlNames[(nvgpu.NV2081_BINAPI<<16)|0x0108] = nil
				names.controlNames[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = getStructName(nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550{})
				names.uvmNames[nvgpu.UVM_SET_PREFERRED_LOCATION] = getStructName(nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550{})
				names.uvmNames[nvgpu.UVM_MIGRATE] = getStructName(nvgpu.UVM_MIGRATE_PARAMS_V550{})

				return names
			}

			return abi
		}

		v550_54_14 := addDriverABI(550, 54, 14, "8c497ff1cfc7c310fb875149bc30faa4fd26d2237b2cba6cd2e8b0780157cfe3", func() *driverABI {
			abi := v550_40_07()
			abi.uvmIoctl[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550], compUtil)

			prevNames := abi.getStructNames
			abi.getStructNames = func() *driverStructNames {
				names := prevNames()
				names.uvmNames[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = getStructName(nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550{})
				names.uvmNames[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = getStructName(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550{})

				return names
			}

			return abi
		})

		v550_90_07 := addDriverABI(550, 90, 07, "51acf579d5a9884f573a1d3f522e7fafa5e7841e22a9cec0b4bbeae31b0b9733", func() *driverABI {
			abi := v550_54_14()
			abi.controlCmd[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = ctrlHandler(rmControlSimple, compUtil)

			prevNames := abi.getStructNames
			abi.getStructNames = func() *driverStructNames {
				names := prevNames()
				names.controlNames[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = simpleIoctl("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE_PARAMS")

				return names
			}

			return abi
		})

		// This version does not belong on any branch, but it is a child of 550.90.07.
		_ = addDriverABI(550, 90, 12, "391883846713b9e700af2ae87f8ac671f5527508ce3f9f60058deb363e05162a", v550_90_07)

		// 555.42.02 is an intermediate unqualified version.
		v555_42_02 := func() *driverABI {
			abi := v550_90_07()
			// NVC36F_CTRL_GET_CLASS_ENGINEID was deleted in 555.42.02:
			// https://github.com/NVIDIA/open-gpu-kernel-modules/commit/5a1c474040e1c3ed20760267510cc9d9332898f1
			delete(abi.controlCmd, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
			prevNames := abi.getStructNames
			abi.getStructNames = func() *driverStructNames {
				names := prevNames()
				delete(names.controlNames, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
				return names
			}
			return abi
		}

		_ = addDriverABI(560, 35, 03, "f2932c92fadd43c5b2341be453fc4f73f0ad7185c26bb7a43fbde81ae29f1fe3", v555_42_02)
	})
}

// simpleIoctl simply returns a slice containing structName. This is used for ioctls that don't
// have a struct defined in nvproxy, but we know the driver struct name.
func simpleIoctl(structName string) []DriverStruct {
	return []DriverStruct{
		{
			Name: structName,
			Type: nil,
		},
	}
}

// getStructName takes an instance of an nvproxy struct and reads the `nvproxy` tag to determine the
// struct name. If the tag is empty, then it returns nil.
func getStructName(params any) []DriverStruct {
	paramType := reflect.TypeOf(params)

	// Right now, we only expect parameter structs
	if paramType.Kind() != reflect.Struct {
		panic(fmt.Sprintf("expected struct, got %v", paramType.Kind()))
	}

	// Look through each field for the tag, panicking if there are not exactly one.
	tagName, found := "", false
	for i := 0; i < paramType.NumField(); i++ {
		field := paramType.Field(i)
		if name, ok := field.Tag.Lookup("nvproxy"); ok {
			if found {
				panic(fmt.Sprintf("multiple nvproxy tags for %v", paramType.Name()))
			}
			tagName = name
			found = true
		}
	}

	if !found {
		panic(fmt.Sprintf("missing nvproxy tag for %v", paramType.Name()))
	}
	var driverName string
	switch tagName {
	case "":
		return nil
	case "same":
		driverName = paramType.Name()
	default:
		driverName = tagName
	}

	return []DriverStruct{
		{
			Name: driverName,
			Type: paramType,
		},
	}
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

// SupportedDrivers returns a list of all supported drivers.
// Precondition: Init() must have been called.
func SupportedDrivers() []DriverVersion {
	var ret []DriverVersion
	for version := range abis {
		ret = append(ret, version)
	}
	sort.Slice(ret, func(i, j int) bool {
		return !ret[i].isGreaterThan(ret[j])
	})
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

// SupportedStructNames returns the list of struct names supported by the given driver version.
// It merges the frontend, uvm, control, and allocation names into one slice.
func SupportedStructNames(version DriverVersion) ([]DriverStructName, bool) {
	namesCons, ok := abis[version]
	if !ok {
		return nil, false
	}
	abi := namesCons.cons()
	names := abi.getStructNames()

	var allNames []DriverStructName
	addNames := func(names []DriverStruct) {
		for _, name := range names {
			allNames = append(allNames, name.Name)
		}
	}

	for _, names := range names.frontendNames {
		addNames(names)
	}
	for _, names := range names.uvmNames {
		addNames(names)
	}
	for _, names := range names.controlNames {
		addNames(names)
	}
	for _, names := range names.allocationNames {
		addNames(names)
	}

	return allNames, true
}

// SupportedStructTypes returns the list of struct types supported by the given driver version.
// It merges the frontend, uvm, control, and allocation names into one slice.
func SupportedStructTypes(version DriverVersion) ([]DriverStruct, bool) {
	namesCons, ok := abis[version]
	if !ok {
		return nil, false
	}
	abi := namesCons.cons()
	names := abi.getStructNames()

	var allNames []DriverStruct
	for _, names := range names.frontendNames {
		allNames = append(allNames, names...)
	}
	for _, names := range names.uvmNames {
		allNames = append(allNames, names...)
	}
	for _, names := range names.controlNames {
		allNames = append(allNames, names...)
	}
	for _, names := range names.allocationNames {
		allNames = append(allNames, names...)
	}

	return allNames, true
}
