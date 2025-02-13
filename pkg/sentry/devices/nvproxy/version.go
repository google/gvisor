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
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
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

// driverABIStructsFunc returns a mapping of struct names used by an ABI version.
// This indirection exists to avoid the memory usage from struct name maps if they are not used.
type driverABIStructsFunc func() *driverABIStructs

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

	getStructs driverABIStructsFunc
}

// driverABIStructs defines all the structs used by a driverABI. This is used
// to help with verifying and supporting new driver versions. This helps keep
// track of all the driver structs that we currently support. We do so by
// mapping ioctl numbers to a list of DriverStructs used by that ioctl.
type driverABIStructs struct {
	frontendStructs   map[uint32][]DriverStruct
	uvmStructs        map[uint32][]DriverStruct
	controlStructs    map[uint32][]DriverStruct
	allocationStructs map[nvgpu.ClassID][]DriverStruct
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
					nvgpu.NV_ESC_CARD_INFO:                     feHandler(frontendIoctlBytes, compUtil), // nv_ioctl_card_info_t array
					nvgpu.NV_ESC_CHECK_VERSION_STR:             feHandler(frontendIoctlSimple[nvgpu.RMAPIVersion], compUtil),
					nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             feHandler(frontendIoctlBytes, compUtil), // NvU32 array containing GPU IDs
					nvgpu.NV_ESC_SYS_PARAMS:                    feHandler(frontendIoctlSimple[nvgpu.IoctlSysParams], compUtil),
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
					nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS:                ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID:          ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_GSYNC_GET_ATTACHED_IDS:            ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO:               ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_DMA_ADV_SCHED_GET_VA_CAPS:         ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_DMA_GET_CAPS:                      ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       ctrlHandler(rmControlSimple, compUtil),
					0x80028b: ctrlHandler(rmControlSimple, compUtil), // unknown, paramsSize == 1
					nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV0080_CTRL_CMD_BSP_GET_CAPS_V2:                         ctrlHandler(rmControlSimple, nvconf.CapGraphics|nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_NVJPG_GET_CAPS_V2:                       ctrlHandler(rmControlSimple, nvconf.CapVideo),
					nvgpu.NV0080_CTRL_CMD_FIFO_GET_ENGINE_CONTEXT_PROPERTIES:      ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO:                            ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], nvconf.CapVideo),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:      ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_CE_GET_CE_PCE_MASK:                      ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_CE_GET_CAPS_V2:                          ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_GPU_CACHE_INFO:                   ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO:                   ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_FB_GET_SEMAPHORE_SURFACE_LAYOUT:         ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                     ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                 ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ID:                              ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:             ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST:              ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENCODER_CAPACITY:                ctrlHandler(rmControlSimple, nvconf.CapVideo),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                      ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:               ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_ZCULL_INFO:                       ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GR_CTXSW_ZCULL_BIND:                     ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                          ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                         ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:           ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                        ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                   ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                  ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                              ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                    ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:            ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_TIME:                          ctrlHandler(rmControlSimple, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO: ctrlHandler(rmControlSimple, compUtil),
					nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                  ctrlHandler(rmControlSimple, compUtil),
					0x20810107:                                                             ctrlHandler(rmControlSimple, nvconf.CapGraphics), // unknown, paramsSize == TODO(ayushranjan)
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
					nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], compUtil),
					nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       ctrlHandler(ctrlMemoryMulticastFabricAttachGPU, compUtil),
					nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES:                                  ctrlHandler(ctrlGetNvU32List, nvconf.CapGraphics),
					nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], compUtil),
					nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlHandler(ctrlSubdevFIFODisableChannels, compUtil),
					nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS], compUtil),
					nvgpu.NV2080_CTRL_CMD_FB_GET_INFO:                                      ctrlHandler(ctrlIoctlHasInfoList[nvgpu.NvxxxCtrlXxxGetInfoParams], nvconf.CapGraphics),
					nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                ctrlHandler(ctrlRegisterVASpace, compUtil),
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
					nvgpu.RM_USER_SHARED_DATA:        allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_FABRIC:           allocHandler(rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS], compUtil),
					nvgpu.NV_MEMORY_MULTICAST_FABRIC: allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS], compUtil),
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
				},

				getStructs: func() *driverABIStructs {
					return &driverABIStructs{
						frontendStructs: map[uint32][]DriverStruct{
							nvgpu.NV_ESC_CARD_INFO:                     simpleDriverStruct("nv_ioctl_card_info_t"),
							nvgpu.NV_ESC_CHECK_VERSION_STR:             driverStructWithName(nvgpu.RMAPIVersion{}, "nv_ioctl_rm_api_version_t"),
							nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             nil, // NvU32 array containing GPU IDs
							nvgpu.NV_ESC_SYS_PARAMS:                    driverStructWithName(nvgpu.IoctlSysParams{}, "nv_ioctl_sys_params_t"),
							nvgpu.NV_ESC_RM_DUP_OBJECT:                 driverStructs(nvgpu.NVOS55_PARAMETERS{}),
							nvgpu.NV_ESC_RM_SHARE:                      driverStructs(nvgpu.NVOS57_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UNMAP_MEMORY:               driverStructs(nvgpu.NVOS34_PARAMETERS{}),
							nvgpu.NV_ESC_RM_ALLOC_CONTEXT_DMA2:         driverStructs(nvgpu.NVOS39_PARAMETERS{}),
							nvgpu.NV_ESC_RM_MAP_MEMORY_DMA:             driverStructs(nvgpu.NVOS46_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA:           driverStructs(nvgpu.NVOS47_PARAMETERS{}),
							nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: driverStructs(nvgpu.NVOS56_PARAMETERS{}),
							nvgpu.NV_ESC_REGISTER_FD:                   driverStructWithName(nvgpu.IoctlRegisterFD{}, "nv_ioctl_register_fd_t"),
							nvgpu.NV_ESC_ALLOC_OS_EVENT:                driverStructWithName(nvgpu.IoctlAllocOSEvent{}, "nv_ioctl_alloc_os_event_t"),
							nvgpu.NV_ESC_FREE_OS_EVENT:                 driverStructWithName(nvgpu.IoctlFreeOSEvent{}, "nv_ioctl_free_os_event_t"),
							nvgpu.NV_ESC_NUMA_INFO:                     nil, // nvproxy ignores this ioctl
							nvgpu.NV_ESC_RM_ALLOC_MEMORY:               driverStructWithName(nvgpu.IoctlNVOS02ParametersWithFD{}, "nv_ioctl_nvos02_parameters_with_fd"),
							nvgpu.NV_ESC_RM_FREE:                       driverStructs(nvgpu.NVOS00_PARAMETERS{}),
							nvgpu.NV_ESC_RM_CONTROL:                    driverStructs(nvgpu.NVOS54_PARAMETERS{}),
							nvgpu.NV_ESC_RM_ALLOC:                      driverStructs(nvgpu.NVOS21_PARAMETERS{}, nvgpu.NVOS64_PARAMETERS{}),
							nvgpu.NV_ESC_RM_IDLE_CHANNELS:              driverStructs(nvgpu.NVOS30_PARAMETERS{}),
							nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           driverStructs(nvgpu.NVOS32_PARAMETERS{}),
							nvgpu.NV_ESC_RM_MAP_MEMORY:                 driverStructWithName(nvgpu.IoctlNVOS33ParametersWithFD{}, "nv_ioctl_nvos33_parameters_with_fd"),
						},
						uvmStructs: map[uint32][]DriverStruct{
							nvgpu.UVM_INITIALIZE:                     driverStructs(nvgpu.UVM_INITIALIZE_PARAMS{}),
							nvgpu.UVM_DEINITIALIZE:                   nil, // Doesn't have any params
							nvgpu.UVM_CREATE_RANGE_GROUP:             driverStructs(nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_DESTROY_RANGE_GROUP:            driverStructs(nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU_VASPACE:           driverStructs(nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU_VASPACE:         driverStructs(nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS{}),
							nvgpu.UVM_REGISTER_CHANNEL:               driverStructs(nvgpu.UVM_REGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_UNREGISTER_CHANNEL:             driverStructs(nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS{}),
							nvgpu.UVM_ENABLE_PEER_ACCESS:             driverStructs(nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_DISABLE_PEER_ACCESS:            driverStructs(nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_RANGE_GROUP:                driverStructs(nvgpu.UVM_SET_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        driverStructs(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS{}),
							nvgpu.UVM_FREE:                           driverStructs(nvgpu.UVM_FREE_PARAMS{}),
							nvgpu.UVM_REGISTER_GPU:                   driverStructs(nvgpu.UVM_REGISTER_GPU_PARAMS{}),
							nvgpu.UVM_UNREGISTER_GPU:                 driverStructs(nvgpu.UVM_UNREGISTER_GPU_PARAMS{}),
							nvgpu.UVM_PAGEABLE_MEM_ACCESS:            driverStructs(nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS{}),
							nvgpu.UVM_SET_PREFERRED_LOCATION:         driverStructs(nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_UNSET_PREFERRED_LOCATION:       driverStructs(nvgpu.UVM_UNSET_PREFERRED_LOCATION_PARAMS{}),
							nvgpu.UVM_DISABLE_READ_DUPLICATION:       driverStructs(nvgpu.UVM_DISABLE_READ_DUPLICATION_PARAMS{}),
							nvgpu.UVM_UNSET_ACCESSED_BY:              driverStructs(nvgpu.UVM_UNSET_ACCESSED_BY_PARAMS{}),
							nvgpu.UVM_MIGRATE:                        driverStructs(nvgpu.UVM_MIGRATE_PARAMS{}),
							nvgpu.UVM_MIGRATE_RANGE_GROUP:            driverStructs(nvgpu.UVM_MIGRATE_RANGE_GROUP_PARAMS{}),
							nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: driverStructs(nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS{}),
							nvgpu.UVM_UNMAP_EXTERNAL:                 driverStructs(nvgpu.UVM_UNMAP_EXTERNAL_PARAMS{}),
							nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           driverStructs(nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS{}),
							nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU:     driverStructs(nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS{}),
							nvgpu.UVM_VALIDATE_VA_RANGE:              driverStructs(nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS{}),
							nvgpu.UVM_CREATE_EXTERNAL_RANGE:          driverStructs(nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS{}),
							nvgpu.UVM_MM_INITIALIZE:                  driverStructs(nvgpu.UVM_MM_INITIALIZE_PARAMS{}),
						},
						controlStructs: map[uint32][]DriverStruct{
							nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        simpleDriverStruct("NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: simpleDriverStruct("NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              simpleDriverStruct("NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS:                simpleDriverStruct("NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                simpleDriverStruct("NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                simpleDriverStruct("NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    simpleDriverStruct("NV0000_CTRL_GPU_ATTACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    simpleDriverStruct("NV0000_CTRL_GPU_DETACH_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  simpleDriverStruct("NV0000_CTRL_GPU_GET_PCI_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID:          simpleDriverStruct("NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             simpleDriverStruct("NV0000_CTRL_GPU_QUERY_DRAIN_STATE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              simpleDriverStruct("NV0000_CTRL_GPU_GET_MEMOP_ENABLE_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GSYNC_GET_ATTACHED_IDS:            simpleDriverStruct("NV0000_CTRL_GSYNC_GET_ATTACHED_IDS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         simpleDriverStruct("NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO:               simpleDriverStruct("NV0000_CTRL_SYSTEM_GET_CPU_INFO_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2:            simpleDriverStruct("NV0000_CTRL_SYSTEM_GET_P2P_CAPS_V2_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          simpleDriverStruct("NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        simpleDriverStruct("NV0000_CTRL_SYSTEM_GET_P2P_CAPS_MATRIX_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FEATURES:               simpleDriverStruct("NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_DMA_ADV_SCHED_GET_VA_CAPS:         simpleDriverStruct("NV0080_CTRL_DMA_ADV_SCHED_GET_VA_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_DMA_GET_CAPS:                      simpleDriverStruct("NV0080_CTRL_DMA_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    simpleDriverStruct("NV0080_CTRL_FB_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            simpleDriverStruct("NV0080_CTRL_GPU_GET_NUM_SUBDEVICES_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    simpleDriverStruct("NV0080_CTRL_GPU_QUERY_SW_STATE_PERSISTENCE_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       simpleDriverStruct("NV0080_CTRL_GPU_GET_VIRTUALIZATION_MODE_PARAMS"),
							0x80028b: nil, // unknown, paramsSize == 1
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             simpleDriverStruct("NV0080_CTRL_GPU_GET_CLASSLIST_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 simpleDriverStruct("NV0080_CTRL_HOST_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_BSP_GET_CAPS_V2:                                  simpleDriverStruct("NV0080_CTRL_BSP_GET_CAPS_PARAMS_V2"),
							nvgpu.NV0080_CTRL_CMD_NVJPG_GET_CAPS_V2:                                simpleDriverStruct("NV0080_CTRL_NVJPG_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_ENGINE_CONTEXT_PROPERTIES:               simpleDriverStruct("NV0080_CTRL_FIFO_GET_ENGINE_CONTEXT_PROPERTIES_PARAMS"),
							nvgpu.NV00F8_CTRL_CMD_ATTACH_MEM:                                       simpleDriverStruct("NV00F8_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_GET_INFO:                                         simpleDriverStruct("NV00FD_CTRL_GET_INFO_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_MEM:                                       simpleDriverStruct("NV00FD_CTRL_ATTACH_MEM_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_DETACH_MEM:                                       simpleDriverStruct("NV00FD_CTRL_DETACH_MEM_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 simpleDriverStruct("NV2080_CTRL_BUS_GET_PCI_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             simpleDriverStruct("NV2080_CTRL_BUS_GET_PCI_BAR_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO:                                     driverStructWithName(nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_BUS_GET_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  simpleDriverStruct("NV2080_CTRL_BUS_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               simpleDriverStruct("NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BUS_GET_C2C_INFO:                                 simpleDriverStruct("NV2080_CTRL_CMD_BUS_GET_C2C_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_CE_PCE_MASK:                               simpleDriverStruct("NV2080_CTRL_CE_GET_CE_PCE_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_CE_GET_CAPS_V2:                                   simpleDriverStruct("NV2080_CTRL_CE_GET_CAPS_V2_PARAMS"),
							0x20810107:                                                             nil, // unknown, paramsSize == TODO(ayushranjan)
							nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  simpleDriverStruct("NV2080_CTRL_CE_GET_ALL_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION:                           simpleDriverStruct("NV2080_CTRL_EVENT_SET_NOTIFICATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   simpleDriverStruct("NV2080_CTRL_FB_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_GPU_CACHE_INFO:                            simpleDriverStruct("NV2080_CTRL_FB_GET_GPU_CACHE_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO:                            simpleDriverStruct("NV2080_CTRL_CMD_FB_GET_FB_REGION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FB_GET_SEMAPHORE_SURFACE_LAYOUT:                  simpleDriverStruct("NV2080_CTRL_FB_GET_SEMAPHORE_SURFACE_LAYOUT_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  simpleDriverStruct("NV2080_CTRL_GPU_GET_INFO_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE:                         simpleDriverStruct("NV2080_CTRL_FLCN_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              simpleDriverStruct("NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        simpleDriverStruct("NV2080_CTRL_GPU_GET_SHORT_NAME_STRING_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          simpleDriverStruct("NV2080_CTRL_GPU_GET_SIMULATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             simpleDriverStruct("NV2080_CTRL_GPU_QUERY_ECC_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     simpleDriverStruct("NV2080_CTRL_GPU_QUERY_COMPUTE_MODE_RULES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ID:                                       simpleDriverStruct("NV2080_CTRL_GPU_GET_ID_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION:                      simpleDriverStruct("NV2080_CTRL_GPU_QUERY_ECC_CONFIGURATION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO:                           simpleDriverStruct("NV2080_CTRL_GPU_GET_OEM_BOARD_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             nil, // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             nil, // undocumented; paramSize == 0
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST:                       simpleDriverStruct("NV2080_CTRL_GPU_GET_ENGINE_PARTNERLIST_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 simpleDriverStruct("NV2080_CTRL_GPU_GET_GID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION:                   simpleDriverStruct("NV2080_CTRL_GPU_GET_INFOROM_OBJECT_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION:                    simpleDriverStruct("NV2080_CTRL_GPU_GET_INFOROM_IMAGE_VERSION_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT:                    nil, // No params.
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENCODER_CAPACITY:                         simpleDriverStruct("NV2080_CTRL_GPU_GET_ENCODER_CAPACITY_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               simpleDriverStruct("NV2080_CTRL_GPU_GET_ENGINES_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     simpleDriverStruct("NV2080_CTRL_GPU_GET_ACTIVE_PARTITION_IDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PIDS:                                     simpleDriverStruct("NV2080_CTRL_GPU_GET_PIDS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_PID_INFO:                                 simpleDriverStruct("NV2080_CTRL_GPU_GET_PID_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    simpleDriverStruct("NV2080_CTRL_GPU_GET_COMPUTE_POLICY_CONFIG_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        simpleDriverStruct("NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_ZCULL_INFO:                                simpleDriverStruct("NV2080_CTRL_GR_GET_ZCULL_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_CTXSW_ZCULL_BIND:                              simpleDriverStruct("NV2080_CTRL_GR_CTXSW_ZCULL_BIND_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     simpleDriverStruct("NV2080_CTRL_GR_SET_CTXSW_PREEMPTION_MODE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           simpleDriverStruct("NV2080_CTRL_GR_GET_CTX_BUFFER_SIZE_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           simpleDriverStruct("NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   simpleDriverStruct("NV2080_CTRL_GR_GET_CAPS_V2_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  simpleDriverStruct("NV2080_CTRL_GR_GET_GPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  simpleDriverStruct("NV2080_CTRL_GR_GET_TPC_MASK_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER:                    simpleDriverStruct("NV2080_CTRL_GR_GET_SM_ISSUE_RATE_MODIFIER_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO:                             simpleDriverStruct("NV2080_CTRL_GRMGR_GET_GR_FS_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 simpleDriverStruct("NV2080_CTRL_GSP_GET_FEATURES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 simpleDriverStruct("NV2080_CTRL_MC_GET_ARCH_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            simpleDriverStruct("NV2080_CTRL_MC_SERVICE_INTERRUPTS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS:                           simpleDriverStruct("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         simpleDriverStruct("NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       simpleDriverStruct("NV2080_CTRL_PERF_BOOST_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             simpleDriverStruct("NV2080_CTRL_RC_GET_WATCHDOG_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     nil, // No params.
							nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         nil, // No params.
							nvgpu.NV2080_CTRL_CMD_TIMER_GET_TIME:                                   simpleDriverStruct("NV2080_CTRL_TIMER_GET_TIME_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          simpleDriverStruct("NV2080_CTRL_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ:                           simpleDriverStruct("NV2080_CTRL_CMD_TIMER_SET_GR_TICK_FREQ_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  simpleDriverStruct("NV503C_CTRL_REGISTER_VIDMEM_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                simpleDriverStruct("NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         simpleDriverStruct("NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   simpleDriverStruct("NV83DE_CTRL_DEBUG_READ_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  simpleDriverStruct("NV83DE_CTRL_DEBUG_CLEAR_ALL_SM_ERROR_STATES_PARAMS"),
							nvgpu.NV906F_CTRL_GET_CLASS_ENGINEID:                                   simpleDriverStruct("NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    simpleDriverStruct("NV906F_CTRL_CMD_RESET_CHANNEL_PARAMS"),
							nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_SIZE:                         simpleDriverStruct("NV9096_CTRL_GET_ZBC_CLEAR_TABLE_SIZE_PARAMS"),
							nvgpu.NV9096_CTRL_CMD_GET_ZBC_CLEAR_TABLE_ENTRY:                        simpleDriverStruct("NV9096_CTRL_GET_ZBC_CLEAR_TABLE_ENTRY_PARAMS"),
							nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: simpleDriverStruct("NV90E6_CTRL_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK_PARAMS"),
							nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   simpleDriverStruct("NVC36F_CTRL_GET_CLASS_ENGINEID_PARAMS"),
							nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     simpleDriverStruct("NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS"),
							nvgpu.NVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX:         simpleDriverStruct("NVC36F_CTRL_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES:                 simpleDriverStruct("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE:                   simpleDriverStruct("NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE_PARAMS"),
							nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS:             simpleDriverStruct("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleDriverStruct("NVA06C_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    simpleDriverStruct("NVA06C_CTRL_SET_TIMESLICE_PARAMS"),
							nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          simpleDriverStruct("NVA06C_CTRL_PREEMPT_PARAMS"),
							nvgpu.NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:                                  simpleDriverStruct("NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS"),
							nvgpu.NVA06F_CTRL_CMD_BIND:                                             simpleDriverStruct("NVA06F_CTRL_BIND_PARAMS"),
							nvgpu.NVC56F_CTRL_CMD_GET_KMB:                                          simpleDriverStruct("NVC56F_CTRL_CMD_GET_KMB_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                                  driverStructs(nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         driverStructs(nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST:                                driverStructWithName(nvgpu.RmapiParamNvU32List{}, "NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS:                                      driverStructWithName(nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_GR_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_CAPS_V2:                                   simpleDriverStruct("NV0080_CTRL_GR_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_GR_GET_INFO:                                      driverStructWithName(nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV0080_CTRL_GR_GET_INFO_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS:                                      driverStructWithName(nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_FB_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS:                                    driverStructWithName(nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_FIFO_GET_CAPS_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CAPS_V2:                                 simpleDriverStruct("NV0080_CTRL_FIFO_GET_CAPS_V2_PARAMS"),
							nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             driverStructs(nvgpu.NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS{}),
							nvgpu.NV0080_CTRL_CMD_MSENC_GET_CAPS:                                   driverStructWithName(nvgpu.NV0080_CTRL_GET_CAPS_PARAMS{}, "NV0080_CTRL_MSENC_GET_CAPS_PARAMS"),
							nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:                              driverStructs(nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD:                      driverStructs(nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD:                    driverStructs(nvgpu.NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS{}),
							nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO:                   driverStructs(nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS{}),
							nvgpu.NV0041_CTRL_CMD_GET_SURFACE_INFO:                                 driverStructWithName(nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV0041_CTRL_GET_SURFACE_INFO_PARAMS"),
							nvgpu.NV00FD_CTRL_CMD_ATTACH_GPU:                                       driverStructs(nvgpu.NV00FD_CTRL_ATTACH_GPU_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES:                                  driverStructWithName(nvgpu.RmapiParamNvU32List{}, "NV2080_CTRL_GPU_GET_ENGINES_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_BIOS_GET_INFO:                                    driverStructWithName(nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_BIOS_GET_INFO_PARAMS"),
							nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            driverStructs(nvgpu.NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      driverStructs(nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS{}),
							nvgpu.NV2080_CTRL_CMD_FB_GET_INFO:                                      driverStructWithName(nvgpu.NvxxxCtrlXxxGetInfoParams{}, "NV2080_CTRL_FB_GET_INFO_PARAMS"),
							nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                driverStructs(nvgpu.NV503C_CTRL_REGISTER_VA_SPACE_PARAMS{}),
						},
						allocationStructs: map[nvgpu.ClassID][]DriverStruct{
							nvgpu.NV01_ROOT:                  driverStructWithName(nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_ROOT_NON_PRIV:         driverStructWithName(nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_CONTEXT_DMA:           driverStructs(nvgpu.NV_CONTEXT_DMA_ALLOCATION_PARAMS{}),
							nvgpu.NV01_MEMORY_SYSTEM:         driverStructs(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_MEMORY_LOCAL_USER:     driverStructs(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV01_ROOT_CLIENT:           driverStructWithName(nvgpu.Handle{}, "NvHandle"),
							nvgpu.NV01_EVENT_OS_EVENT:        driverStructs(nvgpu.NV0005_ALLOC_PARAMETERS{}),
							nvgpu.NV01_MEMORY_VIRTUAL:        driverStructs(nvgpu.NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS{}),
							nvgpu.NV01_DEVICE_0:              driverStructs(nvgpu.NV0080_ALLOC_PARAMETERS{}),
							nvgpu.RM_USER_SHARED_DATA:        driverStructs(nvgpu.NV00DE_ALLOC_PARAMETERS{}),
							nvgpu.NV_MEMORY_FABRIC:           driverStructs(nvgpu.NV00F8_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_MEMORY_MULTICAST_FABRIC: driverStructs(nvgpu.NV00FD_ALLOCATION_PARAMETERS{}),
							nvgpu.NV20_SUBDEVICE_0:           driverStructs(nvgpu.NV2080_ALLOC_PARAMETERS{}),
							nvgpu.NV2081_BINAPI:              driverStructs(nvgpu.NV2081_ALLOC_PARAMETERS{}),
							nvgpu.NV50_MEMORY_VIRTUAL:        driverStructs(nvgpu.NV_MEMORY_ALLOCATION_PARAMS{}),
							nvgpu.NV50_P2P:                   driverStructs(nvgpu.NV503B_ALLOC_PARAMETERS{}),
							nvgpu.NV50_THIRD_PARTY_P2P:       driverStructs(nvgpu.NV503C_ALLOC_PARAMETERS{}),
							nvgpu.GT200_DEBUGGER:             driverStructs(nvgpu.NV83DE_ALLOC_PARAMETERS{}),
							nvgpu.GF100_PROFILER:             nil, // No params
							nvgpu.FERMI_TWOD_A:               driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.FERMI_CONTEXT_SHARE_A:      driverStructs(nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS{}),
							nvgpu.GF100_DISP_SW:              driverStructs(nvgpu.NV9072_ALLOCATION_PARAMETERS{}),
							nvgpu.GF100_ZBC_CLEAR:            nil, // No params
							nvgpu.FERMI_VASPACE_A:            driverStructs(nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS{}),
							nvgpu.KEPLER_CHANNEL_GROUP_A:     driverStructs(nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS{}),
							nvgpu.KEPLER_INLINE_TO_MEMORY_B:  driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.VOLTA_USERMODE_A:           nil, // No params
							nvgpu.TURING_CHANNEL_GPFIFO_A:    driverStructs(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.NVB8B0_VIDEO_DECODER:       driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC4B0_VIDEO_DECODER:       driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC6B0_VIDEO_DECODER:       driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC7B0_VIDEO_DECODER:       driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC9B0_VIDEO_DECODER:       driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC4B7_VIDEO_ENCODER:       driverStructs(nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC7B7_VIDEO_ENCODER:       driverStructs(nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.NVC9B7_VIDEO_ENCODER:       driverStructs(nvgpu.NV_MSENC_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_CHANNEL_GPFIFO_A:    driverStructs(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.HOPPER_CHANNEL_GPFIFO_A:    driverStructs(nvgpu.NV_CHANNEL_ALLOC_PARAMS{}),
							nvgpu.TURING_A:                   driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_A:                   driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.ADA_A:                      driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_A:                   driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_DMA_COPY_A:          driverStructs(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_A:          driverStructs(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_DMA_COPY_B:          driverStructs(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_DMA_COPY_A:          driverStructs(nvgpu.NVB0B5_ALLOCATION_PARAMETERS{}),
							nvgpu.TURING_COMPUTE_A:           driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_A:           driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.AMPERE_COMPUTE_B:           driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.ADA_COMPUTE_A:              driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.NV_CONFIDENTIAL_COMPUTE:    driverStructs(nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS{}),
							nvgpu.HOPPER_COMPUTE_A:           driverStructs(nvgpu.NV_GR_ALLOCATION_PARAMETERS{}),
							nvgpu.HOPPER_USERMODE_A:          driverStructs(nvgpu.NV_HOPPER_USERMODE_A_PARAMS{}),
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
		v535_216_01 := addDriverABI(535, 216, 01, "5ddea1147810012e33967c3181341bcd6624bd3d654c63f845df833b4ece6af7", v535_183_06)
		_ = addDriverABI(535, 230, 02, "20cca9118083fcc8083158466e9cb2b616a7922206bcb7296b1fa5cc9af2e0fd", v535_216_01)

		// 545.23.06 is an intermediate unqualified version from the main branch.
		v545_23_06 := func() *driverABI {
			abi := v535_113_01()
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = ctrlHandler(ctrlHasFrontendFD[nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545], compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS] = ctrlHandler(rmControlSimple, compUtil)
			abi.allocationClass[nvgpu.RM_USER_SHARED_DATA] = allocHandler(rmAllocSimple[nvgpu.NV00DE_ALLOC_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = allocHandler(rmAllocSimple[nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_SYSTEM] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV01_MEMORY_LOCAL_USER] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)
			abi.allocationClass[nvgpu.NV50_MEMORY_VIRTUAL] = allocHandler(rmAllocSimple[nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545], compUtil)

			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.controlStructs[nvgpu.NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO] = driverStructWithName(nvgpu.NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545{}, "NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS")
				structs.controlStructs[nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS] = simpleDriverStruct("NV0000_CTRL_GPU_GET_ACTIVE_DEVICE_IDS_PARAMS")
				structs.allocationStructs[nvgpu.RM_USER_SHARED_DATA] = driverStructWithName(nvgpu.NV00DE_ALLOC_PARAMETERS_V545{}, "NV00DE_ALLOC_PARAMETERS")
				structs.allocationStructs[nvgpu.NV_MEMORY_MULTICAST_FABRIC] = driverStructWithName(nvgpu.NV00FD_ALLOCATION_PARAMETERS_V545{}, "NV00FD_ALLOCATION_PARAMETERS")
				structs.allocationStructs[nvgpu.NV01_MEMORY_SYSTEM] = driverStructWithName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				structs.allocationStructs[nvgpu.NV01_MEMORY_LOCAL_USER] = driverStructWithName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				structs.allocationStructs[nvgpu.NV50_MEMORY_VIRTUAL] = driverStructWithName(nvgpu.NV_MEMORY_ALLOCATION_PARAMS_V545{}, "NV_MEMORY_ALLOCATION_PARAMS")
				return structs
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
			abi.controlCmd[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = ctrlHandler(rmControlSimple, compUtil) // NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS
			abi.controlCmd[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = ctrlHandler(rmControlSimple, compUtil)
			// NV2081_BINAPI forwards all control commands to the GSP in
			// src/nvidia/src/kernel/rmapi/binary_api.c:binapiControl_IMPL().
			abi.controlCmd[(nvgpu.NV2081_BINAPI<<16)|0x0108] = ctrlHandler(rmControlSimple, compUtil)
			abi.controlCmd[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = ctrlHandler(ctrlClientSystemGetP2PCapsV550, compUtil)
			abi.uvmIoctl[nvgpu.UVM_SET_PREFERRED_LOCATION] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MIGRATE] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_MIGRATE_PARAMS_V550], compUtil)
			abi.allocationClass[nvgpu.NVENC_SW_SESSION] = allocHandler(rmAllocSimple[nvgpu.NVA0BC_ALLOC_PARAMETERS], nvconf.CapVideo)

			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.frontendStructs[nvgpu.NV_ESC_WAIT_OPEN_COMPLETE] = driverStructWithName(nvgpu.IoctlWaitOpenComplete{}, "nv_ioctl_wait_open_complete_t")
				structs.frontendStructs[nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA] = driverStructWithName(nvgpu.NVOS47_PARAMETERS_V550{}, "NVOS47_PARAMETERS")
				structs.controlStructs[nvgpu.NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID] = simpleDriverStruct("NV0000_CTRL_GPU_ASYNC_ATTACH_ID_PARAMS")
				structs.controlStructs[nvgpu.NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID] = simpleDriverStruct("NV0000_CTRL_GPU_WAIT_ATTACH_ID_PARAMS")
				structs.controlStructs[nvgpu.NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL] = simpleDriverStruct("NV0080_CTRL_PERF_CUDA_LIMIT_CONTROL_PARAMS")
				structs.controlStructs[nvgpu.NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE] = simpleDriverStruct("NV2080_CTRL_PERF_GET_CURRENT_PSTATE_PARAMS")
				// NV2081_BINAPI forwards all control commands to the GSP in
				// src/nvidia/src/kernel/rmapi/binary_api.c:binapiControl_IMPL().
				// As such, there are no structs defined in the driver for this.
				structs.controlStructs[(nvgpu.NV2081_BINAPI<<16)|0x0108] = nil
				structs.controlStructs[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS] = driverStructWithName(nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550{}, "NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS")
				structs.uvmStructs[nvgpu.UVM_SET_PREFERRED_LOCATION] = driverStructWithName(nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550{}, "UVM_SET_PREFERRED_LOCATION_PARAMS")
				structs.uvmStructs[nvgpu.UVM_MIGRATE] = driverStructWithName(nvgpu.UVM_MIGRATE_PARAMS_V550{}, "UVM_MIGRATE_PARAMS")
				structs.allocationStructs[nvgpu.NVENC_SW_SESSION] = driverStructs(nvgpu.NVA0BC_ALLOC_PARAMETERS{})
				return structs
			}

			return abi
		}

		v550_54_14 := addDriverABI(550, 54, 14, "8c497ff1cfc7c310fb875149bc30faa4fd26d2237b2cba6cd2e8b0780157cfe3", func() *driverABI {
			abi := v550_40_07()
			abi.uvmIoctl[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = uvmHandler(uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550], compUtil)
			abi.uvmIoctl[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = uvmHandler(uvmIoctlHasFrontendFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550], compUtil)

			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.uvmStructs[nvgpu.UVM_ALLOC_SEMAPHORE_POOL] = driverStructWithName(nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550{}, "UVM_ALLOC_SEMAPHORE_POOL_PARAMS")
				structs.uvmStructs[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION] = driverStructWithName(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550{}, "UVM_MAP_EXTERNAL_ALLOCATION_PARAMS")
				return structs
			}

			return abi
		})

		v550_54_15 := addDriverABI(550, 54, 15, "2e859ae5f912a9a47aaa9b2d40a94a14f6f486b5d3b67c0ddf8b72c1c9650385", v550_54_14)

		v550_90_07 := addDriverABI(550, 90, 07, "51acf579d5a9884f573a1d3f522e7fafa5e7841e22a9cec0b4bbeae31b0b9733", func() *driverABI {
			abi := v550_54_15()
			abi.controlCmd[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = ctrlHandler(rmControlSimple, compUtil)

			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.controlStructs[nvgpu.NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE] = simpleDriverStruct("NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_KEY_ROTATION_STATE_PARAMS")
				return structs
			}

			return abi
		})

		// This version does not belong on any branch, but it is a child of 550.90.07.
		_ = addDriverABI(550, 90, 12, "391883846713b9e700af2ae87f8ac671f5527508ce3f9f60058deb363e05162a", v550_90_07)

		// 550.100 is an intermediate unqualified version from the main branch.
		v550_100 := v550_90_07

		// The following exist on the "550" branch. They branched off the main
		// branch at 550.100.
		_ = addDriverABI(550, 127, 05, "d384f34f5d2a896bd7536d3deb6a6d973d8094a3ad485a1c2ee3bf5192086ae9", v550_100)

		// 555.42.02 is an intermediate unqualified version.
		v555_42_02 := func() *driverABI {
			abi := v550_90_07()
			// NVC36F_CTRL_GET_CLASS_ENGINEID was deleted in 555.42.02:
			// https://github.com/NVIDIA/open-gpu-kernel-modules/commit/5a1c474040e1c3ed20760267510cc9d9332898f1
			delete(abi.controlCmd, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				delete(structs.controlStructs, nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID)
				return structs
			}
			return abi
		}

		// 560.28.03 is an intermediate unqualified version from the main branch.
		v560_28_03 := func() *driverABI {
			abi := v555_42_02()
			abi.allocationClass[nvgpu.NVCDB0_VIDEO_DECODER] = allocHandler(rmAllocSimple[nvgpu.NV_BSP_ALLOCATION_PARAMETERS], nvconf.CapVideo)
			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.allocationStructs[nvgpu.NVCDB0_VIDEO_DECODER] = driverStructs(nvgpu.NV_BSP_ALLOCATION_PARAMETERS{})
				return structs
			}
			return abi
		}

		v560_35_03 := addDriverABI(560, 35, 03, "f2932c92fadd43c5b2341be453fc4f73f0ad7185c26bb7a43fbde81ae29f1fe3", v560_28_03)
		v565_57_01 := addDriverABI(565, 57, 01, "6eebe94e585e385e8804f5a74152df414887bf819cc21bd95b72acd0fb182c7a", v560_35_03)

		_ = addDriverABI(570, 86, 15, "87709c19c7401243136bc0ec9e7f147c6803070a11449ae8f0819dee7963f76b", func() *driverABI {
			abi := v565_57_01()
			abi.allocationClass[nvgpu.TURING_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.AMPERE_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)
			abi.allocationClass[nvgpu.HOPPER_CHANNEL_GPFIFO_A] = allocHandler(rmAllocChannelV570, compUtil)

			prevStructs := abi.getStructs
			abi.getStructs = func() *driverABIStructs {
				structs := prevStructs()
				structs.allocationStructs[nvgpu.TURING_CHANNEL_GPFIFO_A] = driverStructWithName(nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				structs.allocationStructs[nvgpu.AMPERE_CHANNEL_GPFIFO_A] = driverStructWithName(nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				structs.allocationStructs[nvgpu.HOPPER_CHANNEL_GPFIFO_A] = driverStructWithName(nvgpu.NV_CHANNEL_ALLOC_PARAMS_V570{}, "NV_CHANNEL_ALLOC_PARAMS")
				return structs
			}
			return abi
		})
	})
}

// simpleDriverStruct constructs DriverStructs for simple ioctls (for whom
// nvproxy doesn't define a struct).
func simpleDriverStruct(names ...string) []DriverStruct {
	res := make([]DriverStruct, 0, len(names))
	for _, name := range names {
		res = append(res, DriverStruct{
			Name: name,
			Type: nil,
		})
	}
	return res
}

// driverStructs takes an instance of an nvproxy struct and initializes a
// DriverStruct using its name.
func driverStructs(params ...any) []DriverStruct {
	res := make([]DriverStruct, 0, len(params))
	for _, param := range params {
		paramType := reflect.TypeOf(param)
		res = append(res, newDriverStruct(paramType, paramType.Name()))
	}
	return res
}

func driverStructWithName(param any, name string) []DriverStruct {
	paramType := reflect.TypeOf(param)
	return []DriverStruct{newDriverStruct(paramType, name)}
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
	names := abi.getStructs()

	var allNames []DriverStructName
	addNames := func(names []DriverStruct) {
		for _, name := range names {
			allNames = append(allNames, name.Name)
		}
	}

	for _, names := range names.frontendStructs {
		addNames(names)
	}
	for _, names := range names.uvmStructs {
		addNames(names)
	}
	for _, names := range names.controlStructs {
		addNames(names)
	}
	for _, names := range names.allocationStructs {
		addNames(names)
	}

	return allNames, true
}

// SupportedStructTypes returns the list of struct types supported by the given driver version.
// It merges the frontend, uvm, control, and allocation names into one slice.
func SupportedStructTypes(version DriverVersion) ([]DriverStruct, bool) {
	abiCons, ok := abis[version]
	if !ok {
		return nil, false
	}
	abi := abiCons.cons()
	structs := abi.getStructs()

	var allStructs []DriverStruct
	for _, s := range structs.frontendStructs {
		allStructs = append(allStructs, s...)
	}
	for _, s := range structs.uvmStructs {
		allStructs = append(allStructs, s...)
	}
	for _, s := range structs.controlStructs {
		allStructs = append(allStructs, s...)
	}
	for _, s := range structs.allocationStructs {
		allStructs = append(allStructs, s...)
	}

	return allStructs, true
}
