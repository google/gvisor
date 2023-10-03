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

package nvgpu

// From src/nvidia/interface/deprecated/rmapi_deprecated.h:
const (
	RM_GSS_LEGACY_MASK = 0x00008000
)

// From src/common/sdk/nvidia/inc/ctrl/ctrlxxxx.h:

// +marshal
type NVXXXX_CTRL_XXX_INFO struct {
	Index uint32
	Data  uint32
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000client.h:
const (
	NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE        = 0xd01
	NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY = 0xd04
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h:
const (
	NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS  = 0x201
	NV0000_CTRL_CMD_GPU_GET_ID_INFO       = 0x202
	NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2    = 0x205
	NV0000_CTRL_CMD_GPU_GET_PROBED_IDS    = 0x214
	NV0000_CTRL_CMD_GPU_ATTACH_IDS        = 0x215
	NV0000_CTRL_CMD_GPU_DETACH_IDS        = 0x216
	NV0000_CTRL_CMD_GPU_GET_PCI_INFO      = 0x21b
	NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE = 0x279
	NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE  = 0x27b
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000syncgpuboost.h:
const (
	NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO = 0xa04
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000system.h:
const (
	NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION   = 0x101
	NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS        = 0x127
	NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS   = 0x136
	NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX = 0x13a
)

// +marshal
type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS struct {
	SizeOfStrings            uint32
	Pad                      [4]byte
	PDriverVersionBuffer     P64
	PVersionBuffer           P64
	PTitleBuffer             P64
	ChangelistNumber         uint32
	OfficialChangelistNumber uint32
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080fb.h:
const (
	NV0080_CTRL_CMD_FB_GET_CAPS_V2 = 0x801307
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080fifo.h:
const (
	NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST = 0x80170d
)

// +marshal
type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS struct {
	NumChannels        uint32
	Pad                [4]byte
	PChannelHandleList P64
	PChannelList       P64
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080gpu.h:
const (
	NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES         = 0x800280
	NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE = 0x800288
	NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE    = 0x800289
	NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2           = 0x800292
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080gr.h:

// +marshal
type NV0080_CTRL_GR_ROUTE_INFO struct {
	Flags uint32
	Pad   [4]byte
	Route uint64
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080host.h:
const (
	NV0080_CTRL_CMD_HOST_GET_CAPS_V2 = 0x801402
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080bus.h:
const (
	NV2080_CTRL_CMD_BUS_GET_PCI_INFO                   = 0x20801801
	NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO               = 0x20801803
	NV2080_CTRL_CMD_BUS_GET_INFO_V2                    = 0x20801823
	NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS = 0x2080182a
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080ce.h:
const (
	NV2080_CTRL_CMD_CE_GET_ALL_CAPS = 0x20802a0a
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080fb.h:
const (
	NV2080_CTRL_CMD_FB_GET_INFO_V2 = 0x20801303
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080fifo.h:
const (
	NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS = 0x2080110b

	NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES = 64
)

// +marshal
type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS struct {
	BDisable               uint8
	Pad1                   [3]byte
	NumChannels            uint32
	BOnlyDisableScheduling uint8
	BRewindGpPut           uint8
	Pad2                   [6]byte
	PRunlistPreemptEvent   P64
	HClientList            [NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES]Handle
	HChannelList           [NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES]Handle
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080gpu.h:
const (
	NV2080_CTRL_CMD_GPU_GET_INFO_V2                      = 0x20800102
	NV2080_CTRL_CMD_GPU_GET_NAME_STRING                  = 0x20800110
	NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING            = 0x20800111
	NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO              = 0x20800119
	NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS                 = 0x2080012f
	NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES         = 0x20800131
	NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION = 0x20800145 // undocumented; paramSize == 0
	NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION = 0x20800146 // undocumented; paramSize == 0
	NV2080_CTRL_CMD_GPU_GET_GID_INFO                     = 0x2080014a
	NV2080_CTRL_CMD_GPU_GET_ENGINES_V2                   = 0x20800170
	NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS         = 0x2080018b
	NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG        = 0x20800195
	NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO            = 0x208001a3
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080gr.h:
const (
	NV2080_CTRL_CMD_GR_GET_INFO                  = 0x20801201
	NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE = 0x20801210
	NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE       = 0x20801218
	NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER       = 0x2080121b
	NV2080_CTRL_CMD_GR_GET_CAPS_V2               = 0x20801227
	NV2080_CTRL_CMD_GR_GET_GPC_MASK              = 0x2080122a
	NV2080_CTRL_CMD_GR_GET_TPC_MASK              = 0x2080122b
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080gsp.h:
const (
	NV2080_CTRL_CMD_GSP_GET_FEATURES = 0x20803601
)

// +marshal
type NV2080_CTRL_GR_GET_INFO_PARAMS struct {
	GRInfoListSize uint32 // in elements
	Pad            [4]byte
	GRInfoList     P64
	GRRouteInfo    NV0080_CTRL_GR_ROUTE_INFO
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h:
const (
	NV2080_CTRL_CMD_MC_GET_ARCH_INFO      = 0x20801701
	NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS = 0x20801702
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080nvlink.h:
const (
	NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS = 0x20803002
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080perf.h:
const (
	NV2080_CTRL_CMD_PERF_BOOST = 0x2080200a
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080rc.h:
const (
	NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO         = 0x20802209
	NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS = 0x2080220c
	NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG     = 0x20802210
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080tmr.h:
const (
	NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO = 0x20800406
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl503c.h:
const (
	NV503C_CTRL_CMD_REGISTER_VA_SPACE = 0x503c0102
	NV503C_CTRL_CMD_REGISTER_VIDMEM   = 0x503c0104
	NV503C_CTRL_CMD_UNREGISTER_VIDMEM = 0x503c0105
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl83de/ctrl83dedebug.h:
const (
	NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK        = 0x83de0309
	NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES  = 0x83de030c
	NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES = 0x83de0310
)

// From src/common/sdk/nvidia/inc/ctrl/ctrlc36f.h:
const (
	NVC36F_CTRL_GET_CLASS_ENGINEID               = 0xc36f0101
	NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN = 0xc36f0108
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl906f.h:
const (
	NV906F_CTRL_CMD_RESET_CHANNEL = 0x906f0102
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl90e6.h:
const (
	NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK = 0x90e60102
)

// From src/common/sdk/nvidia/inc/ctrl/ctrla06c.h:
const (
	NVA06C_CTRL_CMD_GPFIFO_SCHEDULE = 0xa06c0101
	NVA06C_CTRL_CMD_SET_TIMESLICE   = 0xa06c0103
	NVA06C_CTRL_CMD_PREEMPT         = 0xa06c0105
)
