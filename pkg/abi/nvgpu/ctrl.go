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

// From src/nvidia/inc/kernel/rmapi/param_copy.h:
const (
	// RMAPI_PARAM_COPY_MAX_PARAMS_SIZE is the size limit imposed while copying
	// "embedded pointers" in rmapi parameter structs.
	// See src/nvidia/src/kernel/rmapi/param_copy.c:rmapiParamsAcquire().
	RMAPI_PARAM_COPY_MAX_PARAMS_SIZE = 1 * 1024 * 1024
)

// From src/common/sdk/nvidia/inc/ctrl/ctrlxxxx.h:

// NVXXXX_CTRL_XXX_INFO is typedef-ed as the following in the driver:
// - NV2080_CTRL_GR_INFO
// - NV2080_CTRL_BIOS_INFO
// - NV0041_CTRL_SURFACE_INFO
//
// +marshal slice:CtrlXxxInfoSlice
type NVXXXX_CTRL_XXX_INFO struct {
	Index uint32
	Data  uint32
}

// CtrlXxxInfoSize is sizeof(NVXXXX_CTRL_XXX_INFO).
var CtrlXxxInfoSize = uint32((*NVXXXX_CTRL_XXX_INFO)(nil).SizeBytes())

// HasCtrlInfoList is a type constraint for parameter structs containing a list
// of NVXXXX_CTRL_XXX_INFO and are simple otherwise.
type HasCtrlInfoList interface {
	ListSize() uint32
	SetCtrlInfoList(ptr P64)
	CtrlInfoList() P64
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
	NV0000_CTRL_CMD_GPU_ASYNC_ATTACH_ID   = 0x289
	NV0000_CTRL_CMD_GPU_WAIT_ATTACH_ID    = 0x290
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000syncgpuboost.h:
const (
	NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO = 0xa04
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000system.h:
const (
	NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION   = 0x101
	NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS        = 0x127
	NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2     = 0x12b
	NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS   = 0x136
	NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX = 0x13a
	NV0000_CTRL_CMD_SYSTEM_GET_FEATURES        = 0x1f0
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000unix.h:
const (
	NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD    = 0x3d05
	NV0000_CTRL_CMD_OS_UNIX_IMPORT_OBJECT_FROM_FD  = 0x3d06
	NV0000_CTRL_CMD_OS_UNIX_GET_EXPORT_OBJECT_INFO = 0x3d08
	NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE    = 64
)

// +marshal
type NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS struct {
	FD             int32
	DeviceInstance uint32
	MaxObjects     uint16
	Pad            [2]byte
	Metadata       [NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE]uint8
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) GetFrontendFD() int32 {
	return p.FD
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) SetFrontendFD(fd int32) {
	p.FD = fd
}

// +marshal
type NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545 struct {
	FD             int32
	DeviceInstance uint32
	GpuInstanceID  uint32
	MaxObjects     uint16
	Pad            [2]byte
	Metadata       [NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE]uint8
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) GetFrontendFD() int32 {
	return p.FD
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) SetFrontendFD(fd int32) {
	p.FD = fd
}

// +marshal
type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT struct {
	Type uint32 // enum NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TYPE
	// These fields are inside union `data`, in struct `rmObject`.
	HDevice Handle
	HParent Handle
	HObject Handle
}

// +marshal
type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS struct {
	Object NV0000_CTRL_OS_UNIX_EXPORT_OBJECT
	FD     int32
	Flags  uint32
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) GetFrontendFD() int32 {
	return p.FD
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) SetFrontendFD(fd int32) {
	p.FD = fd
}

// +marshal
type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS struct {
	FD     int32
	Object NV0000_CTRL_OS_UNIX_EXPORT_OBJECT
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) GetFrontendFD() int32 {
	return p.FD
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) SetFrontendFD(fd int32) {
	p.FD = fd
}

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

// From src/common/sdk/nvidia/inc/ctrl/ctrl0041.h
const (
	NV0041_CTRL_CMD_GET_SURFACE_INFO = 0x410110
)

// +marshal
type NV0041_CTRL_GET_SURFACE_INFO_PARAMS struct {
	SurfaceInfoListSize uint32
	Pad                 [4]byte
	SurfaceInfoList     P64
}

// ListSize implements HasCtrlInfoList.ListSize.
func (p *NV0041_CTRL_GET_SURFACE_INFO_PARAMS) ListSize() uint32 {
	return p.SurfaceInfoListSize
}

// SetCtrlInfoList implements HasCtrlInfoList.SetCtrlInfoList.
func (p *NV0041_CTRL_GET_SURFACE_INFO_PARAMS) SetCtrlInfoList(ptr P64) {
	p.SurfaceInfoList = ptr
}

// CtrlInfoList implements HasCtrlInfoList.CtrlInfoList.
func (p *NV0041_CTRL_GET_SURFACE_INFO_PARAMS) CtrlInfoList() P64 {
	return p.SurfaceInfoList
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
	NV0080_CTRL_CMD_GPU_GET_CLASSLIST              = 0x800201
	NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES         = 0x800280
	NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE = 0x800288
	NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE    = 0x800289
	NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2           = 0x800292
)

// +marshal
type NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS struct {
	NumClasses uint32
	Pad        [4]byte
	ClassList  P64
}

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

// From src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080perf.h:
const (
	NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL = 0x801909
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl00fd.h:
const (
	NV00FD_CTRL_CMD_GET_INFO   = 0xfd0101
	NV00FD_CTRL_CMD_ATTACH_MEM = 0xfd0102
	NV00FD_CTRL_CMD_ATTACH_GPU = 0xfd0104
	NV00FD_CTRL_CMD_DETACH_MEM = 0xfd0105
)

// +marshal
type NV00FD_CTRL_ATTACH_GPU_PARAMS struct {
	HSubDevice    Handle
	Flags         uint32
	DevDescriptor uint64
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080bios.h:
const (
	NV2080_CTRL_CMD_BIOS_GET_INFO = 0x20800802
)

// +marshal
type NV2080_CTRL_BIOS_GET_INFO_PARAMS struct {
	BiosInfoListSize uint32
	Pad              [4]byte
	BiosInfoList     P64
}

// ListSize implements HasCtrlInfoList.ListSize.
func (p *NV2080_CTRL_BIOS_GET_INFO_PARAMS) ListSize() uint32 {
	return p.BiosInfoListSize
}

// SetCtrlInfoList implements HasCtrlInfoList.SetCtrlInfoList.
func (p *NV2080_CTRL_BIOS_GET_INFO_PARAMS) SetCtrlInfoList(ptr P64) {
	p.BiosInfoList = ptr
}

// CtrlInfoList implements HasCtrlInfoList.CtrlInfoList.
func (p *NV2080_CTRL_BIOS_GET_INFO_PARAMS) CtrlInfoList() P64 {
	return p.BiosInfoList
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080bus.h:
const (
	NV2080_CTRL_CMD_BUS_GET_PCI_INFO                   = 0x20801801
	NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO               = 0x20801803
	NV2080_CTRL_CMD_BUS_GET_INFO_V2                    = 0x20801823
	NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS = 0x2080182a
	NV2080_CTRL_CMD_BUS_GET_C2C_INFO                   = 0x2080182b
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080ce.h:
const (
	NV2080_CTRL_CMD_CE_GET_ALL_CAPS = 0x20802a0a
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080event.h:
const (
	NV2080_CTRL_CMD_EVENT_SET_NOTIFICATION = 0x20800301
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

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080flcn.h:
const (
	NV2080_CTRL_CMD_FLCN_GET_CTX_BUFFER_SIZE = 0x20803125
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
	NV2080_CTRL_CMD_GPU_QUERY_ECC_CONFIGURATION          = 0x20800133
	NV2080_CTRL_CMD_GPU_GET_OEM_BOARD_INFO               = 0x2080013f
	NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION = 0x20800145 // undocumented; paramSize == 0
	NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION = 0x20800146 // undocumented; paramSize == 0
	NV2080_CTRL_CMD_GPU_GET_GID_INFO                     = 0x2080014a
	NV2080_CTRL_CMD_GPU_GET_INFOROM_OBJECT_VERSION       = 0x2080014b
	NV2080_CTRL_CMD_GPU_GET_INFOROM_IMAGE_VERSION        = 0x20800156
	NV2080_CTRL_CMD_GPU_QUERY_INFOROM_ECC_SUPPORT        = 0x20800157
	NV2080_CTRL_CMD_GPU_GET_ENGINES_V2                   = 0x20800170
	NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS         = 0x2080018b
	NV2080_CTRL_CMD_GPU_GET_PIDS                         = 0x2080018d
	NV2080_CTRL_CMD_GPU_GET_PID_INFO                     = 0x2080018e
	NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG        = 0x20800195
	NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO            = 0x208001a3
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080gr.h:
const (
	NV2080_CTRL_CMD_GR_GET_INFO                   = 0x20801201
	NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE  = 0x20801210
	NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE        = 0x20801218
	NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER        = 0x2080121b
	NV2080_CTRL_CMD_GR_GET_CAPS_V2                = 0x20801227
	NV2080_CTRL_CMD_GR_GET_GPC_MASK               = 0x2080122a
	NV2080_CTRL_CMD_GR_GET_TPC_MASK               = 0x2080122b
	NV2080_CTRL_CMD_GR_GET_SM_ISSUE_RATE_MODIFIER = 0x20801230
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080grmgr.h:
const (
	NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO = 0x20803801
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

// ListSize implements HasCtrlInfoList.ListSize.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) ListSize() uint32 {
	return p.GRInfoListSize
}

// SetCtrlInfoList implements HasCtrlInfoList.SetCtrlInfoList.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) SetCtrlInfoList(ptr P64) {
	p.GRInfoList = ptr
}

// CtrlInfoList implements HasCtrlInfoList.CtrlInfoList.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CtrlInfoList() P64 {
	return p.GRInfoList
}

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h:
const (
	NV2080_CTRL_CMD_MC_GET_ARCH_INFO      = 0x20801701
	NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS = 0x20801702
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080nvlink.h:
const (
	NV2080_CTRL_CMD_NVLINK_GET_NVLINK_CAPS   = 0x20803001
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
	NV2080_CTRL_CMD_PERF_GET_CURRENT_PSTATE                 = 0x20802068
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl503c.h:
const (
	NV503C_CTRL_CMD_REGISTER_VA_SPACE = 0x503c0102
	NV503C_CTRL_CMD_REGISTER_VIDMEM   = 0x503c0104
	NV503C_CTRL_CMD_UNREGISTER_VIDMEM = 0x503c0105
)

// +marshal
type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS struct {
	HVASpace     Handle
	Pad          [4]byte
	VASpaceToken uint64
}

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

// From src/common/sdk/nvidia/inc/ctrl/ctrlc56f.h:
const (
	NVC56F_CTRL_CMD_GET_KMB = 0xc56f010b
)

// From src/common/sdk/nvidia/inc/ctrl/ctrl906f.h:
const (
	NV906F_CTRL_GET_CLASS_ENGINEID = 0x906f0101
	NV906F_CTRL_CMD_RESET_CHANNEL  = 0x906f0102
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

// From src/common/sdk/nvidia/inc/ctrl/ctrla06f/ctrla06fgpfifo.h:
const (
	NVA06F_CTRL_CMD_GPFIFO_SCHEDULE = 0xa06f0103
)

// From src/common/sdk/nvidia/inc/ctrl/ctrlcb33.h:
const (
	NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES     = 0xcb330101
	NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE       = 0xcb330104
	NV_CONF_COMPUTE_CTRL_CMD_GPU_GET_NUM_SECURE_CHANNELS = 0xcb33010b
)
