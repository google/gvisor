// Copyright 2026 The gVisor Authors.
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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
)

// Diagnostics for GPU checkpoint/restore. Every driver call that reports a
// non-NV_OK status is logged at Debug from the choke point it passes through,
// so that a failure inside the CUDA or NCCL user-mode driver -- which reports
// only a CUDA error code -- can be traced to the RM call that produced it.

// statusName returns the NV_* name of an RM status code, from
// src/common/sdk/nvidia/inc/nvstatuscodes.h.
func statusName(status uint32) string {
	if name, ok := statusNames[status]; ok {
		return name
	}
	return fmt.Sprintf("NV_ERR_?(%#x)", status)
}

var statusNames = map[uint32]string{
	0x00000000: "NV_OK",
	0x0000FFFF: "NV_ERR_GENERIC",
	0x00000001: "NV_ERR_BROKEN_FB",
	0x00000002: "NV_ERR_BUFFER_TOO_SMALL",
	0x00000003: "NV_ERR_BUSY_RETRY",
	0x00000004: "NV_ERR_CALLBACK_NOT_SCHEDULED",
	0x00000005: "NV_ERR_CARD_NOT_PRESENT",
	0x00000006: "NV_ERR_CYCLE_DETECTED",
	0x00000007: "NV_ERR_DMA_IN_USE",
	0x00000008: "NV_ERR_DMA_MEM_NOT_LOCKED",
	0x00000009: "NV_ERR_DMA_MEM_NOT_UNLOCKED",
	0x0000000A: "NV_ERR_DUAL_LINK_INUSE",
	0x0000000B: "NV_ERR_ECC_ERROR",
	0x0000000C: "NV_ERR_FIFO_BAD_ACCESS",
	0x0000000D: "NV_ERR_FREQ_NOT_SUPPORTED",
	0x0000000E: "NV_ERR_GPU_DMA_NOT_INITIALIZED",
	0x0000000F: "NV_ERR_GPU_IS_LOST",
	0x00000010: "NV_ERR_GPU_IN_FULLCHIP_RESET",
	0x00000011: "NV_ERR_GPU_NOT_FULL_POWER",
	0x00000012: "NV_ERR_GPU_UUID_NOT_FOUND",
	0x00000013: "NV_ERR_HOT_SWITCH",
	0x00000014: "NV_ERR_I2C_ERROR",
	0x00000015: "NV_ERR_I2C_SPEED_TOO_HIGH",
	0x00000016: "NV_ERR_ILLEGAL_ACTION",
	0x00000017: "NV_ERR_IN_USE",
	0x00000018: "NV_ERR_INFLATE_COMPRESSED_DATA_FAILED",
	0x00000019: "NV_ERR_INSERT_DUPLICATE_NAME",
	0x0000001A: "NV_ERR_INSUFFICIENT_RESOURCES",
	0x0000001B: "NV_ERR_INSUFFICIENT_PERMISSIONS",
	0x0000001C: "NV_ERR_INSUFFICIENT_POWER",
	0x0000001D: "NV_ERR_INVALID_ACCESS_TYPE",
	0x0000001E: "NV_ERR_INVALID_ADDRESS",
	0x0000001F: "NV_ERR_INVALID_ARGUMENT",
	0x00000020: "NV_ERR_INVALID_BASE",
	0x00000021: "NV_ERR_INVALID_CHANNEL",
	0x00000022: "NV_ERR_INVALID_CLASS",
	0x00000023: "NV_ERR_INVALID_CLIENT",
	0x00000024: "NV_ERR_INVALID_COMMAND",
	0x00000025: "NV_ERR_INVALID_DATA",
	0x00000026: "NV_ERR_INVALID_DEVICE",
	0x00000027: "NV_ERR_INVALID_DMA_SPECIFIER",
	0x00000028: "NV_ERR_INVALID_EVENT",
	0x00000029: "NV_ERR_INVALID_FLAGS",
	0x0000002A: "NV_ERR_INVALID_FUNCTION",
	0x0000002B: "NV_ERR_INVALID_HEAP",
	0x0000002C: "NV_ERR_INVALID_INDEX",
	0x0000002D: "NV_ERR_INVALID_IRQ_LEVEL",
	0x0000002E: "NV_ERR_INVALID_LIMIT",
	0x0000002F: "NV_ERR_INVALID_LOCK_STATE",
	0x00000030: "NV_ERR_INVALID_METHOD",
	0x00000031: "NV_ERR_INVALID_OBJECT",
	0x00000032: "NV_ERR_INVALID_OBJECT_BUFFER",
	0x00000033: "NV_ERR_INVALID_OBJECT_HANDLE",
	0x00000034: "NV_ERR_INVALID_OBJECT_NEW",
	0x00000035: "NV_ERR_INVALID_OBJECT_OLD",
	0x00000036: "NV_ERR_INVALID_OBJECT_PARENT",
	0x00000037: "NV_ERR_INVALID_OFFSET",
	0x00000038: "NV_ERR_INVALID_OPERATION",
	0x00000039: "NV_ERR_INVALID_OWNER",
	0x0000003A: "NV_ERR_INVALID_PARAM_STRUCT",
	0x0000003B: "NV_ERR_INVALID_PARAMETER",
	0x0000003C: "NV_ERR_INVALID_PATH",
	0x0000003D: "NV_ERR_INVALID_POINTER",
	0x0000003E: "NV_ERR_INVALID_REGISTRY_KEY",
	0x0000003F: "NV_ERR_INVALID_REQUEST",
	0x00000040: "NV_ERR_INVALID_STATE",
	0x00000041: "NV_ERR_INVALID_STRING_LENGTH",
	0x00000042: "NV_ERR_INVALID_READ",
	0x00000043: "NV_ERR_INVALID_WRITE",
	0x00000044: "NV_ERR_INVALID_XLATE",
	0x00000045: "NV_ERR_IRQ_NOT_FIRING",
	0x00000046: "NV_ERR_IRQ_EDGE_TRIGGERED",
	0x00000047: "NV_ERR_MEMORY_TRAINING_FAILED",
	0x00000048: "NV_ERR_MISMATCHED_SLAVE",
	0x00000049: "NV_ERR_MISMATCHED_TARGET",
	0x0000004A: "NV_ERR_MISSING_TABLE_ENTRY",
	0x0000004B: "NV_ERR_MODULE_LOAD_FAILED",
	0x0000004C: "NV_ERR_MORE_DATA_AVAILABLE",
	0x0000004D: "NV_ERR_MORE_PROCESSING_REQUIRED",
	0x0000004E: "NV_ERR_MULTIPLE_MEMORY_TYPES",
	0x0000004F: "NV_ERR_NO_FREE_FIFOS",
	0x00000050: "NV_ERR_NO_INTR_PENDING",
	0x00000051: "NV_ERR_NO_MEMORY",
	0x00000052: "NV_ERR_NO_SUCH_DOMAIN",
	0x00000053: "NV_ERR_NO_VALID_PATH",
	0x00000054: "NV_ERR_NOT_COMPATIBLE",
	0x00000055: "NV_ERR_NOT_READY",
	0x00000056: "NV_ERR_NOT_SUPPORTED",
	0x00000057: "NV_ERR_OBJECT_NOT_FOUND",
	0x00000058: "NV_ERR_OBJECT_TYPE_MISMATCH",
	0x00000059: "NV_ERR_OPERATING_SYSTEM",
	0x0000005A: "NV_ERR_OTHER_DEVICE_FOUND",
	0x0000005B: "NV_ERR_OUT_OF_RANGE",
	0x0000005C: "NV_ERR_OVERLAPPING_UVM_COMMIT",
	0x0000005D: "NV_ERR_PAGE_TABLE_NOT_AVAIL",
	0x0000005E: "NV_ERR_PID_NOT_FOUND",
	0x0000005F: "NV_ERR_PROTECTION_FAULT",
	0x00000060: "NV_ERR_RC_ERROR",
	0x00000061: "NV_ERR_REJECTED_VBIOS",
	0x00000062: "NV_ERR_RESET_REQUIRED",
	0x00000063: "NV_ERR_STATE_IN_USE",
	0x00000064: "NV_ERR_SIGNAL_PENDING",
	0x00000065: "NV_ERR_TIMEOUT",
	0x00000066: "NV_ERR_TIMEOUT_RETRY",
	0x00000067: "NV_ERR_TOO_MANY_PRIMARIES",
	0x00000068: "NV_ERR_UVM_ADDRESS_IN_USE",
	0x00000069: "NV_ERR_MAX_SESSION_LIMIT_REACHED",
	0x0000006A: "NV_ERR_LIB_RM_VERSION_MISMATCH",
	0x0000006B: "NV_ERR_PRIV_SEC_VIOLATION",
	0x0000006C: "NV_ERR_GPU_IN_DEBUG_MODE",
	0x0000006D: "NV_ERR_FEATURE_NOT_ENABLED",
	0x0000006E: "NV_ERR_RESOURCE_LOST",
	0x0000006F: "NV_ERR_PMU_NOT_READY",
	0x00000070: "NV_ERR_FLCN_ERROR",
	0x00000071: "NV_ERR_FATAL_ERROR",
	0x00000072: "NV_ERR_MEMORY_ERROR",
	0x00000073: "NV_ERR_INVALID_LICENSE",
	0x00000074: "NV_ERR_NVLINK_INIT_ERROR",
	0x00000075: "NV_ERR_NVLINK_MINION_ERROR",
	0x00000076: "NV_ERR_NVLINK_CLOCK_ERROR",
	0x00000077: "NV_ERR_NVLINK_TRAINING_ERROR",
	0x00000078: "NV_ERR_NVLINK_CONFIGURATION_ERROR",
	0x00000079: "NV_ERR_RISCV_ERROR",
	0x0000007A: "NV_ERR_FABRIC_MANAGER_NOT_PRESENT",
	0x0000007B: "NV_ERR_ALREADY_SIGNALLED",
	0x0000007C: "NV_ERR_QUEUE_TASK_SLOT_NOT_AVAILABLE",
	0x0000007D: "NV_ERR_KEY_ROTATION_IN_PROGRESS",
	0x0000007E: "NV_ERR_TEST_ONLY_CODE_NOT_ENABLED",
	0x0000007F: "NV_ERR_SECURE_BOOT_FAILED",
	0x00000080: "NV_ERR_INSUFFICIENT_ZBC_ENTRY",
	0x00000081: "NV_ERR_NVLINK_FABRIC_NOT_READY",
	0x00000082: "NV_ERR_NVLINK_FABRIC_FAILURE",
	0x00000083: "NV_ERR_GPU_MEMORY_ONLINING_FAILURE",
	0x00000084: "NV_ERR_REDUCTION_MANAGER_NOT_AVAILABLE",
	0x00000085: "NV_ERR_THRESHOLD_CROSSED",
	0x00000086: "NV_ERR_RESOURCE_RETIREMENT_ERROR",
	0x00000087: "NV_ERR_FABRIC_STATE_OUT_OF_SYNC",
	0x00000088: "NV_ERR_BUFFER_FULL",
	0x00000089: "NV_ERR_BUFFER_EMPTY",
	0x0000008A: "NV_ERR_MC_FLA_OFFSET_TABLE_FULL",
	0x0000008B: "NV_ERR_OPERATION_ABORTED",
	0x0000008C: "NV_ERR_DMA_XFER_FAILED",
	0x0000008D: "NV_ERR_RESOURCE_ACCOUNTING_HARD_LIMIT_EXCEEDED",
	0x00010001: "NV_WARN_HOT_SWITCH",
	0x00010002: "NV_WARN_INCORRECT_PERFMON_DATA",
	0x00010003: "NV_WARN_MISMATCHED_SLAVE",
	0x00010004: "NV_WARN_MISMATCHED_TARGET",
	0x00010005: "NV_WARN_MORE_PROCESSING_REQUIRED",
	0x00010006: "NV_WARN_NOTHING_TO_DO",
	0x00010007: "NV_WARN_NULL_OBJECT",
	0x00010008: "NV_WARN_OUT_OF_RANGE",
	0x00010009: "NV_WARN_THRESHOLD_CROSSED",
	0x0001000A: "NV_WARN_RESOURCE_ACCOUNTING_SOFT_LIMIT_EXCEEDED",
}

// frontendIoctlName returns the NV_ESC_* name of a frontend ioctl number.
func frontendIoctlName(nr uint32) string {
	if name, ok := frontendIoctlNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("NV_ESC_?(%#x)", nr)
}

var frontendIoctlNames = map[uint32]string{
	nvgpu.NV_ESC_CARD_INFO:                     "NV_ESC_CARD_INFO",
	nvgpu.NV_ESC_REGISTER_FD:                   "NV_ESC_REGISTER_FD",
	nvgpu.NV_ESC_ALLOC_OS_EVENT:                "NV_ESC_ALLOC_OS_EVENT",
	nvgpu.NV_ESC_FREE_OS_EVENT:                 "NV_ESC_FREE_OS_EVENT",
	nvgpu.NV_ESC_CHECK_VERSION_STR:             "NV_ESC_CHECK_VERSION_STR",
	nvgpu.NV_ESC_ATTACH_GPUS_TO_FD:             "NV_ESC_ATTACH_GPUS_TO_FD",
	nvgpu.NV_ESC_SYS_PARAMS:                    "NV_ESC_SYS_PARAMS",
	nvgpu.NV_ESC_NUMA_INFO:                     "NV_ESC_NUMA_INFO",
	nvgpu.NV_ESC_EXPORT_TO_DMABUF_FD:           "NV_ESC_EXPORT_TO_DMABUF_FD",
	nvgpu.NV_ESC_WAIT_OPEN_COMPLETE:            "NV_ESC_WAIT_OPEN_COMPLETE",
	nvgpu.NV_ESC_RM_ALLOC_MEMORY:               "NV_ESC_RM_ALLOC_MEMORY",
	nvgpu.NV_ESC_RM_FREE:                       "NV_ESC_RM_FREE",
	nvgpu.NV_ESC_RM_CONTROL:                    "NV_ESC_RM_CONTROL",
	nvgpu.NV_ESC_RM_ALLOC:                      "NV_ESC_RM_ALLOC",
	nvgpu.NV_ESC_RM_DUP_OBJECT:                 "NV_ESC_RM_DUP_OBJECT",
	nvgpu.NV_ESC_RM_SHARE:                      "NV_ESC_RM_SHARE",
	nvgpu.NV_ESC_RM_IDLE_CHANNELS:              "NV_ESC_RM_IDLE_CHANNELS",
	nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           "NV_ESC_RM_VID_HEAP_CONTROL",
	nvgpu.NV_ESC_RM_MAP_MEMORY:                 "NV_ESC_RM_MAP_MEMORY",
	nvgpu.NV_ESC_RM_UNMAP_MEMORY:               "NV_ESC_RM_UNMAP_MEMORY",
	nvgpu.NV_ESC_RM_ALLOC_CONTEXT_DMA2:         "NV_ESC_RM_ALLOC_CONTEXT_DMA2",
	nvgpu.NV_ESC_RM_MAP_MEMORY_DMA:             "NV_ESC_RM_MAP_MEMORY_DMA",
	nvgpu.NV_ESC_RM_UNMAP_MEMORY_DMA:           "NV_ESC_RM_UNMAP_MEMORY_DMA",
	nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: "NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO",
}

// uvmIoctlName returns the UVM_* name of a UVM ioctl command.
func uvmIoctlName(cmd uint32) string {
	if name, ok := uvmIoctlNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("UVM_?(%d)", cmd)
}

var uvmIoctlNames = map[uint32]string{
	nvgpu.UVM_INITIALIZE:                     "UVM_INITIALIZE",
	nvgpu.UVM_DEINITIALIZE:                   "UVM_DEINITIALIZE",
	nvgpu.UVM_CREATE_RANGE_GROUP:             "UVM_CREATE_RANGE_GROUP",
	nvgpu.UVM_DESTROY_RANGE_GROUP:            "UVM_DESTROY_RANGE_GROUP",
	nvgpu.UVM_REGISTER_GPU_VASPACE:           "UVM_REGISTER_GPU_VASPACE",
	nvgpu.UVM_UNREGISTER_GPU_VASPACE:         "UVM_UNREGISTER_GPU_VASPACE",
	nvgpu.UVM_REGISTER_CHANNEL:               "UVM_REGISTER_CHANNEL",
	nvgpu.UVM_UNREGISTER_CHANNEL:             "UVM_UNREGISTER_CHANNEL",
	nvgpu.UVM_ENABLE_PEER_ACCESS:             "UVM_ENABLE_PEER_ACCESS",
	nvgpu.UVM_DISABLE_PEER_ACCESS:            "UVM_DISABLE_PEER_ACCESS",
	nvgpu.UVM_SET_RANGE_GROUP:                "UVM_SET_RANGE_GROUP",
	nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        "UVM_MAP_EXTERNAL_ALLOCATION",
	nvgpu.UVM_FREE:                           "UVM_FREE",
	nvgpu.UVM_REGISTER_GPU:                   "UVM_REGISTER_GPU",
	nvgpu.UVM_UNREGISTER_GPU:                 "UVM_UNREGISTER_GPU",
	nvgpu.UVM_PAGEABLE_MEM_ACCESS:            "UVM_PAGEABLE_MEM_ACCESS",
	nvgpu.UVM_SET_PREFERRED_LOCATION:         "UVM_SET_PREFERRED_LOCATION",
	nvgpu.UVM_UNSET_PREFERRED_LOCATION:       "UVM_UNSET_PREFERRED_LOCATION",
	nvgpu.UVM_ENABLE_READ_DUPLICATION:        "UVM_ENABLE_READ_DUPLICATION",
	nvgpu.UVM_DISABLE_READ_DUPLICATION:       "UVM_DISABLE_READ_DUPLICATION",
	nvgpu.UVM_SET_ACCESSED_BY:                "UVM_SET_ACCESSED_BY",
	nvgpu.UVM_UNSET_ACCESSED_BY:              "UVM_UNSET_ACCESSED_BY",
	nvgpu.UVM_MIGRATE:                        "UVM_MIGRATE",
	nvgpu.UVM_MIGRATE_RANGE_GROUP:            "UVM_MIGRATE_RANGE_GROUP",
	nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY:      "UVM_TOOLS_READ_PROCESS_MEMORY",
	nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY:     "UVM_TOOLS_WRITE_PROCESS_MEMORY",
	nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: "UVM_MAP_DYNAMIC_PARALLELISM_REGION",
	nvgpu.UVM_UNMAP_EXTERNAL:                 "UVM_UNMAP_EXTERNAL",
	nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           "UVM_ALLOC_SEMAPHORE_POOL",
	nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU:     "UVM_PAGEABLE_MEM_ACCESS_ON_GPU",
	nvgpu.UVM_VALIDATE_VA_RANGE:              "UVM_VALIDATE_VA_RANGE",
	nvgpu.UVM_CREATE_EXTERNAL_RANGE:          "UVM_CREATE_EXTERNAL_RANGE",
	nvgpu.UVM_MM_INITIALIZE:                  "UVM_MM_INITIALIZE",
}

// logFrontendIoctlStatus logs a frontend ioctl that the driver answered with a
// non-NV_OK status. It is called from frontendIoctlInvoke(), the single choke
// point every status-bearing frontend ioctl passes through, so no handler can
// be missed. ioctlParams is passed as any so that the handful of parameter
// types worth naming their handles can be recognised; everything else gets the
// generic line.
func logFrontendIoctlStatus(fi *frontendIoctlState, status uint32, ioctlParams any) {
	name := frontendIoctlName(fi.nr)
	switch p := ioctlParams.(type) {
	case *nvgpu.NVOS54_PARAMETERS:
		// Also logged by logRMControlStatus() with the control command; this
		// branch keeps the two lines consistent when a control fails.
		fi.ctx.Debugf("nvproxy: %s failed: cmd=%#x hClient=%v hObject=%v paramsSize=%d status=%#x (%s)",
			name, p.Cmd, p.HClient, p.HObject, p.ParamsSize, status, statusName(status))
	case *nvgpu.NVOS64_PARAMETERS:
		fi.ctx.Debugf("nvproxy: %s failed: hClass=%v hRoot=%v hObjectParent=%v hObjectNew=%v paramsSize=%d status=%#x (%s)",
			name, p.HClass, p.HRoot, p.HObjectParent, p.HObjectNew, p.ParamsSize, status, statusName(status))
	case *nvgpu.NVOS21_PARAMETERS:
		fi.ctx.Debugf("nvproxy: %s failed: hClass=%v hRoot=%v hObjectParent=%v hObjectNew=%v paramsSize=%d status=%#x (%s)",
			name, p.HClass, p.HRoot, p.HObjectParent, p.HObjectNew, p.ParamsSize, status, statusName(status))
	case *nvgpu.NVOS55_PARAMETERS:
		fi.ctx.Debugf("nvproxy: %s failed: hClient=%v hParent=%v hObject=%v hClientSrc=%v hObjectSrc=%v flags=%#x status=%#x (%s)",
			name, p.HClient, p.HParent, p.HObject, p.HClientSrc, p.HObjectSrc, p.Flags, status, statusName(status))
	case *nvgpu.NVOS46_PARAMETERS:
		fi.ctx.Debugf("nvproxy: %s failed: hClient=%v hDevice=%v hDma=%v hMemory=%v offset=%#x length=%#x flags=%#x status=%#x (%s)",
			name, p.Client, p.Device, p.Dma, p.Memory, p.Offset, p.Length, p.Flags, status, statusName(status))
	case *nvgpu.NVOS33_PARAMETERS:
		fi.ctx.Debugf("nvproxy: %s failed: hClient=%v hDevice=%v hMemory=%v offset=%#x length=%#x flags=%#x status=%#x (%s)",
			name, p.HClient, p.HDevice, p.HMemory, p.Offset, p.Length, p.Flags, status, statusName(status))
	case *nvgpu.IoctlNVOS02ParametersWithFD:
		fi.ctx.Debugf("nvproxy: %s failed: hRoot=%v hObjectParent=%v hObjectNew=%v hClass=%v flags=%#x limit=%#x status=%#x (%s)",
			name, p.Params.HRoot, p.Params.HObjectParent, p.Params.HObjectNew, p.Params.HClass, p.Params.Flags, p.Params.Limit, status, statusName(status))
	default:
		fi.ctx.Debugf("nvproxy: %s failed: paramsSize=%d status=%#x (%s)",
			name, fi.ioctlParamsSize, status, statusName(status))
	}
}

// logRMControlStatus logs the outcome of an NV_ESC_RM_CONTROL: every control at
// Debug, and any control the driver answered with a non-NV_OK status at Debug.
// It is called from rmControlInvoke(), which every control handler funnels
// through.
func logRMControlStatus(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) {
	if ioctlParams.Status != nvgpu.NV_OK {
		fi.ctx.Debugf("nvproxy: rm control failed: cmd=%#x hClient=%v hObject=%v paramsSize=%d status=%#x (%s)",
			ioctlParams.Cmd, ioctlParams.HClient, ioctlParams.HObject, ioctlParams.ParamsSize, ioctlParams.Status, statusName(ioctlParams.Status))
		return
	}
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: rm control: cmd=%#x hClient=%v hObject=%v paramsSize=%d status=%#x%s",
			ioctlParams.Cmd, ioctlParams.HClient, ioctlParams.HObject, ioctlParams.ParamsSize, ioctlParams.Status,
			ctrlParamsPreview(fi, ioctlParams))
	}
}

// ctrlParamsPreviewLen is how much of a control's parameters the Debug line
// shows.
const ctrlParamsPreviewLen = 32

// ctrlParamsPreview renders the first bytes of a control's parameters as
// NvU32s, for the NV0000 gpu (0x2xx) and system (0x1xx) controls whose
// parameters begin with gpuIds. Those are the controls by which an application
// discovers which GPUs exist, so seeing the identifiers flow is what tells us
// whether a translation is reaching them.
//
// It returns "" for every other command, and never reads more than the
// application said it passed.
func ctrlParamsPreview(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) string {
	if ioctlParams.Cmd&^0xff != 0x100 && ioctlParams.Cmd&^0xff != 0x200 {
		return ""
	}
	if ioctlParams.Params == 0 || ioctlParams.ParamsSize == 0 {
		return ""
	}
	n := int(ioctlParams.ParamsSize)
	if n > ctrlParamsPreviewLen {
		n = ctrlParamsPreviewLen
	}
	n -= n % 4
	if n == 0 {
		return ""
	}
	buf := make([]byte, n)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), buf); err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(" params=[")
	for i := 0; i+4 <= n; i += 4 {
		if i != 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%#010x", hostarch.ByteOrder.Uint32(buf[i:]))
	}
	b.WriteByte(']')
	return b.String()
}

// logUVMIoctlStatus logs a UVM ioctl that the driver answered with a non-NV_OK
// rmStatus. It is called from uvmIoctlInvoke(), the single choke point for UVM
// ioctls that carry a status.
func logUVMIoctlStatus(ui *uvmIoctlState, status uint32) {
	ui.ctx.Debugf("nvproxy: uvm ioctl %s failed: rmStatus=%#x (%s)", uvmIoctlName(ui.cmd), status, statusName(status))
}
