// Automatically generated marshal implementation. See tools/go_marshal.

package nvgpu

import (
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*ClassID)(nil)
var _ marshal.Marshallable = (*Handle)(nil)
var _ marshal.Marshallable = (*IoctlAllocOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlFreeOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlNVOS02ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlNVOS33ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlRegisterFD)(nil)
var _ marshal.Marshallable = (*IoctlSysParams)(nil)
var _ marshal.Marshallable = (*IoctlWaitOpenComplete)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_GPU_GET_ID_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*NV0005_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_GET_CAPS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_GR_ROUTE_INFO)(nil)
var _ marshal.Marshallable = (*NV00DE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00DE_ALLOC_PARAMETERS_V545)(nil)
var _ marshal.Marshallable = (*NV00F8_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00FD_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00FD_ALLOCATION_PARAMETERS_V545)(nil)
var _ marshal.Marshallable = (*NV00FD_CTRL_ATTACH_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_GR_GET_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2081_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV503B_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV503B_BAR1_P2P_DMA_INFO)(nil)
var _ marshal.Marshallable = (*NV503C_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV503C_CTRL_REGISTER_VA_SPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*NV83DE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV9072_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVA0BC_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVB0B5_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS00_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS02_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS21_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS30_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS32_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS33_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS34_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS39_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS46_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS47_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS47_PARAMETERS_V550)(nil)
var _ marshal.Marshallable = (*NVOS54_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS55_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS56_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS57_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS64_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVXXXX_CTRL_XXX_INFO)(nil)
var _ marshal.Marshallable = (*NV_BSP_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS_V570)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CONTEXT_DMA_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CTXSHARE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_EXPORT_MEM_PACKET)(nil)
var _ marshal.Marshallable = (*NV_GR_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_HOPPER_USERMODE_A_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_ALLOCATION_PARAMS_V545)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_DESC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MSENC_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_VASPACE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NvUUID)(nil)
var _ marshal.Marshallable = (*NvxxxCtrlXxxGetInfoParams)(nil)
var _ marshal.Marshallable = (*P64)(nil)
var _ marshal.Marshallable = (*RMAPIVersion)(nil)
var _ marshal.Marshallable = (*RS_ACCESS_MASK)(nil)
var _ marshal.Marshallable = (*RS_SHARE_POLICY)(nil)
var _ marshal.Marshallable = (*RmapiParamNvU32List)(nil)
var _ marshal.Marshallable = (*UVM_ALLOC_SEMAPHORE_POOL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_EXTERNAL_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DESTROY_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DISABLE_PEER_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DISABLE_READ_DUPLICATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_ENABLE_PEER_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_FREE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_PAGEABLE_MEM_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_SET_PREFERRED_LOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_SET_PREFERRED_LOCATION_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_SET_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNMAP_EXTERNAL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNSET_ACCESSED_BY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNSET_PREFERRED_LOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_VALIDATE_VA_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UvmGpuMappingAttributes)(nil)
var _ marshal.Marshallable = (*nv00f8Map)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (id *ClassID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (id *ClassID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*id))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (id *ClassID) UnmarshalBytes(src []byte) []byte {
    *id = ClassID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (id *ClassID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (id *ClassID) MarshalUnsafe(dst []byte) []byte {
    size := id.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(id), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (id *ClassID) UnmarshalUnsafe(src []byte) []byte {
    size := id.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(id), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (id *ClassID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that id
    // must live until the use above.
    runtime.KeepAlive(id) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (id *ClassID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return id.CopyOutN(cc, addr, id.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (id *ClassID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that id
    // must live until the use above.
    runtime.KeepAlive(id) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (id *ClassID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return id.CopyInN(cc, addr, id.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (id *ClassID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that id
    // must live until the use above.
    runtime.KeepAlive(id) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0005_ALLOC_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0005_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HParentClient.MarshalUnsafe(dst)
    dst = n.HSrcResource.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NotifyIndex))
    dst = dst[4:]
    dst = n.Data.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0005_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HParentClient.UnmarshalUnsafe(src)
    src = n.HSrcResource.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.NotifyIndex = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Data.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0005_ALLOC_PARAMETERS) Packed() bool {
    return n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0005_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0005_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0005_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0005_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0005_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0005_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0005_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0080_ALLOC_PARAMETERS) SizeBytes() int {
    return 36 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0080_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DeviceID))
    dst = dst[4:]
    dst = n.HClientShare.MarshalUnsafe(dst)
    dst = n.HTargetClient.MarshalUnsafe(dst)
    dst = n.HTargetDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASpaceSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VAStartInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VALimitInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.VAMode))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0080_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.DeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HClientShare.UnmarshalUnsafe(src)
    src = n.HTargetClient.UnmarshalUnsafe(src)
    src = n.HTargetDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.VASpaceSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAStartInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VALimitInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAMode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_ALLOC_PARAMETERS) Packed() bool {
    return n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0080_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0080_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0080_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0080_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0080_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        // Type NV0080_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0080_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0080_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        // Type NV0080_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0080_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0080_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        // Type NV0080_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00DE_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00DE_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Reserved))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00DE_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Reserved = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00DE_ALLOC_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00DE_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00DE_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00DE_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00DE_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00DE_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00DE_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00DE_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00DE_ALLOC_PARAMETERS_V545) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00DE_ALLOC_PARAMETERS_V545) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.PolledDataMask))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00DE_ALLOC_PARAMETERS_V545) UnmarshalBytes(src []byte) []byte {
    n.PolledDataMask = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00DE_ALLOC_PARAMETERS_V545) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00DE_ALLOC_PARAMETERS_V545) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00DE_ALLOC_PARAMETERS_V545) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00DE_ALLOC_PARAMETERS_V545) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00F8_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 32 +
        (*nv00f8Map)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00F8_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.PageSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AllocFlags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    dst = n.Map.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00F8_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AllocSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.PageSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    src = n.Map.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00F8_ALLOCATION_PARAMETERS) Packed() bool {
    return n.Map.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00F8_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV00F8_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00F8_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV00F8_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00F8_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00F8_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00F8_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00F8_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00F8_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 32 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PageSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AllocFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumGPUs))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    dst = n.POsEvent.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AllocSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.PageSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.NumGPUs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    src = n.POsEvent.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FD_ALLOCATION_PARAMETERS) Packed() bool {
    return n.POsEvent.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00FD_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.POsEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV00FD_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00FD_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.POsEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV00FD_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00FD_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.POsEvent.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00FD_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00FD_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.POsEvent.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00FD_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00FD_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.POsEvent.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) SizeBytes() int {
    return 2 +
        (*NV_EXPORT_MEM_PACKET)(nil).SizeBytes() +
        1*6 +
        (*NV00FD_ALLOCATION_PARAMETERS)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) MarshalBytes(dst []byte) []byte {
    dst = n.ExpPacket.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Index))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*6] ~= [6]byte{0}
    dst = dst[1*(6):]
    dst = n.NV00FD_ALLOCATION_PARAMETERS.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) UnmarshalBytes(src []byte) []byte {
    src = n.ExpPacket.UnmarshalUnsafe(src)
    n.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([6]byte(n._), src[:sizeof(byte)*6])
    src = src[1*(6):]
    src = n.NV00FD_ALLOCATION_PARAMETERS.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) Packed() bool {
    return n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) MarshalUnsafe(dst []byte) []byte {
    if n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV00FD_ALLOCATION_PARAMETERS_V545 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) UnmarshalUnsafe(src []byte) []byte {
    if n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV00FD_ALLOCATION_PARAMETERS_V545 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS_V545 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS_V545 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) WriteTo(writer io.Writer) (int64, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        // Type NV00FD_ALLOCATION_PARAMETERS_V545 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV2080_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV2080_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV2080_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.SubDeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_ALLOC_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV2080_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV2080_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV2080_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV2080_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV2080_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV2080_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV2080_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV2081_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV2081_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Reserved))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV2081_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Reserved = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2081_ALLOC_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV2081_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV2081_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV2081_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV2081_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV2081_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV2081_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV2081_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV503B_ALLOC_PARAMETERS) SizeBytes() int {
    return 32 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*NV503B_BAR1_P2P_DMA_INFO)(nil).SizeBytes() +
        (*NV503B_BAR1_P2P_DMA_INFO)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV503B_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    dst = n.HPeerSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDevicePeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PeerSubDevicePeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.MailboxBar1Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.MailboxTotalSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceEgmPeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PeerSubDeviceEgmPeerIDMask))
    dst = dst[4:]
    dst = n.L2pBar1P2PDmaInfo.MarshalUnsafe(dst)
    dst = n.P2lBar1P2PDmaInfo.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV503B_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    src = n.HPeerSubDevice.UnmarshalUnsafe(src)
    n.SubDevicePeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PeerSubDevicePeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.MailboxBar1Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.MailboxTotalSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceEgmPeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PeerSubDeviceEgmPeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.L2pBar1P2PDmaInfo.UnmarshalUnsafe(src)
    src = n.P2lBar1P2PDmaInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_ALLOC_PARAMETERS) Packed() bool {
    return n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV503B_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV503B_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV503B_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV503B_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV503B_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        // Type NV503B_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV503B_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV503B_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        // Type NV503B_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV503B_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV503B_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        // Type NV503B_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV503B_BAR1_P2P_DMA_INFO) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV503B_BAR1_P2P_DMA_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaSize))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV503B_BAR1_P2P_DMA_INFO) UnmarshalBytes(src []byte) []byte {
    n.DmaAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.DmaSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_BAR1_P2P_DMA_INFO) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV503B_BAR1_P2P_DMA_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV503B_BAR1_P2P_DMA_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV503B_BAR1_P2P_DMA_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV503B_BAR1_P2P_DMA_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV503B_BAR1_P2P_DMA_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV503B_BAR1_P2P_DMA_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV503B_BAR1_P2P_DMA_INFO) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV503C_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV503C_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV503C_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503C_ALLOC_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV503C_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV503C_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV503C_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV503C_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV503C_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV503C_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV503C_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV83DE_ALLOC_PARAMETERS) SizeBytes() int {
    return 0 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV83DE_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HDebuggerClient_Obsolete.MarshalUnsafe(dst)
    dst = n.HAppClient.MarshalUnsafe(dst)
    dst = n.HClass3DObject.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV83DE_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HDebuggerClient_Obsolete.UnmarshalUnsafe(src)
    src = n.HAppClient.UnmarshalUnsafe(src)
    src = n.HClass3DObject.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV83DE_ALLOC_PARAMETERS) Packed() bool {
    return n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV83DE_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV83DE_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV83DE_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV83DE_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV83DE_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        // Type NV83DE_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV83DE_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV83DE_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        // Type NV83DE_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV83DE_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV83DE_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        // Type NV83DE_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV9072_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV9072_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.LogicalHeadID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DisplayMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Caps))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV9072_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.LogicalHeadID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DisplayMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Caps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV9072_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV9072_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV9072_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV9072_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV9072_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV9072_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV9072_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV9072_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVA0BC_ALLOC_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVA0BC_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CodecType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HResolution))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.VResolution))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    dst = n.HMem.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVA0BC_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.CodecType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.HResolution = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.VResolution = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMem.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVA0BC_ALLOC_PARAMETERS) Packed() bool {
    return n.HMem.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVA0BC_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVA0BC_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVA0BC_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVA0BC_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVA0BC_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMem.Packed() {
        // Type NVA0BC_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVA0BC_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVA0BC_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMem.Packed() {
        // Type NVA0BC_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVA0BC_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVA0BC_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HMem.Packed() {
        // Type NVA0BC_ALLOC_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVB0B5_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVB0B5_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVB0B5_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVB0B5_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVB0B5_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVB0B5_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVB0B5_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_BSP_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_BSP_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_BSP_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_BSP_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_BSP_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_BSP_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_BSP_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS) SizeBytes() int {
    return 40 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV_MAX_SUBDEVICES +
        8*NV_MAX_SUBDEVICES +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_NONCE_SIZE_DWORD
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectError.MarshalUnsafe(dst)
    dst = n.HObjectBuffer.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.GPFIFOOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GPFIFOEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.HContextShare.MarshalUnsafe(dst)
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        dst = n.HUserdMemory[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.UserdOffset[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceID))
    dst = dst[4:]
    dst = n.HObjectECCError.MarshalUnsafe(dst)
    dst = n.InstanceMem.MarshalUnsafe(dst)
    dst = n.UserdMem.MarshalUnsafe(dst)
    dst = n.RamfcMem.MarshalUnsafe(dst)
    dst = n.MthdbufMem.MarshalUnsafe(dst)
    dst = n.HPhysChannelGroup.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.InternalFlags))
    dst = dst[4:]
    dst = n.ErrorNotifierMem.MarshalUnsafe(dst)
    dst = n.ECCErrorNotifierMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProcessID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubProcessID))
    dst = dst[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EncryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DecryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HmacNonce[idx]))
        dst = dst[4:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectError.UnmarshalUnsafe(src)
    src = n.HObjectBuffer.UnmarshalUnsafe(src)
    n.GPFIFOOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.GPFIFOEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HContextShare.UnmarshalUnsafe(src)
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        src = n.HUserdMemory[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        n.UserdOffset[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.CID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HObjectECCError.UnmarshalUnsafe(src)
    src = n.InstanceMem.UnmarshalUnsafe(src)
    src = n.UserdMem.UnmarshalUnsafe(src)
    src = n.RamfcMem.UnmarshalUnsafe(src)
    src = n.MthdbufMem.UnmarshalUnsafe(src)
    src = n.HPhysChannelGroup.UnmarshalUnsafe(src)
    n.InternalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.ErrorNotifierMem.UnmarshalUnsafe(src)
    src = n.ECCErrorNotifierMem.UnmarshalUnsafe(src)
    n.ProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.EncryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.DecryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        n.HmacNonce[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_ALLOC_PARAMS) Packed() bool {
    return n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CHANNEL_ALLOC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CHANNEL_ALLOC_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CHANNEL_ALLOC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CHANNEL_ALLOC_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CHANNEL_ALLOC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CHANNEL_ALLOC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CHANNEL_ALLOC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CHANNEL_ALLOC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CHANNEL_ALLOC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) SizeBytes() int {
    return 8 +
        (*NV_CHANNEL_ALLOC_PARAMS)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) MarshalBytes(dst []byte) []byte {
    dst = n.NV_CHANNEL_ALLOC_PARAMS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.TPCConfigID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) UnmarshalBytes(src []byte) []byte {
    src = n.NV_CHANNEL_ALLOC_PARAMS.UnmarshalUnsafe(src)
    n.TPCConfigID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) Packed() bool {
    return n.NV_CHANNEL_ALLOC_PARAMS.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) MarshalUnsafe(dst []byte) []byte {
    if n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CHANNEL_ALLOC_PARAMS_V570 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CHANNEL_ALLOC_PARAMS_V570 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS_V570 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS_V570 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        // Type NV_CHANNEL_ALLOC_PARAMS_V570 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 5 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectError.MarshalUnsafe(dst)
    dst = n.HObjectECCError.MarshalUnsafe(dst)
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    dst[0] = byte(n.BIsCallingContextVgpuPlugin)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectError.UnmarshalUnsafe(src)
    src = n.HObjectECCError.UnmarshalUnsafe(src)
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BIsCallingContextVgpuPlugin = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) Packed() bool {
    return n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        // Type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        // Type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        // Type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) SizeBytes() int {
    return 0 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.Handle.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.Handle.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) Packed() bool {
    return n.Handle.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.Handle.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.Handle.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Handle.Packed() {
        // Type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Handle.Packed() {
        // Type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Handle.Packed() {
        // Type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.HMemory.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMemory.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) Packed() bool {
    return n.HMemory.Packed() && n.HSubDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HMemory.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CONTEXT_DMA_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HMemory.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CONTEXT_DMA_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        // Type NV_CONTEXT_DMA_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        // Type NV_CONTEXT_DMA_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        // Type NV_CONTEXT_DMA_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubctxID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubctxID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) Packed() bool {
    return n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_CTXSHARE_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_CTXSHARE_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV_CTXSHARE_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV_CTXSHARE_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        // Type NV_CTXSHARE_ALLOCATION_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_EXPORT_MEM_PACKET) SizeBytes() int {
    return 0 +
        1*NV_MEM_EXPORT_UUID_LEN +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_EXPORT_MEM_PACKET) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        dst[0] = byte(n.UUID[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(n.Opaque[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_EXPORT_MEM_PACKET) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        n.UUID[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 16; idx++ {
        n.Opaque[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_EXPORT_MEM_PACKET) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_EXPORT_MEM_PACKET) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_EXPORT_MEM_PACKET) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_EXPORT_MEM_PACKET) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_EXPORT_MEM_PACKET) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_EXPORT_MEM_PACKET) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_EXPORT_MEM_PACKET) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_EXPORT_MEM_PACKET) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_GR_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_GR_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Caps))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_GR_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Caps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_GR_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_GR_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_GR_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_GR_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_GR_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_GR_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_GR_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_GR_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_HOPPER_USERMODE_A_PARAMS) SizeBytes() int {
    return 2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_HOPPER_USERMODE_A_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.Bar1Mapping)
    dst = dst[1:]
    dst[0] = byte(n.Priv)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_HOPPER_USERMODE_A_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Bar1Mapping = uint8(src[0])
    src = src[1:]
    n.Priv = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_HOPPER_USERMODE_A_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_HOPPER_USERMODE_A_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_HOPPER_USERMODE_A_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_HOPPER_USERMODE_A_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS) SizeBytes() int {
    return 108 +
        (*P64)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Owner))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Width))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Height))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Pitch))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Attr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Attr2))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Format))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ComprCovg))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ZcullCovg))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.RangeLo))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.RangeHi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    dst = n.Address.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CtagOffset))
    dst = dst[4:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.InternalFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Tag))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Owner = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Width = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Height = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Pitch = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Attr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Attr2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Format = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ComprCovg = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ZcullCovg = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    n.RangeLo = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.RangeHi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.Address.UnmarshalUnsafe(src)
    n.CtagOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.InternalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Tag = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_ALLOCATION_PARAMS) Packed() bool {
    return n.Address.Packed() && n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_MEMORY_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.Address.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_MEMORY_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_MEMORY_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.Address.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_MEMORY_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_MEMORY_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) SizeBytes() int {
    return 8 +
        (*NV_MEMORY_ALLOCATION_PARAMS)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) MarshalBytes(dst []byte) []byte {
    dst = n.NV_MEMORY_ALLOCATION_PARAMS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumaNode))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) UnmarshalBytes(src []byte) []byte {
    src = n.NV_MEMORY_ALLOCATION_PARAMS.UnmarshalUnsafe(src)
    n.NumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) Packed() bool {
    return n.NV_MEMORY_ALLOCATION_PARAMS.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) MarshalUnsafe(dst []byte) []byte {
    if n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_MEMORY_ALLOCATION_PARAMS_V545 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_MEMORY_ALLOCATION_PARAMS_V545 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS_V545 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS_V545 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        // Type NV_MEMORY_ALLOCATION_PARAMS_V545 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_MEMORY_DESC_PARAMS) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_MEMORY_DESC_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AddressSpace))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CacheAttrib))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_MEMORY_DESC_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AddressSpace = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.CacheAttrib = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_DESC_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_MEMORY_DESC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_MEMORY_DESC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_MEMORY_DESC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_MEMORY_DESC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_MEMORY_DESC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_MEMORY_DESC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_MEMORY_DESC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) Packed() bool {
    return n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        // Type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MSENC_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_MSENC_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 44 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VAStartInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VALimitInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.BigPageSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VABase))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.VASize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAStartInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VALimitInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.BigPageSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.VABase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *nv00f8Map) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *nv00f8Map) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.offset))
    dst = dst[8:]
    dst = n.hVidMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *nv00f8Map) UnmarshalBytes(src []byte) []byte {
    n.offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.hVidMem.UnmarshalUnsafe(src)
    n.flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *nv00f8Map) Packed() bool {
    return n.hVidMem.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *nv00f8Map) MarshalUnsafe(dst []byte) []byte {
    if n.hVidMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type nv00f8Map doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *nv00f8Map) UnmarshalUnsafe(src []byte) []byte {
    if n.hVidMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type nv00f8Map doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *nv00f8Map) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.hVidMem.Packed() {
        // Type nv00f8Map doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *nv00f8Map) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *nv00f8Map) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.hVidMem.Packed() {
        // Type nv00f8Map doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *nv00f8Map) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *nv00f8Map) WriteTo(writer io.Writer) (int64, error) {
    if !n.hVidMem.Packed() {
        // Type nv00f8Map doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) SizeBytes() int {
    return 32 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceInstance))
    dst = dst[4:]
    dst = n.SzName.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SliStatus))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.BoardID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumaID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.GpuID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.GpuFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.SzName.UnmarshalUnsafe(src)
    n.SliStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BoardID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.GpuInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.NumaID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) Packed() bool {
    return n.SzName.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.SzName.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_GPU_GET_ID_INFO_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.SzName.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_GPU_GET_ID_INFO_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.SzName.Packed() {
        // Type NV0000_CTRL_GPU_GET_ID_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.SzName.Packed() {
        // Type NV0000_CTRL_GPU_GET_ID_INFO_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.SzName.Packed() {
        // Type NV0000_CTRL_GPU_GET_ID_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) SizeBytes() int {
    return 4 +
        1*12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Type))
    dst = dst[4:]
    for idx := 0; idx < 12; idx++ {
        dst[0] = byte(n.Data[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) UnmarshalBytes(src []byte) []byte {
    n.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 12; idx++ {
        n.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) SizeBytes() int {
    return 8 +
        (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.Object.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.Object.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) Packed() bool {
    return p.Object.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) SizeBytes() int {
    return 10 +
        1*NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE +
        1*2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.MaxObjects))
    dst = dst[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        dst[0] = byte(p.Metadata[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.MaxObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        p.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) SizeBytes() int {
    return 14 +
        1*NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE +
        1*2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.GpuInstanceID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.MaxObjects))
    dst = dst[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        dst[0] = byte(p.Metadata[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.GpuInstanceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.MaxObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        p.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) SizeBytes() int {
    return 4 +
        (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.Object.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.Object.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) Packed() bool {
    return p.Object.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.Object.Packed() {
        // Type NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) SizeBytes() int {
    return 12 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SizeOfStrings))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.PDriverVersionBuffer.MarshalUnsafe(dst)
    dst = n.PVersionBuffer.MarshalUnsafe(dst)
    dst = n.PTitleBuffer.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ChangelistNumber))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.OfficialChangelistNumber))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.SizeOfStrings = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.PDriverVersionBuffer.UnmarshalUnsafe(src)
    src = n.PVersionBuffer.UnmarshalUnsafe(src)
    src = n.PTitleBuffer.UnmarshalUnsafe(src)
    n.ChangelistNumber = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.OfficialChangelistNumber = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) Packed() bool {
    return n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) SizeBytes() int {
    return 16 +
        4*NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS +
        1*NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE +
        1*7 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuIDs[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2PCaps))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2POptimalReadCEs))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2POptimalWriteCEs))
    dst = dst[4:]
    for idx := 0; idx < NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE; idx++ {
        dst[0] = byte(n.P2PCapsStatus[idx])
        dst = dst[1:]
    }
    // Padding: dst[:sizeof(byte)*7] ~= [7]byte{0}
    dst = dst[1*(7):]
    dst = n.BusPeerIDs.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS; idx++ {
        n.GpuIDs[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.GpuCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2PCaps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2POptimalReadCEs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2POptimalWriteCEs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE; idx++ {
        n.P2PCapsStatus[idx] = uint8(src[0])
        src = src[1:]
    }
    // Padding: ~ copy([7]byte(n._), src[:sizeof(byte)*7])
    src = src[1*(7):]
    src = n.BusPeerIDs.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) Packed() bool {
    return n.BusPeerIDs.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.BusPeerIDs.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.BusPeerIDs.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusPeerIDs.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusPeerIDs.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.BusPeerIDs.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) SizeBytes() int {
    return 0 +
        (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    dst = n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.MarshalUnsafe(dst)
    dst = n.BusEgmPeerIDs.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    src = n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.UnmarshalUnsafe(src)
    src = n.BusEgmPeerIDs.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) Packed() bool {
    return n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        // Type NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.PChannelHandleList.MarshalUnsafe(dst)
    dst = n.PChannelList.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.PChannelHandleList.UnmarshalUnsafe(src)
    src = n.PChannelList.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) Packed() bool {
    return n.PChannelHandleList.Packed() && n.PChannelList.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        // Type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        // Type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        // Type NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CapsTblSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.CapsTbl.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.CapsTblSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.CapsTbl.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_GET_CAPS_PARAMS) Packed() bool {
    return n.CapsTbl.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.CapsTbl.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0080_CTRL_GET_CAPS_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.CapsTbl.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0080_CTRL_GET_CAPS_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.CapsTbl.Packed() {
        // Type NV0080_CTRL_GET_CAPS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.CapsTbl.Packed() {
        // Type NV0080_CTRL_GET_CAPS_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0080_CTRL_GET_CAPS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.CapsTbl.Packed() {
        // Type NV0080_CTRL_GET_CAPS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0080_CTRL_GR_ROUTE_INFO) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0080_CTRL_GR_ROUTE_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Route))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0080_CTRL_GR_ROUTE_INFO) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.Route = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_GR_ROUTE_INFO) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0080_CTRL_GR_ROUTE_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0080_CTRL_GR_ROUTE_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV0080_CTRL_GR_ROUTE_INFO) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DevDescriptor))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DevDescriptor = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) Packed() bool {
    return n.HSubDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV00FD_CTRL_ATTACH_GPU_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV00FD_CTRL_ATTACH_GPU_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSubDevice.Packed() {
        // Type NV00FD_CTRL_ATTACH_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSubDevice.Packed() {
        // Type NV00FD_CTRL_ATTACH_GPU_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HSubDevice.Packed() {
        // Type NV00FD_CTRL_ATTACH_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) SizeBytes() int {
    return 7 +
        1*3 +
        1*6 +
        (*P64)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES +
        (*Handle)(nil).SizeBytes()*NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.BDisable)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    dst[0] = byte(n.BOnlyDisableScheduling)
    dst = dst[1:]
    dst[0] = byte(n.BRewindGpPut)
    dst = dst[1:]
    for idx := 0; idx < 6; idx++ {
        dst[0] = byte(n.Pad2[idx])
        dst = dst[1:]
    }
    dst = n.PRunlistPreemptEvent.MarshalUnsafe(dst)
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        dst = n.HClientList[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        dst = n.HChannelList[idx].MarshalUnsafe(dst)
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.BDisable = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BOnlyDisableScheduling = uint8(src[0])
    src = src[1:]
    n.BRewindGpPut = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 6; idx++ {
        n.Pad2[idx] = src[0]
        src = src[1:]
    }
    src = n.PRunlistPreemptEvent.UnmarshalUnsafe(src)
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        src = n.HClientList[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        src = n.HChannelList[idx].UnmarshalUnsafe(src)
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) Packed() bool {
    return n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        // Type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        // Type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        // Type NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) SizeBytes() int {
    return 0 +
        (*NvxxxCtrlXxxGetInfoParams)(nil).SizeBytes() +
        (*NV0080_CTRL_GR_ROUTE_INFO)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.NvxxxCtrlXxxGetInfoParams.MarshalUnsafe(dst)
    dst = p.GRRouteInfo.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.NvxxxCtrlXxxGetInfoParams.UnmarshalUnsafe(src)
    src = p.GRRouteInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) Packed() bool {
    return p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASpaceToken))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.VASpaceToken = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) Packed() bool {
    return n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        // Type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        // Type NV503C_CTRL_REGISTER_VA_SPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVXXXX_CTRL_XXX_INFO) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVXXXX_CTRL_XXX_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Data))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVXXXX_CTRL_XXX_INFO) UnmarshalBytes(src []byte) []byte {
    n.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Data = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVXXXX_CTRL_XXX_INFO) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVXXXX_CTRL_XXX_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVXXXX_CTRL_XXX_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVXXXX_CTRL_XXX_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVXXXX_CTRL_XXX_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVXXXX_CTRL_XXX_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVXXXX_CTRL_XXX_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVXXXX_CTRL_XXX_INFO) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NvxxxCtrlXxxGetInfoParams) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NvxxxCtrlXxxGetInfoParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.InfoListSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    dst = p.InfoList.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NvxxxCtrlXxxGetInfoParams) UnmarshalBytes(src []byte) []byte {
    p.InfoListSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    src = p.InfoList.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NvxxxCtrlXxxGetInfoParams) Packed() bool {
    return p.InfoList.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NvxxxCtrlXxxGetInfoParams) MarshalUnsafe(dst []byte) []byte {
    if p.InfoList.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type NvxxxCtrlXxxGetInfoParams doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NvxxxCtrlXxxGetInfoParams) UnmarshalUnsafe(src []byte) []byte {
    if p.InfoList.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NvxxxCtrlXxxGetInfoParams doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NvxxxCtrlXxxGetInfoParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.InfoList.Packed() {
        // Type NvxxxCtrlXxxGetInfoParams doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NvxxxCtrlXxxGetInfoParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NvxxxCtrlXxxGetInfoParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.InfoList.Packed() {
        // Type NvxxxCtrlXxxGetInfoParams doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NvxxxCtrlXxxGetInfoParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NvxxxCtrlXxxGetInfoParams) WriteTo(writer io.Writer) (int64, error) {
    if !p.InfoList.Packed() {
        // Type NvxxxCtrlXxxGetInfoParams doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RmapiParamNvU32List) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RmapiParamNvU32List) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.NumElems))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(r.Pad[idx])
        dst = dst[1:]
    }
    dst = r.List.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RmapiParamNvU32List) UnmarshalBytes(src []byte) []byte {
    r.NumElems = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        r.Pad[idx] = src[0]
        src = src[1:]
    }
    src = r.List.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RmapiParamNvU32List) Packed() bool {
    return r.List.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RmapiParamNvU32List) MarshalUnsafe(dst []byte) []byte {
    if r.List.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    // Type RmapiParamNvU32List doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RmapiParamNvU32List) UnmarshalUnsafe(src []byte) []byte {
    if r.List.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type RmapiParamNvU32List doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RmapiParamNvU32List) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.List.Packed() {
        // Type RmapiParamNvU32List doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        r.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *RmapiParamNvU32List) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RmapiParamNvU32List) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.List.Packed() {
        // Type RmapiParamNvU32List doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        r.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RmapiParamNvU32List) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RmapiParamNvU32List) WriteTo(writer io.Writer) (int64, error) {
    if !r.List.Packed() {
        // Type RmapiParamNvU32List doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlAllocOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlAllocOSEvent) MarshalBytes(dst []byte) []byte {
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlAllocOSEvent) UnmarshalBytes(src []byte) []byte {
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HDevice.UnmarshalUnsafe(src)
    p.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlAllocOSEvent) Packed() bool {
    return p.HClient.Packed() && p.HDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlAllocOSEvent) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlAllocOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlAllocOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlAllocOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlAllocOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlAllocOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlAllocOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlFreeOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlFreeOSEvent) MarshalBytes(dst []byte) []byte {
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlFreeOSEvent) UnmarshalBytes(src []byte) []byte {
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HDevice.UnmarshalUnsafe(src)
    p.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlFreeOSEvent) Packed() bool {
    return p.HClient.Packed() && p.HDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlFreeOSEvent) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlFreeOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlFreeOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlFreeOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlFreeOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlFreeOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlFreeOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlNVOS02ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS02_PARAMETERS)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlNVOS02ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = p.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlNVOS02ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = p.Params.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlNVOS02ParametersWithFD) Packed() bool {
    return p.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlNVOS02ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlNVOS02ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlNVOS02ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlNVOS02ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlNVOS02ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlNVOS02ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlNVOS02ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlNVOS33ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS33_PARAMETERS)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlNVOS33ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = p.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlNVOS33ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = p.Params.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlNVOS33ParametersWithFD) Packed() bool {
    return p.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlNVOS33ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlNVOS33ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlNVOS33ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlNVOS33ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlNVOS33ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlNVOS33ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlNVOS33ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !p.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlRegisterFD) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlRegisterFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.CtlFD))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlRegisterFD) UnmarshalBytes(src []byte) []byte {
    p.CtlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlRegisterFD) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlRegisterFD) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlRegisterFD) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlRegisterFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlRegisterFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlRegisterFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlRegisterFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlRegisterFD) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlSysParams) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlSysParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.MemblockSize))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlSysParams) UnmarshalBytes(src []byte) []byte {
    p.MemblockSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlSysParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlSysParams) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlSysParams) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlSysParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlSysParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlSysParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlSysParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlSysParams) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *IoctlWaitOpenComplete) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *IoctlWaitOpenComplete) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Rc))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.AdapterStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *IoctlWaitOpenComplete) UnmarshalBytes(src []byte) []byte {
    p.Rc = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.AdapterStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlWaitOpenComplete) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *IoctlWaitOpenComplete) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *IoctlWaitOpenComplete) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *IoctlWaitOpenComplete) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *IoctlWaitOpenComplete) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *IoctlWaitOpenComplete) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *IoctlWaitOpenComplete) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *IoctlWaitOpenComplete) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *NVOS00_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *NVOS00_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = p.HRoot.MarshalUnsafe(dst)
    dst = p.HObjectParent.MarshalUnsafe(dst)
    dst = p.HObjectOld.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *NVOS00_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = p.HRoot.UnmarshalUnsafe(src)
    src = p.HObjectParent.UnmarshalUnsafe(src)
    src = p.HObjectOld.UnmarshalUnsafe(src)
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NVOS00_PARAMETERS) Packed() bool {
    return p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *NVOS00_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type NVOS00_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *NVOS00_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS00_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *NVOS00_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        // Type NVOS00_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *NVOS00_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *NVOS00_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        // Type NVOS00_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *NVOS00_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *NVOS00_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        // Type NVOS00_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS02_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS02_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.PMemory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS02_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.PMemory.UnmarshalUnsafe(src)
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS02_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS02_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS02_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS02_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS02_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS02_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS02_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS02_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS02_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS02_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS21_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS21_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    dst = n.PAllocParms.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS21_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    src = n.PAllocParms.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS21_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS21_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS21_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS21_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS21_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS21_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS21_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS21_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS21_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS21_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS30_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS30_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Channel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    dst = n.Clients.MarshalUnsafe(dst)
    dst = n.Devices.MarshalUnsafe(dst)
    dst = n.Channels.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Timeout))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS30_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Channel.UnmarshalUnsafe(src)
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Clients.UnmarshalUnsafe(src)
    src = n.Devices.UnmarshalUnsafe(src)
    src = n.Channels.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Timeout = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS30_PARAMETERS) Packed() bool {
    return n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS30_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS30_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS30_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS30_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS30_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        // Type NVOS30_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS30_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS30_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        // Type NVOS30_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS30_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS30_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        // Type NVOS30_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS32_PARAMETERS) SizeBytes() int {
    return 26 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*2 +
        1*144
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS32_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Function))
    dst = dst[4:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.IVCHeapNumber))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Total))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Free))
    dst = dst[8:]
    for idx := 0; idx < 144; idx++ {
        dst[0] = byte(n.Data[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS32_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    n.Function = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.IVCHeapNumber = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Total = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Free = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 144; idx++ {
        n.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS32_PARAMETERS) Packed() bool {
    return n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS32_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS32_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS32_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS32_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS32_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS32_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS32_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS32_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS32_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS33_PARAMETERS) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS33_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Length))
    dst = dst[8:]
    dst = n.PLinearAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS33_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.PLinearAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS33_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS33_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS33_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS33_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS33_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS33_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS33_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS33_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS33_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS33_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS34_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS34_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.PLinearAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS34_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.PLinearAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS34_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS34_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS34_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS34_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS34_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS34_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS34_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS34_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS34_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS34_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS39_PARAMETERS) SizeBytes() int {
    return 28 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS39_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HSubDevice.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Selector))
    dst = dst[4:]
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS39_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HSubDevice.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Selector = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS39_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS39_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS39_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS39_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS39_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS39_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        // Type NVOS39_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS39_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS39_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        // Type NVOS39_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS39_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS39_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        // Type NVOS39_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS46_PARAMETERS) SizeBytes() int {
    return 32 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS46_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS46_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS46_PARAMETERS) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS46_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS46_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS46_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS46_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS46_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS46_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS46_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS46_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS46_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS46_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS46_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS46_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS47_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS47_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS47_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS47_PARAMETERS) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS47_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS47_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS47_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS47_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS47_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS47_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS47_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS47_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS47_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS47_PARAMETERS_V550) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS47_PARAMETERS_V550) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS47_PARAMETERS_V550) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS47_PARAMETERS_V550) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS47_PARAMETERS_V550) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS47_PARAMETERS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS47_PARAMETERS_V550) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS47_PARAMETERS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS47_PARAMETERS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS47_PARAMETERS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS47_PARAMETERS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS47_PARAMETERS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS47_PARAMETERS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        // Type NVOS47_PARAMETERS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS54_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS54_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS54_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    n.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Params.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS54_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS54_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS54_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS54_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS54_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS54_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS54_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS54_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS54_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS54_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS55_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS55_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HParent.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    dst = n.HClientSrc.MarshalUnsafe(dst)
    dst = n.HObjectSrc.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS55_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HParent.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    src = n.HClientSrc.UnmarshalUnsafe(src)
    src = n.HObjectSrc.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS55_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS55_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS55_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS55_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS55_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS55_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS55_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS55_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS55_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS55_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS56_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS56_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.POldCPUAddress.MarshalUnsafe(dst)
    dst = n.PNewCPUAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS56_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.POldCPUAddress.UnmarshalUnsafe(src)
    src = n.PNewCPUAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS56_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS56_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS56_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS56_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS56_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS56_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS56_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS56_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS56_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS56_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS57_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*RS_SHARE_POLICY)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS57_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    dst = n.SharePolicy.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS57_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    src = n.SharePolicy.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS57_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS57_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS57_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS57_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS57_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS57_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS57_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS57_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS57_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS57_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS64_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS64_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    dst = n.PAllocParms.MarshalUnsafe(dst)
    dst = n.PRightsRequested.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS64_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    src = n.PAllocParms.UnmarshalUnsafe(src)
    src = n.PRightsRequested.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS64_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS64_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS64_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS64_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS64_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS64_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NVOS64_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS64_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64_PARAMETERS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NVOS64_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS64_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64_PARAMETERS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *RMAPIVersion) SizeBytes() int {
    return 8 +
        1*64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *RMAPIVersion) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Reply))
    dst = dst[4:]
    for idx := 0; idx < 64; idx++ {
        dst[0] = byte(p.VersionString[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *RMAPIVersion) UnmarshalBytes(src []byte) []byte {
    p.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Reply = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 64; idx++ {
        p.VersionString[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *RMAPIVersion) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *RMAPIVersion) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *RMAPIVersion) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *RMAPIVersion) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *RMAPIVersion) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *RMAPIVersion) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *RMAPIVersion) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *RMAPIVersion) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (h *Handle) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (h *Handle) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(h.Val))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (h *Handle) UnmarshalBytes(src []byte) []byte {
    h.Val = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (h *Handle) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (h *Handle) MarshalUnsafe(dst []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(h), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (h *Handle) UnmarshalUnsafe(src []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(h), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (h *Handle) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that h
    // must live until the use above.
    runtime.KeepAlive(h) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (h *Handle) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyOutN(cc, addr, h.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (h *Handle) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that h
    // must live until the use above.
    runtime.KeepAlive(h) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (h *Handle) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyInN(cc, addr, h.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (h *Handle) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that h
    // must live until the use above.
    runtime.KeepAlive(h) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NvUUID) SizeBytes() int {
    return 1 * 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NvUUID) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(n[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NvUUID) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        n[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NvUUID) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NvUUID) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&n[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NvUUID) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NvUUID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NvUUID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NvUUID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NvUUID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NvUUID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (p *P64) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *P64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*p))
    return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *P64) UnmarshalBytes(src []byte) []byte {
    *p = P64(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *P64) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *P64) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *P64) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *P64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *P64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *P64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *P64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *P64) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RS_ACCESS_MASK) SizeBytes() int {
    return 0 +
        4*SDK_RS_ACCESS_MAX_LIMBS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RS_ACCESS_MASK) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < SDK_RS_ACCESS_MAX_LIMBS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Limbs[idx]))
        dst = dst[4:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RS_ACCESS_MASK) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < SDK_RS_ACCESS_MAX_LIMBS; idx++ {
        r.Limbs[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RS_ACCESS_MASK) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RS_ACCESS_MASK) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RS_ACCESS_MASK) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RS_ACCESS_MASK) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *RS_ACCESS_MASK) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RS_ACCESS_MASK) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RS_ACCESS_MASK) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RS_ACCESS_MASK) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RS_SHARE_POLICY) SizeBytes() int {
    return 7 +
        (*RS_ACCESS_MASK)(nil).SizeBytes() +
        1*1
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RS_SHARE_POLICY) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Target))
    dst = dst[4:]
    dst = r.AccessMask.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Type))
    dst = dst[2:]
    dst[0] = byte(r.Action)
    dst = dst[1:]
    for idx := 0; idx < 1; idx++ {
        dst[0] = byte(r.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RS_SHARE_POLICY) UnmarshalBytes(src []byte) []byte {
    r.Target = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = r.AccessMask.UnmarshalUnsafe(src)
    r.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    r.Action = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 1; idx++ {
        r.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RS_SHARE_POLICY) Packed() bool {
    return r.AccessMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RS_SHARE_POLICY) MarshalUnsafe(dst []byte) []byte {
    if r.AccessMask.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    // Type RS_SHARE_POLICY doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RS_SHARE_POLICY) UnmarshalUnsafe(src []byte) []byte {
    if r.AccessMask.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type RS_SHARE_POLICY doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RS_SHARE_POLICY) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.AccessMask.Packed() {
        // Type RS_SHARE_POLICY doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        r.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *RS_SHARE_POLICY) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RS_SHARE_POLICY) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.AccessMask.Packed() {
        // Type RS_SHARE_POLICY doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        r.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RS_SHARE_POLICY) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RS_SHARE_POLICY) WriteTo(writer io.Writer) (int64, error) {
    if !r.AccessMask.Packed() {
        // Type RS_SHARE_POLICY doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) SizeBytes() int {
    return 28 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) SizeBytes() int {
    return 28 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS_V2 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUIDA.MarshalUnsafe(dst)
    dst = p.GPUUUIDB.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUIDA.UnmarshalUnsafe(src)
    src = p.GPUUUIDB.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) Packed() bool {
    return p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_DISABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_DISABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_DISABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_DISABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_DISABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUIDA.MarshalUnsafe(dst)
    dst = p.GPUUUIDB.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUIDA.UnmarshalUnsafe(src)
    src = p.GPUUUIDB.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) Packed() bool {
    return p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_ENABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_ENABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_ENABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_ENABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        // Type UVM_ENABLE_PEER_ACCESS_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_FREE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_FREE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_FREE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_FREE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_FREE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_FREE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_FREE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_FREE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_FREE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_FREE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_FREE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_INITIALIZE_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) SizeBytes() int {
    return 48 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offset))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HClient))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HMemory))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HClient = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HMemory = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) SizeBytes() int {
    return 48 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS_V2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offset))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HClient))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HMemory))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HClient = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HMemory = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MIGRATE_PARAMS) SizeBytes() int {
    return 56 +
        (*NvUUID)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MIGRATE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.SemaphoreAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.SemaphorePayload))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.CPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceStart))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MIGRATE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(p._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    p.SemaphoreAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.SemaphorePayload = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.CPUNumaNode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.UserSpaceStart = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.UserSpaceLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(p._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_PARAMS) Packed() bool {
    return p.DestinationUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MIGRATE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MIGRATE_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MIGRATE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MIGRATE_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MIGRATE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MIGRATE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MIGRATE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MIGRATE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MIGRATE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MIGRATE_PARAMS_V550) SizeBytes() int {
    return 56 +
        (*NvUUID)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MIGRATE_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.SemaphoreAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.SemaphorePayload))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.CPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceStart))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MIGRATE_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(p._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    p.SemaphoreAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.SemaphorePayload = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.CPUNumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.UserSpaceStart = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.UserSpaceLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(p._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_PARAMS_V550) Packed() bool {
    return p.DestinationUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MIGRATE_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MIGRATE_PARAMS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MIGRATE_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MIGRATE_PARAMS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MIGRATE_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MIGRATE_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MIGRATE_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MIGRATE_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MIGRATE_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) Packed() bool {
    return p.DestinationUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MIGRATE_RANGE_GROUP_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MIGRATE_RANGE_GROUP_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_RANGE_GROUP_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_RANGE_GROUP_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        // Type UVM_MIGRATE_RANGE_GROUP_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_MM_INITIALIZE_PARAMS) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_MM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.UvmFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_MM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.UvmFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_MM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_MM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_MM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_MM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) SizeBytes() int {
    return 5 +
        (*NvUUID)(nil).SizeBytes() +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst[0] = byte(p.PageableMemAccess)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.PageableMemAccess = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) SizeBytes() int {
    return 5 +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(p.PageableMemAccess)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.PageableMemAccess = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_REGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 24 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HChannel.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_REGISTER_CHANNEL_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HChannel.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_CHANNEL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_REGISTER_CHANNEL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_REGISTER_GPU_PARAMS) SizeBytes() int {
    return 13 +
        (*NvUUID)(nil).SizeBytes() +
        1*3 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst[0] = byte(p.NumaEnabled)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumaNodeID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HSMCPartRef.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_REGISTER_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.NumaEnabled = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.NumaNodeID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HSMCPartRef.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_REGISTER_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_REGISTER_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_REGISTER_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_REGISTER_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) SizeBytes() int {
    return 8 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HVASpace.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.PreferredLocation.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.PreferredLocation.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) Packed() bool {
    return p.PreferredLocation.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_SET_PREFERRED_LOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_SET_PREFERRED_LOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) SizeBytes() int {
    return 24 +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.PreferredLocation.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.PreferredCPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.PreferredLocation.UnmarshalUnsafe(src)
    p.PreferredCPUNumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) Packed() bool {
    return p.PreferredLocation.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_SET_PREFERRED_LOCATION_PARAMS_V550 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_SET_PREFERRED_LOCATION_PARAMS_V550 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PreferredLocation.Packed() {
        // Type UVM_SET_PREFERRED_LOCATION_PARAMS_V550 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_SET_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 28 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_SET_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_SET_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_SET_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_SET_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_SET_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) SizeBytes() int {
    return 36 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Buffer))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.TargetVA))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.BytesRead))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(u.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Buffer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.TargetVA = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.BytesRead = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        u.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) SizeBytes() int {
    return 36 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Buffer))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.TargetVA))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.BytesWritten))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(u.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Buffer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.TargetVA = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.BytesWritten = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        u.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNMAP_EXTERNAL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNMAP_EXTERNAL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNMAP_EXTERNAL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNMAP_EXTERNAL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNMAP_EXTERNAL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNMAP_EXTERNAL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNMAP_EXTERNAL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HChannel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HChannel.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNREGISTER_GPU_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNREGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNREGISTER_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNREGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNREGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNREGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNREGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNREGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNREGISTER_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNREGISTER_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNREGISTER_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNREGISTER_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNREGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNREGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        // Type UVM_UNREGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.AccessedByUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.AccessedByUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) Packed() bool {
    return p.AccessedByUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNSET_ACCESSED_BY_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNSET_ACCESSED_BY_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        // Type UVM_UNSET_ACCESSED_BY_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        p.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        // Type UVM_UNSET_ACCESSED_BY_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        p.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.AccessedByUUID.Packed() {
        // Type UVM_UNSET_ACCESSED_BY_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UvmGpuMappingAttributes) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UvmGpuMappingAttributes) MarshalBytes(dst []byte) []byte {
    dst = u.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUMappingType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUCachingType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUFormatType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUElementBits))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUCompressionType))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UvmGpuMappingAttributes) UnmarshalBytes(src []byte) []byte {
    src = u.GPUUUID.UnmarshalUnsafe(src)
    u.GPUMappingType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUCachingType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUFormatType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUElementBits = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUCompressionType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UvmGpuMappingAttributes) Packed() bool {
    return u.GPUUUID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UvmGpuMappingAttributes) MarshalUnsafe(dst []byte) []byte {
    if u.GPUUUID.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
        return dst[size:]
    }
    // Type UvmGpuMappingAttributes doesn't have a packed layout in memory, fallback to MarshalBytes.
    return u.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UvmGpuMappingAttributes) UnmarshalUnsafe(src []byte) []byte {
    if u.GPUUUID.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UvmGpuMappingAttributes doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return u.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UvmGpuMappingAttributes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.GPUUUID.Packed() {
        // Type UvmGpuMappingAttributes doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(u.SizeBytes()) // escapes: okay.
        u.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (u *UvmGpuMappingAttributes) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UvmGpuMappingAttributes) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.GPUUUID.Packed() {
        // Type UvmGpuMappingAttributes doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(u.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        u.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (u *UvmGpuMappingAttributes) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UvmGpuMappingAttributes) WriteTo(writer io.Writer) (int64, error) {
    if !u.GPUUUID.Packed() {
        // Type UvmGpuMappingAttributes doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, u.SizeBytes())
        u.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

