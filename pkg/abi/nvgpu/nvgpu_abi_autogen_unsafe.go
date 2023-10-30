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
var _ marshal.Marshallable = (*Handle)(nil)
var _ marshal.Marshallable = (*IoctlAllocOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlFreeOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlNVOS02ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlNVOS33ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlRegisterFD)(nil)
var _ marshal.Marshallable = (*IoctlSysParams)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0005_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_GR_ROUTE_INFO)(nil)
var _ marshal.Marshallable = (*NV00F8_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00F8_ALLOCATION_PARAMETERS_V535)(nil)
var _ marshal.Marshallable = (*NV2080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_GR_GET_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV503C_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV83DE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVB0B5_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS00Parameters)(nil)
var _ marshal.Marshallable = (*NVOS02Parameters)(nil)
var _ marshal.Marshallable = (*NVOS21Parameters)(nil)
var _ marshal.Marshallable = (*NVOS21ParametersV535)(nil)
var _ marshal.Marshallable = (*NVOS32Parameters)(nil)
var _ marshal.Marshallable = (*NVOS33Parameters)(nil)
var _ marshal.Marshallable = (*NVOS34Parameters)(nil)
var _ marshal.Marshallable = (*NVOS54Parameters)(nil)
var _ marshal.Marshallable = (*NVOS55Parameters)(nil)
var _ marshal.Marshallable = (*NVOS56Parameters)(nil)
var _ marshal.Marshallable = (*NVOS57Parameters)(nil)
var _ marshal.Marshallable = (*NVOS64Parameters)(nil)
var _ marshal.Marshallable = (*NVOS64ParametersV535)(nil)
var _ marshal.Marshallable = (*NVXXXX_CTRL_XXX_INFO)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CTXSHARE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_GR_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_HOPPER_USERMODE_A_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_DESC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_VASPACE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*P64)(nil)
var _ marshal.Marshallable = (*RMAPIVersion)(nil)
var _ marshal.Marshallable = (*RS_ACCESS_MASK)(nil)
var _ marshal.Marshallable = (*RS_SHARE_POLICY)(nil)
var _ marshal.Marshallable = (*UVM_ALLOC_SEMAPHORE_POOL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_EXTERNAL_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DESTROY_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DISABLE_READ_DUPLICATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_FREE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_PAGEABLE_MEM_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_VALIDATE_VA_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UvmGpuMappingAttributes)(nil)
var _ marshal.Marshallable = (*nv00f8Map)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NV0005_ALLOC_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV0005_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HParentClient.MarshalUnsafe(dst)
    dst = n.HSrcResource.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NotifyIndex))
    dst = dst[4:]
    dst = n.Data.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV0005_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HParentClient.UnmarshalUnsafe(src)
    src = n.HSrcResource.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.NotifyIndex = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Data.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0005_ALLOC_PARAMETERS) Packed() bool {
    return n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV0005_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV0005_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV0005_ALLOC_PARAMETERS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV0005_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
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
    if !n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
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
    if !n.Data.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
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
func (n *NV00F8_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 24 +
        (*nv00f8Map)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00F8_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PageSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AllocFlags))
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
    n.PageSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
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
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) SizeBytes() int {
    return 32 +
        (*nv00f8Map)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) MarshalBytes(dst []byte) []byte {
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
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) UnmarshalBytes(src []byte) []byte {
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
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) Packed() bool {
    return n.Map.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) MarshalUnsafe(dst []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV00F8_ALLOCATION_PARAMETERS_V535 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) UnmarshalUnsafe(src []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV00F8_ALLOCATION_PARAMETERS_V535 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS_V535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS_V535 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV00F8_ALLOCATION_PARAMETERS_V535) WriteTo(writer io.Writer) (int64, error) {
    if !n.Map.Packed() {
        // Type NV00F8_ALLOCATION_PARAMETERS_V535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes()
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
    return 4 +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.Handle.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.Handle.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
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
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*NV0080_CTRL_GR_ROUTE_INFO)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GRInfoListSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.GRInfoList.MarshalUnsafe(dst)
    dst = n.GRRouteInfo.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.GRInfoListSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.GRInfoList.UnmarshalUnsafe(src)
    src = n.GRRouteInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) Packed() bool {
    return n.GRInfoList.Packed() && n.GRRouteInfo.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.GRInfoList.Packed() && n.GRRouteInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.GRInfoList.Packed() && n.GRRouteInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.GRInfoList.Packed() && n.GRRouteInfo.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.GRInfoList.Packed() && n.GRRouteInfo.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NV2080_CTRL_GR_GET_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.GRInfoList.Packed() && n.GRRouteInfo.Packed() {
        // Type NV2080_CTRL_GR_GET_INFO_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (i *IoctlAllocOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlAllocOSEvent) MarshalBytes(dst []byte) []byte {
    dst = i.HClient.MarshalUnsafe(dst)
    dst = i.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlAllocOSEvent) UnmarshalBytes(src []byte) []byte {
    src = i.HClient.UnmarshalUnsafe(src)
    src = i.HDevice.UnmarshalUnsafe(src)
    i.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlAllocOSEvent) Packed() bool {
    return i.HClient.Packed() && i.HDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlAllocOSEvent) MarshalUnsafe(dst []byte) []byte {
    if i.HClient.Packed() && i.HDevice.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlAllocOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if i.HClient.Packed() && i.HDevice.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlAllocOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlAllocOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlAllocOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlAllocOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlAllocOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlAllocOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IoctlFreeOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlFreeOSEvent) MarshalBytes(dst []byte) []byte {
    dst = i.HClient.MarshalUnsafe(dst)
    dst = i.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlFreeOSEvent) UnmarshalBytes(src []byte) []byte {
    src = i.HClient.UnmarshalUnsafe(src)
    src = i.HDevice.UnmarshalUnsafe(src)
    i.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlFreeOSEvent) Packed() bool {
    return i.HClient.Packed() && i.HDevice.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlFreeOSEvent) MarshalUnsafe(dst []byte) []byte {
    if i.HClient.Packed() && i.HDevice.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlFreeOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if i.HClient.Packed() && i.HDevice.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlFreeOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlFreeOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlFreeOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlFreeOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlFreeOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !i.HClient.Packed() && i.HDevice.Packed() {
        // Type IoctlFreeOSEvent doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IoctlNVOS02ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS02Parameters)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlNVOS02ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = i.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlNVOS02ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = i.Params.UnmarshalUnsafe(src)
    i.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        i.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlNVOS02ParametersWithFD) Packed() bool {
    return i.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlNVOS02ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if i.Params.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlNVOS02ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if i.Params.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlNVOS02ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlNVOS02ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlNVOS02ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlNVOS02ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlNVOS02ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS02ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IoctlNVOS33ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS33Parameters)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlNVOS33ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = i.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlNVOS33ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = i.Params.UnmarshalUnsafe(src)
    i.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        i.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlNVOS33ParametersWithFD) Packed() bool {
    return i.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlNVOS33ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if i.Params.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlNVOS33ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if i.Params.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlNVOS33ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlNVOS33ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlNVOS33ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlNVOS33ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlNVOS33ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !i.Params.Packed() {
        // Type IoctlNVOS33ParametersWithFD doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IoctlRegisterFD) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlRegisterFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CtlFD))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlRegisterFD) UnmarshalBytes(src []byte) []byte {
    i.CtlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlRegisterFD) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlRegisterFD) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlRegisterFD) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlRegisterFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlRegisterFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlRegisterFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlRegisterFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlRegisterFD) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IoctlSysParams) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IoctlSysParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.MemblockSize))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IoctlSysParams) UnmarshalBytes(src []byte) []byte {
    i.MemblockSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlSysParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IoctlSysParams) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IoctlSysParams) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IoctlSysParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IoctlSysParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IoctlSysParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IoctlSysParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IoctlSysParams) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NVOS00Parameters) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS00Parameters) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectOld.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS00Parameters) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectOld.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS00Parameters) Packed() bool {
    return n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS00Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS00Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS00Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS00Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS00Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() {
        // Type NVOS00Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS00Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS00Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() {
        // Type NVOS00Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS00Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS00Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectOld.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() {
        // Type NVOS00Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS02Parameters) SizeBytes() int {
    return 20 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS02Parameters) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
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
func (n *NVOS02Parameters) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
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
func (n *NVOS02Parameters) Packed() bool {
    return n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS02Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS02Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS02Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS02Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS02Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS02Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS02Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS02Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS02Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        // Type NVOS02Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS21Parameters) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS21Parameters) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
    dst = n.PAllocParms.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS21Parameters) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.PAllocParms.UnmarshalUnsafe(src)
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
func (n *NVOS21Parameters) Packed() bool {
    return n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS21Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS21Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS21Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS21Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS21Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS21Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS21Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS21Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS21Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS21ParametersV535) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS21ParametersV535) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
    dst = n.PAllocParms.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS21ParametersV535) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.PAllocParms.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS21ParametersV535) Packed() bool {
    return n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS21ParametersV535) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS21ParametersV535 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS21ParametersV535) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS21ParametersV535 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS21ParametersV535) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21ParametersV535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS21ParametersV535) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS21ParametersV535) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21ParametersV535 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS21ParametersV535) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS21ParametersV535) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        // Type NVOS21ParametersV535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS32Parameters) SizeBytes() int {
    return 26 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*2 +
        1*144
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS32Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS32Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS32Parameters) Packed() bool {
    return n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS32Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS32Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS32Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS32Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS32Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS32Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS32Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS32Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS32Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        // Type NVOS32Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS33Parameters) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS33Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS33Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS33Parameters) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS33Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS33Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS33Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS33Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS33Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS33Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS33Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS33Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS33Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS33Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS34Parameters) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS34Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS34Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS34Parameters) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS34Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS34Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS34Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS34Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS34Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS34Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS34Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS34Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS34Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        // Type NVOS34Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS54Parameters) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS54Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS54Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS54Parameters) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS54Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS54Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS54Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS54Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS54Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS54Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS54Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS54Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS54Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        // Type NVOS54Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS55Parameters) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS55Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS55Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS55Parameters) Packed() bool {
    return n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS55Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS55Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS55Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS55Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS55Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS55Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS55Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS55Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS55Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        // Type NVOS55Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS56Parameters) SizeBytes() int {
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
func (n *NVOS56Parameters) MarshalBytes(dst []byte) []byte {
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
func (n *NVOS56Parameters) UnmarshalBytes(src []byte) []byte {
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
func (n *NVOS56Parameters) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS56Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS56Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS56Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS56Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS56Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS56Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS56Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS56Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS56Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        // Type NVOS56Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS57Parameters) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*RS_SHARE_POLICY)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS57Parameters) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    dst = n.SharePolicy.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS57Parameters) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    src = n.SharePolicy.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS57Parameters) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS57Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS57Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS57Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS57Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS57Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS57Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS57Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS57Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS57Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        // Type NVOS57Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS64Parameters) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS64Parameters) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
    dst = n.PAllocParms.MarshalUnsafe(dst)
    dst = n.PRightsRequested.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NVOS64Parameters) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.PAllocParms.UnmarshalUnsafe(src)
    src = n.PRightsRequested.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS64Parameters) Packed() bool {
    return n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS64Parameters) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS64Parameters doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS64Parameters) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS64Parameters doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS64Parameters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS64Parameters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS64Parameters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64Parameters doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS64Parameters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS64Parameters) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64Parameters doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS64ParametersV535) SizeBytes() int {
    return 20 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NVOS64ParametersV535) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HClass))
    dst = dst[4:]
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
func (n *NVOS64ParametersV535) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    n.HClass = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
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
func (n *NVOS64ParametersV535) Packed() bool {
    return n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NVOS64ParametersV535) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NVOS64ParametersV535 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NVOS64ParametersV535) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NVOS64ParametersV535 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NVOS64ParametersV535) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64ParametersV535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (n *NVOS64ParametersV535) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NVOS64ParametersV535) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64ParametersV535 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (n *NVOS64ParametersV535) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NVOS64ParametersV535) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        // Type NVOS64ParametersV535 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (r *RMAPIVersion) SizeBytes() int {
    return 8 +
        1*64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RMAPIVersion) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Reply))
    dst = dst[4:]
    for idx := 0; idx < 64; idx++ {
        dst[0] = byte(r.VersionString[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RMAPIVersion) UnmarshalBytes(src []byte) []byte {
    r.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Reply = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 64; idx++ {
        r.VersionString[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RMAPIVersion) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RMAPIVersion) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RMAPIVersion) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RMAPIVersion) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RMAPIVersion) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RMAPIVersion) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RMAPIVersion) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RMAPIVersion) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) SizeBytes() int {
    return 28 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        dst = u.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.GPUAttributesCount))
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
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        src = u.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    u.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) Packed() bool {
    return u.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if u.PerGPUAttributes[0].Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
        return dst[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return u.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if u.PerGPUAttributes[0].Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return u.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !u.PerGPUAttributes[0].Packed() {
        // Type UVM_ALLOC_SEMAPHORE_POOL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
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
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_CREATE_EXTERNAL_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.RangeGroupID))
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
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_CREATE_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.RangeGroupID))
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
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_DESTROY_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
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
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_DISABLE_READ_DUPLICATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_FREE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_FREE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
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
func (u *UVM_FREE_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_FREE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_FREE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_FREE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_FREE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_FREE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_FREE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_FREE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_FREE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_INITIALIZE_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Flags))
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
func (u *UVM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) SizeBytes() int {
    return 20 +
        1*16 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
    dst = dst[8:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(u.GPUUUID[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(u.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 16; idx++ {
        u.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
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
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) SizeBytes() int {
    return 40 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
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
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HMemory.MarshalUnsafe(dst)
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
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HMemory.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) Packed() bool {
    return p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed() {
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
    if !p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed() {
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
    if !p.HClient.Packed() && p.HMemory.Packed() && p.PerGPUAttributes[0].Packed() {
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
func (u *UVM_MM_INITIALIZE_PARAMS) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_MM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.UvmFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.Status))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_MM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.UvmFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_MM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_MM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_MM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_MM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_MM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_MM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_MM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_MM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) SizeBytes() int {
    return 5 +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(u.PageableMemAccess)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(u.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.PageableMemAccess = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        u.Pad[idx] = src[0]
        src = src[1:]
    }
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_PAGEABLE_MEM_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (p *UVM_REGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 24 +
        1*16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(p.GPUUUID[idx])
        dst = dst[1:]
    }
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
    for idx := 0; idx < 16; idx++ {
        p.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
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
    return p.HChannel.Packed() && p.HClient.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HChannel.Packed() && p.HClient.Packed() {
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
    if !p.HChannel.Packed() && p.HClient.Packed() {
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
    if !p.HChannel.Packed() && p.HClient.Packed() {
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
        1*16 +
        1*3 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(p.GPUUUID[idx])
        dst = dst[1:]
    }
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
    for idx := 0; idx < 16; idx++ {
        p.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
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
    return p.HClient.Packed() && p.HSMCPartRef.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_GPU_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HSMCPartRef.Packed() {
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
    if !p.HClient.Packed() && p.HSMCPartRef.Packed() {
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
    if !p.HClient.Packed() && p.HSMCPartRef.Packed() {
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
        1*16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(p.GPUUUID[idx])
        dst = dst[1:]
    }
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
    for idx := 0; idx < 16; idx++ {
        p.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
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
    return p.HClient.Packed() && p.HVASpace.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_REGISTER_GPU_VASPACE_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HVASpace.Packed() {
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
    if !p.HClient.Packed() && p.HVASpace.Packed() {
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
    if !p.HClient.Packed() && p.HVASpace.Packed() {
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
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 4 +
        1*16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(u.GPUUUID[idx])
        dst = dst[1:]
    }
    dst = u.HClient.MarshalUnsafe(dst)
    dst = u.HChannel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        u.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
    src = u.HClient.UnmarshalUnsafe(src)
    src = u.HChannel.UnmarshalUnsafe(src)
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) Packed() bool {
    return u.HChannel.Packed() && u.HClient.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if u.HChannel.Packed() && u.HClient.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
        return dst[size:]
    }
    // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return u.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if u.HChannel.Packed() && u.HClient.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return u.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.HChannel.Packed() && u.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.HChannel.Packed() && u.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_UNREGISTER_CHANNEL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !u.HChannel.Packed() && u.HClient.Packed() {
        // Type UVM_UNREGISTER_CHANNEL_PARAMS doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UVM_UNREGISTER_GPU_PARAMS) SizeBytes() int {
    return 4 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_UNREGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(u.GPUUUID[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_UNREGISTER_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        u.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_UNREGISTER_GPU_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_UNREGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_UNREGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_UNREGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_UNREGISTER_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_UNREGISTER_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_UNREGISTER_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_UNREGISTER_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) SizeBytes() int {
    return 4 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(u.GPUUUID[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RMStatus))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        u.GPUUUID[idx] = uint8(src[0])
        src = src[1:]
    }
    u.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_UNREGISTER_GPU_VASPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
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
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    u.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
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
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UVM_VALIDATE_VA_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UvmGpuMappingAttributes) SizeBytes() int {
    return 20 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UvmGpuMappingAttributes) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(u.GPUUUID[idx])
        dst = dst[1:]
    }
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
    for idx := 0; idx < 16; idx++ {
        u.GPUUUID[idx] = src[0]
        src = src[1:]
    }
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
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UvmGpuMappingAttributes) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UvmGpuMappingAttributes) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UvmGpuMappingAttributes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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

