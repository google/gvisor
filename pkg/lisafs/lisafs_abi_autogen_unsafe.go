// Automatically generated marshal implementation. See tools/go_marshal.

package lisafs

import (
    "gvisor.dev/gvisor/pkg/abi/linux"
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*ChannelResp)(nil)
var _ marshal.Marshallable = (*ConnectReq)(nil)
var _ marshal.Marshallable = (*ErrorResp)(nil)
var _ marshal.Marshallable = (*FAllocateReq)(nil)
var _ marshal.Marshallable = (*FDID)(nil)
var _ marshal.Marshallable = (*FListXattrReq)(nil)
var _ marshal.Marshallable = (*FStatFSReq)(nil)
var _ marshal.Marshallable = (*FlushReq)(nil)
var _ marshal.Marshallable = (*GID)(nil)
var _ marshal.Marshallable = (*Getdents64Req)(nil)
var _ marshal.Marshallable = (*Inode)(nil)
var _ marshal.Marshallable = (*LinkAtResp)(nil)
var _ marshal.Marshallable = (*MID)(nil)
var _ marshal.Marshallable = (*MkdirAtResp)(nil)
var _ marshal.Marshallable = (*MknodAtResp)(nil)
var _ marshal.Marshallable = (*MsgDynamic)(nil)
var _ marshal.Marshallable = (*MsgSimple)(nil)
var _ marshal.Marshallable = (*OpenAtReq)(nil)
var _ marshal.Marshallable = (*OpenAtResp)(nil)
var _ marshal.Marshallable = (*OpenCreateAtResp)(nil)
var _ marshal.Marshallable = (*P9Version)(nil)
var _ marshal.Marshallable = (*PReadReq)(nil)
var _ marshal.Marshallable = (*PWriteResp)(nil)
var _ marshal.Marshallable = (*ReadLinkAtReq)(nil)
var _ marshal.Marshallable = (*SetStatReq)(nil)
var _ marshal.Marshallable = (*SetStatResp)(nil)
var _ marshal.Marshallable = (*StatFS)(nil)
var _ marshal.Marshallable = (*StatReq)(nil)
var _ marshal.Marshallable = (*SymlinkAtResp)(nil)
var _ marshal.Marshallable = (*UID)(nil)
var _ marshal.Marshallable = (*channelHeader)(nil)
var _ marshal.Marshallable = (*createCommon)(nil)
var _ marshal.Marshallable = (*linux.FileMode)(nil)
var _ marshal.Marshallable = (*linux.Statx)(nil)
var _ marshal.Marshallable = (*linux.Timespec)(nil)
var _ marshal.Marshallable = (*sockHeader)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *channelHeader) SizeBytes() int {
    return 2 +
        (*MID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *channelHeader) MarshalBytes(dst []byte) []byte {
    dst = c.message.MarshalUnsafe(dst)
    dst[0] = byte(c.numFDs)
    dst = dst[1:]
    // Padding: dst[:sizeof(uint8)] ~= uint8(0)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *channelHeader) UnmarshalBytes(src []byte) []byte {
    src = c.message.UnmarshalUnsafe(src)
    c.numFDs = uint8(src[0])
    src = src[1:]
    // Padding: var _ uint8 ~= src[:sizeof(uint8)]
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *channelHeader) Packed() bool {
    return c.message.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *channelHeader) MarshalUnsafe(dst []byte) []byte {
    if c.message.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    // Type channelHeader doesn't have a packed layout in memory, fallback to MarshalBytes.
    return c.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *channelHeader) UnmarshalUnsafe(src []byte) []byte {
    if c.message.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type channelHeader doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return c.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *channelHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.message.Packed() {
        // Type channelHeader doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        c.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *channelHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *channelHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !c.message.Packed() {
        // Type channelHeader doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        c.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *channelHeader) WriteTo(writer io.Writer) (int64, error) {
    if !c.message.Packed() {
        // Type channelHeader doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FDID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FDID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*f))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FDID) UnmarshalBytes(src []byte) []byte {
    *f = FDID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FDID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FDID) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FDID) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FDID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FDID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FDID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FDID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyFDIDSliceIn copies in a slice of FDID objects from the task's memory.
//go:nosplit
func CopyFDIDSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []FDID) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*FDID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyFDIDSliceOut copies a slice of FDID objects to the task's memory.
//go:nosplit
func CopyFDIDSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []FDID) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*FDID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeFDIDSlice is like FDID.MarshalUnsafe, but for a []FDID.
func MarshalUnsafeFDIDSlice(src []FDID, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*FDID)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeFDIDSlice is like FDID.UnmarshalUnsafe, but for a []FDID.
func UnmarshalUnsafeFDIDSlice(dst []FDID, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*FDID)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ChannelResp) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ChannelResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.dataOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.dataLength))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ChannelResp) UnmarshalBytes(src []byte) []byte {
    c.dataOffset = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.dataLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ChannelResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ChannelResp) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ChannelResp) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *ChannelResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *ChannelResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *ChannelResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ChannelResp) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ConnectReq) SizeBytes() int {
    return 4 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ConnectReq) MarshalBytes(dst []byte) []byte {
    dst = c.FD.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.SockType))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ConnectReq) UnmarshalBytes(src []byte) []byte {
    src = c.FD.UnmarshalUnsafe(src)
    c.SockType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ConnectReq) Packed() bool {
    return c.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ConnectReq) MarshalUnsafe(dst []byte) []byte {
    if c.FD.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    // Type ConnectReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return c.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ConnectReq) UnmarshalUnsafe(src []byte) []byte {
    if c.FD.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ConnectReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return c.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *ConnectReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.FD.Packed() {
        // Type ConnectReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        c.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *ConnectReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *ConnectReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !c.FD.Packed() {
        // Type ConnectReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        c.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ConnectReq) WriteTo(writer io.Writer) (int64, error) {
    if !c.FD.Packed() {
        // Type ConnectReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *ErrorResp) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ErrorResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.errno))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ErrorResp) UnmarshalBytes(src []byte) []byte {
    e.errno = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ErrorResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ErrorResp) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ErrorResp) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (e *ErrorResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (e *ErrorResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (e *ErrorResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *ErrorResp) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FAllocateReq) SizeBytes() int {
    return 28 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FAllocateReq) MarshalBytes(dst []byte) []byte {
    dst = f.FD.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Mode))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Length))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FAllocateReq) UnmarshalBytes(src []byte) []byte {
    src = f.FD.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Mode = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FAllocateReq) Packed() bool {
    return f.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FAllocateReq) MarshalUnsafe(dst []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FAllocateReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FAllocateReq) UnmarshalUnsafe(src []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FAllocateReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FAllocateReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FD.Packed() {
        // Type FAllocateReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FAllocateReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FAllocateReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !f.FD.Packed() {
        // Type FAllocateReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FAllocateReq) WriteTo(writer io.Writer) (int64, error) {
    if !f.FD.Packed() {
        // Type FAllocateReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FListXattrReq) SizeBytes() int {
    return 12 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FListXattrReq) MarshalBytes(dst []byte) []byte {
    dst = f.FD.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FListXattrReq) UnmarshalBytes(src []byte) []byte {
    src = f.FD.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FListXattrReq) Packed() bool {
    return f.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FListXattrReq) MarshalUnsafe(dst []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FListXattrReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FListXattrReq) UnmarshalUnsafe(src []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FListXattrReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FListXattrReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FD.Packed() {
        // Type FListXattrReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FListXattrReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FListXattrReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !f.FD.Packed() {
        // Type FListXattrReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FListXattrReq) WriteTo(writer io.Writer) (int64, error) {
    if !f.FD.Packed() {
        // Type FListXattrReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FStatFSReq) SizeBytes() int {
    return 0 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FStatFSReq) MarshalBytes(dst []byte) []byte {
    dst = f.FD.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FStatFSReq) UnmarshalBytes(src []byte) []byte {
    src = f.FD.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FStatFSReq) Packed() bool {
    return f.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FStatFSReq) MarshalUnsafe(dst []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FStatFSReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FStatFSReq) UnmarshalUnsafe(src []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FStatFSReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FStatFSReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FD.Packed() {
        // Type FStatFSReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FStatFSReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FStatFSReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !f.FD.Packed() {
        // Type FStatFSReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FStatFSReq) WriteTo(writer io.Writer) (int64, error) {
    if !f.FD.Packed() {
        // Type FStatFSReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FlushReq) SizeBytes() int {
    return 0 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FlushReq) MarshalBytes(dst []byte) []byte {
    dst = f.FD.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FlushReq) UnmarshalBytes(src []byte) []byte {
    src = f.FD.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FlushReq) Packed() bool {
    return f.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FlushReq) MarshalUnsafe(dst []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FlushReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FlushReq) UnmarshalUnsafe(src []byte) []byte {
    if f.FD.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FlushReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FlushReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FD.Packed() {
        // Type FlushReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FlushReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FlushReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !f.FD.Packed() {
        // Type FlushReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FlushReq) WriteTo(writer io.Writer) (int64, error) {
    if !f.FD.Packed() {
        // Type FlushReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (gid *GID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (gid *GID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*gid))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (gid *GID) UnmarshalBytes(src []byte) []byte {
    *gid = GID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (gid *GID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (gid *GID) MarshalUnsafe(dst []byte) []byte {
    size := gid.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(gid), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (gid *GID) UnmarshalUnsafe(src []byte) []byte {
    size := gid.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(gid), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (gid *GID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(gid)))
    hdr.Len = gid.SizeBytes()
    hdr.Cap = gid.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that gid
    // must live until the use above.
    runtime.KeepAlive(gid) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (gid *GID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return gid.CopyOutN(cc, addr, gid.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (gid *GID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(gid)))
    hdr.Len = gid.SizeBytes()
    hdr.Cap = gid.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that gid
    // must live until the use above.
    runtime.KeepAlive(gid) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (gid *GID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(gid)))
    hdr.Len = gid.SizeBytes()
    hdr.Cap = gid.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that gid
    // must live until the use above.
    runtime.KeepAlive(gid) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *Getdents64Req) SizeBytes() int {
    return 4 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *Getdents64Req) MarshalBytes(dst []byte) []byte {
    dst = g.DirFD.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(g.Count))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *Getdents64Req) UnmarshalBytes(src []byte) []byte {
    src = g.DirFD.UnmarshalUnsafe(src)
    g.Count = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *Getdents64Req) Packed() bool {
    return g.DirFD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *Getdents64Req) MarshalUnsafe(dst []byte) []byte {
    if g.DirFD.Packed() {
        size := g.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
        return dst[size:]
    }
    // Type Getdents64Req doesn't have a packed layout in memory, fallback to MarshalBytes.
    return g.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *Getdents64Req) UnmarshalUnsafe(src []byte) []byte {
    if g.DirFD.Packed() {
        size := g.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Getdents64Req doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return g.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (g *Getdents64Req) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !g.DirFD.Packed() {
        // Type Getdents64Req doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(g.SizeBytes()) // escapes: okay.
        g.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (g *Getdents64Req) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (g *Getdents64Req) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !g.DirFD.Packed() {
        // Type Getdents64Req doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(g.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        g.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (g *Getdents64Req) WriteTo(writer io.Writer) (int64, error) {
    if !g.DirFD.Packed() {
        // Type Getdents64Req doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, g.SizeBytes())
        g.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *Inode) SizeBytes() int {
    return 4 +
        (*FDID)(nil).SizeBytes() +
        (*linux.Statx)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inode) MarshalBytes(dst []byte) []byte {
    dst = i.ControlFD.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    dst = i.Stat.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inode) UnmarshalBytes(src []byte) []byte {
    src = i.ControlFD.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    src = i.Stat.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inode) Packed() bool {
    return i.ControlFD.Packed() && i.Stat.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inode) MarshalUnsafe(dst []byte) []byte {
    if i.ControlFD.Packed() && i.Stat.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type Inode doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inode) UnmarshalUnsafe(src []byte) []byte {
    if i.ControlFD.Packed() && i.Stat.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Inode doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *Inode) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.ControlFD.Packed() && i.Stat.Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to MarshalBytes.
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
//go:nosplit
func (i *Inode) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *Inode) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !i.ControlFD.Packed() && i.Stat.Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Inode) WriteTo(writer io.Writer) (int64, error) {
    if !i.ControlFD.Packed() && i.Stat.Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// CopyInodeSliceIn copies in a slice of Inode objects from the task's memory.
func CopyInodeSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Inode) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Inode)(nil).SizeBytes()

    if !dst[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(size * count)
        length, err := cc.CopyInBytes(addr, buf)

        // Unmarshal as much as possible, even on error. First handle full objects.
        limit := length/size
        for idx := 0; idx < limit; idx++ {
            buf = dst[idx].UnmarshalBytes(buf)
        }

        // Handle any final partial object. buf is guaranteed to be long enough for the
        // final element, but may not contain valid data for the entire range. This may
        // result in unmarshalling zero values for some parts of the object.
        if length%size != 0 {
            dst[limit].UnmarshalBytes(buf)
        }

        return length, err
    }

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyInodeSliceOut copies a slice of Inode objects to the task's memory.
func CopyInodeSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Inode) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Inode)(nil).SizeBytes()

    if !src[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(size * count)
        curBuf := buf
        for idx := 0; idx < count; idx++ {
            curBuf = src[idx].MarshalBytes(curBuf)
        }
        return cc.CopyOutBytes(addr, buf)
    }

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeInodeSlice is like Inode.MarshalUnsafe, but for a []Inode.
func MarshalUnsafeInodeSlice(src []Inode, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    if !src[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to MarshalBytes.
        for idx := 0; idx < count; idx++ {
            dst = src[idx].MarshalBytes(dst)
        }
        return dst
    }

    size := (*Inode)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeInodeSlice is like Inode.UnmarshalUnsafe, but for a []Inode.
func UnmarshalUnsafeInodeSlice(dst []Inode, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    if !dst[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        for idx := 0; idx < count; idx++ {
            src = dst[idx].UnmarshalBytes(src)
        }
        return src
    }

    size := (*Inode)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (l *LinkAtResp) SizeBytes() int {
    return 0 +
        (*Inode)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *LinkAtResp) MarshalBytes(dst []byte) []byte {
    dst = l.Link.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *LinkAtResp) UnmarshalBytes(src []byte) []byte {
    src = l.Link.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (l *LinkAtResp) Packed() bool {
    return l.Link.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (l *LinkAtResp) MarshalUnsafe(dst []byte) []byte {
    if l.Link.Packed() {
        size := l.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(l), uintptr(size))
        return dst[size:]
    }
    // Type LinkAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return l.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (l *LinkAtResp) UnmarshalUnsafe(src []byte) []byte {
    if l.Link.Packed() {
        size := l.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(l), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type LinkAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return l.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (l *LinkAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !l.Link.Packed() {
        // Type LinkAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(l.SizeBytes()) // escapes: okay.
        l.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (l *LinkAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return l.CopyOutN(cc, addr, l.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (l *LinkAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !l.Link.Packed() {
        // Type LinkAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(l.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        l.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (l *LinkAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !l.Link.Packed() {
        // Type LinkAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, l.SizeBytes())
        l.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (m *MID) SizeBytes() int {
    return 2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*m))
    return dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MID) UnmarshalBytes(src []byte) []byte {
    *m = MID(uint16(hostarch.ByteOrder.Uint16(src[:2])))
    return src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MID) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MID) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyMIDSliceIn copies in a slice of MID objects from the task's memory.
//go:nosplit
func CopyMIDSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []MID) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*MID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyMIDSliceOut copies a slice of MID objects to the task's memory.
//go:nosplit
func CopyMIDSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []MID) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*MID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeMIDSlice is like MID.MarshalUnsafe, but for a []MID.
func MarshalUnsafeMIDSlice(src []MID, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*MID)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeMIDSlice is like MID.UnmarshalUnsafe, but for a []MID.
func UnmarshalUnsafeMIDSlice(dst []MID, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*MID)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MkdirAtResp) SizeBytes() int {
    return 0 +
        (*Inode)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MkdirAtResp) MarshalBytes(dst []byte) []byte {
    dst = m.ChildDir.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MkdirAtResp) UnmarshalBytes(src []byte) []byte {
    src = m.ChildDir.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MkdirAtResp) Packed() bool {
    return m.ChildDir.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MkdirAtResp) MarshalUnsafe(dst []byte) []byte {
    if m.ChildDir.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
        return dst[size:]
    }
    // Type MkdirAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MkdirAtResp) UnmarshalUnsafe(src []byte) []byte {
    if m.ChildDir.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type MkdirAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return m.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MkdirAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.ChildDir.Packed() {
        // Type MkdirAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        m.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MkdirAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MkdirAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !m.ChildDir.Packed() {
        // Type MkdirAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        m.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MkdirAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !m.ChildDir.Packed() {
        // Type MkdirAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, m.SizeBytes())
        m.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MknodAtResp) SizeBytes() int {
    return 0 +
        (*Inode)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MknodAtResp) MarshalBytes(dst []byte) []byte {
    dst = m.Child.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MknodAtResp) UnmarshalBytes(src []byte) []byte {
    src = m.Child.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MknodAtResp) Packed() bool {
    return m.Child.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MknodAtResp) MarshalUnsafe(dst []byte) []byte {
    if m.Child.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
        return dst[size:]
    }
    // Type MknodAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MknodAtResp) UnmarshalUnsafe(src []byte) []byte {
    if m.Child.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type MknodAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return m.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MknodAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.Child.Packed() {
        // Type MknodAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        m.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MknodAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MknodAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !m.Child.Packed() {
        // Type MknodAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        m.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MknodAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !m.Child.Packed() {
        // Type MknodAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, m.SizeBytes())
        m.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *OpenAtReq) SizeBytes() int {
    return 4 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *OpenAtReq) MarshalBytes(dst []byte) []byte {
    dst = o.FD.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(o.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (o *OpenAtReq) UnmarshalBytes(src []byte) []byte {
    src = o.FD.UnmarshalUnsafe(src)
    o.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (o *OpenAtReq) Packed() bool {
    return o.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (o *OpenAtReq) MarshalUnsafe(dst []byte) []byte {
    if o.FD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(o), uintptr(size))
        return dst[size:]
    }
    // Type OpenAtReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return o.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (o *OpenAtReq) UnmarshalUnsafe(src []byte) []byte {
    if o.FD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(o), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type OpenAtReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return o.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (o *OpenAtReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !o.FD.Packed() {
        // Type OpenAtReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        o.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (o *OpenAtReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return o.CopyOutN(cc, addr, o.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (o *OpenAtReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !o.FD.Packed() {
        // Type OpenAtReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        o.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (o *OpenAtReq) WriteTo(writer io.Writer) (int64, error) {
    if !o.FD.Packed() {
        // Type OpenAtReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, o.SizeBytes())
        o.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *OpenAtResp) SizeBytes() int {
    return 0 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *OpenAtResp) MarshalBytes(dst []byte) []byte {
    dst = o.NewFD.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (o *OpenAtResp) UnmarshalBytes(src []byte) []byte {
    src = o.NewFD.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (o *OpenAtResp) Packed() bool {
    return o.NewFD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (o *OpenAtResp) MarshalUnsafe(dst []byte) []byte {
    if o.NewFD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(o), uintptr(size))
        return dst[size:]
    }
    // Type OpenAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return o.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (o *OpenAtResp) UnmarshalUnsafe(src []byte) []byte {
    if o.NewFD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(o), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type OpenAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return o.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (o *OpenAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !o.NewFD.Packed() {
        // Type OpenAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        o.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (o *OpenAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return o.CopyOutN(cc, addr, o.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (o *OpenAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !o.NewFD.Packed() {
        // Type OpenAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        o.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (o *OpenAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !o.NewFD.Packed() {
        // Type OpenAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, o.SizeBytes())
        o.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *OpenCreateAtResp) SizeBytes() int {
    return 4 +
        (*Inode)(nil).SizeBytes() +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *OpenCreateAtResp) MarshalBytes(dst []byte) []byte {
    dst = o.Child.MarshalUnsafe(dst)
    dst = o.NewFD.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (o *OpenCreateAtResp) UnmarshalBytes(src []byte) []byte {
    src = o.Child.UnmarshalUnsafe(src)
    src = o.NewFD.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (o *OpenCreateAtResp) Packed() bool {
    return o.Child.Packed() && o.NewFD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (o *OpenCreateAtResp) MarshalUnsafe(dst []byte) []byte {
    if o.Child.Packed() && o.NewFD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(o), uintptr(size))
        return dst[size:]
    }
    // Type OpenCreateAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return o.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (o *OpenCreateAtResp) UnmarshalUnsafe(src []byte) []byte {
    if o.Child.Packed() && o.NewFD.Packed() {
        size := o.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(o), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type OpenCreateAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return o.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (o *OpenCreateAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !o.Child.Packed() && o.NewFD.Packed() {
        // Type OpenCreateAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        o.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (o *OpenCreateAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return o.CopyOutN(cc, addr, o.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (o *OpenCreateAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !o.Child.Packed() && o.NewFD.Packed() {
        // Type OpenCreateAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        o.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (o *OpenCreateAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !o.Child.Packed() && o.NewFD.Packed() {
        // Type OpenCreateAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, o.SizeBytes())
        o.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(o)))
    hdr.Len = o.SizeBytes()
    hdr.Cap = o.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that o
    // must live until the use above.
    runtime.KeepAlive(o) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *PReadReq) SizeBytes() int {
    return 12 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *PReadReq) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offset))
    dst = dst[8:]
    dst = p.FD.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Count))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *PReadReq) UnmarshalBytes(src []byte) []byte {
    p.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.FD.UnmarshalUnsafe(src)
    p.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PReadReq) Packed() bool {
    return p.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *PReadReq) MarshalUnsafe(dst []byte) []byte {
    if p.FD.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    // Type PReadReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return p.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *PReadReq) UnmarshalUnsafe(src []byte) []byte {
    if p.FD.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type PReadReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return p.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (p *PReadReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.FD.Packed() {
        // Type PReadReq doesn't have a packed layout in memory, fall back to MarshalBytes.
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
//go:nosplit
func (p *PReadReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (p *PReadReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !p.FD.Packed() {
        // Type PReadReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(p.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *PReadReq) WriteTo(writer io.Writer) (int64, error) {
    if !p.FD.Packed() {
        // Type PReadReq doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (p *PWriteResp) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *PWriteResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Count))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *PWriteResp) UnmarshalBytes(src []byte) []byte {
    p.Count = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PWriteResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *PWriteResp) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *PWriteResp) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (p *PWriteResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
//go:nosplit
func (p *PWriteResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (p *PWriteResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *PWriteResp) WriteTo(writer io.Writer) (int64, error) {
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
func (r *ReadLinkAtReq) SizeBytes() int {
    return 0 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *ReadLinkAtReq) MarshalBytes(dst []byte) []byte {
    dst = r.FD.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *ReadLinkAtReq) UnmarshalBytes(src []byte) []byte {
    src = r.FD.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *ReadLinkAtReq) Packed() bool {
    return r.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *ReadLinkAtReq) MarshalUnsafe(dst []byte) []byte {
    if r.FD.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    // Type ReadLinkAtReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *ReadLinkAtReq) UnmarshalUnsafe(src []byte) []byte {
    if r.FD.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ReadLinkAtReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *ReadLinkAtReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.FD.Packed() {
        // Type ReadLinkAtReq doesn't have a packed layout in memory, fall back to MarshalBytes.
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
//go:nosplit
func (r *ReadLinkAtReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *ReadLinkAtReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !r.FD.Packed() {
        // Type ReadLinkAtReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *ReadLinkAtReq) WriteTo(writer io.Writer) (int64, error) {
    if !r.FD.Packed() {
        // Type ReadLinkAtReq doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SetStatReq) SizeBytes() int {
    return 20 +
        (*FDID)(nil).SizeBytes() +
        (*UID)(nil).SizeBytes() +
        (*GID)(nil).SizeBytes() +
        (*linux.Timespec)(nil).SizeBytes() +
        (*linux.Timespec)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SetStatReq) MarshalBytes(dst []byte) []byte {
    dst = s.FD.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Mask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Mode))
    dst = dst[4:]
    dst = s.UID.MarshalUnsafe(dst)
    dst = s.GID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    dst = s.Atime.MarshalUnsafe(dst)
    dst = s.Mtime.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SetStatReq) UnmarshalBytes(src []byte) []byte {
    src = s.FD.UnmarshalUnsafe(src)
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    s.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = s.UID.UnmarshalUnsafe(src)
    src = s.GID.UnmarshalUnsafe(src)
    s.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.Atime.UnmarshalUnsafe(src)
    src = s.Mtime.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SetStatReq) Packed() bool {
    return s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SetStatReq) MarshalUnsafe(dst []byte) []byte {
    if s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SetStatReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SetStatReq) UnmarshalUnsafe(src []byte) []byte {
    if s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SetStatReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SetStatReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed() {
        // Type SetStatReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SetStatReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SetStatReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed() {
        // Type SetStatReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SetStatReq) WriteTo(writer io.Writer) (int64, error) {
    if !s.Atime.Packed() && s.FD.Packed() && s.GID.Packed() && s.Mtime.Packed() && s.UID.Packed() {
        // Type SetStatReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SetStatResp) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SetStatResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FailureMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FailureErrNo))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SetStatResp) UnmarshalBytes(src []byte) []byte {
    s.FailureMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.FailureErrNo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SetStatResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SetStatResp) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SetStatResp) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SetStatResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SetStatResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SetStatResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SetStatResp) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StatFS) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StatFS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Type))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlockSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksAvailable))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Files))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FilesFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.NameLength))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StatFS) UnmarshalBytes(src []byte) []byte {
    s.Type = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlockSize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksAvailable = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Files = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FilesFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.NameLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *StatFS) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *StatFS) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *StatFS) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *StatFS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *StatFS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *StatFS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *StatFS) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StatReq) SizeBytes() int {
    return 0 +
        (*FDID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StatReq) MarshalBytes(dst []byte) []byte {
    dst = s.FD.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StatReq) UnmarshalBytes(src []byte) []byte {
    src = s.FD.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *StatReq) Packed() bool {
    return s.FD.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *StatReq) MarshalUnsafe(dst []byte) []byte {
    if s.FD.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type StatReq doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *StatReq) UnmarshalUnsafe(src []byte) []byte {
    if s.FD.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type StatReq doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *StatReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.FD.Packed() {
        // Type StatReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *StatReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *StatReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !s.FD.Packed() {
        // Type StatReq doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *StatReq) WriteTo(writer io.Writer) (int64, error) {
    if !s.FD.Packed() {
        // Type StatReq doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SymlinkAtResp) SizeBytes() int {
    return 0 +
        (*Inode)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SymlinkAtResp) MarshalBytes(dst []byte) []byte {
    dst = s.Symlink.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SymlinkAtResp) UnmarshalBytes(src []byte) []byte {
    src = s.Symlink.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SymlinkAtResp) Packed() bool {
    return s.Symlink.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SymlinkAtResp) MarshalUnsafe(dst []byte) []byte {
    if s.Symlink.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SymlinkAtResp doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SymlinkAtResp) UnmarshalUnsafe(src []byte) []byte {
    if s.Symlink.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SymlinkAtResp doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SymlinkAtResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Symlink.Packed() {
        // Type SymlinkAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SymlinkAtResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SymlinkAtResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !s.Symlink.Packed() {
        // Type SymlinkAtResp doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SymlinkAtResp) WriteTo(writer io.Writer) (int64, error) {
    if !s.Symlink.Packed() {
        // Type SymlinkAtResp doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (uid *UID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (uid *UID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*uid))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (uid *UID) UnmarshalBytes(src []byte) []byte {
    *uid = UID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (uid *UID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (uid *UID) MarshalUnsafe(dst []byte) []byte {
    size := uid.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(uid), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (uid *UID) UnmarshalUnsafe(src []byte) []byte {
    size := uid.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(uid), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (uid *UID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(uid)))
    hdr.Len = uid.SizeBytes()
    hdr.Cap = uid.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that uid
    // must live until the use above.
    runtime.KeepAlive(uid) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (uid *UID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return uid.CopyOutN(cc, addr, uid.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (uid *UID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(uid)))
    hdr.Len = uid.SizeBytes()
    hdr.Cap = uid.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that uid
    // must live until the use above.
    runtime.KeepAlive(uid) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (uid *UID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(uid)))
    hdr.Len = uid.SizeBytes()
    hdr.Cap = uid.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that uid
    // must live until the use above.
    runtime.KeepAlive(uid) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *createCommon) SizeBytes() int {
    return 2 +
        (*FDID)(nil).SizeBytes() +
        (*linux.FileMode)(nil).SizeBytes() +
        (*UID)(nil).SizeBytes() +
        (*GID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *createCommon) MarshalBytes(dst []byte) []byte {
    dst = c.DirFD.MarshalUnsafe(dst)
    dst = c.Mode.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    dst = c.UID.MarshalUnsafe(dst)
    dst = c.GID.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *createCommon) UnmarshalBytes(src []byte) []byte {
    src = c.DirFD.UnmarshalUnsafe(src)
    src = c.Mode.UnmarshalUnsafe(src)
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    src = c.UID.UnmarshalUnsafe(src)
    src = c.GID.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *createCommon) Packed() bool {
    return c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *createCommon) MarshalUnsafe(dst []byte) []byte {
    if c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    // Type createCommon doesn't have a packed layout in memory, fallback to MarshalBytes.
    return c.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *createCommon) UnmarshalUnsafe(src []byte) []byte {
    if c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type createCommon doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return c.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *createCommon) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed() {
        // Type createCommon doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        c.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *createCommon) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *createCommon) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed() {
        // Type createCommon doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        c.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *createCommon) WriteTo(writer io.Writer) (int64, error) {
    if !c.DirFD.Packed() && c.GID.Packed() && c.Mode.Packed() && c.UID.Packed() {
        // Type createCommon doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgDynamic) Packed() bool {
    // Type MsgDynamic is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsgDynamic) MarshalUnsafe(dst []byte) []byte {
    // Type MsgDynamic doesn't have a packed layout in memory, fallback to MarshalBytes.
    return m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsgDynamic) UnmarshalUnsafe(src []byte) []byte {
    // Type MsgDynamic doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return m.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MsgDynamic) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type MsgDynamic doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
    m.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MsgDynamic) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MsgDynamic) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Type MsgDynamic doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    m.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MsgDynamic) WriteTo(writer io.Writer) (int64, error) {
    // Type MsgDynamic doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, m.SizeBytes())
    m.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MsgSimple) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MsgSimple) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.A))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.B))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.C))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.D))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsgSimple) UnmarshalBytes(src []byte) []byte {
    m.A = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    m.B = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    m.C = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.D = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgSimple) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsgSimple) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsgSimple) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MsgSimple) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MsgSimple) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MsgSimple) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MsgSimple) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyMsg1SliceIn copies in a slice of MsgSimple objects from the task's memory.
func CopyMsg1SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []MsgSimple) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*MsgSimple)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyMsg1SliceOut copies a slice of MsgSimple objects to the task's memory.
func CopyMsg1SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []MsgSimple) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*MsgSimple)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeMsg1Slice is like MsgSimple.MarshalUnsafe, but for a []MsgSimple.
func MarshalUnsafeMsg1Slice(src []MsgSimple, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*MsgSimple)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeMsg1Slice is like MsgSimple.UnmarshalUnsafe, but for a []MsgSimple.
func UnmarshalUnsafeMsg1Slice(dst []MsgSimple, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*MsgSimple)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *P9Version) Packed() bool {
    // Type P9Version is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *P9Version) MarshalUnsafe(dst []byte) []byte {
    // Type P9Version doesn't have a packed layout in memory, fallback to MarshalBytes.
    return v.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *P9Version) UnmarshalUnsafe(src []byte) []byte {
    // Type P9Version doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return v.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (v *P9Version) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type P9Version doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(v.SizeBytes()) // escapes: okay.
    v.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (v *P9Version) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (v *P9Version) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Type P9Version doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(v.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    v.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *P9Version) WriteTo(writer io.Writer) (int64, error) {
    // Type P9Version doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, v.SizeBytes())
    v.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *sockHeader) SizeBytes() int {
    return 6 +
        (*MID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *sockHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.payloadLen))
    dst = dst[4:]
    dst = s.message.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *sockHeader) UnmarshalBytes(src []byte) []byte {
    s.payloadLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = s.message.UnmarshalUnsafe(src)
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *sockHeader) Packed() bool {
    return s.message.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *sockHeader) MarshalUnsafe(dst []byte) []byte {
    if s.message.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type sockHeader doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *sockHeader) UnmarshalUnsafe(src []byte) []byte {
    if s.message.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type sockHeader doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *sockHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.message.Packed() {
        // Type sockHeader doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *sockHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *sockHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !s.message.Packed() {
        // Type sockHeader doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *sockHeader) WriteTo(writer io.Writer) (int64, error) {
    if !s.message.Packed() {
        // Type sockHeader doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

