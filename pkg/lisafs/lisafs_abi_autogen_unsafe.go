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
var _ marshal.Marshallable = (*ErrorResp)(nil)
var _ marshal.Marshallable = (*FDID)(nil)
var _ marshal.Marshallable = (*GID)(nil)
var _ marshal.Marshallable = (*Inode)(nil)
var _ marshal.Marshallable = (*MID)(nil)
var _ marshal.Marshallable = (*MsgDynamic)(nil)
var _ marshal.Marshallable = (*MsgSimple)(nil)
var _ marshal.Marshallable = (*P9Version)(nil)
var _ marshal.Marshallable = (*UID)(nil)
var _ marshal.Marshallable = (*channelHeader)(nil)
var _ marshal.Marshallable = (*linux.Statx)(nil)
var _ marshal.Marshallable = (*sockHeader)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *channelHeader) SizeBytes() int {
    return 2 +
        (*MID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *channelHeader) MarshalBytes(dst []byte) {
    c.message.MarshalBytes(dst[:c.message.SizeBytes()])
    dst = dst[c.message.SizeBytes():]
    dst[0] = byte(c.numFDs)
    dst = dst[1:]
    // Padding: dst[:sizeof(uint8)] ~= uint8(0)
    dst = dst[1:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *channelHeader) UnmarshalBytes(src []byte) {
    c.message.UnmarshalBytes(src[:c.message.SizeBytes()])
    src = src[c.message.SizeBytes():]
    c.numFDs = uint8(src[0])
    src = src[1:]
    // Padding: var _ uint8 ~= src[:sizeof(uint8)]
    src = src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *channelHeader) Packed() bool {
    return c.message.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *channelHeader) MarshalUnsafe(dst []byte) {
    if c.message.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c),  uintptr(c.SizeBytes()))
    } else {
        // Type channelHeader doesn't have a packed layout in memory, fallback to MarshalBytes.
        c.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *channelHeader) UnmarshalUnsafe(src []byte) {
    if c.message.Packed() {
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(c.SizeBytes()))
    } else {
        // Type channelHeader doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        c.UnmarshalBytes(src)
    }
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
func (f *FDID) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*f))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FDID) UnmarshalBytes(src []byte) {
    *f = FDID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FDID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FDID) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(f.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FDID) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(f.SizeBytes()))
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
func (f *FDID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := w.Write(buf)
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
func MarshalUnsafeFDIDSlice(src []FDID, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*FDID)(nil).SizeBytes()

    dst = dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))
    return size*count, nil
}

// UnmarshalUnsafeFDIDSlice is like FDID.UnmarshalUnsafe, but for a []FDID.
func UnmarshalUnsafeFDIDSlice(dst []FDID, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*FDID)(nil).SizeBytes()

    src = src[:(size*count)]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
    return size*count, nil
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ChannelResp) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ChannelResp) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.dataOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.dataLength))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ChannelResp) UnmarshalBytes(src []byte) {
    c.dataOffset = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.dataLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ChannelResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ChannelResp) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c),  uintptr(c.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ChannelResp) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(c.SizeBytes()))
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
func (e *ErrorResp) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ErrorResp) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.errno))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ErrorResp) UnmarshalBytes(src []byte) {
    e.errno = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ErrorResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ErrorResp) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e),  uintptr(e.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ErrorResp) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(e.SizeBytes()))
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
//go:nosplit
func (gid *GID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (gid *GID) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*gid))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (gid *GID) UnmarshalBytes(src []byte) {
    *gid = GID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (gid *GID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (gid *GID) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(gid), uintptr(gid.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (gid *GID) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(gid), unsafe.Pointer(&src[0]), uintptr(gid.SizeBytes()))
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
func (gid *GID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(gid)))
    hdr.Len = gid.SizeBytes()
    hdr.Cap = gid.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that gid
    // must live until the use above.
    runtime.KeepAlive(gid) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *Inode) SizeBytes() int {
    return 4 +
        (*FDID)(nil).SizeBytes() +
        (*linux.Statx)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inode) MarshalBytes(dst []byte) {
    i.ControlFD.MarshalBytes(dst[:i.ControlFD.SizeBytes()])
    dst = dst[i.ControlFD.SizeBytes():]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    i.Stat.MarshalBytes(dst[:i.Stat.SizeBytes()])
    dst = dst[i.Stat.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inode) UnmarshalBytes(src []byte) {
    i.ControlFD.UnmarshalBytes(src[:i.ControlFD.SizeBytes()])
    src = src[i.ControlFD.SizeBytes():]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    i.Stat.UnmarshalBytes(src[:i.Stat.SizeBytes()])
    src = src[i.Stat.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inode) Packed() bool {
    return i.ControlFD.Packed() && i.Stat.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inode) MarshalUnsafe(dst []byte) {
    if i.ControlFD.Packed() && i.Stat.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i),  uintptr(i.SizeBytes()))
    } else {
        // Type Inode doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inode) UnmarshalUnsafe(src []byte) {
    if i.ControlFD.Packed() && i.Stat.Packed() {
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(i.SizeBytes()))
    } else {
        // Type Inode doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
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
            dst[idx].UnmarshalBytes(buf[size*idx:size*(idx+1)])
        }

        // Handle any final partial object. buf is guaranteed to be long enough for the
        // final element, but may not contain valid data for the entire range. This may
        // result in unmarshalling zero values for some parts of the object.
        if length%size != 0 {
            idx := limit
            dst[idx].UnmarshalBytes(buf[size*idx:size*(idx+1)])
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
        for idx := 0; idx < count; idx++ {
            src[idx].MarshalBytes(buf[size*idx:size*(idx+1)])
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
func MarshalUnsafeInodeSlice(src []Inode, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Inode)(nil).SizeBytes()

    if !src[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to MarshalBytes.
        for idx := 0; idx < count; idx++ {
            src[idx].MarshalBytes(dst[size*idx:(size)*(idx+1)])
        }
        return size * count, nil
    }

    dst = dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))
    return size * count, nil
}

// UnmarshalUnsafeInodeSlice is like Inode.UnmarshalUnsafe, but for a []Inode.
func UnmarshalUnsafeInodeSlice(dst []Inode, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Inode)(nil).SizeBytes()

    if !dst[0].Packed() {
        // Type Inode doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        for idx := 0; idx < count; idx++ {
            dst[idx].UnmarshalBytes(src[size*idx:size*(idx+1)])
        }
        return size * count, nil
    }

    src = src[:(size*count)]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
    return count*size, nil
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (m *MID) SizeBytes() int {
    return 2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MID) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*m))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MID) UnmarshalBytes(src []byte) {
    *m = MID(uint16(hostarch.ByteOrder.Uint16(src[:2])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MID) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(m.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MID) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(m.SizeBytes()))
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
func (m *MID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := w.Write(buf)
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
func MarshalUnsafeMIDSlice(src []MID, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*MID)(nil).SizeBytes()

    dst = dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))
    return size*count, nil
}

// UnmarshalUnsafeMIDSlice is like MID.UnmarshalUnsafe, but for a []MID.
func UnmarshalUnsafeMIDSlice(dst []MID, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*MID)(nil).SizeBytes()

    src = src[:(size*count)]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
    return size*count, nil
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (uid *UID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (uid *UID) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*uid))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (uid *UID) UnmarshalBytes(src []byte) {
    *uid = UID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (uid *UID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (uid *UID) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(uid), uintptr(uid.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (uid *UID) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(uid), unsafe.Pointer(&src[0]), uintptr(uid.SizeBytes()))
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
func (uid *UID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(uid)))
    hdr.Len = uid.SizeBytes()
    hdr.Cap = uid.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that uid
    // must live until the use above.
    runtime.KeepAlive(uid) // escapes: replaced by intrinsic.
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgDynamic) Packed() bool {
    // Type MsgDynamic is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsgDynamic) MarshalUnsafe(dst []byte) {
    // Type MsgDynamic doesn't have a packed layout in memory, fallback to MarshalBytes.
    m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsgDynamic) UnmarshalUnsafe(src []byte) {
    // Type MsgDynamic doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    m.UnmarshalBytes(src)
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
func (m *MsgSimple) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.A))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.B))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.C))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.D))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsgSimple) UnmarshalBytes(src []byte) {
    m.A = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    m.B = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    m.C = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.D = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgSimple) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsgSimple) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m),  uintptr(m.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsgSimple) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(m.SizeBytes()))
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
func MarshalUnsafeMsg1Slice(src []MsgSimple, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*MsgSimple)(nil).SizeBytes()

    dst = dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))
    return size * count, nil
}

// UnmarshalUnsafeMsg1Slice is like MsgSimple.UnmarshalUnsafe, but for a []MsgSimple.
func UnmarshalUnsafeMsg1Slice(dst []MsgSimple, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*MsgSimple)(nil).SizeBytes()

    src = src[:(size*count)]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
    return count*size, nil
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *P9Version) Packed() bool {
    // Type P9Version is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *P9Version) MarshalUnsafe(dst []byte) {
    // Type P9Version doesn't have a packed layout in memory, fallback to MarshalBytes.
    v.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *P9Version) UnmarshalUnsafe(src []byte) {
    // Type P9Version doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    v.UnmarshalBytes(src)
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
func (s *sockHeader) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.payloadLen))
    dst = dst[4:]
    s.message.MarshalBytes(dst[:s.message.SizeBytes()])
    dst = dst[s.message.SizeBytes():]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *sockHeader) UnmarshalBytes(src []byte) {
    s.payloadLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.message.UnmarshalBytes(src[:s.message.SizeBytes()])
    src = src[s.message.SizeBytes():]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *sockHeader) Packed() bool {
    return s.message.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *sockHeader) MarshalUnsafe(dst []byte) {
    if s.message.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s),  uintptr(s.SizeBytes()))
    } else {
        // Type sockHeader doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *sockHeader) UnmarshalUnsafe(src []byte) {
    if s.message.Packed() {
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(s.SizeBytes()))
    } else {
        // Type sockHeader doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
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

