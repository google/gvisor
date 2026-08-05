// Automatically generated marshal implementation. See tools/go_marshal.

package ib

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
var _ marshal.Marshallable = (*Mlx5CreatePrefix)(nil)
var _ marshal.Marshallable = (*UverbsAttr)(nil)
var _ marshal.Marshallable = (*UverbsIoctlHdr)(nil)
var _ marshal.Marshallable = (*UverbsRegMR)(nil)
var _ marshal.Marshallable = (*UverbsRegMRResp)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *Mlx5CreatePrefix) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *Mlx5CreatePrefix) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.BufAddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.DBAddr))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *Mlx5CreatePrefix) UnmarshalBytes(src []byte) []byte {
    m.BufAddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.DBAddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *Mlx5CreatePrefix) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *Mlx5CreatePrefix) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *Mlx5CreatePrefix) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (m *Mlx5CreatePrefix) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (m *Mlx5CreatePrefix) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (m *Mlx5CreatePrefix) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (m *Mlx5CreatePrefix) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *Mlx5CreatePrefix) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UverbsAttr) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UverbsAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.AttrID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.Len))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.Flags))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.AttrData))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Data))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UverbsAttr) UnmarshalBytes(src []byte) []byte {
    u.AttrID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.Len = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.Flags = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.AttrData = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.Data = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UverbsAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UverbsAttr) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UverbsAttr) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UverbsAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UverbsAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UverbsAttr) WriteTo(writer io.Writer) (int64, error) {
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

// CopyUverbsAttrSliceIn copies in a slice of UverbsAttr objects from the task's memory.
func CopyUverbsAttrSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []UverbsAttr) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*UverbsAttr)(nil).SizeBytes()

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

// CopyUverbsAttrSliceOut copies a slice of UverbsAttr objects to the task's memory.
func CopyUverbsAttrSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []UverbsAttr) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*UverbsAttr)(nil).SizeBytes()

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

// MarshalUnsafeUverbsAttrSlice is like UverbsAttr.MarshalUnsafe, but for a []UverbsAttr.
func MarshalUnsafeUverbsAttrSlice(src []UverbsAttr, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*UverbsAttr)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeUverbsAttrSlice is like UverbsAttr.UnmarshalUnsafe, but for a []UverbsAttr.
func UnmarshalUnsafeUverbsAttrSlice(dst []UverbsAttr, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*UverbsAttr)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// ReadUverbsAttrSlice reads a []UverbsAttr. It returns the number of bytes read
func ReadUverbsAttrSlice(src io.Reader, dst []UverbsAttr) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*UverbsAttr)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// WriteUverbsAttrSlice is like UverbsAttr.WriteTo, but for a []UverbsAttr.
func WriteUverbsAttrSlice(dst io.Writer, src []UverbsAttr) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*UverbsAttr)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UverbsIoctlHdr) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UverbsIoctlHdr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.Length))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.ObjectID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.MethodID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(u.NumAttrs))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Reserved1))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.DriverID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.Reserved2))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UverbsIoctlHdr) UnmarshalBytes(src []byte) []byte {
    u.Length = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.ObjectID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.MethodID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.NumAttrs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    u.Reserved1 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.DriverID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.Reserved2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UverbsIoctlHdr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UverbsIoctlHdr) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UverbsIoctlHdr) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UverbsIoctlHdr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsIoctlHdr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UverbsIoctlHdr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsIoctlHdr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UverbsIoctlHdr) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UverbsRegMR) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UverbsRegMR) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Response))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.HcaVA))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.PDHandle))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.AccessFlags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UverbsRegMR) UnmarshalBytes(src []byte) []byte {
    u.Response = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Start = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.HcaVA = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.PDHandle = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.AccessFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UverbsRegMR) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UverbsRegMR) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UverbsRegMR) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UverbsRegMR) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsRegMR) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UverbsRegMR) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsRegMR) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UverbsRegMR) WriteTo(writer io.Writer) (int64, error) {
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
func (u *UverbsRegMRResp) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UverbsRegMRResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.MRHandle))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.LKey))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.RKey))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UverbsRegMRResp) UnmarshalBytes(src []byte) []byte {
    u.MRHandle = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.LKey = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.RKey = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UverbsRegMRResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UverbsRegMRResp) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UverbsRegMRResp) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UverbsRegMRResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsRegMRResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UverbsRegMRResp) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UverbsRegMRResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UverbsRegMRResp) WriteTo(writer io.Writer) (int64, error) {
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

