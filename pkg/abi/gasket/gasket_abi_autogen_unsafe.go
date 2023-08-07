// Automatically generated marshal implementation. See tools/go_marshal.

package gasket

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
var _ marshal.Marshallable = (*GasketInterruptEventFd)(nil)
var _ marshal.Marshallable = (*GasketInterruptMapping)(nil)
var _ marshal.Marshallable = (*GasketPageTableDmaBufIoctl)(nil)
var _ marshal.Marshallable = (*GasketPageTableIoctl)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *GasketInterruptEventFd) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *GasketInterruptEventFd) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Interrupt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.EventFD))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *GasketInterruptEventFd) UnmarshalBytes(src []byte) []byte {
    g.Interrupt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.EventFD = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketInterruptEventFd) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *GasketInterruptEventFd) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *GasketInterruptEventFd) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (g *GasketInterruptEventFd) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (g *GasketInterruptEventFd) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (g *GasketInterruptEventFd) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (g *GasketInterruptEventFd) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (g *GasketInterruptEventFd) WriteTo(writer io.Writer) (int64, error) {
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
func (g *GasketInterruptMapping) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *GasketInterruptMapping) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Interrupt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.EventFD))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.BarIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.RegOffset))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *GasketInterruptMapping) UnmarshalBytes(src []byte) []byte {
    g.Interrupt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.EventFD = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.BarIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.RegOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketInterruptMapping) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *GasketInterruptMapping) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *GasketInterruptMapping) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (g *GasketInterruptMapping) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (g *GasketInterruptMapping) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (g *GasketInterruptMapping) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (g *GasketInterruptMapping) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (g *GasketInterruptMapping) WriteTo(writer io.Writer) (int64, error) {
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
func (g *GasketPageTableDmaBufIoctl) SizeBytes() int {
    return 20
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *GasketPageTableDmaBufIoctl) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.PageTableIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.DeviceAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(g.DMABufID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *GasketPageTableDmaBufIoctl) UnmarshalBytes(src []byte) []byte {
    g.PageTableIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DeviceAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DMABufID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketPageTableDmaBufIoctl) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *GasketPageTableDmaBufIoctl) MarshalUnsafe(dst []byte) []byte {
    // Type GasketPageTableDmaBufIoctl doesn't have a packed layout in memory, fallback to MarshalBytes.
    return g.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *GasketPageTableDmaBufIoctl) UnmarshalUnsafe(src []byte) []byte {
    // Type GasketPageTableDmaBufIoctl doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return g.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (g *GasketPageTableDmaBufIoctl) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type GasketPageTableDmaBufIoctl doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(g.SizeBytes()) // escapes: okay.
    g.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (g *GasketPageTableDmaBufIoctl) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (g *GasketPageTableDmaBufIoctl) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type GasketPageTableDmaBufIoctl doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(g.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    g.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (g *GasketPageTableDmaBufIoctl) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (g *GasketPageTableDmaBufIoctl) WriteTo(writer io.Writer) (int64, error) {
    // Type GasketPageTableDmaBufIoctl doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, g.SizeBytes())
    g.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *GasketPageTableIoctl) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *GasketPageTableIoctl) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.PageTableIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.HostAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.DeviceAddress))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *GasketPageTableIoctl) UnmarshalBytes(src []byte) []byte {
    g.PageTableIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.HostAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DeviceAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketPageTableIoctl) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *GasketPageTableIoctl) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *GasketPageTableIoctl) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (g *GasketPageTableIoctl) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (g *GasketPageTableIoctl) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (g *GasketPageTableIoctl) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (g *GasketPageTableIoctl) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (g *GasketPageTableIoctl) WriteTo(writer io.Writer) (int64, error) {
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

