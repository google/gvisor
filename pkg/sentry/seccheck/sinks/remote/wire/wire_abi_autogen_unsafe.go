// Automatically generated marshal implementation. See tools/go_marshal.

package wire

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
var _ marshal.Marshallable = (*Header)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (h *Header) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (h *Header) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(h.HeaderSize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(h.MessageType))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(h.DroppedCount))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (h *Header) UnmarshalBytes(src []byte) []byte {
    h.HeaderSize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    h.MessageType = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    h.DroppedCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (h *Header) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (h *Header) MarshalUnsafe(dst []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(h), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (h *Header) UnmarshalUnsafe(src []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(h), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (h *Header) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (h *Header) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyOutN(cc, addr, h.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (h *Header) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (h *Header) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyInN(cc, addr, h.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (h *Header) WriteTo(writer io.Writer) (int64, error) {
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

