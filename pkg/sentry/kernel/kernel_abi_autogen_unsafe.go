// Automatically generated marshal implementation. See tools/go_marshal.

package kernel

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
var _ marshal.Marshallable = (*ThreadID)(nil)
var _ marshal.Marshallable = (*vdsoParams)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (tid *ThreadID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (tid *ThreadID) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*tid))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (tid *ThreadID) UnmarshalBytes(src []byte) {
    *tid = ThreadID(int32(hostarch.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (tid *ThreadID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (tid *ThreadID) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(tid), uintptr(tid.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (tid *ThreadID) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(tid), unsafe.Pointer(&src[0]), uintptr(tid.SizeBytes()))
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (tid *ThreadID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tid)))
    hdr.Len = tid.SizeBytes()
    hdr.Cap = tid.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tid
    // must live until the use above.
    runtime.KeepAlive(tid) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (tid *ThreadID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tid.CopyOutN(cc, addr, tid.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (tid *ThreadID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tid)))
    hdr.Len = tid.SizeBytes()
    hdr.Cap = tid.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tid
    // must live until the use above.
    runtime.KeepAlive(tid) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (tid *ThreadID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tid)))
    hdr.Len = tid.SizeBytes()
    hdr.Cap = tid.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that tid
    // must live until the use above.
    runtime.KeepAlive(tid) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *vdsoParams) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *vdsoParams) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicReady))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicBaseCycles))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicBaseRef))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicFrequency))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeReady))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeBaseCycles))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeBaseRef))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeFrequency))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *vdsoParams) UnmarshalBytes(src []byte) {
    v.monotonicReady = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicBaseCycles = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicBaseRef = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicFrequency = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeReady = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeBaseCycles = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeBaseRef = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeFrequency = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *vdsoParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *vdsoParams) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v),  uintptr(v.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *vdsoParams) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(v.SizeBytes()))
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (v *vdsoParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (v *vdsoParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (v *vdsoParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *vdsoParams) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

