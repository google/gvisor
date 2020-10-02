// Automatically generated marshal implementation. See tools/go_marshal.

package kernel

import (
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/marshal"
    "gvisor.dev/gvisor/pkg/safecopy"
    "gvisor.dev/gvisor/pkg/usermem"
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
func (t *ThreadID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *ThreadID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*t))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *ThreadID) UnmarshalBytes(src []byte) {
    *t = ThreadID(int32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *ThreadID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *ThreadID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *ThreadID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *ThreadID) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *ThreadID) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *ThreadID) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *ThreadID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *vdsoParams) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *vdsoParams) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicReady))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicBaseCycles))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicBaseRef))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.monotonicFrequency))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeReady))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeBaseCycles))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeBaseRef))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(v.realtimeFrequency))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *vdsoParams) UnmarshalBytes(src []byte) {
    v.monotonicReady = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicBaseCycles = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicBaseRef = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.monotonicFrequency = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeReady = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeBaseCycles = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeBaseRef = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.realtimeFrequency = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *vdsoParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *vdsoParams) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(v))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *vdsoParams) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(v), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (v *vdsoParams) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (v *vdsoParams) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (v *vdsoParams) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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

