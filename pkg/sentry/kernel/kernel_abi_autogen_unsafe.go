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

