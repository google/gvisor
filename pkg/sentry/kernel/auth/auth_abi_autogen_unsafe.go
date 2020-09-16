// Automatically generated marshal implementation. See tools/go_marshal.

package auth

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
var _ marshal.Marshallable = (*GID)(nil)
var _ marshal.Marshallable = (*UID)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (u *UID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*u))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UID) UnmarshalBytes(src []byte) {
    *u = UID(uint32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(u))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(u), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *UID) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
//go:nosplit
func (u *UID) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *UID) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (g *GID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *GID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*g))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *GID) UnmarshalBytes(src []byte) {
    *g = GID(uint32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (g *GID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(g))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (g *GID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(g), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (g *GID) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (g *GID) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (g *GID) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (g *GID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that g
    // must live until the use above.
    runtime.KeepAlive(g) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyGIDSliceIn copies in a slice of GID objects from the task's memory.
//go:nosplit
func CopyGIDSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []GID) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*GID)(nil).SizeBytes()

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

// CopyGIDSliceOut copies a slice of GID objects to the task's memory.
//go:nosplit
func CopyGIDSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []GID) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*GID)(nil).SizeBytes()

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

// MarshalUnsafeGIDSlice is like GID.MarshalUnsafe, but for a []GID.
func MarshalUnsafeGIDSlice(src []GID, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*GID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeGIDSlice is like GID.UnmarshalUnsafe, but for a []GID.
func UnmarshalUnsafeGIDSlice(dst []GID, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*GID)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

