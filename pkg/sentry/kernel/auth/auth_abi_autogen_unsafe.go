// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build tag aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The build tags here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build tags, see 
// tools/defs.bzl:calculate_sets().

package auth

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
var _ marshal.Marshallable = (*GID)(nil)
var _ marshal.Marshallable = (*UID)(nil)

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

// CopyGIDSliceIn copies in a slice of GID objects from the task's memory.
//go:nosplit
func CopyGIDSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []GID) (int, error) {
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
func CopyGIDSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []GID) (int, error) {
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

    dst = dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))
    return size*count, nil
}

// UnmarshalUnsafeGIDSlice is like GID.UnmarshalUnsafe, but for a []GID.
func UnmarshalUnsafeGIDSlice(dst []GID, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*GID)(nil).SizeBytes()

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

