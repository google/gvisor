// Automatically generated marshal implementation. See tools/go_marshal.

package linux

import (
    "gvisor.dev/gvisor/pkg/safecopy"
    "gvisor.dev/gvisor/pkg/usermem"
    "gvisor.dev/gvisor/tools/go_marshal/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RSeqCriticalSection) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RSeqCriticalSection) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(r.Version))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Start))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.PostCommitOffset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Abort))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RSeqCriticalSection) UnmarshalBytes(src []byte) {
    r.Version = usermem.ByteOrder.Uint32(src[:4])
    src = src[4:]
    r.Flags = usermem.ByteOrder.Uint32(src[:4])
    src = src[4:]
    r.Start = usermem.ByteOrder.Uint64(src[:8])
    src = src[8:]
    r.PostCommitOffset = usermem.ByteOrder.Uint64(src[:8])
    src = src[8:]
    r.Abort = usermem.ByteOrder.Uint64(src[:8])
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
func (r *RSeqCriticalSection) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RSeqCriticalSection) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(r))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RSeqCriticalSection) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(r), src)
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *RSeqCriticalSection) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    // Bypass escape analysis on r. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on r.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(r)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by r's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    len, err := task.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until after the CopyOutBytes.
    runtime.KeepAlive(r)
    return len, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RSeqCriticalSection) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Bypass escape analysis on r. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on r.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(r)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by r's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    len, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until after the CopyInBytes.
    runtime.KeepAlive(r)
    return len, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RSeqCriticalSection) WriteTo(w io.Writer) (int64, error) {
    // Bypass escape analysis on r. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on r.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(r)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by r's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    len, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until after the Write.
    runtime.KeepAlive(r)
    return int64(len), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Timespec) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Timespec) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Nsec))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Timespec) UnmarshalBytes(src []byte) {
    t.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Nsec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
func (t *Timespec) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Timespec) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Timespec) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *Timespec) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    // Bypass escape analysis on t. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on t.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(t)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by t's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    len, err := task.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until after the CopyOutBytes.
    runtime.KeepAlive(t)
    return len, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *Timespec) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Bypass escape analysis on t. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on t.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(t)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by t's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    len, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until after the CopyInBytes.
    runtime.KeepAlive(t)
    return len, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timespec) WriteTo(w io.Writer) (int64, error) {
    // Bypass escape analysis on t. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on t.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(t)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by t's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    len, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until after the Write.
    runtime.KeepAlive(t)
    return int64(len), err
}

