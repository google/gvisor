// Automatically generated marshal implementation. See tools/go_marshal.

package vfs2

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
var _ marshal.Marshallable = (*sigSetWithSize)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *sigSetWithSize) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *sigSetWithSize) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.sigsetAddr))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.sizeofSigset))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *sigSetWithSize) UnmarshalBytes(src []byte) {
    s.sigsetAddr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.sizeofSigset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
func (s *sigSetWithSize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *sigSetWithSize) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *sigSetWithSize) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *sigSetWithSize) CopyOut(task marshal.Task, addr usermem.Addr) error {
    // Bypass escape analysis on s. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on s.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(s)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by s's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    _, err := task.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until after the CopyOutBytes.
    runtime.KeepAlive(s)
    return err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *sigSetWithSize) CopyIn(task marshal.Task, addr usermem.Addr) error {
    // Bypass escape analysis on s. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on s.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(s)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by s's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    _, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until after the CopyInBytes.
    runtime.KeepAlive(s)
    return err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *sigSetWithSize) WriteTo(w io.Writer) (int64, error) {
    // Bypass escape analysis on s. The no-op arithmetic operation on the
    // pointer makes the compiler think val doesn't depend on s.
    // See src/runtime/stubs.go:noescape() in the golang toolchain.
    ptr := unsafe.Pointer(s)
    val := uintptr(ptr)
    val = val^0

    // Construct a slice backed by s's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = val
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    len, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until after the Write.
    runtime.KeepAlive(s)
    return int64(len), err
}

