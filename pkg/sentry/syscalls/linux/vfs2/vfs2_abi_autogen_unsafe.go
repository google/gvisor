// Automatically generated marshal implementation. See tools/go_marshal.

package vfs2

import (
    "gvisor.dev/gvisor/pkg/gohacks"
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
//go:nosplit
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

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *sigSetWithSize) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *sigSetWithSize) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *sigSetWithSize) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *sigSetWithSize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

