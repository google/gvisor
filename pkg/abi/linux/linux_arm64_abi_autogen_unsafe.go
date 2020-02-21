// Automatically generated marshal implementation. See tools/go_marshal.

// +build arm64

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
var _ marshal.Marshallable = (*Stat)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Stat) SizeBytes() int {
    return 80 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Stat) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Dev))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nlink))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Rdev))
    dst = dst[8:]
    // Padding: dst[:sizeof(uint64)] ~= uint64(0)
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Blksize))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    s.ATime.MarshalBytes(dst[:s.ATime.SizeBytes()])
    dst = dst[s.ATime.SizeBytes():]
    s.MTime.MarshalBytes(dst[:s.MTime.SizeBytes()])
    dst = dst[s.MTime.SizeBytes():]
    s.CTime.MarshalBytes(dst[:s.CTime.SizeBytes()])
    dst = dst[s.CTime.SizeBytes():]
    // Padding: dst[:sizeof(int32)*2] ~= [2]int32{0}
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Stat) UnmarshalBytes(src []byte) {
    s.Dev = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Nlink = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Rdev = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    // Padding: var _ uint64 ~= src[:sizeof(uint64)]
    src = src[8:]
    s.Size = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blksize = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
    s.Blocks = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ATime.UnmarshalBytes(src[:s.ATime.SizeBytes()])
    src = src[s.ATime.SizeBytes():]
    s.MTime.UnmarshalBytes(src[:s.MTime.SizeBytes()])
    src = src[s.MTime.SizeBytes():]
    s.CTime.UnmarshalBytes(src[:s.CTime.SizeBytes()])
    src = src[s.CTime.SizeBytes():]
    // Padding: ~ copy([2]int32(s._), src[:sizeof(int32)*2])
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
func (s *Stat) Packed() bool {
    return s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Stat) MarshalUnsafe(dst []byte) {
    if s.MTime.Packed() && s.CTime.Packed() && s.ATime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Stat) UnmarshalUnsafe(src []byte) {
    if s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        s.UnmarshalBytes(src)
    }
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *Stat) CopyOut(task marshal.Task, addr usermem.Addr) error {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        _, err := task.CopyOutBytes(addr, buf)
        return err
    }

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
func (s *Stat) CopyIn(task marshal.Task, addr usermem.Addr) error {
    if !s.MTime.Packed() && s.CTime.Packed() && s.ATime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes())
        _, err := task.CopyInBytes(addr, buf)
        if err != nil {
            return err
        }
        s.UnmarshalBytes(buf)
        return nil
    }

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
func (s *Stat) WriteTo(w io.Writer) (int64, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        n, err := w.Write(buf)
        return int64(n), err
    }

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

