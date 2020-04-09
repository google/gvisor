// Automatically generated marshal implementation. See tools/go_marshal.

// +build amd64

package linux

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
var _ marshal.Marshallable = (*EpollEvent)(nil)
var _ marshal.Marshallable = (*Stat)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *EpollEvent) SizeBytes() int {
    return 4 +
        4*2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *EpollEvent) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(e.Events))
    dst = dst[4:]
    for idx := 0; idx < 2; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(e.Data[idx]))
        dst = dst[4:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *EpollEvent) UnmarshalBytes(src []byte) {
    e.Events = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 2; idx++ {
        e.Data[idx] = int32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
}

// Packed implements marshal.Marshallable.Packed.
func (e *EpollEvent) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *EpollEvent) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(e))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *EpollEvent) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(e), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *EpollEvent) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit])
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *EpollEvent) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return e.CopyOutN(task, addr, e.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *EpollEvent) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *EpollEvent) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Stat) SizeBytes() int {
    return 72 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes() +
        8*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Stat) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Dev))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Nlink))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Rdev))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blksize))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    s.ATime.MarshalBytes(dst[:s.ATime.SizeBytes()])
    dst = dst[s.ATime.SizeBytes():]
    s.MTime.MarshalBytes(dst[:s.MTime.SizeBytes()])
    dst = dst[s.MTime.SizeBytes():]
    s.CTime.MarshalBytes(dst[:s.CTime.SizeBytes()])
    dst = dst[s.CTime.SizeBytes():]
    // Padding: dst[:sizeof(int64)*3] ~= [3]int64{0}
    dst = dst[8*(3):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Stat) UnmarshalBytes(src []byte) {
    s.Dev = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
    s.Rdev = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blksize = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ATime.UnmarshalBytes(src[:s.ATime.SizeBytes()])
    src = src[s.ATime.SizeBytes():]
    s.MTime.UnmarshalBytes(src[:s.MTime.SizeBytes()])
    src = src[s.MTime.SizeBytes():]
    s.CTime.UnmarshalBytes(src[:s.CTime.SizeBytes()])
    src = src[s.CTime.SizeBytes():]
    // Padding: ~ copy([3]int64(s._), src[:sizeof(int64)*3])
    src = src[8*(3):]
}

// Packed implements marshal.Marshallable.Packed.
func (s *Stat) Packed() bool {
    return s.MTime.Packed() && s.CTime.Packed() && s.ATime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Stat) MarshalUnsafe(dst []byte) {
    if s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
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

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Stat) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return task.CopyOutBytes(addr, buf[:limit])
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit])
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *Stat) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Stat) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !s.CTime.Packed() && s.ATime.Packed() && s.MTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes())
        length, err := task.CopyInBytes(addr, buf)
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf)
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Stat) WriteTo(w io.Writer) (int64, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := w.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return int64(length), err
}

