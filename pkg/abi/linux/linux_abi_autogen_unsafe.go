// Automatically generated marshal implementation. See tools/go_marshal.

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
var _ marshal.Marshallable = (*NumaPolicy)(nil)
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*SignalSet)(nil)
var _ marshal.Marshallable = (*Statfs)(nil)
var _ marshal.Marshallable = (*Statx)(nil)
var _ marshal.Marshallable = (*StatxTimestamp)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)
var _ marshal.Marshallable = (*Timeval)(nil)
var _ marshal.Marshallable = (*Utime)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Statx) SizeBytes() int {
    return 80 +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statx) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Mask))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Blksize))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Attributes))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nlink))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Mode))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.AttributesMask))
    dst = dst[8:]
    s.Atime.MarshalBytes(dst[:s.Atime.SizeBytes()])
    dst = dst[s.Atime.SizeBytes():]
    s.Btime.MarshalBytes(dst[:s.Btime.SizeBytes()])
    dst = dst[s.Btime.SizeBytes():]
    s.Ctime.MarshalBytes(dst[:s.Ctime.SizeBytes()])
    dst = dst[s.Ctime.SizeBytes():]
    s.Mtime.MarshalBytes(dst[:s.Mtime.SizeBytes()])
    dst = dst[s.Mtime.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMajor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMinor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.DevMajor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.DevMinor))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statx) UnmarshalBytes(src []byte) {
    s.Mask = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Blksize = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Attributes = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Mode = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    s.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AttributesMask = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Atime.UnmarshalBytes(src[:s.Atime.SizeBytes()])
    src = src[s.Atime.SizeBytes():]
    s.Btime.UnmarshalBytes(src[:s.Btime.SizeBytes()])
    src = src[s.Btime.SizeBytes():]
    s.Ctime.UnmarshalBytes(src[:s.Ctime.SizeBytes()])
    src = src[s.Ctime.SizeBytes():]
    s.Mtime.UnmarshalBytes(src[:s.Mtime.SizeBytes()])
    src = src[s.Mtime.SizeBytes():]
    s.RdevMajor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.RdevMinor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMajor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMinor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statx) Packed() bool {
    return s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() && s.Atime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statx) MarshalUnsafe(dst []byte) {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statx) UnmarshalUnsafe(src []byte) {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Statx) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !s.Ctime.Packed() && s.Mtime.Packed() && s.Atime.Packed() && s.Btime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Statx) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Statx) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statx) WriteTo(w io.Writer) (int64, error) {
    if !s.Mtime.Packed() && s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Statfs) SizeBytes() int {
    return 80 +
        4*2 +
        8*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statfs) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Type))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlockSize))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksFree))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksAvailable))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Files))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FilesFree))
    dst = dst[8:]
    for idx := 0; idx < 2; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(s.FSID[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.NameLength))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FragmentSize))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    for idx := 0; idx < 4; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Spare[idx]))
        dst = dst[8:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statfs) UnmarshalBytes(src []byte) {
    s.Type = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlockSize = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksFree = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksAvailable = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Files = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FilesFree = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 2; idx++ {
        s.FSID[idx] = int32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    s.NameLength = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FragmentSize = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 4; idx++ {
        s.Spare[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statfs) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statfs) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statfs) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Statfs) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Statfs) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Statfs) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statfs) WriteTo(w io.Writer) (int64, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NumaPolicy) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NumaPolicy) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*n))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NumaPolicy) UnmarshalBytes(src []byte) {
    *n = NumaPolicy(int32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NumaPolicy) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NumaPolicy) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(n))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NumaPolicy) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(n), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (n *NumaPolicy) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (n *NumaPolicy) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return n.CopyOutN(task, addr, n.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (n *NumaPolicy) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NumaPolicy) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n)
    return int64(length), err
}

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
    r.Version = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Start = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.PostCommitOffset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.Abort = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
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

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *RSeqCriticalSection) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *RSeqCriticalSection) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return r.CopyOutN(task, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *RSeqCriticalSection) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RSeqCriticalSection) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (s *SignalSet) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalSet) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*s))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalSet) UnmarshalBytes(src []byte) {
    *s = SignalSet(uint64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalSet) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalSet) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalSet) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalSet) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SignalSet) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalSet) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalSet) WriteTo(w io.Writer) (int64, error) {
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
//go:nosplit
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

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Timespec) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Timespec) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return t.CopyOutN(task, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Timespec) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timespec) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Timeval) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Timeval) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Usec))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Timeval) UnmarshalBytes(src []byte) {
    t.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Usec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Timeval) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Timeval) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Timeval) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Timeval) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Timeval) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return t.CopyOutN(task, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Timeval) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timeval) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StatxTimestamp) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StatxTimestamp) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StatxTimestamp) UnmarshalBytes(src []byte) {
    s.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *StatxTimestamp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *StatxTimestamp) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *StatxTimestamp) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *StatxTimestamp) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *StatxTimestamp) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *StatxTimestamp) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *StatxTimestamp) WriteTo(w io.Writer) (int64, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *Utime) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *Utime) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Actime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Modtime))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *Utime) UnmarshalBytes(src []byte) {
    u.Actime = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Modtime = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Utime) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *Utime) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(u))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *Utime) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(u), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *Utime) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u)
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (u *Utime) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return u.CopyOutN(task, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *Utime) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u)
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *Utime) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u)
    return int64(length), err
}

