// Automatically generated marshal implementation. See tools/go_marshal.

package linux

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
var _ marshal.Marshallable = (*ControlMessageCredentials)(nil)
var _ marshal.Marshallable = (*FUSEAttr)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrOut)(nil)
var _ marshal.Marshallable = (*FUSEHeaderIn)(nil)
var _ marshal.Marshallable = (*FUSEHeaderOut)(nil)
var _ marshal.Marshallable = (*FUSEInitIn)(nil)
var _ marshal.Marshallable = (*FUSEInitOut)(nil)
var _ marshal.Marshallable = (*FUSEOpID)(nil)
var _ marshal.Marshallable = (*FUSEOpcode)(nil)
var _ marshal.Marshallable = (*FUSEWriteIn)(nil)
var _ marshal.Marshallable = (*IFConf)(nil)
var _ marshal.Marshallable = (*IFReq)(nil)
var _ marshal.Marshallable = (*IP6TEntry)(nil)
var _ marshal.Marshallable = (*IP6TIP)(nil)
var _ marshal.Marshallable = (*IP6TReplace)(nil)
var _ marshal.Marshallable = (*IPTEntry)(nil)
var _ marshal.Marshallable = (*IPTGetEntries)(nil)
var _ marshal.Marshallable = (*IPTGetinfo)(nil)
var _ marshal.Marshallable = (*IPTIP)(nil)
var _ marshal.Marshallable = (*Inet6Addr)(nil)
var _ marshal.Marshallable = (*InetAddr)(nil)
var _ marshal.Marshallable = (*Linger)(nil)
var _ marshal.Marshallable = (*NumaPolicy)(nil)
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*RobustListHead)(nil)
var _ marshal.Marshallable = (*SignalSet)(nil)
var _ marshal.Marshallable = (*SockAddrInet)(nil)
var _ marshal.Marshallable = (*Statfs)(nil)
var _ marshal.Marshallable = (*Statx)(nil)
var _ marshal.Marshallable = (*StatxTimestamp)(nil)
var _ marshal.Marshallable = (*TCPInfo)(nil)
var _ marshal.Marshallable = (*TableName)(nil)
var _ marshal.Marshallable = (*Termios)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)
var _ marshal.Marshallable = (*Timeval)(nil)
var _ marshal.Marshallable = (*Utime)(nil)
var _ marshal.Marshallable = (*WindowSize)(nil)
var _ marshal.Marshallable = (*Winsize)(nil)
var _ marshal.Marshallable = (*XTCounters)(nil)

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
    return s.Mtime.Packed() && s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statx) MarshalUnsafe(dst []byte) {
    if s.Ctime.Packed() && s.Mtime.Packed() && s.Atime.Packed() && s.Btime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type Statx doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statx) UnmarshalUnsafe(src []byte) {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type Statx doesn't have a packed layout in memory, fallback to UnmarshalBytes.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statx) WriteTo(writer io.Writer) (int64, error) {
    if !s.Mtime.Packed() && s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statfs) WriteTo(writer io.Writer) (int64, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpcode) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpcode) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*f))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpcode) UnmarshalBytes(src []byte) {
    *f = FUSEOpcode(uint32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpcode) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpcode) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpcode) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpcode) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpcode) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpcode) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpcode) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpID) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*f))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpID) UnmarshalBytes(src []byte) {
    *f = FUSEOpID(uint64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpID) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpID) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpID) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEHeaderIn) SizeBytes() int {
    return 28 +
        (*FUSEOpcode)(nil).SizeBytes() +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    f.Opcode.MarshalBytes(dst[:f.Opcode.SizeBytes()])
    dst = dst[f.Opcode.SizeBytes():]
    f.Unique.MarshalBytes(dst[:f.Unique.SizeBytes()])
    dst = dst[f.Unique.SizeBytes():]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderIn) UnmarshalBytes(src []byte) {
    f.Len = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Opcode.UnmarshalBytes(src[:f.Opcode.SizeBytes()])
    src = src[f.Opcode.SizeBytes():]
    f.Unique.UnmarshalBytes(src[:f.Unique.SizeBytes()])
    src = src[f.Unique.SizeBytes():]
    f.NodeID = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderIn) Packed() bool {
    return f.Opcode.Packed() && f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderIn) MarshalUnsafe(dst []byte) {
    if f.Opcode.Packed() && f.Unique.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderIn) UnmarshalUnsafe(src []byte) {
    if f.Opcode.Packed() && f.Unique.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEHeaderIn) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEHeaderIn) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEHeaderIn) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderIn) WriteTo(writer io.Writer) (int64, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEHeaderOut) SizeBytes() int {
    return 8 +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Error))
    dst = dst[4:]
    f.Unique.MarshalBytes(dst[:f.Unique.SizeBytes()])
    dst = dst[f.Unique.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderOut) UnmarshalBytes(src []byte) {
    f.Len = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Error = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Unique.UnmarshalBytes(src[:f.Unique.SizeBytes()])
    src = src[f.Unique.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderOut) Packed() bool {
    return f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderOut) MarshalUnsafe(dst []byte) {
    if f.Unique.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderOut) UnmarshalUnsafe(src []byte) {
    if f.Unique.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEHeaderOut) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEHeaderOut) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEHeaderOut) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEWriteIn) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEWriteIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.WriteFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEWriteIn) UnmarshalBytes(src []byte) {
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.WriteFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEWriteIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEWriteIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEWriteIn) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEWriteIn) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEWriteIn) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEWriteIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEInitIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitIn) UnmarshalBytes(src []byte) {
    f.Major = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEInitIn) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEInitIn) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEInitIn) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEInitOut) SizeBytes() int {
    return 32 +
        4*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.MaxBackground))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.CongestionThreshold))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxWrite))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.TimeGran))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.MaxPages))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.MapAlignment))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint32)*8] ~= [8]uint32{0}
    dst = dst[4*(8):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitOut) UnmarshalBytes(src []byte) {
    f.Major = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxBackground = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.CongestionThreshold = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.MaxWrite = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.TimeGran = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxPages = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.MapAlignment = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([8]uint32(f._), src[:sizeof(uint32)*8])
    src = src[4*(8):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitOut) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitOut) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEInitOut) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEInitOut) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEInitOut) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitOut) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEGetAttrIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEGetAttrIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GetAttrFlags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEGetAttrIn) UnmarshalBytes(src []byte) {
    f.GetAttrFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEGetAttrIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEGetAttrIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEGetAttrIn) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEGetAttrIn) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEGetAttrIn) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEGetAttrIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEAttr) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEAttr) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Atime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Mtime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ctime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.CtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Nlink))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Rdev))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.BlkSize))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEAttr) UnmarshalBytes(src []byte) {
    f.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Atime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mtime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Ctime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.CtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Nlink = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Rdev = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.BlkSize = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEAttr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEAttr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEAttr) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEAttr) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEAttr) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEAttr) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEGetAttrOut) SizeBytes() int {
    return 16 +
        (*FUSEAttr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEGetAttrOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    f.Attr.MarshalBytes(dst[:f.Attr.SizeBytes()])
    dst = dst[f.Attr.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEGetAttrOut) UnmarshalBytes(src []byte) {
    f.AttrValid = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValidNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Attr.UnmarshalBytes(src[:f.Attr.SizeBytes()])
    src = src[f.Attr.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrOut) Packed() bool {
    return f.Attr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEGetAttrOut) MarshalUnsafe(dst []byte) {
    if f.Attr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEGetAttrOut) UnmarshalUnsafe(src []byte) {
    if f.Attr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEGetAttrOut) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEGetAttrOut) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return f.CopyOutN(task, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEGetAttrOut) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEGetAttrOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RobustListHead) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RobustListHead) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.List))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.FutexOffset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.ListOpPending))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RobustListHead) UnmarshalBytes(src []byte) {
    r.List = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.FutexOffset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ListOpPending = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RobustListHead) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RobustListHead) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(r))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RobustListHead) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(r), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *RobustListHead) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *RobustListHead) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return r.CopyOutN(task, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *RobustListHead) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RobustListHead) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IFReq) SizeBytes() int {
    return 0 +
        1*IFNAMSIZ +
        1*24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IFReq) MarshalBytes(dst []byte) {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.IFName[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 24; idx++ {
        dst[0] = byte(i.Data[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IFReq) UnmarshalBytes(src []byte) {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.IFName[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 24; idx++ {
        i.Data[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFReq) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IFReq) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IFReq) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IFReq) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IFReq) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IFReq) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IFReq) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IFConf) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IFConf) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Ptr))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IFConf) UnmarshalBytes(src []byte) {
    i.Len = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    i.Ptr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFConf) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IFConf) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IFConf) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IFConf) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IFConf) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IFConf) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IFConf) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTEntry) SizeBytes() int {
    return 12 +
        (*IPTIP)(nil).SizeBytes() +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTEntry) MarshalBytes(dst []byte) {
    i.IP.MarshalBytes(dst[:i.IP.SizeBytes()])
    dst = dst[i.IP.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    i.Counters.MarshalBytes(dst[:i.Counters.SizeBytes()])
    dst = dst[i.Counters.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTEntry) UnmarshalBytes(src []byte) {
    i.IP.UnmarshalBytes(src[:i.IP.SizeBytes()])
    src = src[i.IP.SizeBytes():]
    i.NFCache = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters.UnmarshalBytes(src[:i.Counters.SizeBytes()])
    src = src[i.Counters.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTEntry) Packed() bool {
    return i.IP.Packed() && i.Counters.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTEntry) MarshalUnsafe(dst []byte) {
    if i.IP.Packed() && i.Counters.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTEntry) UnmarshalUnsafe(src []byte) {
    if i.Counters.Packed() && i.IP.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTEntry) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.IP.Packed() && i.Counters.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTEntry) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTEntry) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.IP.Packed() && i.Counters.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.IP.Packed() && i.Counters.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTIP) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTIP) MarshalBytes(dst []byte) {
    i.Src.MarshalBytes(dst[:i.Src.SizeBytes()])
    dst = dst[i.Src.SizeBytes():]
    i.Dst.MarshalBytes(dst[:i.Dst.SizeBytes()])
    dst = dst[i.Dst.SizeBytes():]
    i.SrcMask.MarshalBytes(dst[:i.SrcMask.SizeBytes()])
    dst = dst[i.SrcMask.SizeBytes():]
    i.DstMask.MarshalBytes(dst[:i.DstMask.SizeBytes()])
    dst = dst[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTIP) UnmarshalBytes(src []byte) {
    i.Src.UnmarshalBytes(src[:i.Src.SizeBytes()])
    src = src[i.Src.SizeBytes():]
    i.Dst.UnmarshalBytes(src[:i.Dst.SizeBytes()])
    src = src[i.Dst.SizeBytes():]
    i.SrcMask.UnmarshalBytes(src[:i.SrcMask.SizeBytes()])
    src = src[i.SrcMask.SizeBytes():]
    i.DstMask.UnmarshalBytes(src[:i.DstMask.SizeBytes()])
    src = src[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTIP) Packed() bool {
    return i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTIP) MarshalUnsafe(dst []byte) {
    if i.DstMask.Packed() && i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTIP doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTIP) UnmarshalUnsafe(src []byte) {
    if i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() && i.Src.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTIP) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.DstMask.Packed() && i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTIP) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTIP) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTCounters) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTCounters) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(x.Pcnt))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(x.Bcnt))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTCounters) UnmarshalBytes(src []byte) {
    x.Pcnt = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    x.Bcnt = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTCounters) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTCounters) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(x))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTCounters) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(x), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (x *XTCounters) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (x *XTCounters) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return x.CopyOutN(task, addr, x.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (x *XTCounters) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTCounters) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTGetinfo) SizeBytes() int {
    return 12 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetinfo) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetinfo) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.ValidHooks = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumEntries = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetinfo) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetinfo) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTGetinfo doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetinfo) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTGetinfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTGetinfo) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTGetinfo) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTGetinfo) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetinfo) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTGetEntries) SizeBytes() int {
    return 4 +
        (*TableName)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetEntries) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetEntries) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetEntries) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetEntries) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTGetEntries doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetEntries) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTGetEntries doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTGetEntries) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTGetEntries) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTGetEntries) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TableName) SizeBytes() int {
    return 1 * XT_TABLE_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TableName) MarshalBytes(dst []byte) {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        dst[0] = byte(t[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TableName) UnmarshalBytes(src []byte) {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        t[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TableName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TableName) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TableName) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TableName) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TableName) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return t.CopyOutN(task, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TableName) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TableName) WriteTo(w io.Writer) (int64, error) {
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
func (i *IP6TReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TReplace) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TReplace) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.ValidHooks = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TReplace) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TReplace) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TReplace doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TReplace) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TReplace doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TReplace) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TReplace) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TReplace) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TEntry) SizeBytes() int {
    return 12 +
        (*IP6TIP)(nil).SizeBytes() +
        1*4 +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TEntry) MarshalBytes(dst []byte) {
    i.IPv6.MarshalBytes(dst[:i.IPv6.SizeBytes()])
    dst = dst[i.IPv6.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    i.Counters.MarshalBytes(dst[:i.Counters.SizeBytes()])
    dst = dst[i.Counters.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TEntry) UnmarshalBytes(src []byte) {
    i.IPv6.UnmarshalBytes(src[:i.IPv6.SizeBytes()])
    src = src[i.IPv6.SizeBytes():]
    i.NFCache = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    i.Counters.UnmarshalBytes(src[:i.Counters.SizeBytes()])
    src = src[i.Counters.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TEntry) Packed() bool {
    return i.IPv6.Packed() && i.Counters.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TEntry) MarshalUnsafe(dst []byte) {
    if i.IPv6.Packed() && i.Counters.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TEntry) UnmarshalUnsafe(src []byte) {
    if i.IPv6.Packed() && i.Counters.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TEntry) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.IPv6.Packed() && i.Counters.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TEntry) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TEntry) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.IPv6.Packed() && i.Counters.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.IPv6.Packed() && i.Counters.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TIP) SizeBytes() int {
    return 5 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TIP) MarshalBytes(dst []byte) {
    i.Src.MarshalBytes(dst[:i.Src.SizeBytes()])
    dst = dst[i.Src.SizeBytes():]
    i.Dst.MarshalBytes(dst[:i.Dst.SizeBytes()])
    dst = dst[i.Dst.SizeBytes():]
    i.SrcMask.MarshalBytes(dst[:i.SrcMask.SizeBytes()])
    dst = dst[i.SrcMask.SizeBytes():]
    i.DstMask.MarshalBytes(dst[:i.DstMask.SizeBytes()])
    dst = dst[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.TOS)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    // Padding: dst[:sizeof(byte)*3] ~= [3]byte{0}
    dst = dst[1*(3):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TIP) UnmarshalBytes(src []byte) {
    i.Src.UnmarshalBytes(src[:i.Src.SizeBytes()])
    src = src[i.Src.SizeBytes():]
    i.Dst.UnmarshalBytes(src[:i.Dst.SizeBytes()])
    src = src[i.Dst.SizeBytes():]
    i.SrcMask.UnmarshalBytes(src[:i.SrcMask.SizeBytes()])
    src = src[i.SrcMask.SizeBytes():]
    i.DstMask.UnmarshalBytes(src[:i.DstMask.SizeBytes()])
    src = src[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.TOS = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    // Padding: ~ copy([3]byte(i._), src[:sizeof(byte)*3])
    src = src[1*(3):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TIP) Packed() bool {
    return i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TIP) MarshalUnsafe(dst []byte) {
    if i.SrcMask.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.Dst.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TIP doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TIP) UnmarshalUnsafe(src []byte) {
    if i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() && i.Src.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TIP) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TIP) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TIP) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !i.DstMask.Packed() && i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := task.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := task.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Src.Packed() && i.Dst.Packed() && i.SrcMask.Packed() && i.DstMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RSeqCriticalSection) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *InetAddr) SizeBytes() int {
    return 1 * 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InetAddr) MarshalBytes(dst []byte) {
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InetAddr) UnmarshalBytes(src []byte) {
    for idx := 0; idx < 4; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetAddr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InetAddr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InetAddr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *InetAddr) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *InetAddr) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *InetAddr) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InetAddr) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrInet) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        1*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrInet) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    s.Addr.MarshalBytes(dst[:s.Addr.SizeBytes()])
    dst = dst[s.Addr.SizeBytes():]
    // Padding: dst[:sizeof(uint8)*8] ~= [8]uint8{0}
    dst = dst[1*(8):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrInet) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Addr.UnmarshalBytes(src[:s.Addr.SizeBytes()])
    src = src[s.Addr.SizeBytes():]
    // Padding: ~ copy([8]uint8(s._), src[:sizeof(uint8)*8])
    src = src[1*(8):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet) Packed() bool {
    return s.Addr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrInet) MarshalUnsafe(dst []byte) {
    if s.Addr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type SockAddrInet doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrInet) UnmarshalUnsafe(src []byte) {
    if s.Addr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type SockAddrInet doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrInet) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrInet) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrInet) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrInet) WriteTo(writer io.Writer) (int64, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Inet6Addr) SizeBytes() int {
    return 1 * 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inet6Addr) MarshalBytes(dst []byte) {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inet6Addr) UnmarshalBytes(src []byte) {
    for idx := 0; idx < 16; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6Addr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inet6Addr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inet6Addr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *Inet6Addr) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *Inet6Addr) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return i.CopyOutN(task, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *Inet6Addr) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Inet6Addr) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (l *Linger) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *Linger) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(l.OnOff))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(l.Linger))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *Linger) UnmarshalBytes(src []byte) {
    l.OnOff = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    l.Linger = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (l *Linger) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (l *Linger) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(l))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (l *Linger) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(l), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (l *Linger) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (l *Linger) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return l.CopyOutN(task, addr, l.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (l *Linger) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (l *Linger) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *TCPInfo) SizeBytes() int {
    return 192
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TCPInfo) MarshalBytes(dst []byte) {
    dst[0] = byte(t.State)
    dst = dst[1:]
    dst[0] = byte(t.CaState)
    dst = dst[1:]
    dst[0] = byte(t.Retransmits)
    dst = dst[1:]
    dst[0] = byte(t.Probes)
    dst = dst[1:]
    dst[0] = byte(t.Backoff)
    dst = dst[1:]
    dst[0] = byte(t.Options)
    dst = dst[1:]
    dst[0] = byte(t.WindowScale)
    dst = dst[1:]
    dst[0] = byte(t.DeliveryRateAppLimited)
    dst = dst[1:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTO))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.ATO))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndMss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvMss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Unacked))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Sacked))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Lost))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Retrans))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Fackets))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataSent))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckSent))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataRecv))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckRecv))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.PMTU))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSsthresh))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTTVar))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndSsthresh))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndCwnd))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Advmss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Reordering))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvRTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSpace))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.TotalRetrans))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.PacingRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.MaxPacingRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BytesAcked))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BytesReceived))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SegsOut))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SegsIn))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.NotSentBytes))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.MinRTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsIn))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsOut))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.DeliveryRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BusyTime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.RwndLimited))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.SndBufLimited))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TCPInfo) UnmarshalBytes(src []byte) {
    t.State = uint8(src[0])
    src = src[1:]
    t.CaState = uint8(src[0])
    src = src[1:]
    t.Retransmits = uint8(src[0])
    src = src[1:]
    t.Probes = uint8(src[0])
    src = src[1:]
    t.Backoff = uint8(src[0])
    src = src[1:]
    t.Options = uint8(src[0])
    src = src[1:]
    t.WindowScale = uint8(src[0])
    src = src[1:]
    t.DeliveryRateAppLimited = uint8(src[0])
    src = src[1:]
    t.RTO = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ATO = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndMss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvMss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Unacked = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Sacked = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Lost = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Retrans = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Fackets = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataSent = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckSent = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataRecv = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckRecv = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PMTU = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSsthresh = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTTVar = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndSsthresh = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndCwnd = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Advmss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Reordering = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvRTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSpace = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TotalRetrans = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PacingRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.MaxPacingRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesAcked = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesReceived = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SegsOut = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SegsIn = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.NotSentBytes = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.MinRTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsIn = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsOut = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveryRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BusyTime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.RwndLimited = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SndBufLimited = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TCPInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TCPInfo) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TCPInfo) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TCPInfo) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TCPInfo) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return t.CopyOutN(task, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TCPInfo) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TCPInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageCredentials) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageCredentials) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.PID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.GID))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageCredentials) UnmarshalBytes(src []byte) {
    c.PID = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageCredentials) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageCredentials) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(c))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageCredentials) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(c), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *ControlMessageCredentials) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *ControlMessageCredentials) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return c.CopyOutN(task, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *ControlMessageCredentials) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageCredentials) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timespec) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timeval) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *StatxTimestamp) WriteTo(writer io.Writer) (int64, error) {
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
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
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
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *Utime) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *Winsize) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *Winsize) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Row))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Col))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Xpixel))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Ypixel))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *Winsize) UnmarshalBytes(src []byte) {
    w.Row = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Col = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Xpixel = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Ypixel = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *Winsize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *Winsize) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(w))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *Winsize) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(w), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (w *Winsize) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (w *Winsize) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return w.CopyOutN(task, addr, w.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (w *Winsize) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *Winsize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Termios) SizeBytes() int {
    return 17 +
        1*NumControlCharacters
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Termios) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.InputFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.OutputFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.ControlFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LocalFlags))
    dst = dst[4:]
    dst[0] = byte(t.LineDiscipline)
    dst = dst[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        dst[0] = byte(t.ControlCharacters[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Termios) UnmarshalBytes(src []byte) {
    t.InputFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ControlFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LocalFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LineDiscipline = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        t.ControlCharacters[idx] = uint8(src[0])
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Termios) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Termios) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Termios) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Termios) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Termios) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return t.CopyOutN(task, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Termios) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Termios) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WindowSize) SizeBytes() int {
    return 4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WindowSize) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Rows))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Cols))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WindowSize) UnmarshalBytes(src []byte) {
    w.Rows = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Cols = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([4]byte(w._), src[:sizeof(byte)*4])
    src = src[1*(4):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *WindowSize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *WindowSize) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(w))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *WindowSize) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(w), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (w *WindowSize) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (w *WindowSize) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return w.CopyOutN(task, addr, w.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (w *WindowSize) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *WindowSize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

