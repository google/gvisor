// Automatically generated marshal implementation. See tools/go_marshal.

// +build amd64
// +build amd64
// +build amd64
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
var _ marshal.Marshallable = (*PtraceRegs)(nil)
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
//go:nosplit
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
//go:nosplit
func (e *EpollEvent) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (e *EpollEvent) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return e.CopyOutN(task, addr, e.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (e *EpollEvent) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *EpollEvent) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyEpollEventSliceIn copies in a slice of EpollEvent objects from the task's memory.
func CopyEpollEventSliceIn(task marshal.Task, addr usermem.Addr, dst []EpollEvent) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := task.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyEpollEventSliceOut copies a slice of EpollEvent objects to the task's memory.
func CopyEpollEventSliceOut(task marshal.Task, addr usermem.Addr, src []EpollEvent) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := task.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeEpollEventSlice is like EpollEvent.MarshalUnsafe, but for a []EpollEvent.
func MarshalUnsafeEpollEventSlice(src []EpollEvent, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeEpollEventSlice is like EpollEvent.UnmarshalUnsafe, but for a []EpollEvent.
func UnmarshalUnsafeEpollEventSlice(dst []EpollEvent, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
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
//go:nosplit
func (s *Stat) Packed() bool {
    return s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Stat) MarshalUnsafe(dst []byte) {
    if s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type Stat doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Stat) UnmarshalUnsafe(src []byte) {
    if s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type Stat doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Stat) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *Stat) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return s.CopyOutN(task, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Stat) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (s *Stat) WriteTo(writer io.Writer) (int64, error) {
    if !s.ATime.Packed() && s.MTime.Packed() && s.CTime.Packed() {
        // Type Stat doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (p *PtraceRegs) SizeBytes() int {
    return 216
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *PtraceRegs) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R15))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R14))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R13))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R12))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rbp))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rbx))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R11))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R10))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R9))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.R8))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rax))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rcx))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rdx))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rsi))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rdi))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Orig_rax))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rip))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Cs))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Eflags))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Rsp))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Ss))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Fs_base))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Gs_base))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Ds))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Es))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Fs))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(p.Gs))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *PtraceRegs) UnmarshalBytes(src []byte) {
    p.R15 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R14 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R13 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R12 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rbp = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rbx = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R11 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R10 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R9 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R8 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rax = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rcx = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rdx = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rsi = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rdi = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Orig_rax = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rip = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Cs = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Eflags = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rsp = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Ss = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Fs_base = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Gs_base = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Ds = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Es = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Fs = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Gs = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PtraceRegs) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *PtraceRegs) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(p))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *PtraceRegs) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(p), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (p *PtraceRegs) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := task.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (p *PtraceRegs) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
    return p.CopyOutN(task, addr, p.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (p *PtraceRegs) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := task.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *PtraceRegs) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

