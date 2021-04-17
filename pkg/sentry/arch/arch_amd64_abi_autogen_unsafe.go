// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build tag aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The build tags here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build tags, see 
// tools/defs.bzl:calculate_sets().

// +build amd64
// +build amd64
// +build amd64

package arch

import (
    "gvisor.dev/gvisor/pkg/abi/linux"
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*SignalContext64)(nil)
var _ marshal.Marshallable = (*SignalStack)(nil)
var _ marshal.Marshallable = (*UContext64)(nil)
var _ marshal.Marshallable = (*linux.SignalSet)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SignalContext64) SizeBytes() int {
    return 184 +
        (*linux.SignalSet)(nil).SizeBytes() +
        8*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalContext64) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R8))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R9))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R10))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R11))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R12))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R13))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R14))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.R15))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rdi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rsi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rbp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rbx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rdx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rax))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rcx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rsp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rip))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Eflags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Cs))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Gs))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Fs))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Ss))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Err))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Trapno))
    dst = dst[8:]
    s.Oldmask.MarshalBytes(dst[:s.Oldmask.SizeBytes()])
    dst = dst[s.Oldmask.SizeBytes():]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Cr2))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Fpstate))
    dst = dst[8:]
    for idx := 0; idx < 8; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Reserved[idx]))
        dst = dst[8:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalContext64) UnmarshalBytes(src []byte) {
    s.R8 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R9 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R10 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R11 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R12 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R13 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R14 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.R15 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rdi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rsi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rbp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rbx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rdx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rax = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rcx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rsp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Rip = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Eflags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Cs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Gs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Fs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Ss = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Err = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Trapno = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Oldmask.UnmarshalBytes(src[:s.Oldmask.SizeBytes()])
    src = src[s.Oldmask.SizeBytes():]
    s.Cr2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Fpstate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 8; idx++ {
        s.Reserved[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalContext64) Packed() bool {
    return s.Oldmask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalContext64) MarshalUnsafe(dst []byte) {
    if s.Oldmask.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s),  uintptr(s.SizeBytes()))
    } else {
        // Type SignalContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalContext64) UnmarshalUnsafe(src []byte) {
    if s.Oldmask.Packed() {
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(s.SizeBytes()))
    } else {
        // Type SignalContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalContext64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Oldmask.Packed() {
        // Type SignalContext64 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SignalContext64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalContext64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !s.Oldmask.Packed() {
        // Type SignalContext64 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalContext64) WriteTo(writer io.Writer) (int64, error) {
    if !s.Oldmask.Packed() {
        // Type SignalContext64 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (u *UContext64) SizeBytes() int {
    return 16 +
        (*SignalStack)(nil).SizeBytes() +
        (*SignalContext64)(nil).SizeBytes() +
        (*linux.SignalSet)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UContext64) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Link))
    dst = dst[8:]
    u.Stack.MarshalBytes(dst[:u.Stack.SizeBytes()])
    dst = dst[u.Stack.SizeBytes():]
    u.MContext.MarshalBytes(dst[:u.MContext.SizeBytes()])
    dst = dst[u.MContext.SizeBytes():]
    u.Sigset.MarshalBytes(dst[:u.Sigset.SizeBytes()])
    dst = dst[u.Sigset.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UContext64) UnmarshalBytes(src []byte) {
    u.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Link = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Stack.UnmarshalBytes(src[:u.Stack.SizeBytes()])
    src = src[u.Stack.SizeBytes():]
    u.MContext.UnmarshalBytes(src[:u.MContext.SizeBytes()])
    src = src[u.MContext.SizeBytes():]
    u.Sigset.UnmarshalBytes(src[:u.Sigset.SizeBytes()])
    src = src[u.Sigset.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UContext64) Packed() bool {
    return u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UContext64) MarshalUnsafe(dst []byte) {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u),  uintptr(u.SizeBytes()))
    } else {
        // Type UContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        u.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UContext64) UnmarshalUnsafe(src []byte) {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(u.SizeBytes()))
    } else {
        // Type UContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        u.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *UContext64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        // Type UContext64 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(u.SizeBytes()) // escapes: okay.
        u.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (u *UContext64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *UContext64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        // Type UContext64 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(u.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        u.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (u *UContext64) WriteTo(writer io.Writer) (int64, error) {
    if !u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        // Type UContext64 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, u.SizeBytes())
        u.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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

