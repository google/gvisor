// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build constraint aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The constraints here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build constraints,
// see tools/defs.bzl:calculate_sets().

//go:build arm64 && arm64 && arm64
// +build arm64,arm64,arm64

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
var _ marshal.Marshallable = (*FpsimdContext)(nil)
var _ marshal.Marshallable = (*SignalContext64)(nil)
var _ marshal.Marshallable = (*UContext64)(nil)
var _ marshal.Marshallable = (*aarch64Ctx)(nil)
var _ marshal.Marshallable = (*linux.SignalSet)(nil)
var _ marshal.Marshallable = (*linux.SignalStack)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FpsimdContext) SizeBytes() int {
    return 8 +
        (*aarch64Ctx)(nil).SizeBytes() +
        8*64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FpsimdContext) MarshalBytes(dst []byte) []byte {
    dst = f.Head.MarshalBytes(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Fpsr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Fpcr))
    dst = dst[4:]
    for idx := 0; idx < 64; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Vregs[idx]))
        dst = dst[8:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FpsimdContext) UnmarshalBytes(src []byte) []byte {
    src = f.Head.UnmarshalBytes(src)
    f.Fpsr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Fpcr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 64; idx++ {
        f.Vregs[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FpsimdContext) Packed() bool {
    return f.Head.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FpsimdContext) MarshalUnsafe(dst []byte) []byte {
    if f.Head.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FpsimdContext doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FpsimdContext) UnmarshalUnsafe(src []byte) []byte {
    if f.Head.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FpsimdContext doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FpsimdContext) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Head.Packed() {
        // Type FpsimdContext doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FpsimdContext) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FpsimdContext) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !f.Head.Packed() {
        // Type FpsimdContext doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FpsimdContext) WriteTo(writer io.Writer) (int64, error) {
    if !f.Head.Packed() {
        // Type FpsimdContext doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SignalContext64) SizeBytes() int {
    return 32 +
        8*31 +
        1*8 +
        (*FpsimdContext)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalContext64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FaultAddr))
    dst = dst[8:]
    for idx := 0; idx < 31; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Regs[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Sp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Pc))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Pstate))
    dst = dst[8:]
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(s._pad[idx])
        dst = dst[1:]
    }
    dst = s.Fpsimd64.MarshalBytes(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalContext64) UnmarshalBytes(src []byte) []byte {
    s.FaultAddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 31; idx++ {
        s.Regs[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    s.Sp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pc = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pstate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 8; idx++ {
        s._pad[idx] = src[0]
        src = src[1:]
    }
    src = s.Fpsimd64.UnmarshalBytes(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalContext64) Packed() bool {
    return s.Fpsimd64.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalContext64) MarshalUnsafe(dst []byte) []byte {
    if s.Fpsimd64.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SignalContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalContext64) UnmarshalUnsafe(src []byte) []byte {
    if s.Fpsimd64.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SignalContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalContext64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Fpsimd64.Packed() {
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
    if !s.Fpsimd64.Packed() {
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
    if !s.Fpsimd64.Packed() {
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
        (*linux.SignalStack)(nil).SizeBytes() +
        (*linux.SignalSet)(nil).SizeBytes() +
        1*120 +
        1*8 +
        (*SignalContext64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UContext64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Link))
    dst = dst[8:]
    dst = u.Stack.MarshalBytes(dst)
    dst = u.Sigset.MarshalBytes(dst)
    for idx := 0; idx < 120; idx++ {
        dst[0] = byte(u._pad[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(u._pad2[idx])
        dst = dst[1:]
    }
    dst = u.MContext.MarshalBytes(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UContext64) UnmarshalBytes(src []byte) []byte {
    u.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Link = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = u.Stack.UnmarshalBytes(src)
    src = u.Sigset.UnmarshalBytes(src)
    for idx := 0; idx < 120; idx++ {
        u._pad[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 8; idx++ {
        u._pad2[idx] = src[0]
        src = src[1:]
    }
    src = u.MContext.UnmarshalBytes(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UContext64) Packed() bool {
    return u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UContext64) MarshalUnsafe(dst []byte) []byte {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
        return dst[size:]
    }
    // Type UContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return u.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UContext64) UnmarshalUnsafe(src []byte) []byte {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type UContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return u.UnmarshalBytes(src)
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (a *aarch64Ctx) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *aarch64Ctx) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Magic))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Size))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (a *aarch64Ctx) UnmarshalBytes(src []byte) []byte {
    a.Magic = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *aarch64Ctx) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (a *aarch64Ctx) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (a *aarch64Ctx) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (a *aarch64Ctx) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that a
    // must live until the use above.
    runtime.KeepAlive(a) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (a *aarch64Ctx) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (a *aarch64Ctx) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that a
    // must live until the use above.
    runtime.KeepAlive(a) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (a *aarch64Ctx) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that a
    // must live until the use above.
    runtime.KeepAlive(a) // escapes: replaced by intrinsic.
    return int64(length), err
}

