// Automatically generated marshal implementation. See tools/go_marshal.

// +build arm64
// +build arm64
// +build arm64

package arch

import (
    "gvisor.dev/gvisor/pkg/abi/linux"
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
var _ marshal.Marshallable = (*FpsimdContext)(nil)
var _ marshal.Marshallable = (*SignalContext64)(nil)
var _ marshal.Marshallable = (*SignalStack)(nil)
var _ marshal.Marshallable = (*UContext64)(nil)
var _ marshal.Marshallable = (*aarch64Ctx)(nil)
var _ marshal.Marshallable = (*linux.SignalSet)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UContext64) SizeBytes() int {
    return 16 +
        (*SignalStack)(nil).SizeBytes() +
        (*linux.SignalSet)(nil).SizeBytes() +
        1*120 +
        1*8 +
        (*SignalContext64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UContext64) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Flags))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Link))
    dst = dst[8:]
    u.Stack.MarshalBytes(dst[:u.Stack.SizeBytes()])
    dst = dst[u.Stack.SizeBytes():]
    u.Sigset.MarshalBytes(dst[:u.Sigset.SizeBytes()])
    dst = dst[u.Sigset.SizeBytes():]
    for idx := 0; idx < 120; idx++ {
        dst[0] = byte(u._pad[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(u._pad2[idx])
        dst = dst[1:]
    }
    u.MContext.MarshalBytes(dst[:u.MContext.SizeBytes()])
    dst = dst[u.MContext.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UContext64) UnmarshalBytes(src []byte) {
    u.Flags = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Link = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Stack.UnmarshalBytes(src[:u.Stack.SizeBytes()])
    src = src[u.Stack.SizeBytes():]
    u.Sigset.UnmarshalBytes(src[:u.Sigset.SizeBytes()])
    src = src[u.Sigset.SizeBytes():]
    for idx := 0; idx < 120; idx++ {
        u._pad[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 8; idx++ {
        u._pad2[idx] = src[0]
        src = src[1:]
    }
    u.MContext.UnmarshalBytes(src[:u.MContext.SizeBytes()])
    src = src[u.MContext.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UContext64) Packed() bool {
    return u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UContext64) MarshalUnsafe(dst []byte) {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(u))
    } else {
        // Type UContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        u.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UContext64) UnmarshalUnsafe(src []byte) {
    if u.MContext.Packed() && u.Sigset.Packed() && u.Stack.Packed() {
        safecopy.CopyOut(unsafe.Pointer(u), src)
    } else {
        // Type UContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        u.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *UContext64) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (u *UContext64) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *UContext64) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (s *SignalContext64) SizeBytes() int {
    return 32 +
        8*31 +
        1*8 +
        (*FpsimdContext)(nil).SizeBytes() +
        1*3568
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalContext64) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FaultAddr))
    dst = dst[8:]
    for idx := 0; idx < 31; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Regs[idx]))
        dst = dst[8:]
    }
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Sp))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Pc))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Pstate))
    dst = dst[8:]
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(s._pad[idx])
        dst = dst[1:]
    }
    s.Fpsimd64.MarshalBytes(dst[:s.Fpsimd64.SizeBytes()])
    dst = dst[s.Fpsimd64.SizeBytes():]
    for idx := 0; idx < 3568; idx++ {
        dst[0] = byte(s.Reserved[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalContext64) UnmarshalBytes(src []byte) {
    s.FaultAddr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 31; idx++ {
        s.Regs[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    s.Sp = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pc = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pstate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 8; idx++ {
        s._pad[idx] = src[0]
        src = src[1:]
    }
    s.Fpsimd64.UnmarshalBytes(src[:s.Fpsimd64.SizeBytes()])
    src = src[s.Fpsimd64.SizeBytes():]
    for idx := 0; idx < 3568; idx++ {
        s.Reserved[idx] = uint8(src[0])
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalContext64) Packed() bool {
    return s.Fpsimd64.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalContext64) MarshalUnsafe(dst []byte) {
    if s.Fpsimd64.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type SignalContext64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalContext64) UnmarshalUnsafe(src []byte) {
    if s.Fpsimd64.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type SignalContext64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalContext64) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (s *SignalContext64) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalContext64) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (a *aarch64Ctx) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *aarch64Ctx) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(a.Magic))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(a.Size))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (a *aarch64Ctx) UnmarshalBytes(src []byte) {
    a.Magic = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *aarch64Ctx) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (a *aarch64Ctx) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(a))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (a *aarch64Ctx) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(a), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (a *aarch64Ctx) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (a *aarch64Ctx) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (a *aarch64Ctx) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FpsimdContext) SizeBytes() int {
    return 8 +
        (*aarch64Ctx)(nil).SizeBytes() +
        8*64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FpsimdContext) MarshalBytes(dst []byte) {
    f.Head.MarshalBytes(dst[:f.Head.SizeBytes()])
    dst = dst[f.Head.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Fpsr))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Fpcr))
    dst = dst[4:]
    for idx := 0; idx < 64; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Vregs[idx]))
        dst = dst[8:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FpsimdContext) UnmarshalBytes(src []byte) {
    f.Head.UnmarshalBytes(src[:f.Head.SizeBytes()])
    src = src[f.Head.SizeBytes():]
    f.Fpsr = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Fpcr = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 64; idx++ {
        f.Vregs[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FpsimdContext) Packed() bool {
    return f.Head.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FpsimdContext) MarshalUnsafe(dst []byte) {
    if f.Head.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FpsimdContext doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FpsimdContext) UnmarshalUnsafe(src []byte) {
    if f.Head.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FpsimdContext doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FpsimdContext) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (f *FpsimdContext) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FpsimdContext) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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

