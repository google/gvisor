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
var _ marshal.Marshallable = (*MessageHeader64)(nil)
var _ marshal.Marshallable = (*SchedParam)(nil)
var _ marshal.Marshallable = (*direntHdr)(nil)
var _ marshal.Marshallable = (*multipleMessageHeader64)(nil)
var _ marshal.Marshallable = (*oldDirentHdr)(nil)
var _ marshal.Marshallable = (*rlimit64)(nil)
var _ marshal.Marshallable = (*userSockFprog)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *oldDirentHdr) SizeBytes() int {
    return 18
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *oldDirentHdr) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(o.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(o.Off))
    dst = dst[8:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(o.Reclen))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (o *oldDirentHdr) UnmarshalBytes(src []byte) {
    o.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    o.Off = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    o.Reclen = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (o *oldDirentHdr) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (o *oldDirentHdr) MarshalUnsafe(dst []byte) {
    // Type oldDirentHdr doesn't have a packed layout in memory, fallback to MarshalBytes.
    o.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (o *oldDirentHdr) UnmarshalUnsafe(src []byte) {
    // Type oldDirentHdr doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    o.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (o *oldDirentHdr) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Type oldDirentHdr doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
    o.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (o *oldDirentHdr) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return o.CopyOutN(cc, addr, o.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (o *oldDirentHdr) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Type oldDirentHdr doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(o.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    o.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (o *oldDirentHdr) WriteTo(writer io.Writer) (int64, error) {
    // Type oldDirentHdr doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, o.SizeBytes())
    o.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (d *direntHdr) SizeBytes() int {
    return 1 +
        (*oldDirentHdr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (d *direntHdr) MarshalBytes(dst []byte) {
    d.OldHdr.MarshalBytes(dst[:d.OldHdr.SizeBytes()])
    dst = dst[d.OldHdr.SizeBytes():]
    dst[0] = byte(d.Typ)
    dst = dst[1:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (d *direntHdr) UnmarshalBytes(src []byte) {
    d.OldHdr.UnmarshalBytes(src[:d.OldHdr.SizeBytes()])
    src = src[d.OldHdr.SizeBytes():]
    d.Typ = uint8(src[0])
    src = src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (d *direntHdr) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (d *direntHdr) MarshalUnsafe(dst []byte) {
    // Type direntHdr doesn't have a packed layout in memory, fallback to MarshalBytes.
    d.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (d *direntHdr) UnmarshalUnsafe(src []byte) {
    // Type direntHdr doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    d.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (d *direntHdr) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Type direntHdr doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(d.SizeBytes()) // escapes: okay.
    d.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (d *direntHdr) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return d.CopyOutN(cc, addr, d.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (d *direntHdr) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Type direntHdr doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(d.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    d.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (d *direntHdr) WriteTo(writer io.Writer) (int64, error) {
    // Type direntHdr doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, d.SizeBytes())
    d.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *rlimit64) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *rlimit64) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Cur))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Max))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *rlimit64) UnmarshalBytes(src []byte) {
    r.Cur = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.Max = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *rlimit64) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *rlimit64) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(r))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *rlimit64) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(r), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *rlimit64) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *rlimit64) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *rlimit64) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *rlimit64) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SchedParam) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SchedParam) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.schedPriority))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SchedParam) UnmarshalBytes(src []byte) {
    s.schedPriority = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SchedParam) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SchedParam) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SchedParam) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SchedParam) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (s *SchedParam) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SchedParam) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (s *SchedParam) WriteTo(writer io.Writer) (int64, error) {
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
func (u *userSockFprog) SizeBytes() int {
    return 10 +
        1*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *userSockFprog) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(u.Len))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*6] ~= [6]byte{0}
    dst = dst[1*(6):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Filter))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *userSockFprog) UnmarshalBytes(src []byte) {
    u.Len = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([6]byte(u._), src[:sizeof(byte)*6])
    src = src[1*(6):]
    u.Filter = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *userSockFprog) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *userSockFprog) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(u))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *userSockFprog) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(u), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *userSockFprog) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (u *userSockFprog) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *userSockFprog) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (u *userSockFprog) WriteTo(writer io.Writer) (int64, error) {
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
func (m *multipleMessageHeader64) SizeBytes() int {
    return 8 +
        (*MessageHeader64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *multipleMessageHeader64) MarshalBytes(dst []byte) {
    m.msgHdr.MarshalBytes(dst[:m.msgHdr.SizeBytes()])
    dst = dst[m.msgHdr.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(m.msgLen))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *multipleMessageHeader64) UnmarshalBytes(src []byte) {
    m.msgHdr.UnmarshalBytes(src[:m.msgHdr.SizeBytes()])
    src = src[m.msgHdr.SizeBytes():]
    m.msgLen = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *multipleMessageHeader64) Packed() bool {
    return m.msgHdr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *multipleMessageHeader64) MarshalUnsafe(dst []byte) {
    if m.msgHdr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(m))
    } else {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        m.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *multipleMessageHeader64) UnmarshalUnsafe(src []byte) {
    if m.msgHdr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(m), src)
    } else {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        m.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *multipleMessageHeader64) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !m.msgHdr.Packed() {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        m.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *multipleMessageHeader64) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *multipleMessageHeader64) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !m.msgHdr.Packed() {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        m.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *multipleMessageHeader64) WriteTo(writer io.Writer) (int64, error) {
    if !m.msgHdr.Packed() {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, m.SizeBytes())
        m.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MessageHeader64) SizeBytes() int {
    return 56
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MessageHeader64) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(m.Name))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(m.NameLen))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(m.Iov))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(m.IovLen))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(m.Control))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(m.ControlLen))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(m.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MessageHeader64) UnmarshalBytes(src []byte) {
    m.Name = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.NameLen = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    m.Iov = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.IovLen = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.Control = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.ControlLen = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.Flags = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MessageHeader64) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MessageHeader64) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(m))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MessageHeader64) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(m), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MessageHeader64) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (m *MessageHeader64) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MessageHeader64) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MessageHeader64) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return int64(length), err
}

