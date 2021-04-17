// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build tag aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The build tags here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build tags, see 
// tools/defs.bzl:calculate_sets().

package vfs2

import (
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*MessageHeader64)(nil)
var _ marshal.Marshallable = (*multipleMessageHeader64)(nil)
var _ marshal.Marshallable = (*sigSetWithSize)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *sigSetWithSize) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *sigSetWithSize) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.sigsetAddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.sizeofSigset))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *sigSetWithSize) UnmarshalBytes(src []byte) {
    s.sigsetAddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.sizeofSigset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *sigSetWithSize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *sigSetWithSize) MarshalUnsafe(dst []byte) {
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s),  uintptr(s.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *sigSetWithSize) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(s.SizeBytes()))
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *sigSetWithSize) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *sigSetWithSize) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *sigSetWithSize) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MessageHeader64) SizeBytes() int {
    return 56
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MessageHeader64) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.Name))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.NameLen))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.Iov))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.IovLen))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.Control))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.ControlLen))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MessageHeader64) UnmarshalBytes(src []byte) {
    m.Name = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.NameLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    m.Iov = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.IovLen = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.Control = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.ControlLen = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.Flags = int32(hostarch.ByteOrder.Uint32(src[:4]))
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
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m),  uintptr(m.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MessageHeader64) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(m.SizeBytes()))
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *MessageHeader64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (m *MessageHeader64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *MessageHeader64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *multipleMessageHeader64) SizeBytes() int {
    return 8 +
        (*MessageHeader64)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *multipleMessageHeader64) MarshalBytes(dst []byte) {
    m.msgHdr.MarshalBytes(dst[:m.msgHdr.SizeBytes()])
    dst = dst[m.msgHdr.SizeBytes():]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.msgLen))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *multipleMessageHeader64) UnmarshalBytes(src []byte) {
    m.msgHdr.UnmarshalBytes(src[:m.msgHdr.SizeBytes()])
    src = src[m.msgHdr.SizeBytes():]
    m.msgLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
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
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m),  uintptr(m.SizeBytes()))
    } else {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fallback to MarshalBytes.
        m.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *multipleMessageHeader64) UnmarshalUnsafe(src []byte) {
    if m.msgHdr.Packed() {
        gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(m.SizeBytes()))
    } else {
        // Type multipleMessageHeader64 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        m.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (m *multipleMessageHeader64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (m *multipleMessageHeader64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (m *multipleMessageHeader64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
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

