// Automatically generated marshal implementation. See tools/go_marshal.

// +build 386 amd64 arm64

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
var _ marshal.Marshallable = (*SignalAct)(nil)
var _ marshal.Marshallable = (*SignalInfo)(nil)
var _ marshal.Marshallable = (*SignalStack)(nil)
var _ marshal.Marshallable = (*linux.SignalSet)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SignalAct) SizeBytes() int {
    return 24 +
        (*linux.SignalSet)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalAct) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Handler))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Restorer))
    dst = dst[8:]
    s.Mask.MarshalBytes(dst[:s.Mask.SizeBytes()])
    dst = dst[s.Mask.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalAct) UnmarshalBytes(src []byte) {
    s.Handler = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Restorer = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Mask.UnmarshalBytes(src[:s.Mask.SizeBytes()])
    src = src[s.Mask.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalAct) Packed() bool {
    return s.Mask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalAct) MarshalUnsafe(dst []byte) {
    if s.Mask.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type SignalAct doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalAct) UnmarshalUnsafe(src []byte) {
    if s.Mask.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type SignalAct doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalAct) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !s.Mask.Packed() {
        // Type SignalAct doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SignalAct) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalAct) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !s.Mask.Packed() {
        // Type SignalAct doesn't have a packed layout in memory, fall back to UnmarshalBytes.
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
func (s *SignalAct) WriteTo(writer io.Writer) (int64, error) {
    if !s.Mask.Packed() {
        // Type SignalAct doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SignalInfo) SizeBytes() int {
    return 16 +
        1*(128-16)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalInfo) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    for idx := 0; idx < (128-16); idx++ {
        dst[0] = byte(s.Fields[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalInfo) UnmarshalBytes(src []byte) {
    s.Signo = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    for idx := 0; idx < (128-16); idx++ {
        s.Fields[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalInfo) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalInfo) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalInfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (s *SignalInfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalInfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (s *SignalInfo) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SignalStack) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalStack) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalStack) UnmarshalBytes(src []byte) {
    s.Addr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    s.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalStack) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalStack) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalStack) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalStack) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
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
func (s *SignalStack) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalStack) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
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
func (s *SignalStack) WriteTo(writer io.Writer) (int64, error) {
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

