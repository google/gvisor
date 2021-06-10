// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build tag aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The build tags here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build tags, see 
// tools/defs.bzl:calculate_sets().

package arch

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
var _ marshal.Marshallable = (*SignalInfo)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SignalInfo) SizeBytes() int {
    return 16 +
        1*(128-16)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalInfo) MarshalBytes(dst []byte) {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
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
    s.Signo = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(hostarch.ByteOrder.Uint32(src[:4]))
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
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s),  uintptr(s.SizeBytes()))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalInfo) UnmarshalUnsafe(src []byte) {
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(s.SizeBytes()))
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SignalInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
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

