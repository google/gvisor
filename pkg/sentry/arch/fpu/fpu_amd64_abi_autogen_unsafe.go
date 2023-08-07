// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build constraint aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The constraints here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build constraints,
// see tools/defs.bzl:calculate_sets().

//go:build amd64 || i386
// +build amd64 i386

package fpu

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
var _ marshal.Marshallable = (*FPSoftwareFrame)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FPSoftwareFrame) SizeBytes() int {
    return 20 +
        4*7
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FPSoftwareFrame) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Magic1))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.ExtendedSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Xfeatures))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.XstateSize))
    dst = dst[4:]
    for idx := 0; idx < 7; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Padding[idx]))
        dst = dst[4:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FPSoftwareFrame) UnmarshalBytes(src []byte) []byte {
    f.Magic1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ExtendedSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Xfeatures = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.XstateSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 7; idx++ {
        f.Padding[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FPSoftwareFrame) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FPSoftwareFrame) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FPSoftwareFrame) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FPSoftwareFrame) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FPSoftwareFrame) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FPSoftwareFrame) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FPSoftwareFrame) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FPSoftwareFrame) WriteTo(writer io.Writer) (int64, error) {
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

