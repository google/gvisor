// Automatically generated marshal implementation. See tools/go_marshal.

package tmpfs

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
var _ marshal.Marshallable = (*fsckptRegularFileSegment)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *fsckptRegularFileSegment) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *fsckptRegularFileSegment) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.End))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Value))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *fsckptRegularFileSegment) UnmarshalBytes(src []byte) []byte {
    f.Start = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.End = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Value = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *fsckptRegularFileSegment) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *fsckptRegularFileSegment) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *fsckptRegularFileSegment) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *fsckptRegularFileSegment) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *fsckptRegularFileSegment) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *fsckptRegularFileSegment) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *fsckptRegularFileSegment) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *fsckptRegularFileSegment) WriteTo(writer io.Writer) (int64, error) {
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

// CopyCheckpointRegularFileSegmentSliceIn copies in a slice of fsckptRegularFileSegment objects from the task's memory.
func CopyCheckpointRegularFileSegmentSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []fsckptRegularFileSegment) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*fsckptRegularFileSegment)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyCheckpointRegularFileSegmentSliceOut copies a slice of fsckptRegularFileSegment objects to the task's memory.
func CopyCheckpointRegularFileSegmentSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []fsckptRegularFileSegment) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*fsckptRegularFileSegment)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeCheckpointRegularFileSegmentSlice is like fsckptRegularFileSegment.MarshalUnsafe, but for a []fsckptRegularFileSegment.
func MarshalUnsafeCheckpointRegularFileSegmentSlice(src []fsckptRegularFileSegment, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*fsckptRegularFileSegment)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeCheckpointRegularFileSegmentSlice is like fsckptRegularFileSegment.UnmarshalUnsafe, but for a []fsckptRegularFileSegment.
func UnmarshalUnsafeCheckpointRegularFileSegmentSlice(dst []fsckptRegularFileSegment, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*fsckptRegularFileSegment)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// ReadCheckpointRegularFileSegmentSlice reads a []fsckptRegularFileSegment. It returns the number of bytes read
func ReadCheckpointRegularFileSegmentSlice(src io.Reader, dst []fsckptRegularFileSegment) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*fsckptRegularFileSegment)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// WriteCheckpointRegularFileSegmentSlice is like fsckptRegularFileSegment.WriteTo, but for a []fsckptRegularFileSegment.
func WriteCheckpointRegularFileSegmentSlice(dst io.Writer, src []fsckptRegularFileSegment) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*fsckptRegularFileSegment)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

