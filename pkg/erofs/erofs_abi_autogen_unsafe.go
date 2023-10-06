// Automatically generated marshal implementation. See tools/go_marshal.

package erofs

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
var _ marshal.Marshallable = (*Dirent)(nil)
var _ marshal.Marshallable = (*InodeCompact)(nil)
var _ marshal.Marshallable = (*InodeExtended)(nil)
var _ marshal.Marshallable = (*SuperBlock)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (d *Dirent) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (d *Dirent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(d.Nid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(d.NameOff))
    dst = dst[2:]
    dst[0] = byte(d.FileType)
    dst = dst[1:]
    dst[0] = byte(d.Reserved)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (d *Dirent) UnmarshalBytes(src []byte) []byte {
    d.Nid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    d.NameOff = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    d.FileType = uint8(src[0])
    src = src[1:]
    d.Reserved = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (d *Dirent) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (d *Dirent) MarshalUnsafe(dst []byte) []byte {
    // Type Dirent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return d.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (d *Dirent) UnmarshalUnsafe(src []byte) []byte {
    // Type Dirent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return d.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (d *Dirent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type Dirent doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(d.SizeBytes()) // escapes: okay.
    d.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (d *Dirent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return d.CopyOutN(cc, addr, d.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (d *Dirent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type Dirent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(d.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    d.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (d *Dirent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return d.CopyInN(cc, addr, d.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (d *Dirent) WriteTo(writer io.Writer) (int64, error) {
    // Type Dirent doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, d.SizeBytes())
    d.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *InodeCompact) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InodeCompact) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Format))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.XattrCount))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Mode))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Nlink))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Reserved))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RawBlockAddr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Ino))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.UID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.GID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Reserved2))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InodeCompact) UnmarshalBytes(src []byte) []byte {
    i.Format = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.XattrCount = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Nlink = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Reserved = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RawBlockAddr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Ino = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.GID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Reserved2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InodeCompact) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InodeCompact) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InodeCompact) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InodeCompact) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *InodeCompact) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InodeCompact) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *InodeCompact) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InodeCompact) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *InodeExtended) SizeBytes() int {
    return 48 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InodeExtended) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Format))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.XattrCount))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Mode))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Reserved))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RawBlockAddr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Ino))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Mtime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.MtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Nlink))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i.Reserved2[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InodeExtended) UnmarshalBytes(src []byte) []byte {
    i.Format = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.XattrCount = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Reserved = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.RawBlockAddr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Ino = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Mtime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.MtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Nlink = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        i.Reserved2[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InodeExtended) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InodeExtended) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InodeExtended) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InodeExtended) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *InodeExtended) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InodeExtended) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *InodeExtended) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InodeExtended) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (sb *SuperBlock) SizeBytes() int {
    return 58 +
        1*16 +
        1*16 +
        1*38
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (sb *SuperBlock) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.Magic))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.Checksum))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.FeatureCompat))
    dst = dst[4:]
    dst[0] = byte(sb.BlockSizeBits)
    dst = dst[1:]
    dst[0] = byte(sb.ExtSlots)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(sb.RootNid))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sb.Inodes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sb.BuildTime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.BuildTimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.Blocks))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.MetaBlockAddr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.XattrBlockAddr))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(sb.UUID[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(sb.VolumeName[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sb.FeatureIncompat))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(sb.Union1))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(sb.ExtraDevices))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(sb.DevTableSlotOff))
    dst = dst[2:]
    for idx := 0; idx < 38; idx++ {
        dst[0] = byte(sb.Reserved[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (sb *SuperBlock) UnmarshalBytes(src []byte) []byte {
    sb.Magic = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.Checksum = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.FeatureCompat = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.BlockSizeBits = uint8(src[0])
    src = src[1:]
    sb.ExtSlots = uint8(src[0])
    src = src[1:]
    sb.RootNid = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    sb.Inodes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    sb.BuildTime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    sb.BuildTimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.Blocks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.MetaBlockAddr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.XattrBlockAddr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        sb.UUID[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 16; idx++ {
        sb.VolumeName[idx] = uint8(src[0])
        src = src[1:]
    }
    sb.FeatureIncompat = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sb.Union1 = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    sb.ExtraDevices = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    sb.DevTableSlotOff = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 38; idx++ {
        sb.Reserved[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (sb *SuperBlock) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (sb *SuperBlock) MarshalUnsafe(dst []byte) []byte {
    size := sb.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(sb), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (sb *SuperBlock) UnmarshalUnsafe(src []byte) []byte {
    size := sb.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(sb), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (sb *SuperBlock) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sb)))
    hdr.Len = sb.SizeBytes()
    hdr.Cap = sb.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sb
    // must live until the use above.
    runtime.KeepAlive(sb) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (sb *SuperBlock) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sb.CopyOutN(cc, addr, sb.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (sb *SuperBlock) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sb)))
    hdr.Len = sb.SizeBytes()
    hdr.Cap = sb.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sb
    // must live until the use above.
    runtime.KeepAlive(sb) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (sb *SuperBlock) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sb.CopyInN(cc, addr, sb.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (sb *SuperBlock) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sb)))
    hdr.Len = sb.SizeBytes()
    hdr.Cap = sb.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that sb
    // must live until the use above.
    runtime.KeepAlive(sb) // escapes: replaced by intrinsic.
    return int64(length), err
}

