// Automatically generated marshal implementation. See tools/go_marshal.

package fuse

import (
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*fuseInitRes)(nil)

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *fuseInitRes) Packed() bool {
    // Type fuseInitRes is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *fuseInitRes) MarshalUnsafe(dst []byte) []byte {
    // Type fuseInitRes doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *fuseInitRes) UnmarshalUnsafe(src []byte) []byte {
    // Type fuseInitRes doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *fuseInitRes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type fuseInitRes doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *fuseInitRes) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *fuseInitRes) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    // Type fuseInitRes doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *fuseInitRes) WriteTo(writer io.Writer) (int64, error) {
    // Type fuseInitRes doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

