// Automatically generated marshal implementation. See tools/go_marshal.

package linux

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
var _ marshal.Marshallable = (*BPFInstruction)(nil)
var _ marshal.Marshallable = (*CString)(nil)
var _ marshal.Marshallable = (*CapUserData)(nil)
var _ marshal.Marshallable = (*CapUserHeader)(nil)
var _ marshal.Marshallable = (*ClockT)(nil)
var _ marshal.Marshallable = (*CloneArgs)(nil)
var _ marshal.Marshallable = (*ControlMessageCredentials)(nil)
var _ marshal.Marshallable = (*ControlMessageHeader)(nil)
var _ marshal.Marshallable = (*ControlMessageIPPacketInfo)(nil)
var _ marshal.Marshallable = (*ControlMessageIPv6PacketInfo)(nil)
var _ marshal.Marshallable = (*ElfHeader64)(nil)
var _ marshal.Marshallable = (*ElfProg64)(nil)
var _ marshal.Marshallable = (*ElfSection64)(nil)
var _ marshal.Marshallable = (*ErrorName)(nil)
var _ marshal.Marshallable = (*EthtoolCmd)(nil)
var _ marshal.Marshallable = (*EthtoolGFeatures)(nil)
var _ marshal.Marshallable = (*EthtoolGetFeaturesBlock)(nil)
var _ marshal.Marshallable = (*ExtensionName)(nil)
var _ marshal.Marshallable = (*FOwnerEx)(nil)
var _ marshal.Marshallable = (*FUSEAccessIn)(nil)
var _ marshal.Marshallable = (*FUSEAttr)(nil)
var _ marshal.Marshallable = (*FUSEAttrOut)(nil)
var _ marshal.Marshallable = (*FUSECreateIn)(nil)
var _ marshal.Marshallable = (*FUSECreateMeta)(nil)
var _ marshal.Marshallable = (*FUSECreateOut)(nil)
var _ marshal.Marshallable = (*FUSEDirent)(nil)
var _ marshal.Marshallable = (*FUSEDirentMeta)(nil)
var _ marshal.Marshallable = (*FUSEDirents)(nil)
var _ marshal.Marshallable = (*FUSEEmptyIn)(nil)
var _ marshal.Marshallable = (*FUSEEntryOut)(nil)
var _ marshal.Marshallable = (*FUSEFallocateIn)(nil)
var _ marshal.Marshallable = (*FUSEFlushIn)(nil)
var _ marshal.Marshallable = (*FUSEFsyncIn)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEHeaderIn)(nil)
var _ marshal.Marshallable = (*FUSEHeaderOut)(nil)
var _ marshal.Marshallable = (*FUSEInitIn)(nil)
var _ marshal.Marshallable = (*FUSEInitOut)(nil)
var _ marshal.Marshallable = (*FUSELinkIn)(nil)
var _ marshal.Marshallable = (*FUSELookupIn)(nil)
var _ marshal.Marshallable = (*FUSEMkdirIn)(nil)
var _ marshal.Marshallable = (*FUSEMkdirMeta)(nil)
var _ marshal.Marshallable = (*FUSEMknodIn)(nil)
var _ marshal.Marshallable = (*FUSEMknodMeta)(nil)
var _ marshal.Marshallable = (*FUSEOpID)(nil)
var _ marshal.Marshallable = (*FUSEOpcode)(nil)
var _ marshal.Marshallable = (*FUSEOpenIn)(nil)
var _ marshal.Marshallable = (*FUSEOpenOut)(nil)
var _ marshal.Marshallable = (*FUSEReadIn)(nil)
var _ marshal.Marshallable = (*FUSEReleaseIn)(nil)
var _ marshal.Marshallable = (*FUSERenameIn)(nil)
var _ marshal.Marshallable = (*FUSERmDirIn)(nil)
var _ marshal.Marshallable = (*FUSESetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEStatfsOut)(nil)
var _ marshal.Marshallable = (*FUSESymlinkIn)(nil)
var _ marshal.Marshallable = (*FUSEUnlinkIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteOut)(nil)
var _ marshal.Marshallable = (*FUSEWritePayloadIn)(nil)
var _ marshal.Marshallable = (*FileMode)(nil)
var _ marshal.Marshallable = (*Flock)(nil)
var _ marshal.Marshallable = (*ICMP6Filter)(nil)
var _ marshal.Marshallable = (*IFConf)(nil)
var _ marshal.Marshallable = (*IFReq)(nil)
var _ marshal.Marshallable = (*IOCallback)(nil)
var _ marshal.Marshallable = (*IOCqRingOffsets)(nil)
var _ marshal.Marshallable = (*IOEvent)(nil)
var _ marshal.Marshallable = (*IORingIndex)(nil)
var _ marshal.Marshallable = (*IORings)(nil)
var _ marshal.Marshallable = (*IOSqRingOffsets)(nil)
var _ marshal.Marshallable = (*IOUring)(nil)
var _ marshal.Marshallable = (*IOUringCqe)(nil)
var _ marshal.Marshallable = (*IOUringParams)(nil)
var _ marshal.Marshallable = (*IOUringSqe)(nil)
var _ marshal.Marshallable = (*IP6TEntry)(nil)
var _ marshal.Marshallable = (*IP6TIP)(nil)
var _ marshal.Marshallable = (*IP6TReplace)(nil)
var _ marshal.Marshallable = (*IPCPerm)(nil)
var _ marshal.Marshallable = (*IPTEntry)(nil)
var _ marshal.Marshallable = (*IPTGetEntries)(nil)
var _ marshal.Marshallable = (*IPTGetinfo)(nil)
var _ marshal.Marshallable = (*IPTIP)(nil)
var _ marshal.Marshallable = (*IPTOwnerInfo)(nil)
var _ marshal.Marshallable = (*IPTReplace)(nil)
var _ marshal.Marshallable = (*Inet6Addr)(nil)
var _ marshal.Marshallable = (*Inet6MulticastRequest)(nil)
var _ marshal.Marshallable = (*InetAddr)(nil)
var _ marshal.Marshallable = (*InetMulticastRequest)(nil)
var _ marshal.Marshallable = (*InetMulticastRequestWithNIC)(nil)
var _ marshal.Marshallable = (*InterfaceAddrMessage)(nil)
var _ marshal.Marshallable = (*InterfaceInfoMessage)(nil)
var _ marshal.Marshallable = (*ItimerVal)(nil)
var _ marshal.Marshallable = (*Itimerspec)(nil)
var _ marshal.Marshallable = (*KernelIP6TEntry)(nil)
var _ marshal.Marshallable = (*KernelIP6TGetEntries)(nil)
var _ marshal.Marshallable = (*KernelIPTEntry)(nil)
var _ marshal.Marshallable = (*KernelIPTGetEntries)(nil)
var _ marshal.Marshallable = (*Linger)(nil)
var _ marshal.Marshallable = (*MqAttr)(nil)
var _ marshal.Marshallable = (*MsgBuf)(nil)
var _ marshal.Marshallable = (*MsgInfo)(nil)
var _ marshal.Marshallable = (*MsqidDS)(nil)
var _ marshal.Marshallable = (*NFNATRange)(nil)
var _ marshal.Marshallable = (*NFNATRange2)(nil)
var _ marshal.Marshallable = (*NetlinkAttrHeader)(nil)
var _ marshal.Marshallable = (*NetlinkErrorMessage)(nil)
var _ marshal.Marshallable = (*NetlinkMessageHeader)(nil)
var _ marshal.Marshallable = (*NfNATIPV4MultiRangeCompat)(nil)
var _ marshal.Marshallable = (*NfNATIPV4Range)(nil)
var _ marshal.Marshallable = (*NumaPolicy)(nil)
var _ marshal.Marshallable = (*PollFD)(nil)
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*RobustListHead)(nil)
var _ marshal.Marshallable = (*RouteMessage)(nil)
var _ marshal.Marshallable = (*RtAttr)(nil)
var _ marshal.Marshallable = (*Rusage)(nil)
var _ marshal.Marshallable = (*SeccompData)(nil)
var _ marshal.Marshallable = (*SeccompNotif)(nil)
var _ marshal.Marshallable = (*SeccompNotifResp)(nil)
var _ marshal.Marshallable = (*SeccompNotifSizes)(nil)
var _ marshal.Marshallable = (*SemInfo)(nil)
var _ marshal.Marshallable = (*Sembuf)(nil)
var _ marshal.Marshallable = (*ShmInfo)(nil)
var _ marshal.Marshallable = (*ShmParams)(nil)
var _ marshal.Marshallable = (*ShmidDS)(nil)
var _ marshal.Marshallable = (*SigAction)(nil)
var _ marshal.Marshallable = (*Sigevent)(nil)
var _ marshal.Marshallable = (*SignalInfo)(nil)
var _ marshal.Marshallable = (*SignalSet)(nil)
var _ marshal.Marshallable = (*SignalStack)(nil)
var _ marshal.Marshallable = (*SignalfdSiginfo)(nil)
var _ marshal.Marshallable = (*SockAddrInet)(nil)
var _ marshal.Marshallable = (*SockAddrInet6)(nil)
var _ marshal.Marshallable = (*SockAddrLink)(nil)
var _ marshal.Marshallable = (*SockAddrNetlink)(nil)
var _ marshal.Marshallable = (*SockAddrUnix)(nil)
var _ marshal.Marshallable = (*SockErrCMsgIPv4)(nil)
var _ marshal.Marshallable = (*SockErrCMsgIPv6)(nil)
var _ marshal.Marshallable = (*SockExtendedErr)(nil)
var _ marshal.Marshallable = (*Statfs)(nil)
var _ marshal.Marshallable = (*Statx)(nil)
var _ marshal.Marshallable = (*StatxTimestamp)(nil)
var _ marshal.Marshallable = (*Sysinfo)(nil)
var _ marshal.Marshallable = (*TCPInfo)(nil)
var _ marshal.Marshallable = (*TableName)(nil)
var _ marshal.Marshallable = (*Termios)(nil)
var _ marshal.Marshallable = (*TimeT)(nil)
var _ marshal.Marshallable = (*TimerID)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)
var _ marshal.Marshallable = (*Timeval)(nil)
var _ marshal.Marshallable = (*Tms)(nil)
var _ marshal.Marshallable = (*Utime)(nil)
var _ marshal.Marshallable = (*UtsName)(nil)
var _ marshal.Marshallable = (*VFIODeviceInfo)(nil)
var _ marshal.Marshallable = (*VFIOIommuType1DmaMap)(nil)
var _ marshal.Marshallable = (*VFIOIommuType1DmaUnmap)(nil)
var _ marshal.Marshallable = (*VFIOIrqInfo)(nil)
var _ marshal.Marshallable = (*VFIOIrqSet)(nil)
var _ marshal.Marshallable = (*VFIORegionInfo)(nil)
var _ marshal.Marshallable = (*WindowSize)(nil)
var _ marshal.Marshallable = (*Winsize)(nil)
var _ marshal.Marshallable = (*XTCounters)(nil)
var _ marshal.Marshallable = (*XTEntryMatch)(nil)
var _ marshal.Marshallable = (*XTEntryTarget)(nil)
var _ marshal.Marshallable = (*XTErrorTarget)(nil)
var _ marshal.Marshallable = (*XTGetRevision)(nil)
var _ marshal.Marshallable = (*XTNATTargetV0)(nil)
var _ marshal.Marshallable = (*XTNATTargetV1)(nil)
var _ marshal.Marshallable = (*XTNATTargetV2)(nil)
var _ marshal.Marshallable = (*XTOwnerMatchInfo)(nil)
var _ marshal.Marshallable = (*XTRedirectTarget)(nil)
var _ marshal.Marshallable = (*XTStandardTarget)(nil)
var _ marshal.Marshallable = (*XTTCP)(nil)
var _ marshal.Marshallable = (*XTUDP)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IOCallback) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOCallback) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.OpCode))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.ReqPrio))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Buf))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Bytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Reserved2))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ResFD))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOCallback) UnmarshalBytes(src []byte) []byte {
    i.Data = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Key = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    i.OpCode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.ReqPrio = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Buf = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Bytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Offset = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Reserved2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.ResFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOCallback) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOCallback) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOCallback) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOCallback) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOCallback) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOCallback) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOCallback) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOCallback) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IOEvent) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOEvent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Obj))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Result))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Result2))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOEvent) UnmarshalBytes(src []byte) []byte {
    i.Data = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Obj = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result2 = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOEvent) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOEvent) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOEvent) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOEvent) WriteTo(writer io.Writer) (int64, error) {
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
func (b *BPFInstruction) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (b *BPFInstruction) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(b.OpCode))
    dst = dst[2:]
    dst[0] = byte(b.JumpIfTrue)
    dst = dst[1:]
    dst[0] = byte(b.JumpIfFalse)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(b.K))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (b *BPFInstruction) UnmarshalBytes(src []byte) []byte {
    b.OpCode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    b.JumpIfTrue = uint8(src[0])
    src = src[1:]
    b.JumpIfFalse = uint8(src[0])
    src = src[1:]
    b.K = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (b *BPFInstruction) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (b *BPFInstruction) MarshalUnsafe(dst []byte) []byte {
    size := b.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(b), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (b *BPFInstruction) UnmarshalUnsafe(src []byte) []byte {
    size := b.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(b), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (b *BPFInstruction) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (b *BPFInstruction) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyOutN(cc, addr, b.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (b *BPFInstruction) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (b *BPFInstruction) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyInN(cc, addr, b.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *BPFInstruction) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyBPFInstructionSliceIn copies in a slice of BPFInstruction objects from the task's memory.
func CopyBPFInstructionSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []BPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

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

// CopyBPFInstructionSliceOut copies a slice of BPFInstruction objects to the task's memory.
func CopyBPFInstructionSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []BPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

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

// MarshalUnsafeBPFInstructionSlice is like BPFInstruction.MarshalUnsafe, but for a []BPFInstruction.
func MarshalUnsafeBPFInstructionSlice(src []BPFInstruction, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*BPFInstruction)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeBPFInstructionSlice is like BPFInstruction.UnmarshalUnsafe, but for a []BPFInstruction.
func UnmarshalUnsafeBPFInstructionSlice(dst []BPFInstruction, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*BPFInstruction)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CapUserData) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CapUserData) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Effective))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Permitted))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Inheritable))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CapUserData) UnmarshalBytes(src []byte) []byte {
    c.Effective = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Permitted = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Inheritable = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserData) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *CapUserData) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *CapUserData) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *CapUserData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *CapUserData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *CapUserData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *CapUserData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *CapUserData) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyCapUserDataSliceIn copies in a slice of CapUserData objects from the task's memory.
func CopyCapUserDataSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []CapUserData) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

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

// CopyCapUserDataSliceOut copies a slice of CapUserData objects to the task's memory.
func CopyCapUserDataSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []CapUserData) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

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

// MarshalUnsafeCapUserDataSlice is like CapUserData.MarshalUnsafe, but for a []CapUserData.
func MarshalUnsafeCapUserDataSlice(src []CapUserData, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*CapUserData)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeCapUserDataSlice is like CapUserData.UnmarshalUnsafe, but for a []CapUserData.
func UnmarshalUnsafeCapUserDataSlice(dst []CapUserData, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*CapUserData)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CapUserHeader) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CapUserHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Pid))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CapUserHeader) UnmarshalBytes(src []byte) []byte {
    c.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Pid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserHeader) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *CapUserHeader) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *CapUserHeader) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *CapUserHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *CapUserHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *CapUserHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *CapUserHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *CapUserHeader) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CloneArgs) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CloneArgs) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Pidfd))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ChildTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ParentTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ExitSignal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Stack))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.StackSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.TLS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.SetTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.SetTIDSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Cgroup))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CloneArgs) UnmarshalBytes(src []byte) []byte {
    c.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Pidfd = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ChildTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ParentTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ExitSignal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Stack = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.StackSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.TLS = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.SetTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.SetTIDSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Cgroup = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CloneArgs) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *CloneArgs) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *CloneArgs) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *CloneArgs) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *CloneArgs) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *CloneArgs) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *CloneArgs) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *CloneArgs) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *ElfHeader64) SizeBytes() int {
    return 48 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ElfHeader64) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(e.Ident[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Machine))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Entry))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Phoff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Shoff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Ehsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Phentsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Phnum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shentsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shnum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shstrndx))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ElfHeader64) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        e.Ident[idx] = src[0]
        src = src[1:]
    }
    e.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Machine = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Entry = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Phoff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Shoff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Ehsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Phentsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Phnum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shentsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shnum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shstrndx = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfHeader64) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ElfHeader64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ElfHeader64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *ElfHeader64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *ElfHeader64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *ElfHeader64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *ElfHeader64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *ElfHeader64) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *ElfProg64) SizeBytes() int {
    return 56
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ElfProg64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Vaddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Paddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Filesz))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Memsz))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Align))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ElfProg64) UnmarshalBytes(src []byte) []byte {
    e.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Vaddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Paddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Filesz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Memsz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Align = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfProg64) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ElfProg64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ElfProg64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *ElfProg64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *ElfProg64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *ElfProg64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *ElfProg64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *ElfProg64) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *ElfSection64) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ElfSection64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Name))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Link))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Info))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Addralign))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Entsize))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ElfSection64) UnmarshalBytes(src []byte) []byte {
    e.Name = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Link = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Info = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Addralign = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Entsize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfSection64) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ElfSection64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ElfSection64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *ElfSection64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *ElfSection64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *ElfSection64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *ElfSection64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *ElfSection64) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockErrCMsgIPv4) SizeBytes() int {
    return 0 +
        (*SockExtendedErr)(nil).SizeBytes() +
        (*SockAddrInet)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockErrCMsgIPv4) MarshalBytes(dst []byte) []byte {
    dst = s.SockExtendedErr.MarshalUnsafe(dst)
    dst = s.Offender.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockErrCMsgIPv4) UnmarshalBytes(src []byte) []byte {
    src = s.SockExtendedErr.UnmarshalUnsafe(src)
    src = s.Offender.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockErrCMsgIPv4) Packed() bool {
    return s.Offender.Packed() && s.SockExtendedErr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockErrCMsgIPv4) MarshalUnsafe(dst []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SockErrCMsgIPv4 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockErrCMsgIPv4) UnmarshalUnsafe(src []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SockErrCMsgIPv4 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockErrCMsgIPv4) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv4 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockErrCMsgIPv4) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockErrCMsgIPv4) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv4 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockErrCMsgIPv4) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockErrCMsgIPv4) WriteTo(writer io.Writer) (int64, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv4 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockErrCMsgIPv6) SizeBytes() int {
    return 0 +
        (*SockExtendedErr)(nil).SizeBytes() +
        (*SockAddrInet6)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockErrCMsgIPv6) MarshalBytes(dst []byte) []byte {
    dst = s.SockExtendedErr.MarshalUnsafe(dst)
    dst = s.Offender.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockErrCMsgIPv6) UnmarshalBytes(src []byte) []byte {
    src = s.SockExtendedErr.UnmarshalUnsafe(src)
    src = s.Offender.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockErrCMsgIPv6) Packed() bool {
    return s.Offender.Packed() && s.SockExtendedErr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockErrCMsgIPv6) MarshalUnsafe(dst []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SockErrCMsgIPv6 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockErrCMsgIPv6) UnmarshalUnsafe(src []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SockErrCMsgIPv6 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockErrCMsgIPv6) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv6 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockErrCMsgIPv6) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockErrCMsgIPv6) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv6 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockErrCMsgIPv6) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockErrCMsgIPv6) WriteTo(writer io.Writer) (int64, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        // Type SockErrCMsgIPv6 doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockExtendedErr) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockExtendedErr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    dst[0] = byte(s.Origin)
    dst = dst[1:]
    dst[0] = byte(s.Type)
    dst = dst[1:]
    dst[0] = byte(s.Code)
    dst = dst[1:]
    dst[0] = byte(s.Pad)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Info))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Data))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockExtendedErr) UnmarshalBytes(src []byte) []byte {
    s.Errno = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Origin = uint8(src[0])
    src = src[1:]
    s.Type = uint8(src[0])
    src = src[1:]
    s.Code = uint8(src[0])
    src = src[1:]
    s.Pad = uint8(src[0])
    src = src[1:]
    s.Info = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Data = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockExtendedErr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockExtendedErr) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockExtendedErr) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockExtendedErr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SockExtendedErr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockExtendedErr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockExtendedErr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockExtendedErr) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FOwnerEx) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FOwnerEx) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FOwnerEx) UnmarshalBytes(src []byte) []byte {
    f.Type = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FOwnerEx) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FOwnerEx) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FOwnerEx) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FOwnerEx) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FOwnerEx) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FOwnerEx) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FOwnerEx) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FOwnerEx) WriteTo(writer io.Writer) (int64, error) {
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
func (f *Flock) SizeBytes() int {
    return 24 +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *Flock) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.Whence))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Len))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *Flock) UnmarshalBytes(src []byte) []byte {
    f.Type = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.Whence = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([4]byte(f._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    f.Start = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Len = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(f._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *Flock) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *Flock) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *Flock) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *Flock) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *Flock) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *Flock) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *Flock) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *Flock) WriteTo(writer io.Writer) (int64, error) {
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
//go:nosplit
func (m *FileMode) SizeBytes() int {
    return 2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *FileMode) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*m))
    return dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *FileMode) UnmarshalBytes(src []byte) []byte {
    *m = FileMode(uint16(hostarch.ByteOrder.Uint16(src[:2])))
    return src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *FileMode) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *FileMode) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *FileMode) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (m *FileMode) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (m *FileMode) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (m *FileMode) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (m *FileMode) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *FileMode) WriteTo(writer io.Writer) (int64, error) {
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
func (s *Statx) SizeBytes() int {
    return 80 +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statx) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Mask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Blksize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Attributes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Nlink))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Mode))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.AttributesMask))
    dst = dst[8:]
    dst = s.Atime.MarshalUnsafe(dst)
    dst = s.Btime.MarshalUnsafe(dst)
    dst = s.Ctime.MarshalUnsafe(dst)
    dst = s.Mtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMajor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMinor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.DevMajor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.DevMinor))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statx) UnmarshalBytes(src []byte) []byte {
    s.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Blksize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Attributes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    s.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AttributesMask = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.Atime.UnmarshalUnsafe(src)
    src = s.Btime.UnmarshalUnsafe(src)
    src = s.Ctime.UnmarshalUnsafe(src)
    src = s.Mtime.UnmarshalUnsafe(src)
    s.RdevMajor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.RdevMinor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMajor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMinor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statx) Packed() bool {
    return s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statx) MarshalUnsafe(dst []byte) []byte {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type Statx doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statx) UnmarshalUnsafe(src []byte) []byte {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Statx doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Statx) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *Statx) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *Statx) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Statx) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statx) WriteTo(writer io.Writer) (int64, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// CheckedMarshal implements marshal.CheckedMarshallable.CheckedMarshal.
func (s *Statx) CheckedMarshal(dst []byte) ([]byte, bool) {
    if s.SizeBytes() > len(dst) {
        return dst, false
    }
    return s.MarshalUnsafe(dst), true
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *Statx) CheckedUnmarshal(src []byte) ([]byte, bool) {
    if s.SizeBytes() > len(src) {
        return src, false
    }
    return s.UnmarshalUnsafe(src), true
}

// CopyStatxSliceIn copies in a slice of Statx objects from the task's memory.
func CopyStatxSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Statx) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !dst[0].Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(size * count)
        length, err := cc.CopyInBytes(addr, buf)

        // Unmarshal as much as possible, even on error. First handle full objects.
        limit := length/size
        for idx := 0; idx < limit; idx++ {
            buf = dst[idx].UnmarshalBytes(buf)
        }

        // Handle any final partial object. buf is guaranteed to be long enough for the
        // final element, but may not contain valid data for the entire range. This may
        // result in unmarshalling zero values for some parts of the object.
        if length%size != 0 {
            dst[limit].UnmarshalBytes(buf)
        }

        return length, err
    }

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

// CopyStatxSliceOut copies a slice of Statx objects to the task's memory.
func CopyStatxSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Statx) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !src[0].Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(size * count)
        curBuf := buf
        for idx := 0; idx < count; idx++ {
            curBuf = src[idx].MarshalBytes(curBuf)
        }
        return cc.CopyOutBytes(addr, buf)
    }

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

// MarshalUnsafeStatxSlice is like Statx.MarshalUnsafe, but for a []Statx.
func MarshalUnsafeStatxSlice(src []Statx, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    if !src[0].Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        for idx := 0; idx < count; idx++ {
            dst = src[idx].MarshalBytes(dst)
        }
        return dst
    }

    size := (*Statx)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeStatxSlice is like Statx.UnmarshalUnsafe, but for a []Statx.
func UnmarshalUnsafeStatxSlice(dst []Statx, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    if !dst[0].Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        for idx := 0; idx < count; idx++ {
            src = dst[idx].UnmarshalBytes(src)
        }
        return src
    }

    size := (*Statx)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Statfs) SizeBytes() int {
    return 80 +
        4*2 +
        8*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statfs) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Type))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlockSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksAvailable))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Files))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FilesFree))
    dst = dst[8:]
    for idx := 0; idx < 2; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FSID[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.NameLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FragmentSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    for idx := 0; idx < 4; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Spare[idx]))
        dst = dst[8:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statfs) UnmarshalBytes(src []byte) []byte {
    s.Type = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlockSize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksAvailable = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Files = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FilesFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 2; idx++ {
        s.FSID[idx] = int32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    s.NameLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FragmentSize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 4; idx++ {
        s.Spare[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statfs) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statfs) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statfs) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Statfs) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *Statfs) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *Statfs) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Statfs) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statfs) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *CString) Packed() bool {
    // Type CString is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *CString) MarshalUnsafe(dst []byte) []byte {
    // Type CString doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *CString) UnmarshalUnsafe(src []byte) []byte {
    // Type CString doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *CString) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type CString doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    s.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *CString) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (s *CString) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type CString doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    s.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *CString) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *CString) WriteTo(writer io.Writer) (int64, error) {
    // Type CString doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEAccessIn) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEAccessIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mask))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEAccessIn) UnmarshalBytes(src []byte) []byte {
    f.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAccessIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEAccessIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEAccessIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEAccessIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEAccessIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEAccessIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEAccessIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEAccessIn) WriteTo(writer io.Writer) (int64, error) {
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
func (a *FUSEAttr) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *FUSEAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Atime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Mtime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Ctime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.MtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.CtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Nlink))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Rdev))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.BlkSize))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (a *FUSEAttr) UnmarshalBytes(src []byte) []byte {
    a.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Atime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Mtime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Ctime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.AtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.MtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.CtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Nlink = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Rdev = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.BlkSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *FUSEAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (a *FUSEAttr) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (a *FUSEAttr) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (a *FUSEAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (a *FUSEAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (a *FUSEAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that a
    // must live until the use above.
    runtime.KeepAlive(a) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (a *FUSEAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (a *FUSEAttr) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEAttrOut) SizeBytes() int {
    return 16 +
        (*FUSEAttr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEAttrOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    dst = f.Attr.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEAttrOut) UnmarshalBytes(src []byte) []byte {
    f.AttrValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValidNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    src = f.Attr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAttrOut) Packed() bool {
    return f.Attr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEAttrOut) MarshalUnsafe(dst []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FUSEAttrOut doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEAttrOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FUSEAttrOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEAttrOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEAttrOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEAttrOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEAttrOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FUSEAttrOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEAttrOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        // Type FUSEAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSECreateIn) Packed() bool {
    // Type FUSECreateIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSECreateIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSECreateIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSECreateIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSECreateIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSECreateIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSECreateIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSECreateIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSECreateIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSECreateIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSECreateIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSECreateIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSECreateIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSECreateMeta) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSECreateMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSECreateMeta) UnmarshalBytes(src []byte) []byte {
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSECreateMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSECreateMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSECreateMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSECreateMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSECreateMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSECreateMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSECreateMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSECreateMeta) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSECreateOut) SizeBytes() int {
    return 0 +
        (*FUSEEntryOut)(nil).SizeBytes() +
        (*FUSEOpenOut)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSECreateOut) MarshalBytes(dst []byte) []byte {
    dst = f.FUSEEntryOut.MarshalUnsafe(dst)
    dst = f.FUSEOpenOut.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSECreateOut) UnmarshalBytes(src []byte) []byte {
    src = f.FUSEEntryOut.UnmarshalUnsafe(src)
    src = f.FUSEOpenOut.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSECreateOut) Packed() bool {
    return f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSECreateOut) MarshalUnsafe(dst []byte) []byte {
    if f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FUSECreateOut doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSECreateOut) UnmarshalUnsafe(src []byte) []byte {
    if f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FUSECreateOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSECreateOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        // Type FUSECreateOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSECreateOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSECreateOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        // Type FUSECreateOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FUSECreateOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSECreateOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        // Type FUSECreateOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEDirent) Packed() bool {
    // Type FUSEDirent is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEDirent) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEDirent doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEDirent) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEDirent doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEDirent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEDirent doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEDirent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEDirent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEDirent doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEDirent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEDirent) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEDirent doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEDirentMeta) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEDirentMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.NameLen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEDirentMeta) UnmarshalBytes(src []byte) []byte {
    f.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.NameLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEDirentMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEDirentMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEDirentMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEDirentMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEDirentMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEDirentMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEDirentMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEDirentMeta) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEDirents) Packed() bool {
    // Type FUSEDirents is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEDirents) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEDirents doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEDirents) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEDirents doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEDirents) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEDirents doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEDirents) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEDirents) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEDirents doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEDirents) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEDirents) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEDirents doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEEmptyIn) Packed() bool {
    // Type FUSEEmptyIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEEmptyIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEEmptyIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEEmptyIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEEmptyIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEEmptyIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEEmptyIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEEmptyIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEEmptyIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEEmptyIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEEmptyIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEEmptyIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEEmptyIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEEntryOut) SizeBytes() int {
    return 40 +
        (*FUSEAttr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEEntryOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Generation))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.EntryValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.EntryValidNSec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNSec))
    dst = dst[4:]
    dst = f.Attr.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEEntryOut) UnmarshalBytes(src []byte) []byte {
    f.NodeID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Generation = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValidNSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.AttrValidNSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Attr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEEntryOut) Packed() bool {
    return f.Attr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEEntryOut) MarshalUnsafe(dst []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FUSEEntryOut doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEEntryOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FUSEEntryOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEEntryOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEEntryOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEEntryOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FUSEEntryOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEEntryOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEFallocateIn) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEFallocateIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEFallocateIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFallocateIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEFallocateIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEFallocateIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEFallocateIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFallocateIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEFallocateIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFallocateIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEFallocateIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEFlushIn) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEFlushIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEFlushIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFlushIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEFlushIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEFlushIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEFlushIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFlushIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEFlushIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFlushIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEFlushIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEFsyncIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEFsyncIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.FsyncFlags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEFsyncIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.FsyncFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFsyncIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEFsyncIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEFsyncIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEFsyncIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFsyncIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEFsyncIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEFsyncIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEFsyncIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEGetAttrIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEGetAttrIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GetAttrFlags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEGetAttrIn) UnmarshalBytes(src []byte) []byte {
    f.GetAttrFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEGetAttrIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEGetAttrIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEGetAttrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEGetAttrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEGetAttrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEGetAttrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEGetAttrIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEHeaderIn) SizeBytes() int {
    return 28 +
        (*FUSEOpcode)(nil).SizeBytes() +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    dst = f.Opcode.MarshalUnsafe(dst)
    dst = f.Unique.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderIn) UnmarshalBytes(src []byte) []byte {
    f.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Opcode.UnmarshalUnsafe(src)
    src = f.Unique.UnmarshalUnsafe(src)
    f.NodeID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderIn) Packed() bool {
    return f.Opcode.Packed() && f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderIn) MarshalUnsafe(dst []byte) []byte {
    if f.Opcode.Packed() && f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderIn) UnmarshalUnsafe(src []byte) []byte {
    if f.Opcode.Packed() && f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEHeaderIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEHeaderIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEHeaderIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FUSEHeaderIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderIn) WriteTo(writer io.Writer) (int64, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEHeaderOut) SizeBytes() int {
    return 8 +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Error))
    dst = dst[4:]
    dst = f.Unique.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderOut) UnmarshalBytes(src []byte) []byte {
    f.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Unique.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderOut) Packed() bool {
    return f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderOut) MarshalUnsafe(dst []byte) []byte {
    if f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to MarshalBytes.
    return f.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return f.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEHeaderOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEHeaderOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEHeaderOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (f *FUSEHeaderOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (f *FUSEInitIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitIn) UnmarshalBytes(src []byte) []byte {
    f.Major = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEInitIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEInitIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEInitIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEInitIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEInitOut) SizeBytes() int {
    return 32 +
        4*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.MaxBackground))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.CongestionThreshold))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxWrite))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.TimeGran))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.MaxPages))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    // Padding: dst[:sizeof(uint32)*8] ~= [8]uint32{0}
    dst = dst[4*(8):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitOut) UnmarshalBytes(src []byte) []byte {
    f.Major = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxBackground = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.CongestionThreshold = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.MaxWrite = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.TimeGran = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxPages = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    // Padding: ~ copy([8]uint32(f._), src[:sizeof(uint32)*8])
    src = src[4*(8):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEInitOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEInitOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEInitOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEInitOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitOut) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSELinkIn) Packed() bool {
    // Type FUSELinkIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSELinkIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSELinkIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSELinkIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSELinkIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSELinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSELinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSELinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSELinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSELinkIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSELinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSELinkIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSELinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSELookupIn) Packed() bool {
    // Type FUSELookupIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSELookupIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSELookupIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSELookupIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSELookupIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSELookupIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSELookupIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSELookupIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSELookupIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSELookupIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSELookupIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSELookupIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSELookupIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEMkdirIn) Packed() bool {
    // Type FUSEMkdirIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEMkdirIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEMkdirIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEMkdirIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEMkdirIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEMkdirIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEMkdirIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEMkdirIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEMkdirIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEMkdirIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEMkdirIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEMkdirIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEMkdirIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEMkdirMeta) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEMkdirMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEMkdirMeta) UnmarshalBytes(src []byte) []byte {
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMkdirMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEMkdirMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEMkdirMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEMkdirMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEMkdirMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEMkdirMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEMkdirMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEMkdirMeta) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEMknodIn) Packed() bool {
    // Type FUSEMknodIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEMknodIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEMknodIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEMknodIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEMknodIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEMknodIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEMknodIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEMknodIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEMknodIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEMknodIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEMknodIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEMknodIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEMknodIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEMknodMeta) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEMknodMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Rdev))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEMknodMeta) UnmarshalBytes(src []byte) []byte {
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Rdev = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMknodMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEMknodMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEMknodMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEMknodMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEMknodMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEMknodMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEMknodMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEMknodMeta) WriteTo(writer io.Writer) (int64, error) {
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
//go:nosplit
func (f *FUSEOpID) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*f))
    return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpID) UnmarshalBytes(src []byte) []byte {
    *f = FUSEOpID(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpID) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpID) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEOpID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEOpID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpID) WriteTo(writer io.Writer) (int64, error) {
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
//go:nosplit
func (f *FUSEOpcode) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpcode) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*f))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpcode) UnmarshalBytes(src []byte) []byte {
    *f = FUSEOpcode(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpcode) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpcode) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpcode) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEOpcode) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpcode) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEOpcode) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpcode) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpcode) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEOpenIn) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpenIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpenIn) UnmarshalBytes(src []byte) []byte {
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpenIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpenIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEOpenIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpenIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEOpenIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpenIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpenIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEOpenOut) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpenOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.OpenFlag))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpenOut) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.OpenFlag = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpenOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpenOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEOpenOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpenOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEOpenOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEOpenOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpenOut) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEReadIn) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEReadIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.ReadFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEReadIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReadFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReadIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEReadIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEReadIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEReadIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEReadIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEReadIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEReadIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEReadIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEReleaseIn) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEReleaseIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.ReleaseFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEReleaseIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReleaseFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReleaseIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEReleaseIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEReleaseIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEReleaseIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEReleaseIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEReleaseIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEReleaseIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEReleaseIn) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSERenameIn) Packed() bool {
    // Type FUSERenameIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSERenameIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSERenameIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSERenameIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSERenameIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSERenameIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSERenameIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSERenameIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSERenameIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSERenameIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSERenameIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSERenameIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSERenameIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSERmDirIn) Packed() bool {
    // Type FUSERmDirIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSERmDirIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSERmDirIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSERmDirIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSERmDirIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSERmDirIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSERmDirIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSERmDirIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSERmDirIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSERmDirIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSERmDirIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSERmDirIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSERmDirIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSESetAttrIn) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSESetAttrIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Valid))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Atime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Mtime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Ctime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.CtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSESetAttrIn) UnmarshalBytes(src []byte) []byte {
    f.Valid = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Atime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mtime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Ctime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.CtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSESetAttrIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSESetAttrIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSESetAttrIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSESetAttrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSESetAttrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSESetAttrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSESetAttrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSESetAttrIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEStatfsOut) SizeBytes() int {
    return 56 +
        4*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEStatfsOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.BlocksFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.BlocksAvailable))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Files))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.FilesFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.BlockSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.NameLength))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.FragmentSize))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    for idx := 0; idx < 6; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Spare[idx]))
        dst = dst[4:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEStatfsOut) UnmarshalBytes(src []byte) []byte {
    f.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlocksFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlocksAvailable = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Files = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.FilesFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlockSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.NameLength = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.FragmentSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    for idx := 0; idx < 6; idx++ {
        f.Spare[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEStatfsOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEStatfsOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEStatfsOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEStatfsOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEStatfsOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEStatfsOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEStatfsOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEStatfsOut) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSESymlinkIn) Packed() bool {
    // Type FUSESymlinkIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSESymlinkIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSESymlinkIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSESymlinkIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSESymlinkIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSESymlinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSESymlinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSESymlinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSESymlinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSESymlinkIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSESymlinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSESymlinkIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSESymlinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEUnlinkIn) Packed() bool {
    // Type FUSEUnlinkIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEUnlinkIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEUnlinkIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEUnlinkIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEUnlinkIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEUnlinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEUnlinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEUnlinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEUnlinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEUnlinkIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEUnlinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEUnlinkIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEUnlinkIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEWriteIn) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEWriteIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.WriteFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEWriteIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.WriteFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEWriteIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEWriteIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEWriteIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEWriteIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEWriteIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEWriteIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEWriteIn) WriteTo(writer io.Writer) (int64, error) {
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
func (f *FUSEWriteOut) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEWriteOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEWriteOut) UnmarshalBytes(src []byte) []byte {
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEWriteOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEWriteOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (f *FUSEWriteOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEWriteOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (f *FUSEWriteOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (f *FUSEWriteOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEWriteOut) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEWritePayloadIn) Packed() bool {
    // Type FUSEWritePayloadIn is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *FUSEWritePayloadIn) MarshalUnsafe(dst []byte) []byte {
    // Type FUSEWritePayloadIn doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *FUSEWritePayloadIn) UnmarshalUnsafe(src []byte) []byte {
    // Type FUSEWritePayloadIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEWritePayloadIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEWritePayloadIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    r.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (r *FUSEWritePayloadIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEWritePayloadIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type FUSEWritePayloadIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    r.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *FUSEWritePayloadIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *FUSEWritePayloadIn) WriteTo(writer io.Writer) (int64, error) {
    // Type FUSEWritePayloadIn doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RobustListHead) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RobustListHead) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.List))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.FutexOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.ListOpPending))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RobustListHead) UnmarshalBytes(src []byte) []byte {
    r.List = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.FutexOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ListOpPending = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RobustListHead) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RobustListHead) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RobustListHead) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RobustListHead) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RobustListHead) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RobustListHead) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RobustListHead) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RobustListHead) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IOCqRingOffsets) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOCqRingOffsets) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Overflow))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Cqes))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv1))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Resv2))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOCqRingOffsets) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Overflow = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Cqes = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOCqRingOffsets) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOCqRingOffsets) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOCqRingOffsets) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOCqRingOffsets) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOCqRingOffsets) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOCqRingOffsets) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOCqRingOffsets) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOCqRingOffsets) WriteTo(writer io.Writer) (int64, error) {
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
//go:nosplit
func (i *IORingIndex) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IORingIndex) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*i))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IORingIndex) UnmarshalBytes(src []byte) []byte {
    *i = IORingIndex(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IORingIndex) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IORingIndex) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IORingIndex) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IORingIndex) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IORingIndex) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IORingIndex) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IORingIndex) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IORingIndex) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IORings) SizeBytes() int {
    return 32 +
        (*IOUring)(nil).SizeBytes() +
        (*IOUring)(nil).SizeBytes() +
        1*32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IORings) MarshalBytes(dst []byte) []byte {
    dst = i.Sq.MarshalUnsafe(dst)
    dst = i.Cq.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqRingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqRingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqRingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqRingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.sqDropped))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.sqFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.cqFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqOverflow))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*32] ~= [32]byte{0}
    dst = dst[1*(32):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IORings) UnmarshalBytes(src []byte) []byte {
    src = i.Sq.UnmarshalUnsafe(src)
    src = i.Cq.UnmarshalUnsafe(src)
    i.SqRingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqRingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqRingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqRingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.sqDropped = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.sqFlags = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.cqFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqOverflow = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([32]byte(i._), src[:sizeof(byte)*32])
    src = src[1*(32):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IORings) Packed() bool {
    return i.Cq.Packed() && i.Sq.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IORings) MarshalUnsafe(dst []byte) []byte {
    if i.Cq.Packed() && i.Sq.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IORings doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IORings) UnmarshalUnsafe(src []byte) []byte {
    if i.Cq.Packed() && i.Sq.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IORings doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IORings) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
        // Type IORings doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IORings) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IORings) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
        // Type IORings doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IORings) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IORings) WriteTo(writer io.Writer) (int64, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
        // Type IORings doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IOSqRingOffsets) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOSqRingOffsets) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Dropped))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Array))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv1))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Resv2))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOSqRingOffsets) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Dropped = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Array = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOSqRingOffsets) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOSqRingOffsets) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOSqRingOffsets) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOSqRingOffsets) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOSqRingOffsets) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOSqRingOffsets) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOSqRingOffsets) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOSqRingOffsets) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IOUring) SizeBytes() int {
    return 8 +
        1*60 +
        1*60
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOUring) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*60] ~= [60]byte{0}
    dst = dst[1*(60):]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*60] ~= [60]byte{0}
    dst = dst[1*(60):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOUring) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([60]byte(i._), src[:sizeof(byte)*60])
    src = src[1*(60):]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([60]byte(i._), src[:sizeof(byte)*60])
    src = src[1*(60):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUring) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOUring) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOUring) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOUring) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUring) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOUring) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUring) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOUring) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IOUringCqe) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOUringCqe) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.UserData))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Res))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOUringCqe) UnmarshalBytes(src []byte) []byte {
    i.UserData = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Res = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringCqe) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOUringCqe) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOUringCqe) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOUringCqe) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUringCqe) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOUringCqe) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUringCqe) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOUringCqe) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IOUringParams) SizeBytes() int {
    return 28 +
        4*3 +
        (*IOSqRingOffsets)(nil).SizeBytes() +
        (*IOCqRingOffsets)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOUringParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqThreadCPU))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqThreadIdle))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Features))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.WqFd))
    dst = dst[4:]
    for idx := 0; idx < 3; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv[idx]))
        dst = dst[4:]
    }
    dst = i.SqOff.MarshalUnsafe(dst)
    dst = i.CqOff.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOUringParams) UnmarshalBytes(src []byte) []byte {
    i.SqEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqThreadCPU = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqThreadIdle = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Features = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.WqFd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 3; idx++ {
        i.Resv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    src = i.SqOff.UnmarshalUnsafe(src)
    src = i.CqOff.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringParams) Packed() bool {
    return i.CqOff.Packed() && i.SqOff.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOUringParams) MarshalUnsafe(dst []byte) []byte {
    if i.CqOff.Packed() && i.SqOff.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IOUringParams doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOUringParams) UnmarshalUnsafe(src []byte) []byte {
    if i.CqOff.Packed() && i.SqOff.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IOUringParams doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOUringParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
        // Type IOUringParams doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IOUringParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOUringParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
        // Type IOUringParams doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IOUringParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOUringParams) WriteTo(writer io.Writer) (int64, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
        // Type IOUringParams doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IOUringSqe) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOUringSqe) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Opcode)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.IoPrio))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Fd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.OffOrAddrOrCmdOp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.AddrOrSpliceOff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.specialFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.UserData))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.BufIndexOrGroup))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.personality))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.spliceFDOrFileIndex))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.addr3))
    dst = dst[8:]
    // Padding: dst[:sizeof(uint64)] ~= uint64(0)
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOUringSqe) UnmarshalBytes(src []byte) []byte {
    i.Opcode = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.IoPrio = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Fd = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.OffOrAddrOrCmdOp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.AddrOrSpliceOff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.specialFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UserData = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.BufIndexOrGroup = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.personality = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.spliceFDOrFileIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.addr3 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    // Padding: var _ uint64 ~= src[:sizeof(uint64)]
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringSqe) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOUringSqe) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOUringSqe) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IOUringSqe) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUringSqe) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IOUringSqe) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IOUringSqe) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOUringSqe) WriteTo(writer io.Writer) (int64, error) {
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
func (i *IPCPerm) SizeBytes() int {
    return 48
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPCPerm) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CUID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CGID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Mode))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Seq))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.unused1))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.unused2))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPCPerm) UnmarshalBytes(src []byte) []byte {
    i.Key = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CUID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CGID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    i.Seq = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    i.unused1 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.unused2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPCPerm) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPCPerm) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPCPerm) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPCPerm) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IPCPerm) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPCPerm) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IPCPerm) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPCPerm) WriteTo(writer io.Writer) (int64, error) {
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
func (s *Sysinfo) SizeBytes() int {
    return 78 +
        8*3 +
        1*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sysinfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Uptime))
    dst = dst[8:]
    for idx := 0; idx < 3; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Loads[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SharedRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BufferRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Procs))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*6] ~= [6]byte{0}
    dst = dst[1*(6):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalHigh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeHigh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Unit))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sysinfo) UnmarshalBytes(src []byte) []byte {
    s.Uptime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 3; idx++ {
        s.Loads[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    s.TotalRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SharedRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BufferRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.TotalSwap = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeSwap = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Procs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([6]byte(s._), src[:sizeof(byte)*6])
    src = src[1*(6):]
    s.TotalHigh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeHigh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unit = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sysinfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sysinfo) MarshalUnsafe(dst []byte) []byte {
    // Type Sysinfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sysinfo) UnmarshalUnsafe(src []byte) []byte {
    // Type Sysinfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Sysinfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    s.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *Sysinfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *Sysinfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    s.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Sysinfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sysinfo) WriteTo(writer io.Writer) (int64, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NumaPolicy) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NumaPolicy) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*n))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NumaPolicy) UnmarshalBytes(src []byte) []byte {
    *n = NumaPolicy(int32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NumaPolicy) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NumaPolicy) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NumaPolicy) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NumaPolicy) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NumaPolicy) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NumaPolicy) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NumaPolicy) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NumaPolicy) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MqAttr) SizeBytes() int {
    return 32 +
        8*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MqAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqFlags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqMaxmsg))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqMsgsize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqCurmsgs))
    dst = dst[8:]
    // Padding: dst[:sizeof(int64)*4] ~= [4]int64{0}
    dst = dst[8*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MqAttr) UnmarshalBytes(src []byte) []byte {
    m.MqFlags = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqMaxmsg = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqMsgsize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqCurmsgs = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    // Padding: ~ copy([4]int64(m._), src[:sizeof(int64)*4])
    src = src[8*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MqAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MqAttr) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MqAttr) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (m *MqAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (m *MqAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (m *MqAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (m *MqAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MqAttr) WriteTo(writer io.Writer) (int64, error) {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (b *MsgBuf) Packed() bool {
    // Type MsgBuf is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (b *MsgBuf) MarshalUnsafe(dst []byte) []byte {
    // Type MsgBuf doesn't have a packed layout in memory, fallback to MarshalBytes.
    return b.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (b *MsgBuf) UnmarshalUnsafe(src []byte) []byte {
    // Type MsgBuf doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return b.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (b *MsgBuf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type MsgBuf doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(b.SizeBytes()) // escapes: okay.
    b.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (b *MsgBuf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyOutN(cc, addr, b.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (b *MsgBuf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type MsgBuf doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(b.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    b.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (b *MsgBuf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyInN(cc, addr, b.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *MsgBuf) WriteTo(writer io.Writer) (int64, error) {
    // Type MsgBuf doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, b.SizeBytes())
    b.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MsgInfo) SizeBytes() int {
    return 30
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MsgInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgPool))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMap))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMax))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMnb))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMni))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgSsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgTql))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.MsgSeg))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsgInfo) UnmarshalBytes(src []byte) []byte {
    m.MsgPool = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMap = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMax = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMnb = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMni = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgSsz = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgTql = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgSeg = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgInfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsgInfo) MarshalUnsafe(dst []byte) []byte {
    // Type MsgInfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsgInfo) UnmarshalUnsafe(src []byte) []byte {
    // Type MsgInfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return m.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (m *MsgInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type MsgInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
    m.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (m *MsgInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (m *MsgInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type MsgInfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    m.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (m *MsgInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MsgInfo) WriteTo(writer io.Writer) (int64, error) {
    // Type MsgInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, m.SizeBytes())
    m.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MsqidDS) SizeBytes() int {
    return 48 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MsqidDS) MarshalBytes(dst []byte) []byte {
    dst = m.MsgPerm.MarshalUnsafe(dst)
    dst = m.MsgStime.MarshalUnsafe(dst)
    dst = m.MsgRtime.MarshalUnsafe(dst)
    dst = m.MsgCtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgCbytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgQnum))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgQbytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgLspid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgLrpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.unused4))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.unused5))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsqidDS) UnmarshalBytes(src []byte) []byte {
    src = m.MsgPerm.UnmarshalUnsafe(src)
    src = m.MsgStime.UnmarshalUnsafe(src)
    src = m.MsgRtime.UnmarshalUnsafe(src)
    src = m.MsgCtime.UnmarshalUnsafe(src)
    m.MsgCbytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgQnum = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgQbytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgLspid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgLrpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.unused4 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.unused5 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsqidDS) Packed() bool {
    return m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (m *MsqidDS) MarshalUnsafe(dst []byte) []byte {
    if m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
        return dst[size:]
    }
    // Type MsqidDS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return m.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (m *MsqidDS) UnmarshalUnsafe(src []byte) []byte {
    if m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type MsqidDS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return m.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (m *MsqidDS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        // Type MsqidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (m *MsqidDS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (m *MsqidDS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        // Type MsqidDS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(m.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that m
    // must live until the use above.
    runtime.KeepAlive(m) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (m *MsqidDS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (m *MsqidDS) WriteTo(writer io.Writer) (int64, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        // Type MsqidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
//go:nosplit
func (e *EthtoolCmd) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *EthtoolCmd) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*e))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *EthtoolCmd) UnmarshalBytes(src []byte) []byte {
    *e = EthtoolCmd(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolCmd) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *EthtoolCmd) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *EthtoolCmd) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *EthtoolCmd) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *EthtoolCmd) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *EthtoolCmd) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *EthtoolCmd) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *EthtoolCmd) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *EthtoolGFeatures) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *EthtoolGFeatures) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Size))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *EthtoolGFeatures) UnmarshalBytes(src []byte) []byte {
    e.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolGFeatures) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *EthtoolGFeatures) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *EthtoolGFeatures) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *EthtoolGFeatures) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *EthtoolGFeatures) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *EthtoolGFeatures) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *EthtoolGFeatures) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *EthtoolGFeatures) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (e *EthtoolGetFeaturesBlock) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *EthtoolGetFeaturesBlock) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Available))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Requested))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Active))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.NeverChanged))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *EthtoolGetFeaturesBlock) UnmarshalBytes(src []byte) []byte {
    e.Available = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Requested = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Active = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.NeverChanged = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolGetFeaturesBlock) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *EthtoolGetFeaturesBlock) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *EthtoolGetFeaturesBlock) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (e *EthtoolGetFeaturesBlock) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (e *EthtoolGetFeaturesBlock) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (e *EthtoolGetFeaturesBlock) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (e *EthtoolGetFeaturesBlock) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *EthtoolGetFeaturesBlock) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IFConf) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IFConf) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Ptr))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IFConf) UnmarshalBytes(src []byte) []byte {
    i.Len = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    i.Ptr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFConf) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IFConf) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IFConf) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IFConf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IFConf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IFConf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *IFConf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IFConf) WriteTo(writer io.Writer) (int64, error) {
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
func (ifr *IFReq) SizeBytes() int {
    return 0 +
        1*IFNAMSIZ +
        1*24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ifr *IFReq) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(ifr.IFName[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 24; idx++ {
        dst[0] = byte(ifr.Data[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ifr *IFReq) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        ifr.IFName[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 24; idx++ {
        ifr.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ifr *IFReq) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ifr *IFReq) MarshalUnsafe(dst []byte) []byte {
    size := ifr.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(ifr), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ifr *IFReq) UnmarshalUnsafe(src []byte) []byte {
    size := ifr.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(ifr), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (ifr *IFReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that ifr
    // must live until the use above.
    runtime.KeepAlive(ifr) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ifr *IFReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ifr.CopyOutN(cc, addr, ifr.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (ifr *IFReq) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that ifr
    // must live until the use above.
    runtime.KeepAlive(ifr) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ifr *IFReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ifr.CopyInN(cc, addr, ifr.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ifr *IFReq) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that ifr
    // must live until the use above.
    runtime.KeepAlive(ifr) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (en *ErrorName) SizeBytes() int {
    return 1 * XT_FUNCTION_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (en *ErrorName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_FUNCTION_MAXNAMELEN; idx++ {
        dst[0] = byte(en[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (en *ErrorName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_FUNCTION_MAXNAMELEN; idx++ {
        en[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (en *ErrorName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (en *ErrorName) MarshalUnsafe(dst []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&en[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (en *ErrorName) UnmarshalUnsafe(src []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(en), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (en *ErrorName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (en *ErrorName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyOutN(cc, addr, en.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (en *ErrorName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (en *ErrorName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyInN(cc, addr, en.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (en *ErrorName) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (en *ExtensionName) SizeBytes() int {
    return 1 * XT_EXTENSION_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (en *ExtensionName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        dst[0] = byte(en[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (en *ExtensionName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        en[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (en *ExtensionName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (en *ExtensionName) MarshalUnsafe(dst []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&en[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (en *ExtensionName) UnmarshalUnsafe(src []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(en), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (en *ExtensionName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (en *ExtensionName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyOutN(cc, addr, en.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (en *ExtensionName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (en *ExtensionName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyInN(cc, addr, en.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (en *ExtensionName) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that en
    // must live until the use above.
    runtime.KeepAlive(en) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTEntry) SizeBytes() int {
    return 12 +
        (*IPTIP)(nil).SizeBytes() +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTEntry) MarshalBytes(dst []byte) []byte {
    dst = i.IP.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    dst = i.Counters.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTEntry) UnmarshalBytes(src []byte) []byte {
    src = i.IP.UnmarshalUnsafe(src)
    i.NFCache = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = i.Counters.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTEntry) Packed() bool {
    return i.Counters.Packed() && i.IP.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTEntry) MarshalUnsafe(dst []byte) []byte {
    if i.Counters.Packed() && i.IP.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IPTEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTEntry) UnmarshalUnsafe(src []byte) []byte {
    if i.Counters.Packed() && i.IP.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IPTEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IPTEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IPTEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IPTGetEntries) SizeBytes() int {
    return 4 +
        (*TableName)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetEntries) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetEntries) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetEntries) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetEntries) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IPTGetEntries doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetEntries) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IPTGetEntries doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IPTGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IPTGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IPTGetinfo) SizeBytes() int {
    return 12 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetinfo) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetinfo) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetinfo) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetinfo) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IPTGetinfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetinfo) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IPTGetinfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTGetinfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IPTGetinfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTGetinfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IPTGetinfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetinfo) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IPTIP) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTIP) MarshalBytes(dst []byte) []byte {
    dst = i.Src.MarshalUnsafe(dst)
    dst = i.Dst.MarshalUnsafe(dst)
    dst = i.SrcMask.MarshalUnsafe(dst)
    dst = i.DstMask.MarshalUnsafe(dst)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTIP) UnmarshalBytes(src []byte) []byte {
    src = i.Src.UnmarshalUnsafe(src)
    src = i.Dst.UnmarshalUnsafe(src)
    src = i.SrcMask.UnmarshalUnsafe(src)
    src = i.DstMask.UnmarshalUnsafe(src)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTIP) MarshalUnsafe(dst []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IPTIP doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTIP) UnmarshalUnsafe(src []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IPTIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTIP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IPTIP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTIP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IPTIP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IPTOwnerInfo) SizeBytes() int {
    return 18 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTOwnerInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SID))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i.Comm[idx])
        dst = dst[1:]
    }
    dst[0] = byte(i.Match)
    dst = dst[1:]
    dst[0] = byte(i.Invert)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTOwnerInfo) UnmarshalBytes(src []byte) []byte {
    i.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        i.Comm[idx] = src[0]
        src = src[1:]
    }
    i.Match = uint8(src[0])
    src = src[1:]
    i.Invert = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTOwnerInfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTOwnerInfo) MarshalUnsafe(dst []byte) []byte {
    // Type IPTOwnerInfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTOwnerInfo) UnmarshalUnsafe(src []byte) []byte {
    // Type IPTOwnerInfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTOwnerInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type IPTOwnerInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
    i.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (i *IPTOwnerInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTOwnerInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type IPTOwnerInfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    i.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (i *IPTOwnerInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTOwnerInfo) WriteTo(writer io.Writer) (int64, error) {
    // Type IPTOwnerInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, i.SizeBytes())
    i.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTReplace) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTReplace) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTReplace) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTReplace) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IPTReplace doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTReplace) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IPTReplace doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IPTReplace) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IPTReplace) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IPTReplace) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTReplace doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IPTReplace) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIPTEntry) Packed() bool {
    // Type KernelIPTEntry is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ke *KernelIPTEntry) MarshalUnsafe(dst []byte) []byte {
    // Type KernelIPTEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
    return ke.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ke *KernelIPTEntry) UnmarshalUnsafe(src []byte) []byte {
    // Type KernelIPTEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIPTEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    ke.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ke *KernelIPTEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIPTEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIPTEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    ke.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ke *KernelIPTEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ke *KernelIPTEntry) WriteTo(writer io.Writer) (int64, error) {
    // Type KernelIPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIPTGetEntries) Packed() bool {
    // Type KernelIPTGetEntries is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ke *KernelIPTGetEntries) MarshalUnsafe(dst []byte) []byte {
    // Type KernelIPTGetEntries doesn't have a packed layout in memory, fallback to MarshalBytes.
    return ke.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ke *KernelIPTGetEntries) UnmarshalUnsafe(src []byte) []byte {
    // Type KernelIPTGetEntries doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIPTGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    ke.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ke *KernelIPTGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIPTGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIPTGetEntries doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    ke.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ke *KernelIPTGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ke *KernelIPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    // Type KernelIPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NfNATIPV4MultiRangeCompat) SizeBytes() int {
    return 4 +
        (*NfNATIPV4Range)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NfNATIPV4MultiRangeCompat) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RangeSize))
    dst = dst[4:]
    dst = n.RangeIPV4.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NfNATIPV4MultiRangeCompat) UnmarshalBytes(src []byte) []byte {
    n.RangeSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.RangeIPV4.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NfNATIPV4MultiRangeCompat) Packed() bool {
    return n.RangeIPV4.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NfNATIPV4MultiRangeCompat) MarshalUnsafe(dst []byte) []byte {
    if n.RangeIPV4.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NfNATIPV4MultiRangeCompat doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NfNATIPV4MultiRangeCompat) UnmarshalUnsafe(src []byte) []byte {
    if n.RangeIPV4.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NfNATIPV4MultiRangeCompat doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NfNATIPV4MultiRangeCompat) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.RangeIPV4.Packed() {
        // Type NfNATIPV4MultiRangeCompat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NfNATIPV4MultiRangeCompat) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NfNATIPV4MultiRangeCompat) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.RangeIPV4.Packed() {
        // Type NfNATIPV4MultiRangeCompat doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NfNATIPV4MultiRangeCompat) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NfNATIPV4MultiRangeCompat) WriteTo(writer io.Writer) (int64, error) {
    if !n.RangeIPV4.Packed() {
        // Type NfNATIPV4MultiRangeCompat doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NfNATIPV4Range) SizeBytes() int {
    return 8 +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NfNATIPV4Range) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.MinIP[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.MaxIP[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinPort))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxPort))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NfNATIPV4Range) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.MinIP[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 4; idx++ {
        n.MaxIP[idx] = src[0]
        src = src[1:]
    }
    n.MinPort = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxPort = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NfNATIPV4Range) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NfNATIPV4Range) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NfNATIPV4Range) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NfNATIPV4Range) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NfNATIPV4Range) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NfNATIPV4Range) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NfNATIPV4Range) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NfNATIPV4Range) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (tn *TableName) SizeBytes() int {
    return 1 * XT_TABLE_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (tn *TableName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        dst[0] = byte(tn[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (tn *TableName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        tn[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (tn *TableName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (tn *TableName) MarshalUnsafe(dst []byte) []byte {
    size := tn.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&tn[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (tn *TableName) UnmarshalUnsafe(src []byte) []byte {
    size := tn.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(tn), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (tn *TableName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tn
    // must live until the use above.
    runtime.KeepAlive(tn) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (tn *TableName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tn.CopyOutN(cc, addr, tn.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (tn *TableName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tn
    // must live until the use above.
    runtime.KeepAlive(tn) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (tn *TableName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tn.CopyInN(cc, addr, tn.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (tn *TableName) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that tn
    // must live until the use above.
    runtime.KeepAlive(tn) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTCounters) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTCounters) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(x.Pcnt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(x.Bcnt))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTCounters) UnmarshalBytes(src []byte) []byte {
    x.Pcnt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    x.Bcnt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTCounters) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTCounters) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTCounters) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTCounters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTCounters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTCounters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTCounters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTCounters) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTEntryMatch) SizeBytes() int {
    return 3 +
        (*ExtensionName)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTEntryMatch) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.MatchSize))
    dst = dst[2:]
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTEntryMatch) UnmarshalBytes(src []byte) []byte {
    x.MatchSize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTEntryMatch) Packed() bool {
    return x.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTEntryMatch) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTEntryMatch doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTEntryMatch) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTEntryMatch doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTEntryMatch) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTEntryMatch doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTEntryMatch) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTEntryMatch) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTEntryMatch doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTEntryMatch) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTEntryMatch) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        // Type XTEntryMatch doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTEntryTarget) SizeBytes() int {
    return 3 +
        (*ExtensionName)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTEntryTarget) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.TargetSize))
    dst = dst[2:]
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTEntryTarget) UnmarshalBytes(src []byte) []byte {
    x.TargetSize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTEntryTarget) Packed() bool {
    return x.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTEntryTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTEntryTarget doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTEntryTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTEntryTarget doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTEntryTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTEntryTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTEntryTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTEntryTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTEntryTarget doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTEntryTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTEntryTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        // Type XTEntryTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTErrorTarget) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*ErrorName)(nil).SizeBytes() +
        1*2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTErrorTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Name.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(byte)*2] ~= [2]byte{0}
    dst = dst[1*(2):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTErrorTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Name.UnmarshalUnsafe(src)
    // Padding: ~ copy([2]byte(x._), src[:sizeof(byte)*2])
    src = src[1*(2):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTErrorTarget) Packed() bool {
    return x.Name.Packed() && x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTErrorTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTErrorTarget doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTErrorTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTErrorTarget doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTErrorTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        // Type XTErrorTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTErrorTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTErrorTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        // Type XTErrorTarget doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTErrorTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTErrorTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        // Type XTErrorTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTGetRevision) SizeBytes() int {
    return 1 +
        (*ExtensionName)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTGetRevision) MarshalBytes(dst []byte) []byte {
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTGetRevision) UnmarshalBytes(src []byte) []byte {
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTGetRevision) Packed() bool {
    return x.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTGetRevision) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTGetRevision doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTGetRevision) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTGetRevision doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTGetRevision) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTGetRevision) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTGetRevision) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTGetRevision) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTGetRevision) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTNATTargetV0) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NfNATIPV4MultiRangeCompat)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTNATTargetV0) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.NfRange.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTNATTargetV0) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.NfRange.UnmarshalUnsafe(src)
    // Padding: ~ copy([4]byte(x._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV0) Packed() bool {
    return x.NfRange.Packed() && x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTNATTargetV0) MarshalUnsafe(dst []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTNATTargetV0 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTNATTargetV0) UnmarshalUnsafe(src []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTNATTargetV0 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTNATTargetV0) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTNATTargetV0 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTNATTargetV0) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTNATTargetV0) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTNATTargetV0 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTNATTargetV0) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTNATTargetV0) WriteTo(writer io.Writer) (int64, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTNATTargetV0 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTNATTargetV1) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NFNATRange)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTNATTargetV1) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Range.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTNATTargetV1) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Range.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV1) Packed() bool {
    return x.Range.Packed() && x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTNATTargetV1) MarshalUnsafe(dst []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTNATTargetV1 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTNATTargetV1) UnmarshalUnsafe(src []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTNATTargetV1 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTNATTargetV1) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV1 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTNATTargetV1) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTNATTargetV1) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV1 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTNATTargetV1) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTNATTargetV1) WriteTo(writer io.Writer) (int64, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV1 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTNATTargetV2) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NFNATRange2)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTNATTargetV2) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Range.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTNATTargetV2) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Range.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV2) Packed() bool {
    return x.Range.Packed() && x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTNATTargetV2) MarshalUnsafe(dst []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTNATTargetV2 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTNATTargetV2) UnmarshalUnsafe(src []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTNATTargetV2 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTNATTargetV2) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV2 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTNATTargetV2) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTNATTargetV2) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV2 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTNATTargetV2) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTNATTargetV2) WriteTo(writer io.Writer) (int64, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        // Type XTNATTargetV2 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTOwnerMatchInfo) SizeBytes() int {
    return 18 +
        1*2
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTOwnerMatchInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.UIDMin))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.UIDMax))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.GIDMin))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.GIDMax))
    dst = dst[4:]
    dst[0] = byte(x.Match)
    dst = dst[1:]
    dst[0] = byte(x.Invert)
    dst = dst[1:]
    // Padding: dst[:sizeof(byte)*2] ~= [2]byte{0}
    dst = dst[1*(2):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTOwnerMatchInfo) UnmarshalBytes(src []byte) []byte {
    x.UIDMin = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.UIDMax = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.GIDMin = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.GIDMax = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.Match = uint8(src[0])
    src = src[1:]
    x.Invert = uint8(src[0])
    src = src[1:]
    // Padding: ~ copy([2]byte(x._), src[:sizeof(byte)*2])
    src = src[1*(2):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTOwnerMatchInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTOwnerMatchInfo) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTOwnerMatchInfo) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTOwnerMatchInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTOwnerMatchInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTOwnerMatchInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTOwnerMatchInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTOwnerMatchInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTRedirectTarget) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NfNATIPV4MultiRangeCompat)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTRedirectTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.NfRange.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTRedirectTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.NfRange.UnmarshalUnsafe(src)
    // Padding: ~ copy([4]byte(x._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTRedirectTarget) Packed() bool {
    return x.NfRange.Packed() && x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTRedirectTarget) MarshalUnsafe(dst []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTRedirectTarget doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTRedirectTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTRedirectTarget doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTRedirectTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTRedirectTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTRedirectTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTRedirectTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTRedirectTarget doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTRedirectTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTRedirectTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        // Type XTRedirectTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTStandardTarget) SizeBytes() int {
    return 4 +
        (*XTEntryTarget)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTStandardTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.Verdict))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTStandardTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    x.Verdict = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(x._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTStandardTarget) Packed() bool {
    return x.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTStandardTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    // Type XTStandardTarget doesn't have a packed layout in memory, fallback to MarshalBytes.
    return x.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTStandardTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type XTStandardTarget doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return x.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTStandardTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        // Type XTStandardTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTStandardTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTStandardTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        // Type XTStandardTarget doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTStandardTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTStandardTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Target.Packed() {
        // Type XTStandardTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTTCP) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTTCP) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortEnd))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortEnd))
    dst = dst[2:]
    dst[0] = byte(x.Option)
    dst = dst[1:]
    dst[0] = byte(x.FlagMask)
    dst = dst[1:]
    dst[0] = byte(x.FlagCompare)
    dst = dst[1:]
    dst[0] = byte(x.InverseFlags)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTTCP) UnmarshalBytes(src []byte) []byte {
    x.SourcePortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.SourcePortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.Option = uint8(src[0])
    src = src[1:]
    x.FlagMask = uint8(src[0])
    src = src[1:]
    x.FlagCompare = uint8(src[0])
    src = src[1:]
    x.InverseFlags = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTTCP) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTTCP) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTTCP) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTTCP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTTCP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTTCP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTTCP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTTCP) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTUDP) SizeBytes() int {
    return 10
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTUDP) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortEnd))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortEnd))
    dst = dst[2:]
    dst[0] = byte(x.InverseFlags)
    dst = dst[1:]
    // Padding: dst[:sizeof(uint8)] ~= uint8(0)
    dst = dst[1:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTUDP) UnmarshalBytes(src []byte) []byte {
    x.SourcePortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.SourcePortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.InverseFlags = uint8(src[0])
    src = src[1:]
    // Padding: var _ uint8 ~= src[:sizeof(uint8)]
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTUDP) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTUDP) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTUDP) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (x *XTUDP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (x *XTUDP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (x *XTUDP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (x *XTUDP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTUDP) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TEntry) SizeBytes() int {
    return 12 +
        (*IP6TIP)(nil).SizeBytes() +
        1*4 +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TEntry) MarshalBytes(dst []byte) []byte {
    dst = i.IPv6.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    dst = i.Counters.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TEntry) UnmarshalBytes(src []byte) []byte {
    src = i.IPv6.UnmarshalUnsafe(src)
    i.NFCache = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    src = i.Counters.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TEntry) Packed() bool {
    return i.Counters.Packed() && i.IPv6.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TEntry) MarshalUnsafe(dst []byte) []byte {
    if i.Counters.Packed() && i.IPv6.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IP6TEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TEntry) UnmarshalUnsafe(src []byte) []byte {
    if i.Counters.Packed() && i.IPv6.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IP6TEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IP6TEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IP6TEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IP6TEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IP6TEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IP6TIP) SizeBytes() int {
    return 5 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TIP) MarshalBytes(dst []byte) []byte {
    dst = i.Src.MarshalUnsafe(dst)
    dst = i.Dst.MarshalUnsafe(dst)
    dst = i.SrcMask.MarshalUnsafe(dst)
    dst = i.DstMask.MarshalUnsafe(dst)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.TOS)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    // Padding: dst[:sizeof(byte)*3] ~= [3]byte{0}
    dst = dst[1*(3):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TIP) UnmarshalBytes(src []byte) []byte {
    src = i.Src.UnmarshalUnsafe(src)
    src = i.Dst.UnmarshalUnsafe(src)
    src = i.SrcMask.UnmarshalUnsafe(src)
    src = i.DstMask.UnmarshalUnsafe(src)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.TOS = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    // Padding: ~ copy([3]byte(i._), src[:sizeof(byte)*3])
    src = src[1*(3):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TIP) MarshalUnsafe(dst []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IP6TIP doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TIP) UnmarshalUnsafe(src []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IP6TIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IP6TIP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IP6TIP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IP6TIP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IP6TIP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *IP6TReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TReplace) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TReplace) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TReplace) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TReplace) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type IP6TReplace doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TReplace) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type IP6TReplace doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *IP6TReplace) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *IP6TReplace) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *IP6TReplace) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *IP6TReplace) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIP6TEntry) Packed() bool {
    // Type KernelIP6TEntry is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ke *KernelIP6TEntry) MarshalUnsafe(dst []byte) []byte {
    // Type KernelIP6TEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
    return ke.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ke *KernelIP6TEntry) UnmarshalUnsafe(src []byte) []byte {
    // Type KernelIP6TEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIP6TEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    ke.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ke *KernelIP6TEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIP6TEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIP6TEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    ke.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ke *KernelIP6TEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ke *KernelIP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    // Type KernelIP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIP6TGetEntries) Packed() bool {
    // Type KernelIP6TGetEntries is dynamic so it might have slice/string headers. Hence, it is not packed.
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ke *KernelIP6TGetEntries) MarshalUnsafe(dst []byte) []byte {
    // Type KernelIP6TGetEntries doesn't have a packed layout in memory, fallback to MarshalBytes.
    return ke.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ke *KernelIP6TGetEntries) UnmarshalUnsafe(src []byte) []byte {
    // Type KernelIP6TGetEntries doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIP6TGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIP6TGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    ke.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ke *KernelIP6TGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIP6TGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type KernelIP6TGetEntries doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(ke.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    ke.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ke *KernelIP6TGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ke *KernelIP6TGetEntries) WriteTo(writer io.Writer) (int64, error) {
    // Type KernelIP6TGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NFNATRange) SizeBytes() int {
    return 8 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NFNATRange) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.MinAddr.MarshalUnsafe(dst)
    dst = n.MaxAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxProto))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NFNATRange) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.MinAddr.UnmarshalUnsafe(src)
    src = n.MaxAddr.UnmarshalUnsafe(src)
    n.MinProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NFNATRange) Packed() bool {
    return n.MaxAddr.Packed() && n.MinAddr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NFNATRange) MarshalUnsafe(dst []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NFNATRange doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NFNATRange) UnmarshalUnsafe(src []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NFNATRange doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NFNATRange) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NFNATRange) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NFNATRange) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NFNATRange) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NFNATRange) WriteTo(writer io.Writer) (int64, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NFNATRange2) SizeBytes() int {
    return 10 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NFNATRange2) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.MinAddr.MarshalUnsafe(dst)
    dst = n.MaxAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.BaseProto))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*6] ~= [6]byte{0}
    dst = dst[1*(6):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NFNATRange2) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.MinAddr.UnmarshalUnsafe(src)
    src = n.MaxAddr.UnmarshalUnsafe(src)
    n.MinProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.BaseProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([6]byte(n._), src[:sizeof(byte)*6])
    src = src[1*(6):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NFNATRange2) Packed() bool {
    return n.MaxAddr.Packed() && n.MinAddr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NFNATRange2) MarshalUnsafe(dst []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NFNATRange2 doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NFNATRange2) UnmarshalUnsafe(src []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NFNATRange2 doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NFNATRange2) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange2 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NFNATRange2) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NFNATRange2) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange2 doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NFNATRange2) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NFNATRange2) WriteTo(writer io.Writer) (int64, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
        // Type NFNATRange2 doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NetlinkAttrHeader) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NetlinkAttrHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Length))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Type))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NetlinkAttrHeader) UnmarshalBytes(src []byte) []byte {
    n.Length = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkAttrHeader) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NetlinkAttrHeader) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NetlinkAttrHeader) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NetlinkAttrHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NetlinkAttrHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NetlinkAttrHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NetlinkAttrHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NetlinkAttrHeader) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NetlinkErrorMessage) SizeBytes() int {
    return 4 +
        (*NetlinkMessageHeader)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NetlinkErrorMessage) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Error))
    dst = dst[4:]
    dst = n.Header.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NetlinkErrorMessage) UnmarshalBytes(src []byte) []byte {
    n.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Header.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkErrorMessage) Packed() bool {
    return n.Header.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NetlinkErrorMessage) MarshalUnsafe(dst []byte) []byte {
    if n.Header.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    // Type NetlinkErrorMessage doesn't have a packed layout in memory, fallback to MarshalBytes.
    return n.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NetlinkErrorMessage) UnmarshalUnsafe(src []byte) []byte {
    if n.Header.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type NetlinkErrorMessage doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return n.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NetlinkErrorMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Header.Packed() {
        // Type NetlinkErrorMessage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NetlinkErrorMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NetlinkErrorMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Header.Packed() {
        // Type NetlinkErrorMessage doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NetlinkErrorMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NetlinkErrorMessage) WriteTo(writer io.Writer) (int64, error) {
    if !n.Header.Packed() {
        // Type NetlinkErrorMessage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *NetlinkMessageHeader) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NetlinkMessageHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Length))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Flags))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Seq))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PortID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NetlinkMessageHeader) UnmarshalBytes(src []byte) []byte {
    n.Length = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Flags = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Seq = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PortID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkMessageHeader) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NetlinkMessageHeader) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NetlinkMessageHeader) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (n *NetlinkMessageHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (n *NetlinkMessageHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (n *NetlinkMessageHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (n *NetlinkMessageHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NetlinkMessageHeader) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrNetlink) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrNetlink) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.PortID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Groups))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrNetlink) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    s.PortID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Groups = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrNetlink) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrNetlink) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrNetlink) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockAddrNetlink) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SockAddrNetlink) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockAddrNetlink) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockAddrNetlink) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrNetlink) WriteTo(writer io.Writer) (int64, error) {
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
func (i *InterfaceAddrMessage) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InterfaceAddrMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Family)
    dst = dst[1:]
    dst[0] = byte(i.PrefixLen)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.Scope)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Index))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InterfaceAddrMessage) UnmarshalBytes(src []byte) []byte {
    i.Family = uint8(src[0])
    src = src[1:]
    i.PrefixLen = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.Scope = uint8(src[0])
    src = src[1:]
    i.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InterfaceAddrMessage) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InterfaceAddrMessage) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InterfaceAddrMessage) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InterfaceAddrMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InterfaceAddrMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InterfaceAddrMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InterfaceAddrMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InterfaceAddrMessage) WriteTo(writer io.Writer) (int64, error) {
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
func (i *InterfaceInfoMessage) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InterfaceInfoMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Family)
    dst = dst[1:]
    // Padding: dst[:sizeof(uint8)] ~= uint8(0)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Change))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InterfaceInfoMessage) UnmarshalBytes(src []byte) []byte {
    i.Family = uint8(src[0])
    src = src[1:]
    // Padding: var _ uint8 ~= src[:sizeof(uint8)]
    src = src[1:]
    i.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Index = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Change = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InterfaceInfoMessage) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InterfaceInfoMessage) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InterfaceInfoMessage) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InterfaceInfoMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InterfaceInfoMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InterfaceInfoMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InterfaceInfoMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InterfaceInfoMessage) WriteTo(writer io.Writer) (int64, error) {
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
func (r *RouteMessage) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RouteMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(r.Family)
    dst = dst[1:]
    dst[0] = byte(r.DstLen)
    dst = dst[1:]
    dst[0] = byte(r.SrcLen)
    dst = dst[1:]
    dst[0] = byte(r.TOS)
    dst = dst[1:]
    dst[0] = byte(r.Table)
    dst = dst[1:]
    dst[0] = byte(r.Protocol)
    dst = dst[1:]
    dst[0] = byte(r.Scope)
    dst = dst[1:]
    dst[0] = byte(r.Type)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RouteMessage) UnmarshalBytes(src []byte) []byte {
    r.Family = uint8(src[0])
    src = src[1:]
    r.DstLen = uint8(src[0])
    src = src[1:]
    r.SrcLen = uint8(src[0])
    src = src[1:]
    r.TOS = uint8(src[0])
    src = src[1:]
    r.Table = uint8(src[0])
    src = src[1:]
    r.Protocol = uint8(src[0])
    src = src[1:]
    r.Scope = uint8(src[0])
    src = src[1:]
    r.Type = uint8(src[0])
    src = src[1:]
    r.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RouteMessage) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RouteMessage) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RouteMessage) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RouteMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RouteMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RouteMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RouteMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RouteMessage) WriteTo(writer io.Writer) (int64, error) {
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
func (r *RtAttr) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RtAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Len))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Type))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RtAttr) UnmarshalBytes(src []byte) []byte {
    r.Len = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    r.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RtAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RtAttr) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RtAttr) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RtAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RtAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RtAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RtAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RtAttr) WriteTo(writer io.Writer) (int64, error) {
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
func (p *PollFD) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *PollFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.Events))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.REvents))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *PollFD) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Events = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.REvents = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PollFD) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *PollFD) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *PollFD) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (p *PollFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (p *PollFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (p *PollFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (p *PollFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *PollFD) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyPollFDSliceIn copies in a slice of PollFD objects from the task's memory.
func CopyPollFDSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []PollFD) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

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

// CopyPollFDSliceOut copies a slice of PollFD objects to the task's memory.
func CopyPollFDSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []PollFD) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

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

// MarshalUnsafePollFDSlice is like PollFD.MarshalUnsafe, but for a []PollFD.
func MarshalUnsafePollFDSlice(src []PollFD, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*PollFD)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafePollFDSlice is like PollFD.UnmarshalUnsafe, but for a []PollFD.
func UnmarshalUnsafePollFDSlice(dst []PollFD, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*PollFD)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RSeqCriticalSection) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RSeqCriticalSection) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.PostCommitOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.Abort))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RSeqCriticalSection) UnmarshalBytes(src []byte) []byte {
    r.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Start = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.PostCommitOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.Abort = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RSeqCriticalSection) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RSeqCriticalSection) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RSeqCriticalSection) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *RSeqCriticalSection) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (r *RSeqCriticalSection) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *RSeqCriticalSection) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *RSeqCriticalSection) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RSeqCriticalSection) WriteTo(writer io.Writer) (int64, error) {
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
func (r *Rusage) SizeBytes() int {
    return 112 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *Rusage) MarshalBytes(dst []byte) []byte {
    dst = r.UTime.MarshalUnsafe(dst)
    dst = r.STime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MaxRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.IXRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.IDRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.ISRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MinFlt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MajFlt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.InBlock))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.OuBlock))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MsgSnd))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MsgRcv))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NSignals))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NVCSw))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NIvCSw))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *Rusage) UnmarshalBytes(src []byte) []byte {
    src = r.UTime.UnmarshalUnsafe(src)
    src = r.STime.UnmarshalUnsafe(src)
    r.MaxRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IXRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IDRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ISRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MinFlt = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MajFlt = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSwap = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.InBlock = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.OuBlock = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgSnd = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgRcv = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSignals = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NVCSw = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NIvCSw = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *Rusage) Packed() bool {
    return r.STime.Packed() && r.UTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *Rusage) MarshalUnsafe(dst []byte) []byte {
    if r.STime.Packed() && r.UTime.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    // Type Rusage doesn't have a packed layout in memory, fallback to MarshalBytes.
    return r.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *Rusage) UnmarshalUnsafe(src []byte) []byte {
    if r.STime.Packed() && r.UTime.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Rusage doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (r *Rusage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        r.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (r *Rusage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (r *Rusage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        r.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (r *Rusage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *Rusage) WriteTo(writer io.Writer) (int64, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (sd *SeccompData) SizeBytes() int {
    return 16 +
        8*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (sd *SeccompData) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sd.Nr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sd.Arch))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sd.InstructionPointer))
    dst = dst[8:]
    for idx := 0; idx < 6; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(sd.Args[idx]))
        dst = dst[8:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (sd *SeccompData) UnmarshalBytes(src []byte) []byte {
    sd.Nr = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sd.Arch = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sd.InstructionPointer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 6; idx++ {
        sd.Args[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (sd *SeccompData) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (sd *SeccompData) MarshalUnsafe(dst []byte) []byte {
    size := sd.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(sd), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (sd *SeccompData) UnmarshalUnsafe(src []byte) []byte {
    size := sd.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(sd), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (sd *SeccompData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sd
    // must live until the use above.
    runtime.KeepAlive(sd) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (sd *SeccompData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sd.CopyOutN(cc, addr, sd.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (sd *SeccompData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sd
    // must live until the use above.
    runtime.KeepAlive(sd) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (sd *SeccompData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sd.CopyInN(cc, addr, sd.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (sd *SeccompData) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that sd
    // must live until the use above.
    runtime.KeepAlive(sd) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SeccompNotif) SizeBytes() int {
    return 16 +
        (*SeccompData)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SeccompNotif) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Pid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    dst = s.Data.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SeccompNotif) UnmarshalBytes(src []byte) []byte {
    s.ID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = s.Data.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotif) Packed() bool {
    return s.Data.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SeccompNotif) MarshalUnsafe(dst []byte) []byte {
    if s.Data.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SeccompNotif doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SeccompNotif) UnmarshalUnsafe(src []byte) []byte {
    if s.Data.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SeccompNotif doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SeccompNotif) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Data.Packed() {
        // Type SeccompNotif doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SeccompNotif) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SeccompNotif) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Data.Packed() {
        // Type SeccompNotif doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SeccompNotif) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SeccompNotif) WriteTo(writer io.Writer) (int64, error) {
    if !s.Data.Packed() {
        // Type SeccompNotif doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SeccompNotifResp) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SeccompNotifResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Val))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Error))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SeccompNotifResp) UnmarshalBytes(src []byte) []byte {
    s.ID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Val = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotifResp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SeccompNotifResp) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SeccompNotifResp) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SeccompNotifResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SeccompNotifResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SeccompNotifResp) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SeccompNotifResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SeccompNotifResp) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SeccompNotifSizes) SizeBytes() int {
    return 6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SeccompNotifSizes) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Notif))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Notif_resp))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Data))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SeccompNotifSizes) UnmarshalBytes(src []byte) []byte {
    s.Notif = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Notif_resp = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Data = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotifSizes) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SeccompNotifSizes) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SeccompNotifSizes) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SeccompNotifSizes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SeccompNotifSizes) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SeccompNotifSizes) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SeccompNotifSizes) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SeccompNotifSizes) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SemInfo) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SemInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMap))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMni))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMns))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMnu))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMsl))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemOpm))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemUme))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemUsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemVmx))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemAem))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SemInfo) UnmarshalBytes(src []byte) []byte {
    s.SemMap = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMni = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMns = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMnu = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMsl = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemOpm = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemUme = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemUsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemVmx = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemAem = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SemInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SemInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SemInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SemInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SemInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SemInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SemInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SemInfo) WriteTo(writer io.Writer) (int64, error) {
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
func (s *Sembuf) SizeBytes() int {
    return 6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sembuf) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemNum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemOp))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemFlg))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sembuf) UnmarshalBytes(src []byte) []byte {
    s.SemNum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemOp = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemFlg = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sembuf) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sembuf) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sembuf) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Sembuf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *Sembuf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *Sembuf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Sembuf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sembuf) WriteTo(writer io.Writer) (int64, error) {
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

// CopySembufSliceIn copies in a slice of Sembuf objects from the task's memory.
func CopySembufSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Sembuf) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

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

// CopySembufSliceOut copies a slice of Sembuf objects to the task's memory.
func CopySembufSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Sembuf) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

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

// MarshalUnsafeSembufSlice is like Sembuf.MarshalUnsafe, but for a []Sembuf.
func MarshalUnsafeSembufSlice(src []Sembuf, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Sembuf)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeSembufSlice is like Sembuf.UnmarshalUnsafe, but for a []Sembuf.
func UnmarshalUnsafeSembufSlice(dst []Sembuf, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Sembuf)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *ShmInfo) SizeBytes() int {
    return 44 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UsedIDs))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmTot))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmRss))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSwp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SwapAttempts))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SwapSuccesses))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmInfo) UnmarshalBytes(src []byte) []byte {
    s.UsedIDs = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(s._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    s.ShmTot = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmRss = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSwp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapAttempts = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapSuccesses = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *ShmInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *ShmInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *ShmInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *ShmInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmInfo) WriteTo(writer io.Writer) (int64, error) {
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
func (s *ShmParams) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMax))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMin))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMni))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSeg))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmAll))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmParams) UnmarshalBytes(src []byte) []byte {
    s.ShmMax = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMin = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMni = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSeg = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmAll = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmParams) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmParams) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *ShmParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *ShmParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *ShmParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *ShmParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmParams) WriteTo(writer io.Writer) (int64, error) {
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
func (s *ShmidDS) SizeBytes() int {
    return 40 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmidDS) MarshalBytes(dst []byte) []byte {
    dst = s.ShmPerm.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSegsz))
    dst = dst[8:]
    dst = s.ShmAtime.MarshalUnsafe(dst)
    dst = s.ShmDtime.MarshalUnsafe(dst)
    dst = s.ShmCtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.ShmCpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.ShmLpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmNattach))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Unused4))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Unused5))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmidDS) UnmarshalBytes(src []byte) []byte {
    src = s.ShmPerm.UnmarshalUnsafe(src)
    s.ShmSegsz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.ShmAtime.UnmarshalUnsafe(src)
    src = s.ShmDtime.UnmarshalUnsafe(src)
    src = s.ShmCtime.UnmarshalUnsafe(src)
    s.ShmCpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmLpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmNattach = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused4 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused5 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmidDS) Packed() bool {
    return s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmidDS) MarshalUnsafe(dst []byte) []byte {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type ShmidDS doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmidDS) UnmarshalUnsafe(src []byte) []byte {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ShmidDS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *ShmidDS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *ShmidDS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *ShmidDS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *ShmidDS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmidDS) WriteTo(writer io.Writer) (int64, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SigAction) SizeBytes() int {
    return 24 +
        (*SignalSet)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SigAction) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Handler))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Restorer))
    dst = dst[8:]
    dst = s.Mask.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SigAction) UnmarshalBytes(src []byte) []byte {
    s.Handler = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Restorer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.Mask.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SigAction) Packed() bool {
    return s.Mask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SigAction) MarshalUnsafe(dst []byte) []byte {
    if s.Mask.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SigAction doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SigAction) UnmarshalUnsafe(src []byte) []byte {
    if s.Mask.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SigAction doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SigAction) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Mask.Packed() {
        // Type SigAction doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SigAction) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SigAction) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Mask.Packed() {
        // Type SigAction doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SigAction) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SigAction) WriteTo(writer io.Writer) (int64, error) {
    if !s.Mask.Packed() {
        // Type SigAction doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *Sigevent) SizeBytes() int {
    return 20 +
        1*44
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sigevent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Value))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Notify))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Tid))
    dst = dst[4:]
    for idx := 0; idx < 44; idx++ {
        dst[0] = byte(s.UnRemainder[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sigevent) UnmarshalBytes(src []byte) []byte {
    s.Value = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Signo = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Notify = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Tid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 44; idx++ {
        s.UnRemainder[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sigevent) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sigevent) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sigevent) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *Sigevent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *Sigevent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *Sigevent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *Sigevent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sigevent) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SignalInfo) MarshalBytes(dst []byte) []byte {
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
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalInfo) UnmarshalBytes(src []byte) []byte {
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
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
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
func (s *SignalInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SignalInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SignalInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
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
//go:nosplit
func (s *SignalSet) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalSet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*s))
    return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalSet) UnmarshalBytes(src []byte) []byte {
    *s = SignalSet(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalSet) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalSet) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalSet) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SignalSet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SignalSet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SignalSet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SignalSet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalSet) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SignalStack) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalStack) UnmarshalBytes(src []byte) []byte {
    s.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    s.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalStack) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalStack) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalStack) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SignalStack) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SignalStack) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SignalStack) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SignalStack) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SignalfdSiginfo) SizeBytes() int {
    return 82 +
        1*48
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalfdSiginfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.TID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Band))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Overrun))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.TrapNo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Int))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Ptr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.UTime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.STime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.AddrLSB))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint8)*48] ~= [48]uint8{0}
    dst = dst[1*(48):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalfdSiginfo) UnmarshalBytes(src []byte) []byte {
    s.Signo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Band = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Overrun = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TrapNo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Status = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Int = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Ptr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.UTime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.STime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AddrLSB = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([48]uint8(s._), src[:sizeof(uint8)*48])
    src = src[1*(48):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalfdSiginfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalfdSiginfo) MarshalUnsafe(dst []byte) []byte {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalfdSiginfo) UnmarshalUnsafe(src []byte) []byte {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SignalfdSiginfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    s.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (s *SignalfdSiginfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SignalfdSiginfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    s.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SignalfdSiginfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalfdSiginfo) WriteTo(writer io.Writer) (int64, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageCredentials) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageCredentials) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.GID))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageCredentials) UnmarshalBytes(src []byte) []byte {
    c.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageCredentials) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageCredentials) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageCredentials) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *ControlMessageCredentials) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *ControlMessageCredentials) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *ControlMessageCredentials) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *ControlMessageCredentials) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageCredentials) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageHeader) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Level))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Type))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageHeader) UnmarshalBytes(src []byte) []byte {
    c.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Level = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Type = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageHeader) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageHeader) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageHeader) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *ControlMessageHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *ControlMessageHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *ControlMessageHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *ControlMessageHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageHeader) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageIPPacketInfo) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageIPPacketInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.NIC))
    dst = dst[4:]
    dst = c.LocalAddr.MarshalUnsafe(dst)
    dst = c.DestinationAddr.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageIPPacketInfo) UnmarshalBytes(src []byte) []byte {
    c.NIC = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = c.LocalAddr.UnmarshalUnsafe(src)
    src = c.DestinationAddr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageIPPacketInfo) Packed() bool {
    return c.DestinationAddr.Packed() && c.LocalAddr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageIPPacketInfo) MarshalUnsafe(dst []byte) []byte {
    if c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    // Type ControlMessageIPPacketInfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return c.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageIPPacketInfo) UnmarshalUnsafe(src []byte) []byte {
    if c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ControlMessageIPPacketInfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return c.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *ControlMessageIPPacketInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        // Type ControlMessageIPPacketInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        c.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *ControlMessageIPPacketInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *ControlMessageIPPacketInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        // Type ControlMessageIPPacketInfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        c.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *ControlMessageIPPacketInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageIPPacketInfo) WriteTo(writer io.Writer) (int64, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        // Type ControlMessageIPPacketInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageIPv6PacketInfo) SizeBytes() int {
    return 4 +
        (*Inet6Addr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageIPv6PacketInfo) MarshalBytes(dst []byte) []byte {
    dst = c.Addr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.NIC))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageIPv6PacketInfo) UnmarshalBytes(src []byte) []byte {
    src = c.Addr.UnmarshalUnsafe(src)
    c.NIC = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageIPv6PacketInfo) Packed() bool {
    return c.Addr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageIPv6PacketInfo) MarshalUnsafe(dst []byte) []byte {
    if c.Addr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    // Type ControlMessageIPv6PacketInfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    return c.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageIPv6PacketInfo) UnmarshalUnsafe(src []byte) []byte {
    if c.Addr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ControlMessageIPv6PacketInfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return c.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *ControlMessageIPv6PacketInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.Addr.Packed() {
        // Type ControlMessageIPv6PacketInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        c.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *ControlMessageIPv6PacketInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *ControlMessageIPv6PacketInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.Addr.Packed() {
        // Type ControlMessageIPv6PacketInfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(c.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        c.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *ControlMessageIPv6PacketInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageIPv6PacketInfo) WriteTo(writer io.Writer) (int64, error) {
    if !c.Addr.Packed() {
        // Type ControlMessageIPv6PacketInfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *ICMP6Filter) SizeBytes() int {
    return 0 +
        4*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *ICMP6Filter) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 8; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Filter[idx]))
        dst = dst[4:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *ICMP6Filter) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 8; idx++ {
        i.Filter[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *ICMP6Filter) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *ICMP6Filter) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *ICMP6Filter) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *ICMP6Filter) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *ICMP6Filter) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *ICMP6Filter) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *ICMP6Filter) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *ICMP6Filter) WriteTo(writer io.Writer) (int64, error) {
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
//go:nosplit
func (i *Inet6Addr) SizeBytes() int {
    return 1 * 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inet6Addr) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inet6Addr) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6Addr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inet6Addr) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&i[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inet6Addr) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *Inet6Addr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *Inet6Addr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *Inet6Addr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *Inet6Addr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Inet6Addr) WriteTo(writer io.Writer) (int64, error) {
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
func (i *Inet6MulticastRequest) SizeBytes() int {
    return 4 +
        (*Inet6Addr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inet6MulticastRequest) MarshalBytes(dst []byte) []byte {
    dst = i.MulticastAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.InterfaceIndex))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inet6MulticastRequest) UnmarshalBytes(src []byte) []byte {
    src = i.MulticastAddr.UnmarshalUnsafe(src)
    i.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6MulticastRequest) Packed() bool {
    return i.MulticastAddr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inet6MulticastRequest) MarshalUnsafe(dst []byte) []byte {
    if i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type Inet6MulticastRequest doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inet6MulticastRequest) UnmarshalUnsafe(src []byte) []byte {
    if i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Inet6MulticastRequest doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *Inet6MulticastRequest) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.MulticastAddr.Packed() {
        // Type Inet6MulticastRequest doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *Inet6MulticastRequest) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *Inet6MulticastRequest) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.MulticastAddr.Packed() {
        // Type Inet6MulticastRequest doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *Inet6MulticastRequest) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Inet6MulticastRequest) WriteTo(writer io.Writer) (int64, error) {
    if !i.MulticastAddr.Packed() {
        // Type Inet6MulticastRequest doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
//go:nosplit
func (i *InetAddr) SizeBytes() int {
    return 1 * 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InetAddr) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InetAddr) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 4; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetAddr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InetAddr) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&i[0]), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InetAddr) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InetAddr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InetAddr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InetAddr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (i *InetAddr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InetAddr) WriteTo(writer io.Writer) (int64, error) {
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
func (i *InetMulticastRequest) SizeBytes() int {
    return 0 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InetMulticastRequest) MarshalBytes(dst []byte) []byte {
    dst = i.MulticastAddr.MarshalUnsafe(dst)
    dst = i.InterfaceAddr.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InetMulticastRequest) UnmarshalBytes(src []byte) []byte {
    src = i.MulticastAddr.UnmarshalUnsafe(src)
    src = i.InterfaceAddr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetMulticastRequest) Packed() bool {
    return i.InterfaceAddr.Packed() && i.MulticastAddr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InetMulticastRequest) MarshalUnsafe(dst []byte) []byte {
    if i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type InetMulticastRequest doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InetMulticastRequest) UnmarshalUnsafe(src []byte) []byte {
    if i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type InetMulticastRequest doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InetMulticastRequest) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        // Type InetMulticastRequest doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *InetMulticastRequest) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InetMulticastRequest) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        // Type InetMulticastRequest doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *InetMulticastRequest) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InetMulticastRequest) WriteTo(writer io.Writer) (int64, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        // Type InetMulticastRequest doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *InetMulticastRequestWithNIC) SizeBytes() int {
    return 4 +
        (*InetMulticastRequest)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InetMulticastRequestWithNIC) MarshalBytes(dst []byte) []byte {
    dst = i.InetMulticastRequest.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.InterfaceIndex))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InetMulticastRequestWithNIC) UnmarshalBytes(src []byte) []byte {
    src = i.InetMulticastRequest.UnmarshalUnsafe(src)
    i.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetMulticastRequestWithNIC) Packed() bool {
    return i.InetMulticastRequest.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InetMulticastRequestWithNIC) MarshalUnsafe(dst []byte) []byte {
    if i.InetMulticastRequest.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type InetMulticastRequestWithNIC doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InetMulticastRequestWithNIC) UnmarshalUnsafe(src []byte) []byte {
    if i.InetMulticastRequest.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type InetMulticastRequestWithNIC doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *InetMulticastRequestWithNIC) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InetMulticastRequest.Packed() {
        // Type InetMulticastRequestWithNIC doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *InetMulticastRequestWithNIC) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *InetMulticastRequestWithNIC) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InetMulticastRequest.Packed() {
        // Type InetMulticastRequestWithNIC doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *InetMulticastRequestWithNIC) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InetMulticastRequestWithNIC) WriteTo(writer io.Writer) (int64, error) {
    if !i.InetMulticastRequest.Packed() {
        // Type InetMulticastRequestWithNIC doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (l *Linger) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *Linger) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(l.OnOff))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(l.Linger))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *Linger) UnmarshalBytes(src []byte) []byte {
    l.OnOff = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    l.Linger = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (l *Linger) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (l *Linger) MarshalUnsafe(dst []byte) []byte {
    size := l.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(l), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (l *Linger) UnmarshalUnsafe(src []byte) []byte {
    size := l.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(l), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (l *Linger) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (l *Linger) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return l.CopyOutN(cc, addr, l.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (l *Linger) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (l *Linger) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return l.CopyInN(cc, addr, l.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (l *Linger) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrInet) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        1*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrInet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    dst = s.Addr.MarshalUnsafe(dst)
    // Padding: dst[:sizeof(uint8)*8] ~= [8]uint8{0}
    dst = dst[1*(8):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrInet) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = s.Addr.UnmarshalUnsafe(src)
    // Padding: ~ copy([8]uint8(s._), src[:sizeof(uint8)*8])
    src = src[1*(8):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet) Packed() bool {
    return s.Addr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrInet) MarshalUnsafe(dst []byte) []byte {
    if s.Addr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    // Type SockAddrInet doesn't have a packed layout in memory, fallback to MarshalBytes.
    return s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrInet) UnmarshalUnsafe(src []byte) []byte {
    if s.Addr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type SockAddrInet doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockAddrInet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockAddrInet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockAddrInet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
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

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockAddrInet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrInet) WriteTo(writer io.Writer) (int64, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
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
func (s *SockAddrInet6) SizeBytes() int {
    return 12 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrInet6) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flowinfo))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(s.Addr[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Scope_id))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrInet6) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Flowinfo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        s.Addr[idx] = src[0]
        src = src[1:]
    }
    s.Scope_id = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet6) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrInet6) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrInet6) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockAddrInet6) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SockAddrInet6) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockAddrInet6) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockAddrInet6) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrInet6) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SockAddrLink) SizeBytes() int {
    return 12 +
        1*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrLink) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Protocol))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.InterfaceIndex))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.ARPHardwareType))
    dst = dst[2:]
    dst[0] = byte(s.PacketType)
    dst = dst[1:]
    dst[0] = byte(s.HardwareAddrLen)
    dst = dst[1:]
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(s.HardwareAddr[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrLink) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ARPHardwareType = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.PacketType = src[0]
    src = src[1:]
    s.HardwareAddrLen = src[0]
    src = src[1:]
    for idx := 0; idx < 8; idx++ {
        s.HardwareAddr[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrLink) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrLink) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrLink) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockAddrLink) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SockAddrLink) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockAddrLink) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockAddrLink) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrLink) WriteTo(writer io.Writer) (int64, error) {
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
func (s *SockAddrUnix) SizeBytes() int {
    return 2 +
        1*UnixPathMax
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrUnix) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        dst[0] = byte(s.Path[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrUnix) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        s.Path[idx] = int8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrUnix) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrUnix) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrUnix) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (s *SockAddrUnix) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (s *SockAddrUnix) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (s *SockAddrUnix) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (s *SockAddrUnix) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrUnix) WriteTo(writer io.Writer) (int64, error) {
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
func (t *TCPInfo) SizeBytes() int {
    return 224
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TCPInfo) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(t.State)
    dst = dst[1:]
    dst[0] = byte(t.CaState)
    dst = dst[1:]
    dst[0] = byte(t.Retransmits)
    dst = dst[1:]
    dst[0] = byte(t.Probes)
    dst = dst[1:]
    dst[0] = byte(t.Backoff)
    dst = dst[1:]
    dst[0] = byte(t.Options)
    dst = dst[1:]
    dst[0] = byte(t.WindowScale)
    dst = dst[1:]
    dst[0] = byte(t.DeliveryRateAppLimited)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTO))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ATO))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndMss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvMss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Unacked))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Sacked))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Lost))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Retrans))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Fackets))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataSent))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckSent))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataRecv))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckRecv))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.PMTU))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSsthresh))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTTVar))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndSsthresh))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndCwnd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Advmss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Reordering))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvRTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSpace))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TotalRetrans))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.PacingRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.MaxPacingRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesAcked))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesReceived))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SegsOut))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SegsIn))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.NotSentBytes))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.MinRTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsIn))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsOut))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.DeliveryRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BusyTime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.RwndLimited))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.SndBufLimited))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Delivered))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DeliveredCE))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesSent))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesRetrans))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DSACKDups))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ReordSeen))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TCPInfo) UnmarshalBytes(src []byte) []byte {
    t.State = uint8(src[0])
    src = src[1:]
    t.CaState = uint8(src[0])
    src = src[1:]
    t.Retransmits = uint8(src[0])
    src = src[1:]
    t.Probes = uint8(src[0])
    src = src[1:]
    t.Backoff = uint8(src[0])
    src = src[1:]
    t.Options = uint8(src[0])
    src = src[1:]
    t.WindowScale = uint8(src[0])
    src = src[1:]
    t.DeliveryRateAppLimited = uint8(src[0])
    src = src[1:]
    t.RTO = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ATO = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndMss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvMss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Unacked = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Sacked = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Lost = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Retrans = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Fackets = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataSent = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckSent = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataRecv = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckRecv = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PMTU = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSsthresh = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTTVar = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndSsthresh = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndCwnd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Advmss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Reordering = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvRTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSpace = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TotalRetrans = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PacingRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.MaxPacingRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesAcked = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesReceived = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SegsOut = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SegsIn = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.NotSentBytes = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.MinRTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsIn = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsOut = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveryRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BusyTime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.RwndLimited = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SndBufLimited = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Delivered = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveredCE = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.BytesSent = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesRetrans = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.DSACKDups = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ReordSeen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TCPInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TCPInfo) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TCPInfo) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *TCPInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *TCPInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (t *TCPInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *TCPInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TCPInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (c *ClockT) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ClockT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*c))
    return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ClockT) UnmarshalBytes(src []byte) []byte {
    *c = ClockT(int64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ClockT) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ClockT) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ClockT) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (c *ClockT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (c *ClockT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (c *ClockT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (c *ClockT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ClockT) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *ItimerVal) SizeBytes() int {
    return 0 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *ItimerVal) MarshalBytes(dst []byte) []byte {
    dst = i.Interval.MarshalUnsafe(dst)
    dst = i.Value.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *ItimerVal) UnmarshalBytes(src []byte) []byte {
    src = i.Interval.UnmarshalUnsafe(src)
    src = i.Value.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *ItimerVal) Packed() bool {
    return i.Interval.Packed() && i.Value.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *ItimerVal) MarshalUnsafe(dst []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type ItimerVal doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *ItimerVal) UnmarshalUnsafe(src []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type ItimerVal doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *ItimerVal) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *ItimerVal) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *ItimerVal) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *ItimerVal) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *ItimerVal) WriteTo(writer io.Writer) (int64, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (i *Itimerspec) SizeBytes() int {
    return 0 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Itimerspec) MarshalBytes(dst []byte) []byte {
    dst = i.Interval.MarshalUnsafe(dst)
    dst = i.Value.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Itimerspec) UnmarshalBytes(src []byte) []byte {
    src = i.Interval.UnmarshalUnsafe(src)
    src = i.Value.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Itimerspec) Packed() bool {
    return i.Interval.Packed() && i.Value.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Itimerspec) MarshalUnsafe(dst []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    // Type Itimerspec doesn't have a packed layout in memory, fallback to MarshalBytes.
    return i.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Itimerspec) UnmarshalUnsafe(src []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Itimerspec doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return i.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (i *Itimerspec) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (i *Itimerspec) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (i *Itimerspec) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (i *Itimerspec) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Itimerspec) WriteTo(writer io.Writer) (int64, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

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
func (sxts *StatxTimestamp) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (sxts *StatxTimestamp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sxts.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sxts.Nsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (sxts *StatxTimestamp) UnmarshalBytes(src []byte) []byte {
    sxts.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    sxts.Nsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (sxts *StatxTimestamp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (sxts *StatxTimestamp) MarshalUnsafe(dst []byte) []byte {
    size := sxts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(sxts), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (sxts *StatxTimestamp) UnmarshalUnsafe(src []byte) []byte {
    size := sxts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(sxts), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (sxts *StatxTimestamp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sxts
    // must live until the use above.
    runtime.KeepAlive(sxts) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (sxts *StatxTimestamp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sxts.CopyOutN(cc, addr, sxts.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (sxts *StatxTimestamp) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that sxts
    // must live until the use above.
    runtime.KeepAlive(sxts) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (sxts *StatxTimestamp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sxts.CopyInN(cc, addr, sxts.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (sxts *StatxTimestamp) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that sxts
    // must live until the use above.
    runtime.KeepAlive(sxts) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimeT) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TimeT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*t))
    return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TimeT) UnmarshalBytes(src []byte) []byte {
    *t = TimeT(int64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimeT) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TimeT) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TimeT) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *TimeT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *TimeT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (t *TimeT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *TimeT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TimeT) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimerID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TimerID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*t))
    return dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TimerID) UnmarshalBytes(src []byte) []byte {
    *t = TimerID(int32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimerID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TimerID) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TimerID) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *TimerID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *TimerID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (t *TimerID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *TimerID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TimerID) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (ts *Timespec) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (ts *Timespec) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(ts.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(ts.Nsec))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (ts *Timespec) UnmarshalBytes(src []byte) []byte {
    ts.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    ts.Nsec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ts *Timespec) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (ts *Timespec) MarshalUnsafe(dst []byte) []byte {
    size := ts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(ts), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (ts *Timespec) UnmarshalUnsafe(src []byte) []byte {
    size := ts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(ts), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (ts *Timespec) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that ts
    // must live until the use above.
    runtime.KeepAlive(ts) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (ts *Timespec) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ts.CopyOutN(cc, addr, ts.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (ts *Timespec) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that ts
    // must live until the use above.
    runtime.KeepAlive(ts) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (ts *Timespec) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ts.CopyInN(cc, addr, ts.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (ts *Timespec) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that ts
    // must live until the use above.
    runtime.KeepAlive(ts) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyTimespecSliceIn copies in a slice of Timespec objects from the task's memory.
func CopyTimespecSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Timespec) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

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

// CopyTimespecSliceOut copies a slice of Timespec objects to the task's memory.
func CopyTimespecSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Timespec) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

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

// MarshalUnsafeTimespecSlice is like Timespec.MarshalUnsafe, but for a []Timespec.
func MarshalUnsafeTimespecSlice(src []Timespec, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Timespec)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeTimespecSlice is like Timespec.UnmarshalUnsafe, but for a []Timespec.
func UnmarshalUnsafeTimespecSlice(dst []Timespec, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Timespec)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (tv *Timeval) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (tv *Timeval) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(tv.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(tv.Usec))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (tv *Timeval) UnmarshalBytes(src []byte) []byte {
    tv.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    tv.Usec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (tv *Timeval) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (tv *Timeval) MarshalUnsafe(dst []byte) []byte {
    size := tv.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(tv), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (tv *Timeval) UnmarshalUnsafe(src []byte) []byte {
    size := tv.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(tv), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (tv *Timeval) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tv
    // must live until the use above.
    runtime.KeepAlive(tv) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (tv *Timeval) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tv.CopyOutN(cc, addr, tv.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (tv *Timeval) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that tv
    // must live until the use above.
    runtime.KeepAlive(tv) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (tv *Timeval) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tv.CopyInN(cc, addr, tv.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (tv *Timeval) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that tv
    // must live until the use above.
    runtime.KeepAlive(tv) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyTimevalSliceIn copies in a slice of Timeval objects from the task's memory.
func CopyTimevalSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Timeval) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

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

// CopyTimevalSliceOut copies a slice of Timeval objects to the task's memory.
func CopyTimevalSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Timeval) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

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

// MarshalUnsafeTimevalSlice is like Timeval.MarshalUnsafe, but for a []Timeval.
func MarshalUnsafeTimevalSlice(src []Timeval, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Timeval)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

// UnmarshalUnsafeTimevalSlice is like Timeval.UnmarshalUnsafe, but for a []Timeval.
func UnmarshalUnsafeTimevalSlice(dst []Timeval, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Timeval)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Tms) SizeBytes() int {
    return 0 +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Tms) MarshalBytes(dst []byte) []byte {
    dst = t.UTime.MarshalUnsafe(dst)
    dst = t.STime.MarshalUnsafe(dst)
    dst = t.CUTime.MarshalUnsafe(dst)
    dst = t.CSTime.MarshalUnsafe(dst)
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Tms) UnmarshalBytes(src []byte) []byte {
    src = t.UTime.UnmarshalUnsafe(src)
    src = t.STime.UnmarshalUnsafe(src)
    src = t.CUTime.UnmarshalUnsafe(src)
    src = t.CSTime.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Tms) Packed() bool {
    return t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Tms) MarshalUnsafe(dst []byte) []byte {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        size := t.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
        return dst[size:]
    }
    // Type Tms doesn't have a packed layout in memory, fallback to MarshalBytes.
    return t.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Tms) UnmarshalUnsafe(src []byte) []byte {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        size := t.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    // Type Tms doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    return t.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *Tms) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(t.SizeBytes()) // escapes: okay.
        t.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *Tms) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (t *Tms) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(t.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        t.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *Tms) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Tms) WriteTo(writer io.Writer) (int64, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, t.SizeBytes())
        t.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *Utime) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *Utime) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Actime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Modtime))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *Utime) UnmarshalBytes(src []byte) []byte {
    u.Actime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Modtime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Utime) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *Utime) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *Utime) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *Utime) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *Utime) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *Utime) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (u *Utime) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *Utime) WriteTo(writer io.Writer) (int64, error) {
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
func (t *Termios) SizeBytes() int {
    return 17 +
        1*NumControlCharacters
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Termios) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.InputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.OutputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ControlFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LocalFlags))
    dst = dst[4:]
    dst[0] = byte(t.LineDiscipline)
    dst = dst[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        dst[0] = byte(t.ControlCharacters[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Termios) UnmarshalBytes(src []byte) []byte {
    t.InputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ControlFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LocalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LineDiscipline = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        t.ControlCharacters[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Termios) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Termios) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Termios) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *Termios) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *Termios) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (t *Termios) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *Termios) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Termios) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WindowSize) SizeBytes() int {
    return 4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WindowSize) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Rows))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Cols))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WindowSize) UnmarshalBytes(src []byte) []byte {
    w.Rows = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Cols = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([4]byte(w._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *WindowSize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *WindowSize) MarshalUnsafe(dst []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(w), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *WindowSize) UnmarshalUnsafe(src []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(w), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (w *WindowSize) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (w *WindowSize) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyOutN(cc, addr, w.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (w *WindowSize) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (w *WindowSize) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyInN(cc, addr, w.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *WindowSize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *Winsize) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *Winsize) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Row))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Col))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Xpixel))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Ypixel))
    dst = dst[2:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *Winsize) UnmarshalBytes(src []byte) []byte {
    w.Row = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Col = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Xpixel = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Ypixel = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *Winsize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *Winsize) MarshalUnsafe(dst []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(w), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *Winsize) UnmarshalUnsafe(src []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(w), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (w *Winsize) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (w *Winsize) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyOutN(cc, addr, w.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (w *Winsize) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (w *Winsize) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyInN(cc, addr, w.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *Winsize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UtsName) SizeBytes() int {
    return 0 +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UtsName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Sysname[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Nodename[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Release[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Version[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Machine[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Domainname[idx])
        dst = dst[1:]
    }
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UtsName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Sysname[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Nodename[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Release[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Version[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Machine[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Domainname[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UtsName) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UtsName) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UtsName) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (u *UtsName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
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
func (u *UtsName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (u *UtsName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (u *UtsName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UtsName) WriteTo(writer io.Writer) (int64, error) {
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
func (v *VFIODeviceInfo) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIODeviceInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.NumRegions))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.NumIrqs))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.CapOffset))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.pad))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIODeviceInfo) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.NumRegions = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.NumIrqs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.CapOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.pad = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIODeviceInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIODeviceInfo) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIODeviceInfo) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIODeviceInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIODeviceInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIODeviceInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIODeviceInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIODeviceInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *VFIOIommuType1DmaMap) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIOIommuType1DmaMap) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Vaddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.IOVa))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIOIommuType1DmaMap) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Vaddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.IOVa = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIommuType1DmaMap) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIOIommuType1DmaMap) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIOIommuType1DmaMap) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIOIommuType1DmaMap) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIOIommuType1DmaMap) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIOIommuType1DmaMap) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIOIommuType1DmaMap) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIOIommuType1DmaMap) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *VFIOIommuType1DmaUnmap) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIOIommuType1DmaUnmap) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.IOVa))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIOIommuType1DmaUnmap) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.IOVa = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIommuType1DmaUnmap) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIOIommuType1DmaUnmap) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIOIommuType1DmaUnmap) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIOIommuType1DmaUnmap) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIOIommuType1DmaUnmap) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIOIommuType1DmaUnmap) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIOIommuType1DmaUnmap) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIOIommuType1DmaUnmap) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *VFIOIrqInfo) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIOIrqInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Count))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIOIrqInfo) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIrqInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIOIrqInfo) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIOIrqInfo) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIOIrqInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIOIrqInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIOIrqInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIOIrqInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIOIrqInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *VFIOIrqSet) SizeBytes() int {
    return 20
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIOIrqSet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Start))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Count))
    dst = dst[4:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIOIrqSet) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Start = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIrqSet) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIOIrqSet) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIOIrqSet) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIOIrqSet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIOIrqSet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIOIrqSet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIOIrqSet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIOIrqSet) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *VFIORegionInfo) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *VFIORegionInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.capOffset))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Offset))
    dst = dst[8:]
    return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (v *VFIORegionInfo) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.capOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIORegionInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (v *VFIORegionInfo) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (v *VFIORegionInfo) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (v *VFIORegionInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (v *VFIORegionInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
func (v *VFIORegionInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return length, err
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (v *VFIORegionInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

// WriteTo implements io.WriterTo.WriteTo.
func (v *VFIORegionInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that v
    // must live until the use above.
    runtime.KeepAlive(v) // escapes: replaced by intrinsic.
    return int64(length), err
}

