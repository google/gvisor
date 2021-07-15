// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package socket provides the interfaces that need to be provided by socket
// implementations and providers, as well as per family demultiplexing of socket
// creation.
package socket

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/usermem"
)

// ControlMessages represents the union of unix control messages and tcpip
// control messages.
type ControlMessages struct {
	Unix transport.ControlMessages
	IP   IPControlMessages
}

// packetInfoToLinux converts IPPacketInfo from tcpip format to Linux format.
func packetInfoToLinux(packetInfo tcpip.IPPacketInfo) linux.ControlMessageIPPacketInfo {
	var p linux.ControlMessageIPPacketInfo
	p.NIC = int32(packetInfo.NIC)
	copy(p.LocalAddr[:], []byte(packetInfo.LocalAddr))
	copy(p.DestinationAddr[:], []byte(packetInfo.DestinationAddr))
	return p
}

// errOriginToLinux maps tcpip socket origin to Linux socket origin constants.
func errOriginToLinux(origin tcpip.SockErrOrigin) uint8 {
	switch origin {
	case tcpip.SockExtErrorOriginNone:
		return linux.SO_EE_ORIGIN_NONE
	case tcpip.SockExtErrorOriginLocal:
		return linux.SO_EE_ORIGIN_LOCAL
	case tcpip.SockExtErrorOriginICMP:
		return linux.SO_EE_ORIGIN_ICMP
	case tcpip.SockExtErrorOriginICMP6:
		return linux.SO_EE_ORIGIN_ICMP6
	default:
		panic(fmt.Sprintf("unknown socket origin: %d", origin))
	}
}

// sockErrCmsgToLinux converts SockError control message from tcpip format to
// Linux format.
func sockErrCmsgToLinux(sockErr *tcpip.SockError) linux.SockErrCMsg {
	if sockErr == nil {
		return nil
	}

	ee := linux.SockExtendedErr{
		Errno:  uint32(syserr.TranslateNetstackError(sockErr.Err).ToLinux()),
		Origin: errOriginToLinux(sockErr.Cause.Origin()),
		Type:   sockErr.Cause.Type(),
		Code:   sockErr.Cause.Code(),
		Info:   sockErr.Cause.Info(),
	}

	switch sockErr.NetProto {
	case header.IPv4ProtocolNumber:
		errMsg := &linux.SockErrCMsgIPv4{SockExtendedErr: ee}
		if len(sockErr.Offender.Addr) > 0 {
			addr, _ := ConvertAddress(linux.AF_INET, sockErr.Offender)
			errMsg.Offender = *addr.(*linux.SockAddrInet)
		}
		return errMsg
	case header.IPv6ProtocolNumber:
		errMsg := &linux.SockErrCMsgIPv6{SockExtendedErr: ee}
		if len(sockErr.Offender.Addr) > 0 {
			addr, _ := ConvertAddress(linux.AF_INET6, sockErr.Offender)
			errMsg.Offender = *addr.(*linux.SockAddrInet6)
		}
		return errMsg
	default:
		panic(fmt.Sprintf("invalid net proto for creating SockErrCMsg: %d", sockErr.NetProto))
	}
}

// NewIPControlMessages converts the tcpip ControlMessgaes (which does not
// have Linux specific format) to Linux format.
func NewIPControlMessages(family int, cmgs tcpip.ControlMessages) IPControlMessages {
	var orgDstAddr linux.SockAddr
	if cmgs.HasOriginalDstAddress {
		orgDstAddr, _ = ConvertAddress(family, cmgs.OriginalDstAddress)
	}
	return IPControlMessages{
		HasTimestamp:       cmgs.HasTimestamp,
		Timestamp:          cmgs.Timestamp,
		HasInq:             cmgs.HasInq,
		Inq:                cmgs.Inq,
		HasTOS:             cmgs.HasTOS,
		TOS:                cmgs.TOS,
		HasTClass:          cmgs.HasTClass,
		TClass:             cmgs.TClass,
		HasIPPacketInfo:    cmgs.HasIPPacketInfo,
		PacketInfo:         packetInfoToLinux(cmgs.PacketInfo),
		OriginalDstAddress: orgDstAddr,
		SockErr:            sockErrCmsgToLinux(cmgs.SockErr),
	}
}

// IPControlMessages contains socket control messages for IP sockets.
// This can contain Linux specific structures unlike tcpip.ControlMessages.
//
// +stateify savable
type IPControlMessages struct {
	// HasTimestamp indicates whether Timestamp is valid/set.
	HasTimestamp bool

	// Timestamp is the time (in ns) that the last packet used to create
	// the read data was received.
	Timestamp int64

	// HasInq indicates whether Inq is valid/set.
	HasInq bool

	// Inq is the number of bytes ready to be received.
	Inq int32

	// HasTOS indicates whether Tos is valid/set.
	HasTOS bool

	// TOS is the IPv4 type of service of the associated packet.
	TOS uint8

	// HasTClass indicates whether TClass is valid/set.
	HasTClass bool

	// TClass is the IPv6 traffic class of the associated packet.
	TClass uint32

	// HasIPPacketInfo indicates whether PacketInfo is set.
	HasIPPacketInfo bool

	// PacketInfo holds interface and address data on an incoming packet.
	PacketInfo linux.ControlMessageIPPacketInfo

	// OriginalDestinationAddress holds the original destination address
	// and port of the incoming packet.
	OriginalDstAddress linux.SockAddr

	// SockErr is the dequeued socket error on recvmsg(MSG_ERRQUEUE).
	SockErr linux.SockErrCMsg
}

// Release releases Unix domain socket credentials and rights.
func (c *ControlMessages) Release(ctx context.Context) {
	c.Unix.Release(ctx)
}

// Socket is an interface combining fs.FileOperations and SocketOps,
// representing a VFS1 socket file.
type Socket interface {
	fs.FileOperations
	SocketOps
}

// SocketVFS2 is an interface combining vfs.FileDescription and SocketOps,
// representing a VFS2 socket file.
type SocketVFS2 interface {
	vfs.FileDescriptionImpl
	SocketOps
}

// SocketOps is the interface containing socket syscalls used by the syscall
// layer to redirect them to the appropriate implementation.
//
// It is implemented by both Socket and SocketVFS2.
type SocketOps interface {
	// Connect implements the connect(2) linux unix.
	Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error

	// Accept implements the accept4(2) linux unix.
	// Returns fd, real peer address length and error. Real peer address
	// length is only set if len(peer) > 0.
	Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error)

	// Bind implements the bind(2) linux unix.
	Bind(t *kernel.Task, sockaddr []byte) *syserr.Error

	// Listen implements the listen(2) linux unix.
	Listen(t *kernel.Task, backlog int) *syserr.Error

	// Shutdown implements the shutdown(2) linux unix.
	Shutdown(t *kernel.Task, how int) *syserr.Error

	// GetSockOpt implements the getsockopt(2) linux unix.
	GetSockOpt(t *kernel.Task, level int, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error)

	// SetSockOpt implements the setsockopt(2) linux unix.
	SetSockOpt(t *kernel.Task, level int, name int, opt []byte) *syserr.Error

	// GetSockName implements the getsockname(2) linux unix.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetSockName(t *kernel.Task) (addr linux.SockAddr, addrLen uint32, err *syserr.Error)

	// GetPeerName implements the getpeername(2) linux unix.
	//
	// addrLen is the address length to be returned to the application, not
	// necessarily the actual length of the address.
	GetPeerName(t *kernel.Task) (addr linux.SockAddr, addrLen uint32, err *syserr.Error)

	// RecvMsg implements the recvmsg(2) linux unix.
	//
	// senderAddrLen is the address length to be returned to the application,
	// not necessarily the actual length of the address.
	//
	// flags control how RecvMsg should be completed. msgFlags indicate how
	// the RecvMsg call was completed. Note that control message truncation
	// may still be required even if the MSG_CTRUNC bit is not set in
	// msgFlags. In that case, the caller should set MSG_CTRUNC appropriately.
	//
	// If err != nil, the recv was not successful.
	RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (n int, msgFlags int, senderAddr linux.SockAddr, senderAddrLen uint32, controlMessages ControlMessages, err *syserr.Error)

	// SendMsg implements the sendmsg(2) linux unix. SendMsg does not take
	// ownership of the ControlMessage on error.
	//
	// If n > 0, err will either be nil or an error from t.Block.
	SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages ControlMessages) (n int, err *syserr.Error)

	// SetRecvTimeout sets the timeout (in ns) for recv operations. Zero means
	// no timeout, and negative means DONTWAIT.
	SetRecvTimeout(nanoseconds int64)

	// RecvTimeout gets the current timeout (in ns) for recv operations. Zero
	// means no timeout, and negative means DONTWAIT.
	RecvTimeout() int64

	// SetSendTimeout sets the timeout (in ns) for send operations. Zero means
	// no timeout, and negative means DONTWAIT.
	SetSendTimeout(nanoseconds int64)

	// SendTimeout gets the current timeout (in ns) for send operations. Zero
	// means no timeout, and negative means DONTWAIT.
	SendTimeout() int64

	// State returns the current state of the socket, as represented by Linux in
	// procfs. The returned state value is protocol-specific.
	State() uint32

	// Type returns the family, socket type and protocol of the socket.
	Type() (family int, skType linux.SockType, protocol int)
}

// Provider is the interface implemented by providers of sockets for specific
// address families (e.g., AF_INET).
type Provider interface {
	// Socket creates a new socket.
	//
	// If a nil Socket _and_ a nil error is returned, it means that the
	// protocol is not supported. A non-nil error should only be returned
	// if the protocol is supported, but an error occurs during creation.
	Socket(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *syserr.Error)

	// Pair creates a pair of connected sockets.
	//
	// See Socket for error information.
	Pair(t *kernel.Task, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error)
}

// families holds a map of all known address families and their providers.
var families = make(map[int][]Provider)

// RegisterProvider registers the provider of a given address family so that
// sockets of that type can be created via socket() and/or socketpair()
// syscalls.
//
// This should only be called during the initialization of the address family.
func RegisterProvider(family int, provider Provider) {
	families[family] = append(families[family], provider)
}

// New creates a new socket with the given family, type and protocol.
func New(t *kernel.Task, family int, stype linux.SockType, protocol int) (*fs.File, *syserr.Error) {
	for _, p := range families[family] {
		s, err := p.Socket(t, stype, protocol)
		if err != nil {
			return nil, err
		}
		if s != nil {
			t.Kernel().RecordSocket(s)
			return s, nil
		}
	}

	return nil, syserr.ErrAddressFamilyNotSupported
}

// Pair creates a new connected socket pair with the given family, type and
// protocol.
func Pair(t *kernel.Task, family int, stype linux.SockType, protocol int) (*fs.File, *fs.File, *syserr.Error) {
	providers, ok := families[family]
	if !ok {
		return nil, nil, syserr.ErrAddressFamilyNotSupported
	}

	for _, p := range providers {
		s1, s2, err := p.Pair(t, stype, protocol)
		if err != nil {
			return nil, nil, err
		}
		if s1 != nil && s2 != nil {
			k := t.Kernel()
			k.RecordSocket(s1)
			k.RecordSocket(s2)
			return s1, s2, nil
		}
	}

	return nil, nil, syserr.ErrSocketNotSupported
}

// NewDirent returns a sockfs fs.Dirent that resides on device d.
func NewDirent(ctx context.Context, d *device.Device) *fs.Dirent {
	ino := d.NextIno()
	iops := &fsutil.SimpleFileInode{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), fs.FilePermissions{
			User: fs.PermMask{Read: true, Write: true},
		}, linux.SOCKFS_MAGIC),
	}
	inode := fs.NewInode(ctx, iops, fs.NewPseudoMountSource(ctx), fs.StableAttr{
		Type:      fs.Socket,
		DeviceID:  d.DeviceID(),
		InodeID:   ino,
		BlockSize: hostarch.PageSize,
	})

	// Dirent name matches net/socket.c:sockfs_dname.
	return fs.NewDirent(ctx, inode, fmt.Sprintf("socket:[%d]", ino))
}

// ProviderVFS2 is the vfs2 interface implemented by providers of sockets for
// specific address families (e.g., AF_INET).
type ProviderVFS2 interface {
	// Socket creates a new socket.
	//
	// If a nil Socket _and_ a nil error is returned, it means that the
	// protocol is not supported. A non-nil error should only be returned
	// if the protocol is supported, but an error occurs during creation.
	Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error)

	// Pair creates a pair of connected sockets.
	//
	// See Socket for error information.
	Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error)
}

// familiesVFS2 holds a map of all known address families and their providers.
var familiesVFS2 = make(map[int][]ProviderVFS2)

// RegisterProviderVFS2 registers the provider of a given address family so that
// sockets of that type can be created via socket() and/or socketpair()
// syscalls.
//
// This should only be called during the initialization of the address family.
func RegisterProviderVFS2(family int, provider ProviderVFS2) {
	familiesVFS2[family] = append(familiesVFS2[family], provider)
}

// NewVFS2 creates a new socket with the given family, type and protocol.
func NewVFS2(t *kernel.Task, family int, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	for _, p := range familiesVFS2[family] {
		s, err := p.Socket(t, stype, protocol)
		if err != nil {
			return nil, err
		}
		if s != nil {
			t.Kernel().RecordSocketVFS2(s)
			return s, nil
		}
	}

	return nil, syserr.ErrAddressFamilyNotSupported
}

// PairVFS2 creates a new connected socket pair with the given family, type and
// protocol.
func PairVFS2(t *kernel.Task, family int, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	providers, ok := familiesVFS2[family]
	if !ok {
		return nil, nil, syserr.ErrAddressFamilyNotSupported
	}

	for _, p := range providers {
		s1, s2, err := p.Pair(t, stype, protocol)
		if err != nil {
			return nil, nil, err
		}
		if s1 != nil && s2 != nil {
			k := t.Kernel()
			k.RecordSocketVFS2(s1)
			k.RecordSocketVFS2(s2)
			return s1, s2, nil
		}
	}

	return nil, nil, syserr.ErrSocketNotSupported
}

// SendReceiveTimeout stores timeouts for send and receive calls.
//
// It is meant to be embedded into Socket implementations to help satisfy the
// interface.
//
// Care must be taken when copying SendReceiveTimeout as it contains atomic
// variables.
//
// +stateify savable
type SendReceiveTimeout struct {
	// send is length of the send timeout in nanoseconds.
	//
	// send must be accessed atomically.
	send int64

	// recv is length of the receive timeout in nanoseconds.
	//
	// recv must be accessed atomically.
	recv int64
}

// SetRecvTimeout implements Socket.SetRecvTimeout.
func (to *SendReceiveTimeout) SetRecvTimeout(nanoseconds int64) {
	atomic.StoreInt64(&to.recv, nanoseconds)
}

// RecvTimeout implements Socket.RecvTimeout.
func (to *SendReceiveTimeout) RecvTimeout() int64 {
	return atomic.LoadInt64(&to.recv)
}

// SetSendTimeout implements Socket.SetSendTimeout.
func (to *SendReceiveTimeout) SetSendTimeout(nanoseconds int64) {
	atomic.StoreInt64(&to.send, nanoseconds)
}

// SendTimeout implements Socket.SendTimeout.
func (to *SendReceiveTimeout) SendTimeout() int64 {
	return atomic.LoadInt64(&to.send)
}

// GetSockOptEmitUnimplementedEvent emits unimplemented event if name is valid.
// It contains names that are valid for GetSockOpt when level is SOL_SOCKET.
func GetSockOptEmitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_ACCEPTCONN,
		linux.SO_BPF_EXTENSIONS,
		linux.SO_COOKIE,
		linux.SO_DOMAIN,
		linux.SO_ERROR,
		linux.SO_GET_FILTER,
		linux.SO_INCOMING_NAPI_ID,
		linux.SO_MEMINFO,
		linux.SO_PEERCRED,
		linux.SO_PEERGROUPS,
		linux.SO_PEERNAME,
		linux.SO_PEERSEC,
		linux.SO_PROTOCOL,
		linux.SO_SNDLOWAT,
		linux.SO_TYPE:

		t.Kernel().EmitUnimplementedEvent(t)

	default:
		emitUnimplementedEvent(t, name)
	}
}

// SetSockOptEmitUnimplementedEvent emits unimplemented event if name is valid.
// It contains names that are valid for SetSockOpt when level is SOL_SOCKET.
func SetSockOptEmitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_ATTACH_BPF,
		linux.SO_ATTACH_FILTER,
		linux.SO_ATTACH_REUSEPORT_CBPF,
		linux.SO_ATTACH_REUSEPORT_EBPF,
		linux.SO_CNX_ADVICE,
		linux.SO_DETACH_FILTER,
		linux.SO_SNDBUFFORCE:

		t.Kernel().EmitUnimplementedEvent(t)

	default:
		emitUnimplementedEvent(t, name)
	}
}

// emitUnimplementedEvent emits unimplemented event if name is valid. It
// contains names that are common between Get and SetSocketOpt when level is
// SOL_SOCKET.
func emitUnimplementedEvent(t *kernel.Task, name int) {
	switch name {
	case linux.SO_BINDTODEVICE,
		linux.SO_BROADCAST,
		linux.SO_BSDCOMPAT,
		linux.SO_BUSY_POLL,
		linux.SO_DEBUG,
		linux.SO_DONTROUTE,
		linux.SO_INCOMING_CPU,
		linux.SO_KEEPALIVE,
		linux.SO_LINGER,
		linux.SO_LOCK_FILTER,
		linux.SO_MARK,
		linux.SO_MAX_PACING_RATE,
		linux.SO_NOFCS,
		linux.SO_OOBINLINE,
		linux.SO_PASSCRED,
		linux.SO_PASSSEC,
		linux.SO_PEEK_OFF,
		linux.SO_PRIORITY,
		linux.SO_RCVBUF,
		linux.SO_RCVLOWAT,
		linux.SO_RCVTIMEO,
		linux.SO_REUSEADDR,
		linux.SO_REUSEPORT,
		linux.SO_RXQ_OVFL,
		linux.SO_SELECT_ERR_QUEUE,
		linux.SO_SNDBUF,
		linux.SO_SNDTIMEO,
		linux.SO_TIMESTAMP,
		linux.SO_TIMESTAMPING,
		linux.SO_TIMESTAMPNS,
		linux.SO_TXTIME,
		linux.SO_WIFI_STATUS,
		linux.SO_ZEROCOPY:

		t.Kernel().EmitUnimplementedEvent(t)
	}
}

// UnmarshalSockAddr unmarshals memory representing a struct sockaddr to one of
// the ABI socket address types.
//
// Precondition: data must be long enough to represent a socket address of the
// given family.
func UnmarshalSockAddr(family int, data []byte) linux.SockAddr {
	switch family {
	case unix.AF_INET:
		var addr linux.SockAddrInet
		addr.UnmarshalUnsafe(data[:addr.SizeBytes()])
		return &addr
	case unix.AF_INET6:
		var addr linux.SockAddrInet6
		addr.UnmarshalUnsafe(data[:addr.SizeBytes()])
		return &addr
	case unix.AF_UNIX:
		var addr linux.SockAddrUnix
		addr.UnmarshalUnsafe(data[:addr.SizeBytes()])
		return &addr
	case unix.AF_NETLINK:
		var addr linux.SockAddrNetlink
		addr.UnmarshalUnsafe(data[:addr.SizeBytes()])
		return &addr
	default:
		panic(fmt.Sprintf("Unsupported socket family %v", family))
	}
}

var sockAddrLinkSize = (&linux.SockAddrLink{}).SizeBytes()
var sockAddrInetSize = (&linux.SockAddrInet{}).SizeBytes()
var sockAddrInet6Size = (&linux.SockAddrInet6{}).SizeBytes()

// Ntohs converts a 16-bit number from network byte order to host byte order. It
// assumes that the host is little endian.
func Ntohs(v uint16) uint16 {
	return v<<8 | v>>8
}

// Htons converts a 16-bit number from host byte order to network byte order. It
// assumes that the host is little endian.
func Htons(v uint16) uint16 {
	return Ntohs(v)
}

// isLinkLocal determines if the given IPv6 address is link-local. This is the
// case when it has the fe80::/10 prefix. This check is used to determine when
// the NICID is relevant for a given IPv6 address.
func isLinkLocal(addr tcpip.Address) bool {
	return len(addr) >= 2 && addr[0] == 0xfe && addr[1]&0xc0 == 0x80
}

// ConvertAddress converts the given address to a native format.
func ConvertAddress(family int, addr tcpip.FullAddress) (linux.SockAddr, uint32) {
	switch family {
	case linux.AF_UNIX:
		var out linux.SockAddrUnix
		out.Family = linux.AF_UNIX
		l := len([]byte(addr.Addr))
		for i := 0; i < l; i++ {
			out.Path[i] = int8(addr.Addr[i])
		}

		// Linux returns the used length of the address struct (including the
		// null terminator) for filesystem paths. The Family field is 2 bytes.
		// It is sometimes allowed to exclude the null terminator if the
		// address length is the max. Abstract and empty paths always return
		// the full exact length.
		if l == 0 || out.Path[0] == 0 || l == len(out.Path) {
			return &out, uint32(2 + l)
		}
		return &out, uint32(3 + l)

	case linux.AF_INET:
		var out linux.SockAddrInet
		copy(out.Addr[:], addr.Addr)
		out.Family = linux.AF_INET
		out.Port = Htons(addr.Port)
		return &out, uint32(sockAddrInetSize)

	case linux.AF_INET6:
		var out linux.SockAddrInet6
		if len(addr.Addr) == header.IPv4AddressSize {
			// Copy address in v4-mapped format.
			copy(out.Addr[12:], addr.Addr)
			out.Addr[10] = 0xff
			out.Addr[11] = 0xff
		} else {
			copy(out.Addr[:], addr.Addr)
		}
		out.Family = linux.AF_INET6
		out.Port = Htons(addr.Port)
		if isLinkLocal(addr.Addr) {
			out.Scope_id = uint32(addr.NIC)
		}
		return &out, uint32(sockAddrInet6Size)

	case linux.AF_PACKET:
		var out linux.SockAddrLink
		out.Family = linux.AF_PACKET
		out.InterfaceIndex = int32(addr.NIC)
		out.HardwareAddrLen = header.EthernetAddressSize
		copy(out.HardwareAddr[:], addr.Addr)
		return &out, uint32(sockAddrLinkSize)

	default:
		return nil, 0
	}
}

// BytesToIPAddress converts an IPv4 or IPv6 address from the user to the
// netstack representation taking any addresses into account.
func BytesToIPAddress(addr []byte) tcpip.Address {
	if bytes.Equal(addr, make([]byte, 4)) || bytes.Equal(addr, make([]byte, 16)) {
		return ""
	}
	return tcpip.Address(addr)
}

// AddressAndFamily reads an sockaddr struct from the given address and
// converts it to the FullAddress format. It supports AF_UNIX, AF_INET,
// AF_INET6, and AF_PACKET addresses.
//
// AddressAndFamily returns an address and its family.
func AddressAndFamily(addr []byte) (tcpip.FullAddress, uint16, *syserr.Error) {
	// Make sure we have at least 2 bytes for the address family.
	if len(addr) < 2 {
		return tcpip.FullAddress{}, 0, syserr.ErrInvalidArgument
	}

	// Get the rest of the fields based on the address family.
	switch family := hostarch.ByteOrder.Uint16(addr); family {
	case linux.AF_UNIX:
		path := addr[2:]
		if len(path) > linux.UnixPathMax {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		// Drop the terminating NUL (if one exists) and everything after
		// it for filesystem (non-abstract) addresses.
		if len(path) > 0 && path[0] != 0 {
			if n := bytes.IndexByte(path[1:], 0); n >= 0 {
				path = path[:n+1]
			}
		}
		return tcpip.FullAddress{
			Addr: tcpip.Address(path),
		}, family, nil

	case linux.AF_INET:
		var a linux.SockAddrInet
		if len(addr) < sockAddrInetSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		a.UnmarshalUnsafe(addr[:sockAddrInetSize])

		out := tcpip.FullAddress{
			Addr: BytesToIPAddress(a.Addr[:]),
			Port: Ntohs(a.Port),
		}
		return out, family, nil

	case linux.AF_INET6:
		var a linux.SockAddrInet6
		if len(addr) < sockAddrInet6Size {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		a.UnmarshalUnsafe(addr[:sockAddrInet6Size])

		out := tcpip.FullAddress{
			Addr: BytesToIPAddress(a.Addr[:]),
			Port: Ntohs(a.Port),
		}
		if isLinkLocal(out.Addr) {
			out.NIC = tcpip.NICID(a.Scope_id)
		}
		return out, family, nil

	case linux.AF_PACKET:
		var a linux.SockAddrLink
		if len(addr) < sockAddrLinkSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}
		a.UnmarshalUnsafe(addr[:sockAddrLinkSize])
		if a.Family != linux.AF_PACKET || a.HardwareAddrLen != header.EthernetAddressSize {
			return tcpip.FullAddress{}, family, syserr.ErrInvalidArgument
		}

		return tcpip.FullAddress{
			NIC:  tcpip.NICID(a.InterfaceIndex),
			Addr: tcpip.Address(a.HardwareAddr[:header.EthernetAddressSize]),
		}, family, nil

	case linux.AF_UNSPEC:
		return tcpip.FullAddress{}, family, nil

	default:
		return tcpip.FullAddress{}, 0, syserr.ErrAddressFamilyNotSupported
	}
}
