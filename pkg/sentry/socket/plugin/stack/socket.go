// Copyright 2023 The gVisor Authors.
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

package stack

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

type socketOperations struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD
	socket.SendReceiveTimeout

	family   int
	skType   linux.SockType
	protocol int

	// fd holds the current socket fd created by plugin stack.
	fd uint32 `state:"nosave"`

	// eventInfo holds current socket fd's corresponding notification queue
	// and events status. It will be used to interact with plugin
	// network stack for event reporting.
	eventInfo plugin.EventInfo
}

var _ = socket.Socket(&socketOperations{})

const (
	sizeofSockaddr = syscall.SizeofSockaddrInet6

	// Lo IF index.
	ifLoIndex = 1
)

func newSocket(t *kernel.Task, family int, skType linux.SockType, protocol int, notifier *Notifier, fd int, flags uint32) (*vfs.FileDescription, *syserr.Error) {
	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t, mnt)
	defer d.DecRef(t)

	switch skType {
	case syscall.SOCK_STREAM:
	case syscall.SOCK_DGRAM:
	default:
		return nil, syserr.ErrSocketNotSupported
	}

	wq := &waiter.Queue{}
	sop := &socketOperations{
		family:    family,
		fd:        uint32(fd),
		protocol:  protocol,
		skType:    skType,
		eventInfo: plugin.EventInfo{Wq: wq},
	}

	sop.LockFD.Init(&vfs.FileLocks{})

	vfsfd := &sop.vfsfd
	if err := vfsfd.Init(sop, linux.O_RDWR|(flags&linux.O_NONBLOCK), mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, syserr.FromError(err)
	}

	notifier.AddFD(uint32(fd), &sop.eventInfo)

	return vfsfd, nil
}

// Bind implements socket.Socket.Bind.
func (s *socketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	return int2err(cgo.Bind(s.fd, sockaddr))
}

// Listen implements socket.Socket.Listen.
func (s *socketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	return int2err(cgo.Listen(s.fd, backlog))
}

// Accept implements socket.Socket.Accept.
func (s *socketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	peerAddrBuf := make([]byte, sizeofSockaddr)
	peerAddrlen := uint32(len(peerAddrBuf))
	peerAddrPtr := &peerAddrBuf[0]
	peerAddrlenPtr := &peerAddrlen

	rc := cgo.Accept(s.fd, peerAddrPtr, peerAddrlenPtr)
	if blocking {
		for rc < 0 && (-rc) == errno.EAGAIN {
			if err := s.waitEvent(t, waiter.EventIn); err != nil {
				return 0, nil, 0, syserr.FromError(err)
			}

			rc = cgo.Accept(s.fd, peerAddrPtr, peerAddrlenPtr)
		}
	}

	if rc < 0 {
		return 0, nil, 0, int2err(rc)
	}

	f, err := newSocket(t, s.family, s.skType, s.protocol, stack.notifier, int(rc), uint32(flags&syscall.SOCK_NONBLOCK))
	if err != nil {
		cgo.Close(uint32(rc))
		return 0, nil, 0, err
	}
	defer f.DecRef(t)

	kfd, kerr := t.NewFDFrom(0, f, kernel.FDFlags{
		CloseOnExec: flags&syscall.SOCK_CLOEXEC != 0,
	})
	if kerr != nil {
		cgo.Close(uint32(rc))
		return 0, nil, 0, syserr.FromError(kerr)
	}

	t.Kernel().RecordSocket(f)

	if !peerRequested {
		return kfd, nil, 0, nil
	}

	peerAddr := socket.UnmarshalSockAddr(s.family, peerAddrBuf[:peerAddrlen])
	return kfd, peerAddr, peerAddrlen, nil
}

// Connect implements socket.Socket.Connect.
func (s *socketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	var ret int64

	if !blocking {
		ret = cgo.Connect(s.fd, sockaddr)

		if ret == 0 {
			return nil
		}
		return int2err(ret)
	}

	ret = cgo.Connect(s.fd, sockaddr)

	if ret == 0 {
		return nil
	} else if ret < 0 && (-ret) != errno.EINPROGRESS {
		// Return error if errno is EALREADY/EISCONN/ECONNREFUSED/EINVAL
		return int2err(ret)
	}

	if err := s.waitEvent(t, waiter.EventOut); err != nil {
		return syserr.FromError(err)
	}

	// Call connect() again after blocking to find connect's result.
	ret = cgo.Connect(s.fd, sockaddr)
	if ret == 0 {
		return nil
	} else if ret < 0 && (-ret) == errno.EISCONN {
		return nil
	}
	return int2err(ret)
}

// Shutdown implements socket.Socket.Shutdown.
func (s *socketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	ret := cgo.Shutdown(s.fd, how)
	return int2err(ret)
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *socketOperations) GetSockOpt(t *kernel.Task, level int, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	optVal := make([]byte, outLen)
	if outLen == 0 {
		optPtr := primitive.ByteSlice(optVal)
		return &optPtr, nil
	}
	rc, outLen := cgo.Getsockopt(s.fd, level, name, optVal, outLen)
	if rc < 0 {
		return nil, int2err(rc)
	}
	optPtr := primitive.ByteSlice(optVal[:outLen])
	return &optPtr, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *socketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	rc := cgo.Setsockopt(s.fd, level, name, optVal)
	return int2err(rc)
}

// State implements socket.Socket.State.
func (s *socketOperations) State() uint32 {
	optVal := make([]byte, 1)
	rc, _ := cgo.Getsockopt(s.fd, syscall.SOL_TCP, syscall.TCP_INFO, optVal, 1)
	if rc < 0 {
		return 0
	}
	return uint32(optVal[0])
}

// Type implements socket.Socket.Type.
func (s *socketOperations) Type() (family int, skType linux.SockType, protocol int) {
	return s.family, s.skType, s.protocol
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (s *socketOperations) OnClose(ctx context.Context) error {
	return nil
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *socketOperations) EventRegister(e *waiter.Entry) error {
	s.eventInfo.Wq.EventRegister(e)
	stack.notifier.UpdateFD(s.fd)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *socketOperations) EventUnregister(e *waiter.Entry) {
	s.eventInfo.Wq.EventUnregister(e)
	stack.notifier.UpdateFD(s.fd)
}

// Readiness implements socket.Socket.Readiness.
func (s *socketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	var events waiter.EventMask

	evInfo := &s.eventInfo
	iomask := mask & (waiter.EventIn | waiter.EventOut)

	// Fast path condition:
	// 1. The event needed has been reported by plugin stack io-thread; or
	// 2. POLLIN or POLLOUT event has been reported by io-thread.
	// Directly report current event without invoking cgo Readiness again.
	if evInfo.Ready&iomask == iomask {
		events = evInfo.Ready & mask
		// Clear plugin stack eventInfo record after consuming IN/OUT event.
		evInfo.Ready &= ^iomask
	} else {
		events = waiter.EventMask(cgo.Readiness(s.fd, uint64(mask)))
	}

	return events
}

// Epollable implements socket.Socket.Epollable.
func (s *socketOperations) Epollable() bool {
	return true
}

// Refers to implementation in epsocket
func interfaceIoctl(ctx context.Context, io usermem.IO, cmd uint32, ifr *linux.IFReq) *syserr.Error {
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		return syserr.ErrNoDevice
	}

	// SIOCGIFNAME uses ifr.ifr_ifindex rather than ifr.ifr_name to
	// identify a device.
	if cmd == syscall.SIOCGIFNAME {
		// Gets the name of the interface given the interface index
		// stored in ifr_ifindex.
		index := int32(hostarch.ByteOrder.Uint32(ifr.Data[:4]))
		if iface, ok := stack.Interfaces()[index]; ok {
			ifr.SetName(iface.Name)
			return nil
		}
		return syserr.ErrNoDevice
	}

	// Find the relevant device.
	var iface inet.Interface
	index := int32(-1)
	for i, iface := range stack.Interfaces() {
		if iface.Name == ifr.Name() {
			index = i
			break
		}
	}
	if index == -1 {
		return syserr.ErrNoDevice
	}

	switch cmd {
	case syscall.SIOCGIFINDEX:
		// Copy out the index to the data.
		hostarch.ByteOrder.PutUint32(ifr.Data[:], uint32(index))

	case syscall.SIOCGIFHWADDR:
		// Use IEEE802.3 instead of IEEE802.2 ARP type
		// so that ifconfig command can recognize it
		devType := 1
		if index == ifLoIndex {
			devType = 772 // Loopback
		}
		hostarch.ByteOrder.PutUint16(ifr.Data[:2], uint16(devType))
		n := copy(ifr.Data[2:], iface.Addr)
		for i := 2 + n; i < len(ifr.Data); i++ {
			ifr.Data[i] = 0 // Clear padding.
		}

	case syscall.SIOCGIFFLAGS:
		f := iface.Flags
		// Drop the flags that don't fit in the size that we need to
		// return. This matches Linux behavior.
		hostarch.ByteOrder.PutUint16(ifr.Data[:2], uint16(f))

	case syscall.SIOCGIFADDR:
		// Copy the IPv4 address out.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			copyAddrOut(ifr, &addr)
			break
		}

	case syscall.SIOCGIFMETRIC:
		// Gets the metric of the device. As per netdevice(7), this
		// always just sets ifr_metric to 0.
		hostarch.ByteOrder.PutUint32(ifr.Data[:4], 0)

	case syscall.SIOCGIFMTU:
		// Gets the MTU of the device.
		hostarch.ByteOrder.PutUint32(ifr.Data[:4], iface.MTU)

	case syscall.SIOCGIFMAP:
		// Gets the hardware parameters of the device.
		hostarch.ByteOrder.PutUint64(ifr.Data[:8], 0)
		hostarch.ByteOrder.PutUint32(ifr.Data[8:12], 0)
		ifr.Data[12] = 0

	case syscall.SIOCGIFTXQLEN:
		hostarch.ByteOrder.PutUint32(ifr.Data[:4], 1024)

	case syscall.SIOCGIFDSTADDR:
		// Gets the destination address of a point-to-point device.
		// TODO: Implement SIOCGIFDSTADDR handler.

	case syscall.SIOCGIFBRDADDR:
		// Gets the broadcast address of a device.
		// TODO: Implement SIOCGIFBRDADDR handler.

	case syscall.SIOCGIFNETMASK:
		// Gets the network mask of a device.
		for _, addr := range stack.InterfaceAddrs()[index] {
			// This ioctl is only compatible with AF_INET addresses.
			if addr.Family != linux.AF_INET {
				continue
			}
			// Populate ifr.ifr_netmask (type sockaddr).
			hostarch.ByteOrder.PutUint16(ifr.Data[0:2], uint16(addr.Family))
			hostarch.ByteOrder.PutUint16(ifr.Data[2:4], 0)
			// Netmask is expected to be returned as a big endian value.
			mask := uint32(0xffffffff << (32 - addr.PrefixLen))
			binary.BigEndian.PutUint32(ifr.Data[4:8], mask)
			break
		}

	default:
		// Not a valid call.
		return syserr.ErrInvalidArgument
	}

	return nil
}

func ifconfIoctlFromStack(ctx context.Context, io usermem.IO, ifc *linux.IFConf) error {
	// If Ptr is NULL, return the necessary buffer size via Len.
	// Otherwise, write up to Len bytes starting at Ptr containing ifreq
	// structs.
	t := ctx.(*kernel.Task)
	s := t.NetworkContext().(*Stack)
	if s == nil {
		return syserr.ErrNoDevice.ToError()
	}

	if ifc.Ptr == 0 {
		ifc.Len = int32(len(s.Interfaces())) * int32(linux.SizeOfIFReq)
		return nil
	}

	max := ifc.Len
	ifc.Len = 0
	for idx, iface := range s.Interfaces() {
		ifaceAddrs := s.InterfaceAddrs()[idx]
		for _, ifaceAddr := range ifaceAddrs {
			if ifaceAddr.Family != syscall.AF_INET {
				continue
			}

			// Don't write past the end of the buffer.
			if ifc.Len+int32(linux.SizeOfIFReq) > max {
				break
			}

			// Populate ifr.ifr_addr.
			ifr := linux.IFReq{}
			ifr.SetName(iface.Name)
			copyAddrOut(&ifr, &ifaceAddr)

			// Copy the ifr to userspace.
			dst := uintptr(ifc.Ptr) + uintptr(ifc.Len)
			ifc.Len += int32(linux.SizeOfIFReq)
			if _, err := ifr.CopyOut(t, hostarch.Addr(dst)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Ioctl implements socket.Socket.Ioctl.
func (s *socketOperations) Ioctl(ctx context.Context, io usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := uint32(args[1].Int())
	arg := args[2].Pointer()

	var buf []byte
	switch cmd {
	case syscall.SIOCGIFADDR,
		syscall.SIOCGIFBRDADDR,
		syscall.SIOCGIFDSTADDR,
		syscall.SIOCGIFFLAGS,
		syscall.SIOCGIFHWADDR,
		syscall.SIOCGIFINDEX,
		syscall.SIOCGIFMAP,
		syscall.SIOCGIFMETRIC,
		syscall.SIOCGIFMTU,
		syscall.SIOCGIFNAME,
		syscall.SIOCGIFNETMASK,
		syscall.SIOCGIFTXQLEN:
		var ifr linux.IFReq
		ifrBuf := ctx.(*kernel.Task).CopyScratchBuffer(linux.SizeOfIFReq)
		if _, err := io.CopyIn(ctx, args[2].Pointer(), ifrBuf, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		// Decode ifr from ifrBuf
		// Note that these code may need to be modified if linux.IFReq struct changes
		copy(ifr.IFName[0:linux.IFNAMSIZ], ifrBuf[0:linux.IFNAMSIZ])
		copy(ifr.Data[0:linux.SizeOfIFReq-linux.IFNAMSIZ], ifrBuf[linux.IFNAMSIZ:linux.SizeOfIFReq])
		if err := interfaceIoctl(ctx, io, cmd, &ifr); err != nil {
			return 0, err.ToError()
		}
		copy(ifrBuf[0:linux.IFNAMSIZ], ifr.IFName[0:linux.IFNAMSIZ])
		copy(ifrBuf[linux.IFNAMSIZ:linux.SizeOfIFReq], ifr.Data[0:linux.SizeOfIFReq-linux.IFNAMSIZ])
		_, err := io.CopyOut(ctx, arg, ifrBuf, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case syscall.SIOCGIFCONF:
		// SIOCGIFCONF has slightly different behavior than the others, in that it
		// will need to populate the array of ifreqs.
		var ifc linux.IFConf
		ifcBuf := ctx.(*kernel.Task).CopyScratchBuffer(linux.SizeOfIFConf)
		if _, err := io.CopyIn(ctx, arg, ifcBuf, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		// Decode ifc from ifcBuf
		// Note that these code may need to be modified if linux.IFconf struct changes
		ifc.Len = int32(hostarch.ByteOrder.Uint32(ifcBuf[0:4]))
		ifc.Ptr = hostarch.ByteOrder.Uint64(ifcBuf[8:])

		if err := ifconfIoctlFromStack(ctx, io, &ifc); err != nil {
			return 0, err
		}
		hostarch.ByteOrder.PutUint32(ifcBuf[0:4], uint32(ifc.Len))
		hostarch.ByteOrder.PutUint64(ifcBuf[8:], ifc.Ptr)
		_, err := io.CopyOut(ctx, arg, ifcBuf, usermem.IOOpts{
			AddressSpaceActive: true,
		})

		return 0, err
	case linux.SIOCGIFMEM, linux.SIOCGIFPFLAGS, linux.SIOCGMIIPHY, linux.SIOCGMIIREG:
		unimpl.EmitUnimplementedEvent(ctx, sysno)
		return 0, linuxerr.ENOTTY
	case syscall.TIOCINQ, syscall.TIOCOUTQ:
		buf = make([]byte, 4)
	case syscall.SIOCGSTAMP:
		buf = make([]byte, 16)
	default:
		return 0, linuxerr.ENOTTY
	}

	rc := cgo.Ioctl(s.fd, cmd, buf)
	if rc < 0 {
		_, err := translateReturn(int64(rc))
		return 0, err
	}

	_, err := io.CopyOut(ctx, arg, buf, usermem.IOOpts{
		AddressSpaceActive: true,
	})

	return 0, err
}

// Release implements socket.Socket.Release.
func (s *socketOperations) Release(ctx context.Context) {
	t := kernel.TaskFromContext(ctx)
	t.Kernel().DeleteSocket(&s.vfsfd)
	stack.notifier.RemoveFD(s.fd)
	cgo.Close(s.fd)
}

// GetSockName implements socket.Socket.GetSockName.
func (s *socketOperations) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addrlen := uint32(sizeofSockaddr)
	addr := make([]byte, sizeofSockaddr)
	rc := cgo.Getsockname(s.fd, addr, &addrlen)
	if rc < 0 {
		return nil, 0, int2err(rc)
	}
	return socket.UnmarshalSockAddr(s.family, addr), addrlen, nil
}

// GetPeerName implements socket.Socket.GetPeerName.
func (s *socketOperations) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addrlen := uint32(sizeofSockaddr)
	addr := make([]byte, sizeofSockaddr)
	rc := cgo.GetPeername(s.fd, addr, &addrlen)
	if rc < 0 {
		return nil, 0, int2err(rc)
	}
	return socket.UnmarshalSockAddr(s.family, addr), addrlen, nil
}

// recv is a helper function for doing non-blocking read once.
// It returns:
// 1. number of bytes received;
// 2. sender address for non-stream socket;
// 3. control message;
// 4. message flag;
// 5. internal error if any
func (s *socketOperations) recv(t *kernel.Task, dst usermem.IOSequence, sysflags int, addr []byte, control []byte) (int64, []byte, []byte, int, error) {
	bytes := dst.NumBytes()
	// Directly return if dst is empty.
	if bytes == 0 {
		return 0, addr, control, 0, nil
	}

	// Slow path for non-stream socket(e.g., UDP, raw socket).
	if s.skType != linux.SOCK_STREAM {
		if len(addr) == 0 && s.skType == linux.SOCK_DGRAM {
			addr = make([]byte, sizeofSockaddr)
		}

		tmpBuf := make([]byte, bytes)
		tmpBS := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(tmpBuf))
		iovs := iovecsFromBlockSeq(tmpBS, nil)
		rc, la, lc, flag := cgo.Recvmsg(s.fd, iovs, addr, control, sysflags)
		if rc < 0 {
			_, err := translateReturn(rc)
			return 0, addr /* return the original slice */, control /* return the original slice */, 0, err
		}

		n, err := dst.CopyOut(t, tmpBuf[:rc])
		return int64(n), addr[:la], control[:lc], flag, err
	}

	// Fast path for stream socket(e.g., TCP socket).
	rw := getReadWriter(s.fd)
	rw.to = control
	rw.flags = uint32(sysflags)

	n, err := dst.CopyOutFrom(t, rw)

	control = rw.to
	msgFlags := int(rw.flags)
	putReadWriter(rw)

	return n, nil /* ignore for TCP */, control, msgFlags, err
}

// RecvMsg implements socket.Socket.RecvMsg.
func (s *socketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	var addr, control []byte
	if senderRequested {
		if s.skType != linux.SOCK_STREAM {
			addr = make([]byte, sizeofSockaddr)
		} else {
			// According to UNIX98, msg_name/msg_namelen are ignored on connected socket.
			senderRequested = false
		}
	}
	if controlDataLen > 0 {
		control = make([]byte, controlDataLen)
	}

	// Store nonblock info from original flag.
	nonblock := flags&syscall.MSG_DONTWAIT != 0
	waitall := nonblock == false && flags&syscall.MSG_WAITALL != 0

	var mflag int
	var n int64
	var err error
	// Always set as non-blocking for recv.
	sysflags := flags | syscall.MSG_DONTWAIT
	n, addr, control, mflag, err = s.recv(t, dst, sysflags, addr, control)

	var senderAddr linux.SockAddr
	var addrlen uint32
	// For non-blocking RecvMsg, we could return after recv once.
	if nonblock {
		if err != nil {
			// Clear controlMessages when error occurs.
			control = nil
		} else if senderRequested && len(addr) > 0 {
			senderAddr = socket.UnmarshalSockAddr(s.family, addr)
			addrlen = uint32(len(addr))
		}
		controlMessages := buildControlMessage(control)
		// The socket is shutdown, report ErrWouldBlock for non-blocking mode.
		if err == error(syscall.ESHUTDOWN) {
			err = linuxerr.ErrWouldBlock
		}
		return int(n), mflag, senderAddr, addrlen, *controlMessages, syserr.FromError(err)
	}

	// For blocking RecvMsg, we need to finish reading all data before return.
	rn := n
	for err == linuxerr.ErrWouldBlock || (waitall && err == nil && rn < dst.NumBytes()) {
		dst = dst.DropFirst(int(rn))
		// Wait on POLLIN event.
		if haveDeadline {
			err = s.waitEventT(t, waiter.EventIn, deadline)
		} else {
			err = s.waitEvent(t, waiter.EventIn)
		}
		if err != nil {
			if n == 0 {
				// There is no POLLIN event reported before timeout.
				if err == linuxerr.ETIMEDOUT {
					err = linuxerr.ErrWouldBlock
				}
				return 0, 0, nil, 0, socket.ControlMessages{}, syserr.FromError(err)
			}
			// Clear event-waiting error.
			err = nil
			mflag = 0
			break
		}
		rn, addr, control, mflag, err = s.recv(t, dst, sysflags, addr, control)
		n += rn
	}

	// Plugin stack finds the socket has been shutdown,
	// report ESHUTDOWN through controlMessages.
	if err == error(syscall.ESHUTDOWN) {
		n = 0
		err = nil
	} else if n > 0 {
		// If any data has been received, clear internal error.
		err = nil
	}

	// For receiving error other than ESHUTDOWN and not receiving any data,
	// clear controlMessages and report through internal error.
	if err != nil {
		control = nil
	} else if senderRequested && len(addr) > 0 {
		senderAddr = socket.UnmarshalSockAddr(s.family, addr)
		addrlen = uint32(len(addr))
	}
	controlMessages := buildControlMessage(control)
	return int(n), mflag, senderAddr, addrlen, *controlMessages, syserr.FromError(err)
}

// Read implements socket.Socket.Read.
func (s *socketOperations) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if opts.Flags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}
	nonblock := (s.vfsfd.StatusFlags() & linux.O_NONBLOCK) != 0

	bytes := dst.NumBytes()
	// Directly return if dst is empty.
	if bytes == 0 {
		return 0, nil
	}

	rw := getReadWriter(s.fd)
	n, err := dst.CopyOutFrom(ctx, rw)
	putReadWriter(rw)

	if err == error(syscall.ESHUTDOWN) {
		if nonblock {
			err = linuxerr.ErrWouldBlock
		} else {
			n = 0
			err = nil
		}
	}

	return int64(n), err
}

func (s *socketOperations) send(t *kernel.Task, src usermem.IOSequence, to []byte, sysflags int) (int64, error) {
	bytes := src.NumBytes()
	// If src is empty, let plugin stack handle sending 0-byte data based on protocol.
	if bytes == 0 {
		rc := cgo.Sendto(s.fd, 0, 0, sysflags, to)
		ret, err := translateReturn(rc)
		return int64(ret), err
	}

	rw := getReadWriter(s.fd)
	rw.to = to
	n, err := src.CopyInTo(t, rw)
	putReadWriter(rw)
	return n, err
}

// SendMsg implements socket.Socket.SendMsg.
func (s *socketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	total := src.NumBytes()
	nonblock := flags & syscall.MSG_DONTWAIT
	sysflags := flags | syscall.MSG_DONTWAIT

	n, err := s.send(t, src, to, sysflags)

	if nonblock != 0 {
		return int(n), syserr.FromError(err)
	}

	var sent int64
	for err == nil || err == linuxerr.ErrWouldBlock {
		if n > 0 {
			src = src.DropFirst64(n)
			sent += n
		}

		if sent == total {
			return int(total), nil
		}

		if haveDeadline {
			err = s.waitEventT(t, waiter.EventOut, deadline)
		} else {
			err = s.waitEvent(t, waiter.EventOut)
		}

		if err != nil {
			if err == linuxerr.ETIMEDOUT {
				err = linuxerr.ErrWouldBlock
			}
			return int(sent), syserr.FromError(err)
		}

		n, err = s.send(t, src, to, sysflags)
	}

	return int(sent), syserr.FromError(err)
}

// Write implements socket.Socket.Write.
func (s *socketOperations) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	bytes := src.NumBytes()
	// If src is empty, let plugin stack handle sending 0-byte data based on protocol.
	if bytes == 0 {
		rc := cgo.Write(s.fd, 0, 0)
		ret, err := translateReturn(rc)
		return int64(ret), err
	}

	rw := getReadWriter(s.fd)
	n, err := src.CopyInTo(ctx, rw)
	putReadWriter(rw)
	if n < bytes && err == nil {
		return n, linuxerr.ErrWouldBlock
	}
	return int64(n), err
}

// waitEvent implements blocking wait on given events
// until one of the events have been reported.
func (s *socketOperations) waitEvent(ctx context.Context, event waiter.EventMask) error {
	var err error
	t := ctx.(*kernel.Task)
	e, ch := waiter.NewChannelEntry(event | waiter.EventErr | waiter.EventHUp)
	s.EventRegister(&e)

	// It's possible events happens between last check and EventRegister.
	// If this happens and we don't check readiness again, we would miss
	// the event and get blocked forever.
	if s.Readiness(event|waiter.EventErr|waiter.EventHUp) == 0 {
		err = t.Block(ch)
	}

	s.EventUnregister(&e)
	return err
}

// waitEventT implements blocking wait on given events
// until one of the events have been reported or timeout based on given deadline.
func (s *socketOperations) waitEventT(ctx context.Context, event waiter.EventMask, deadline ktime.Time) error {
	var err error
	t := ctx.(*kernel.Task)
	e, ch := waiter.NewChannelEntry(event | waiter.EventErr | waiter.EventHUp)
	s.EventRegister(&e)

	if s.Readiness(event|waiter.EventErr|waiter.EventHUp) == 0 {
		err = t.BlockWithDeadline(ch, true, deadline)
	}

	s.EventUnregister(&e)
	return err
}
