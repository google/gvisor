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

package hostinet

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
)

func firstBytePtr(bs []byte) unsafe.Pointer {
	if bs == nil {
		return nil
	}
	return unsafe.Pointer(&bs[0])
}

// Preconditions: len(dsts) != 0.
func readv(fd int, dsts []unix.Iovec) (uint64, error) {
	n, _, errno := unix.Syscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&dsts[0])), uintptr(len(dsts)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

// Preconditions: len(srcs) != 0.
func writev(fd int, srcs []unix.Iovec) (uint64, error) {
	n, _, errno := unix.Syscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&srcs[0])), uintptr(len(srcs)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

func ioctl(ctx context.Context, fd int, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := uintptr(args[1].Int()); cmd {
	case unix.TIOCINQ, unix.TIOCOUTQ:
		var val int32
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&val))); errno != 0 {
			return 0, translateIOSyscallError(errno)
		}
		var buf [4]byte
		hostarch.ByteOrder.PutUint32(buf[:], uint32(val))
		_, err := io.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case unix.SIOCGIFFLAGS:
		cc := &usermem.IOCopyContext{
			Ctx: ctx,
			IO:  io,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		}
		var ifr linux.IFReq
		if _, err := ifr.CopyIn(cc, args[2].Pointer()); err != nil {
			return 0, err
		}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
			return 0, translateIOSyscallError(errno)
		}
		_, err := ifr.CopyOut(cc, args[2].Pointer())
		return 0, err
	case unix.SIOCGIFCONF:
		cc := &usermem.IOCopyContext{
			Ctx: ctx,
			IO:  io,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		}
		var ifc linux.IFConf
		if _, err := ifc.CopyIn(cc, args[2].Pointer()); err != nil {
			return 0, err
		}
		// TODO(b/209503078): Check ifc.Ptr range is in untrusted range.
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&ifc))); errno != 0 {
			return 0, translateIOSyscallError(errno)
		}
		_, err := ifc.CopyOut(cc, args[2].Pointer())
		return 0, err
	case linux.SIOCETHTOOL:
		cc := &usermem.IOCopyContext{
			Ctx: ctx,
			IO:  io,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		}
		var ifr linux.IFReq
		if _, err := ifr.CopyIn(cc, args[2].Pointer()); err != nil {
			return 0, err
		}
		// SIOCETHTOOL commands specify the subcommand in the first 32 bytes pointed
		// to by ifr.ifr_data. We need to copy it in first to understand the actual
		// structure pointed by ifr.ifr_data.
		ifrData := hostarch.Addr(hostarch.ByteOrder.Uint64(ifr.Data[:8]))
		var ethtoolCmd linux.EthtoolCmd
		if _, err := ethtoolCmd.CopyIn(cc, ifrData); err != nil {
			return 0, err
		}
		// We only support ETHTOOL_GFEATURES.
		if ethtoolCmd != linux.ETHTOOL_GFEATURES {
			return 0, linuxerr.EOPNOTSUPP
		}
		var gfeatures linux.EthtoolGFeatures
		if _, err := gfeatures.CopyIn(cc, ifrData); err != nil {
			return 0, err
		}

		// Find the requested device.
		stk := inet.StackFromContext(ctx)
		if stk == nil {
			return 0, linuxerr.ENODEV
		}

		var (
			iface inet.Interface
			found bool
		)
		for _, iface = range stk.Interfaces() {
			if iface.Name == ifr.Name() {
				found = true
				break
			}
		}
		if !found {
			return 0, linuxerr.ENODEV
		}

		// Copy out the feature blocks to the memory pointed to by ifrData.
		blksToCopy := int(gfeatures.Size)
		if blksToCopy > len(iface.Features) {
			blksToCopy = len(iface.Features)
		}
		gfeatures.Size = uint32(blksToCopy)
		if _, err := gfeatures.CopyOut(cc, ifrData); err != nil {
			return 0, err
		}
		next, ok := ifrData.AddLength(uint64(unsafe.Sizeof(linux.EthtoolGFeatures{})))
		for i := 0; i < blksToCopy; i++ {
			if !ok {
				return 0, linuxerr.EFAULT
			}
			if _, err := iface.Features[i].CopyOut(cc, next); err != nil {
				return 0, err
			}
			next, ok = next.AddLength(uint64(unsafe.Sizeof(linux.EthtoolGetFeaturesBlock{})))
		}

		return 0, nil
	default:
		return 0, linuxerr.ENOTTY
	}
}

func accept4(fd int, addr *byte, addrlen *uint32, flags int) (int, error) {
	afd, _, errno := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(fd), uintptr(unsafe.Pointer(addr)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return int(afd), nil
}

func getsockopt(fd int, level, name int, opt []byte) ([]byte, error) {
	optlen32 := int32(len(opt))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(firstBytePtr(opt)), uintptr(unsafe.Pointer(&optlen32)), 0)
	if errno != 0 {
		return nil, errno
	}
	return opt[:optlen32], nil
}

// GetSockName implements socket.Socket.GetSockName.
func (s *socketOpsCommon) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr := make([]byte, sizeofSockaddr)
	addrlen := uint32(len(addr))
	_, _, errno := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(s.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return nil, 0, syserr.FromError(errno)
	}
	return socket.UnmarshalSockAddr(s.family, addr), addrlen, nil
}

// GetPeerName implements socket.Socket.GetPeerName.
func (s *socketOpsCommon) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	addr := make([]byte, sizeofSockaddr)
	addrlen := uint32(len(addr))
	_, _, errno := unix.Syscall(unix.SYS_GETPEERNAME, uintptr(s.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return nil, 0, syserr.FromError(errno)
	}
	return socket.UnmarshalSockAddr(s.family, addr), addrlen, nil
}

func recvfrom(fd int, dst []byte, flags int, from *[]byte) (uint64, error) {
	fromLen := uint32(len(*from))
	n, _, errno := unix.Syscall6(unix.SYS_RECVFROM, uintptr(fd), uintptr(firstBytePtr(dst)), uintptr(len(dst)), uintptr(flags), uintptr(firstBytePtr(*from)), uintptr(unsafe.Pointer(&fromLen)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	*from = (*from)[:fromLen]
	return uint64(n), nil
}

func recvmsg(fd int, msg *unix.Msghdr, flags int) (uint64, error) {
	n, _, errno := unix.Syscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

func sendmsg(fd int, msg *unix.Msghdr, flags int) (uint64, error) {
	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}
