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
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

func firstBytePtr(bs []byte) unsafe.Pointer {
	if bs == nil {
		return nil
	}
	return unsafe.Pointer(&bs[0])
}

// Preconditions: len(dsts) != 0.
func readv(fd int, dsts []syscall.Iovec) (uint64, error) {
	n, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&dsts[0])), uintptr(len(dsts)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

// Preconditions: len(srcs) != 0.
func writev(fd int, srcs []syscall.Iovec) (uint64, error) {
	n, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&srcs[0])), uintptr(len(srcs)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

// Ioctl implements fs.FileOperations.Ioctl.
func (s *socketOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := uintptr(args[1].Int()); cmd {
	case syscall.TIOCINQ, syscall.TIOCOUTQ:
		var val int32
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s.fd), cmd, uintptr(unsafe.Pointer(&val))); errno != 0 {
			return 0, translateIOSyscallError(errno)
		}
		var buf [4]byte
		usermem.ByteOrder.PutUint32(buf[:], uint32(val))
		_, err := io.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

func accept4(fd int, addr *byte, addrlen *uint32, flags int) (int, error) {
	afd, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4, uintptr(fd), uintptr(unsafe.Pointer(addr)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return int(afd), nil
}

func getsockopt(fd int, level, name int, optlen int) ([]byte, error) {
	opt := make([]byte, optlen)
	optlen32 := int32(len(opt))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(firstBytePtr(opt)), uintptr(unsafe.Pointer(&optlen32)), 0)
	if errno != 0 {
		return nil, errno
	}
	return opt[:optlen32], nil
}

// GetSockName implements socket.Socket.GetSockName.
func (s *socketOperations) GetSockName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr := make([]byte, sizeofSockaddr)
	addrlen := uint32(len(addr))
	_, _, errno := syscall.Syscall(syscall.SYS_GETSOCKNAME, uintptr(s.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return nil, 0, syserr.FromError(errno)
	}
	return addr[:addrlen], addrlen, nil
}

// GetPeerName implements socket.Socket.GetPeerName.
func (s *socketOperations) GetPeerName(t *kernel.Task) (interface{}, uint32, *syserr.Error) {
	addr := make([]byte, sizeofSockaddr)
	addrlen := uint32(len(addr))
	_, _, errno := syscall.Syscall(syscall.SYS_GETPEERNAME, uintptr(s.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return nil, 0, syserr.FromError(errno)
	}
	return addr[:addrlen], addrlen, nil
}

func recvfrom(fd int, dst []byte, flags int, from *[]byte) (uint64, error) {
	fromLen := uint32(len(*from))
	n, _, errno := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(fd), uintptr(firstBytePtr(dst)), uintptr(len(dst)), uintptr(flags), uintptr(firstBytePtr(*from)), uintptr(unsafe.Pointer(&fromLen)))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	*from = (*from)[:fromLen]
	return uint64(n), nil
}

func recvmsg(fd int, msg *syscall.Msghdr, flags int) (uint64, error) {
	n, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}

func sendmsg(fd int, msg *syscall.Msghdr, flags int) (uint64, error) {
	n, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	if errno != 0 {
		return 0, translateIOSyscallError(errno)
	}
	return uint64(n), nil
}
