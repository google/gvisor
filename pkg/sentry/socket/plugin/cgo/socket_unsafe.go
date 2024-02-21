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

package cgo

/*
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>

// epoll
int plugin_epoll_create(void);
int plugin_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int plugin_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

// socket control operations
int plugin_socket(int domain, int type, int protocol, uint64_t *err);
int plugin_listen(int sockfd, int backlog, uint64_t *err);
int plugin_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err);
int plugin_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err);
int plugin_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen, uint64_t *err);
int plugin_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen, uint64_t *err);
int plugin_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_ioctl(int fd, uint64_t *err, unsigned long int request, void *buf);
int plugin_shutdown(int sockfd, int how, uint64_t *err);
int plugin_close(int fd);
int plugin_readiness(int fd, int events);

// receiving data operations
ssize_t plugin_recv(int sockfd, void *buf, size_t len, int flags, uint64_t *err);
ssize_t plugin_recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen, uint64_t *err);
ssize_t plugin_recvmsg(int sockfd, struct msghdr *msg, int flags, uint64_t *err);
ssize_t plugin_read(int fd, void *buf, size_t count, uint64_t *err);
ssize_t plugin_readv(int fd, const struct iovec *iov, int iovcnt, uint64_t *err);

// sending data operations
ssize_t plugin_send(int sockfd, const void *buf, size_t len, int flags, uint64_t *err);
ssize_t plugin_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen, uint64_t *err);
ssize_t plugin_sendmsg(int sockfd, const struct msghdr *msg, int flags, uint64_t *err);
ssize_t plugin_write(int fd, const void *buf, size_t count, uint64_t *err);
ssize_t plugin_writev(int fd, const struct iovec *iov, int iovcnt, uint64_t *err);
*/
import "C"
import (
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	linuxerrno "gvisor.dev/gvisor/pkg/abi/linux/errno"
)

// EpollCreate works as a CGO wrapper for plugin_epoll_create.
func EpollCreate() int {
	return int(C.plugin_epoll_create())
}

// EpollCtl works as a CGO wrapper for plugin_epoll_ctl.
func EpollCtl(epfd int32, op int, handle uint32, w uint64) {
	event := syscall.EpollEvent{
		Events: uint32(w),
		Fd:     int32(handle),
	}
	C.plugin_epoll_ctl(
		C.int(epfd),
		C.int(op),
		C.int(handle),
		(*C.struct_epoll_event)(unsafe.Pointer(&event)))
}

// EpollWait works as a CGO wrapper for plugin_epoll_wait.
func EpollWait(epfd int32, events []syscall.EpollEvent, n int, us int) int {
	if len(events) == 0 {
		return 0
	}
	return int(C.plugin_epoll_wait(
		C.int(epfd),
		(*C.struct_epoll_event)(unsafe.Pointer(&events[0])),
		C.int(n),
		C.int(us)))
}

// Socket works as a CGO wrapper for plugin_socket.
func Socket(domain, skType, protocol int) int {
	var errno uint64
	if fd := int(C.plugin_socket(
		C.int(domain),
		C.int(skType),
		C.int(protocol),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); fd < 0 {
		return -int(errno)
	} else {
		nonblock := 1
		C.plugin_ioctl(
			C.int(fd),
			(*C.uint64_t)(unsafe.Pointer(&errno)),
			C.uint64_t(linux.FIONBIO),
			unsafe.Pointer(&nonblock))
		return fd
	}
}

// Bind works as a CGO wrapper for plugin_bind.
func Bind(handle uint32, sa []byte) int {
	var errno uint64
	if ret := int(C.plugin_bind(
		C.int(handle),
		(*C.struct_sockaddr)(GetPtr(sa)),
		C.uint(len(sa)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret != 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Listen works as a CGO wrapper for plugin_listen.
func Listen(handle uint32, backlog int) int {
	var errno uint64
	if ret := int(C.plugin_listen(
		C.int(handle),
		C.int(backlog),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret != 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Accept works as a CGO wrapper for plugin_accept.
func Accept(handle uint32, addrPtr *byte, lenPtr *uint32) int {
	var errno uint64
	if fd := int(C.plugin_accept(
		C.int(handle),
		(*C.struct_sockaddr)(unsafe.Pointer(addrPtr)),
		(*C.socklen_t)(unsafe.Pointer(lenPtr)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); fd < 0 {
		return -int(errno)
	} else {
		non_blocking := 1
		C.plugin_ioctl(
			C.int(fd),
			(*C.uint64_t)(unsafe.Pointer(&errno)),
			C.uint64_t(linux.FIONBIO),
			unsafe.Pointer(&non_blocking))
		return fd
	}
}

// Ioctl works as a CGO wrapper for plugin_ioctl.
func Ioctl(handle uint32, cmd uint32, buf []byte) int {
	var errno uint64
	if ret := int(C.plugin_ioctl(
		C.int(handle),
		(*C.uint64_t)(unsafe.Pointer(&errno)),
		C.uint64_t(cmd),
		GetPtr(buf))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Connect works as a CGO wrapper for plugin_connect.
func Connect(handle uint32, addr []byte) int {
	var errno uint64
	if ret := int(C.plugin_connect(
		C.int(handle),
		(*C.struct_sockaddr)(GetPtr(addr)),
		C.socklen_t(len(addr)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Getsockopt works as a CGO wrapper for plugin_getsockopt.
func Getsockopt(handle uint32, l int, n int, val []byte, s int) (int, int) {
	var errno uint64
	if ret := int(C.plugin_getsockopt(
		C.int(handle),
		C.int(l),
		C.int(n),
		GetPtr(val),
		(*C.uint)(unsafe.Pointer(&s)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno), s
	} else {
		return ret, s
	}
}

// Setsockopt works as a CGO wrapper for plugin_setsockopt.
func Setsockopt(handle uint32, l int, n int, val []byte) int {
	var errno uint64
	if ret := int(C.plugin_setsockopt(
		C.int(handle),
		C.int(l),
		C.int(n),
		GetPtr(val),
		C.uint(len(val)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Shutdown works as a CGO wrapper for plugin_shutdown.
func Shutdown(handle uint32, how int) int {
	var errno uint64
	if ret := int(C.plugin_shutdown(
		C.int(handle),
		C.int(how),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Close works as a CGO wrapper for plugin_close.
func Close(handle uint32) {
	C.plugin_close(C.int(handle))
}

// Getsockname works as a CGO wrapper for plugin_getsockname.
func Getsockname(handle uint32, addr []byte, addrlen *uint32) int {
	var errno uint64
	if len(addr) == 0 {
		return -linuxerrno.EINVAL
	}
	if ret := int(C.plugin_getsockname(
		C.int(handle),
		(*C.struct_sockaddr)(unsafe.Pointer(&addr[0])),
		(*C.socklen_t)(unsafe.Pointer(addrlen)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// GetPeername works as a CGO wrapper for plugin_getpeername.
func GetPeername(handle uint32, addr []byte, addrlen *uint32) int {
	var errno uint64
	if len(addr) == 0 {
		return -linuxerrno.EINVAL
	}
	if ret := int(C.plugin_getpeername(
		C.int(handle),
		(*C.struct_sockaddr)(unsafe.Pointer(&addr[0])),
		(*C.socklen_t)(unsafe.Pointer(addrlen)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int(errno)
	} else {
		return ret
	}
}

// Readiness works as a CGO wrapper for plugin_readiness.
func Readiness(handle uint32, mask uint64) int {
	return int(C.plugin_readiness(C.int(handle), C.int(mask)))
}

// Read works as a CGO wrapper for plugin_read.
func Read(handle uint32, buf uintptr, count int) int64 {
	var errno uint64
	if ret := int64(C.plugin_read(
		C.int(handle),
		unsafe.Pointer(buf),
		C.size_t(count),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}

// Readv works as a CGO wrapper for plugin_readv.
func Readv(handle uint32, iovs []syscall.Iovec) int64 {
	var errno uint64
	if len(iovs) == 0 {
		return 0
	}
	if ret := int64(C.plugin_readv(
		C.int(handle),
		(*C.struct_iovec)(unsafe.Pointer(&iovs[0])),
		C.int(len(iovs)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}

// Recvfrom works as a CGO wrapper for plugin_recvfrom.
func Recvfrom(handle uint32, buf, addr []byte, flags int) (int64, int) {
	var errno uint64
	addrlen := len(addr)
	if ret := int64(C.plugin_recvfrom(
		C.int(handle),
		GetPtr(buf),
		C.size_t(len(buf)),
		C.int(flags),
		(*C.struct_sockaddr)(GetPtr(addr)),
		(*C.socklen_t)(unsafe.Pointer(&addrlen)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno), addrlen
	} else {
		return ret, addrlen
	}
}

// Recvmsg works as a CGO wrapper for plugin_recvmsg.
func Recvmsg(handle uint32, iovs []syscall.Iovec, addr, control []byte, flags int) (int64, int, int, int) {
	len_addr := len(addr)
	len_ctl := len(control)
	sysflags := flags | syscall.MSG_DONTWAIT

	if len(iovs) == 0 {
		return 0, len_addr, len_ctl, 0
	}

	var ptr_addr, ptr_ctl *byte
	if len_addr > 0 {
		ptr_addr = &addr[0]
	}

	if len_ctl > 0 {
		ptr_ctl = &control[0]
	}

	msg := syscall.Msghdr{
		Iov:        &iovs[0],
		Iovlen:     uint64(len(iovs)),
		Name:       ptr_addr,
		Namelen:    uint32(len_addr),
		Control:    ptr_ctl,
		Controllen: uint64(len_ctl),
	}

	var errno uint64
	if ret := int64(C.plugin_recvmsg(
		C.int(handle),
		(*C.struct_msghdr)(unsafe.Pointer(&msg)),
		C.int(sysflags),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno), len_addr, len_ctl, 0
	} else {
		return ret, int(msg.Namelen), int(msg.Controllen), int(msg.Flags)
	}
}

// Write works as a CGO wrapper for plugin_write.
func Write(handle uint32, buf uintptr, count int) int64 {
	var errno uint64
	if ret := int64(C.plugin_write(
		C.int(handle),
		unsafe.Pointer(buf),
		C.size_t(count),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}

// Writev works as a CGO wrapper for plugin_writev.
func Writev(handle uint32, iovs []syscall.Iovec) int64 {
	var errno uint64
	if len(iovs) == 0 {
		return 0
	}
	if ret := int64(C.plugin_writev(
		C.int(handle),
		(*C.struct_iovec)(unsafe.Pointer(&iovs[0])),
		C.int(len(iovs)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}

// Sendto works as a CGO wrapper for plugin_sendto.
func Sendto(handle uint32, buf uintptr, count int, flags int, addr []byte) int64 {
	var errno uint64
	if ret := int64(C.plugin_sendto(
		C.int(handle),
		unsafe.Pointer(buf),
		C.size_t(count),
		C.int(flags),
		(*C.struct_sockaddr)(GetPtr(addr)),
		C.socklen_t(len(addr)),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}

// Sendmsg works as a CGO wrapper for plugin_sendmsg.
func Sendmsg(handle uint32, iovs []syscall.Iovec, addr []byte, flags int) int64 {
	var errno uint64
	if len(iovs) == 0 {
		return 0
	}
	if len(addr) == 0 {
		return -linuxerrno.EINVAL
	}

	msg := syscall.Msghdr{
		Iov:     &iovs[0],
		Iovlen:  uint64(len(iovs)),
		Name:    &addr[0],
		Namelen: uint32(len(addr)),
	}
	if ret := int64(C.plugin_sendmsg(
		C.int(handle),
		(*C.struct_msghdr)(unsafe.Pointer(&msg)),
		C.int(flags),
		(*C.uint64_t)(unsafe.Pointer(&errno)))); ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}
