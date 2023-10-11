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
#include <sys/socket.h>

// socket control operations
int external_socket(int domain, int type, int protocol);
int external_listen(int sockfd, int backlog);
int external_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int external_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int external_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int external_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen);
int external_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen);
int external_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int external_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int external_ioctl(int d,  unsigned long int request, ...);
int external_shutdown(int sockfd, int how);
int external_close(int fd);

// receiving data operations
ssize_t external_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t external_recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t external_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t external_read(int fd, void *buf, size_t count);
ssize_t external_readv(int fd, const struct iovec *iov, int iovcnt);

// sending data operations
ssize_t external_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t external_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t external_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t external_write(int fd, const void *buf, size_t count);
ssize_t external_writev(int fd, const struct iovec *iov, int iovcnt);

*/
import "C"
import (
	"syscall"
)

func Socket(domain, skType, protocol int) int {
	//TODO: implement cgo wrapper
	return 0
}

func Bind(handle uint32, sa []byte) int {
	//TODO: implement cgo wrapper
	return 0
}

func Listen(handle uint32, backlog int) int {
	//TODO: implement cgo wrapper
	return 0
}

func Accept(handle uint32, addrPtr *byte, lenPtr *uint32) int {
	//TODO: implement cgo wrapper
	return 0
}

func Ioctl(handle uint32, cmd uint32, buf []byte) int {
	//TODO: implement cgo wrapper
	return 0
}

func Connect(handle uint32, addr []byte) int {
	//TODO: implement cgo wrapper
	return 0
}

func Getsockopt(handle uint32, l int, n int, val []byte, s int) (int, int) {
	//TODO: implement cgo wrapper
	return 0, 0
}

func Setsockopt(handle uint32, l int, n int, val []byte) int {
	//TODO: implement cgo wrapper
	return 0
}

func Shutdown(handle uint32, how int) int {
	//TODO: implement cgo wrapper
	return 0
}

func Close(handle uint32) {
	//TODO: implement cgo wrapper
}

func Read(handle uint32, buf uintptr, count int) int64 {
	//TODO: implement cgo wrapper
	return 0
}

func Readv(handle uint32, iovs []syscall.Iovec) int64 {
	//TODO: implement cgo wrapper
	return 0
}

func Recvfrom(handle uint32, buf, addr []byte, flags int) (int64, int) {
	//TODO: implement cgo wrapper
	return 0, 0
}

func Recvmsg(handle uint32, iovs []syscall.Iovec, addr, control []byte, flags int) (int64, int, int, int) {
	//TODO: implement cgo wrapper
	return 0, 0, 0, 0
}

func Write(handle uint32, buf uintptr, count int) int64 {
	//TODO: implement cgo wrapper
	return 0
}

func Writev(handle uint32, iovs []syscall.Iovec) int64 {
	//TODO: implement cgo wrapper
	return 0
}

func Sendto(handle uint32, buf uintptr, count int, flags int, addr []byte) int64 {
	//TODO: implement cgo wrapper
	return 0
}

func Sendmsg(handle uint32, iovs []syscall.Iovec, addr []byte, flags int) int64 {
	//TODO: implement cgo wrapper
	return 0
}
