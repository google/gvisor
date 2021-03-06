// Copyright 2020 The gVisor Authors.
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

package iptables

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

type originalDstError struct {
	errno unix.Errno
}

func (e originalDstError) Error() string {
	return fmt.Sprintf("errno (%d) when calling getsockopt(SO_ORIGINAL_DST): %v", int(e.errno), e.errno.Error())
}

// SO_ORIGINAL_DST gets the original destination of a redirected packet via
// getsockopt.
const SO_ORIGINAL_DST = 80

func originalDestination4(connfd int) (unix.RawSockaddrInet4, error) {
	var addr unix.RawSockaddrInet4
	var addrLen uint32 = unix.SizeofSockaddrInet4
	if errno := originalDestination(connfd, unix.SOL_IP, unsafe.Pointer(&addr), &addrLen); errno != 0 {
		return unix.RawSockaddrInet4{}, originalDstError{errno}
	}
	return addr, nil
}

func originalDestination6(connfd int) (unix.RawSockaddrInet6, error) {
	var addr unix.RawSockaddrInet6
	var addrLen uint32 = unix.SizeofSockaddrInet6
	if errno := originalDestination(connfd, unix.SOL_IPV6, unsafe.Pointer(&addr), &addrLen); errno != 0 {
		return unix.RawSockaddrInet6{}, originalDstError{errno}
	}
	return addr, nil
}

func originalDestination(connfd int, level uintptr, optval unsafe.Pointer, optlen *uint32) unix.Errno {
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(connfd),
		level,
		SO_ORIGINAL_DST,
		uintptr(optval),
		uintptr(unsafe.Pointer(optlen)),
		0)
	return errno
}
