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

package host

import (
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func ioctlGetTermios(fd int) (*linux.Termios, error) {
	var t linux.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.TCGETS, uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return nil, errno
	}
	return &t, nil
}

func ioctlSetTermios(fd int, req uint64, t *linux.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlGetWinsize(fd int) (*linux.Winsize, error) {
	var w linux.Winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.TIOCGWINSZ, uintptr(unsafe.Pointer(&w)))
	if errno != 0 {
		return nil, errno
	}
	return &w, nil
}

func ioctlSetWinsize(fd int, w *linux.Winsize) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.TIOCSWINSZ, uintptr(unsafe.Pointer(w)))
	if errno != 0 {
		return errno
	}
	return nil
}
