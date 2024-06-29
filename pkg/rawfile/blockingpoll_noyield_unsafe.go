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

//go:build linux && !amd64 && !arm64
// +build linux,!amd64,!arm64

package rawfile

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// BlockingPoll is just a stub function that forwards to the ppoll() system call
// on non-amd64 and non-arm64 platforms.
func BlockingPoll(fds *PollEvent, nfds int, timeout *unix.Timespec) (int, unix.Errno) {
	n, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(fds)),
		uintptr(nfds), uintptr(unsafe.Pointer(timeout)), 0, 0, 0)

	return int(n), e
}
