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

// +build linux,!amd64

package rawfile

import (
	"syscall"
	"unsafe"
)

// BlockingPoll is just a stub function that forwards to the poll() system call
// on non-amd64 platforms.
func BlockingPoll(fds *PollEvent, nfds int, timeout int64) (int, syscall.Errno) {
	n, _, e := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(fds)), uintptr(nfds), uintptr(timeout))
	return int(n), e
}
