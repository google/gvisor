// Copyright 2019 The gVisor Authors.
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

// +build amd64

package host

import (
	"syscall"
	"unsafe"
)

func fstatat(fd int, name string, flags int) (syscall.Stat_t, error) {
	var stat syscall.Stat_t
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return stat, err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_NEWFSTATAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&stat)),
		uintptr(flags),
		0, 0)
	if errno != 0 {
		return stat, errno
	}
	return stat, nil
}
