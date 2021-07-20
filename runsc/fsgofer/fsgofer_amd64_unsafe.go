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

//go:build amd64
// +build amd64

package fsgofer

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/syserr"
)

func statAt(dirFd int, name string) (unix.Stat_t, error) {
	nameBytes, err := unix.BytePtrFromString(name)
	if err != nil {
		return unix.Stat_t{}, err
	}
	namePtr := unsafe.Pointer(nameBytes)

	var stat unix.Stat_t
	statPtr := unsafe.Pointer(&stat)

	if _, _, errno := unix.Syscall6(
		unix.SYS_NEWFSTATAT,
		uintptr(dirFd),
		uintptr(namePtr),
		uintptr(statPtr),
		unix.AT_SYMLINK_NOFOLLOW,
		0,
		0); errno != 0 {

		return unix.Stat_t{}, syserr.FromHost(errno).ToError()
	}
	return stat, nil
}
