// Copyright 2018 Google Inc.
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

package fsgofer

import (
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

func statAt(dirFd int, name string) (syscall.Stat_t, error) {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return syscall.Stat_t{}, extractErrno(err)
	}
	namePtr := uintptr(unsafe.Pointer(nameBytes))

	var stat syscall.Stat_t
	statPtr := uintptr(unsafe.Pointer(&stat))

	if _, _, err := syscall.Syscall6(syscall.SYS_NEWFSTATAT, uintptr(dirFd), namePtr, statPtr, linux.AT_SYMLINK_NOFOLLOW, 0, 0); err != 0 {
		return syscall.Stat_t{}, err
	}
	return stat, nil
}

func utimensat(dirFd int, name string, times [2]syscall.Timespec, flags int) error {
	// utimensat(2) doesn't accept empty name, instead name must be nil to make it
	// operate directly on 'dirFd' unlike other *at syscalls.
	var namePtr uintptr
	if name != "" {
		nameBytes, err := syscall.BytePtrFromString(name)
		if err != nil {
			return extractErrno(err)
		}
		namePtr = uintptr(unsafe.Pointer(nameBytes))
	}

	timesPtr := uintptr(unsafe.Pointer(&times[0]))

	if _, _, err := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(dirFd), namePtr, timesPtr, uintptr(flags), 0, 0); err != 0 {
		return err
	}
	return nil
}
