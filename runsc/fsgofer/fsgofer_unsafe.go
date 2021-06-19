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

package fsgofer

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/syserr"
)

var unixDirentMaxSize uint32 = uint32(unsafe.Sizeof(unix.Dirent{}))

func utimensat(dirFd int, name string, times [2]unix.Timespec, flags int) error {
	// utimensat(2) doesn't accept empty name, instead name must be nil to make it
	// operate directly on 'dirFd' unlike other *at syscalls.
	var namePtr unsafe.Pointer
	if name != "" {
		nameBytes, err := unix.BytePtrFromString(name)
		if err != nil {
			return err
		}
		namePtr = unsafe.Pointer(nameBytes)
	}

	timesPtr := unsafe.Pointer(&times[0])

	if _, _, errno := unix.Syscall6(
		unix.SYS_UTIMENSAT,
		uintptr(dirFd),
		uintptr(namePtr),
		uintptr(timesPtr),
		uintptr(flags),
		0,
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

func renameat(oldDirFD int, oldName string, newDirFD int, newName string) error {
	var oldNamePtr unsafe.Pointer
	if oldName != "" {
		nameBytes, err := unix.BytePtrFromString(oldName)
		if err != nil {
			return err
		}
		oldNamePtr = unsafe.Pointer(nameBytes)
	}
	var newNamePtr unsafe.Pointer
	if newName != "" {
		nameBytes, err := unix.BytePtrFromString(newName)
		if err != nil {
			return err
		}
		newNamePtr = unsafe.Pointer(nameBytes)
	}

	if _, _, errno := unix.Syscall6(
		unix.SYS_RENAMEAT,
		uintptr(oldDirFD),
		uintptr(oldNamePtr),
		uintptr(newDirFD),
		uintptr(newNamePtr),
		0,
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

func parseDirents(buf []byte, handleDirent func(ino uint64, off int64, ftype uint8, name string) bool) {
	for len(buf) > 0 {
		// Interpret the buf populated by unix.Getdents as unix.Dirent.
		dirent := *(*unix.Dirent)(unsafe.Pointer(&buf[0]))

		// Extracting the name is pretty tedious...
		var nameBuf [unix.NAME_MAX]byte
		var nameLen int
		for i := 0; i < len(dirent.Name); i++ {
			// The name is null terminated.
			if dirent.Name[i] == 0 {
				nameLen = i
				break
			}
			nameBuf[i] = byte(dirent.Name[i])
		}
		name := string(nameBuf[:nameLen])

		// Deliver results to caller.
		if !handleDirent(dirent.Ino, dirent.Off, dirent.Type, name) {
			return
		}

		// Advance buf for the next dirent.
		buf = buf[dirent.Reclen:]
	}
}
