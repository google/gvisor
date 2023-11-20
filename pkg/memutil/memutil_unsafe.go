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

// Package memutil provides utilities for working with shared memory files.
package memutil

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MapSlice is like MapFile, but returns a slice instead of a uintptr.
func MapSlice(addr, size, prot, flags, fd, offset uintptr) ([]byte, error) {
	addr, err := MapFile(addr, size, prot, flags, fd, offset)
	if err != nil {
		return nil, err
	}
	var slice []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	hdr.Data = addr
	hdr.Len = int(size)
	hdr.Cap = int(size)
	return slice, nil
}

// UnmapSlice unmaps a mapping returned by MapSlice.
func UnmapSlice(slice []byte) error {
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	_, _, err := unix.RawSyscall6(unix.SYS_MUNMAP, uintptr(unsafe.Pointer(hdr.Data)), uintptr(hdr.Cap), 0, 0, 0, 0)
	return err
}

// MapAlignedPrivateAnon returns a memory mapping configured by the given
// options. MAP_PRIVATE and MAP_ANONYMOUS are implicitly added to flags. If
// MapAlignedPrivateAnon succeeds, the returned address is an integer multiple
// of align.
//
// Preconditions: align must be a power of two multiple of the page size.
func MapAlignedPrivateAnon(size, align, prot, flags uintptr) (uintptr, error) {
	sizePadded := size + align
	if sizePadded < size {
		return 0, unix.ENOMEM
	}
	m, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0, sizePadded, prot, uintptr(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)|flags, ^uintptr(0), 0)
	if errno != 0 {
		return 0, errno
	}
	mask := align - 1
	mAligned := (m + mask) &^ mask
	padHead := mAligned - m
	if padHead != 0 {
		unix.RawSyscall(unix.SYS_MUNMAP, m, padHead, 0)
	}
	padTail := align - padHead
	if padTail != 0 {
		unix.RawSyscall(unix.SYS_MUNMAP, mAligned+size, padTail, 0)
	}
	return mAligned, nil
}
