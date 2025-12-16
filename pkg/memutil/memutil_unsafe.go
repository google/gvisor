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
	"unsafe"

	"golang.org/x/sys/unix"
)

// MapSlice is like MapFile, but returns a slice instead of a uintptr.
func MapSlice(addr, size, prot, flags, fd, offset uintptr) ([]byte, error) {
	addr, err := MapFile(addr, size, prot, flags, fd, offset)
	if err != nil {
		return nil, err
	}

	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(size)), nil
}

// UnmapSlice unmaps a mapping returned by MapSlice.
func UnmapSlice(slice []byte) error {
	ptr := unsafe.SliceData(slice)
	_, _, err := unix.RawSyscall6(unix.SYS_MUNMAP, uintptr(unsafe.Pointer(ptr)), uintptr(cap(slice)), 0, 0, 0, 0)
	return err
}
