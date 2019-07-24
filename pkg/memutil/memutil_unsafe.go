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

// +build linux

// Package memutil provides a wrapper for the memfd_create() system call.
package memutil

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// CreateMemFD creates a memfd file and returns the fd.
func CreateMemFD(name string, flags int) (*os.File, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	fd, _, e := syscall.Syscall(unix.SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(p)), uintptr(flags), 0)
	if e != 0 {
		if e == syscall.ENOSYS {
			return nil, fmt.Errorf("memfd_create(2) is not implemented. Check that you have Linux 3.17 or higher")
		}
		return nil, e
	}
	return os.NewFile(fd, name), nil
}
