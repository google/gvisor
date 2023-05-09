// Copyright 2020 The gVisor Authors.
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

//go:build go1.1
// +build go1.1

package memutil

import (
	"golang.org/x/sys/unix"
)

// MapFile returns a memory mapping configured by the given options as per
// mmap(2).
func MapFile(addr, size, prot, flags, fd, offset uintptr) (uintptr, error) {
	m, _, e := unix.RawSyscall6(unix.SYS_MMAP, addr, size, prot, flags, fd, offset)
	if e != 0 {
		return 0, e
	}
	return m, nil
}
