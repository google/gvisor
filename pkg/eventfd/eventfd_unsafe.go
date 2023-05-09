// Copyright 2021 The gVisor Authors.
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

package eventfd

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// nonBlockingWrite writes the given buffer to a file descriptor. It fails if
// partial data is written.
func nonBlockingWrite(fd int, buf []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	nwritten, _, errno := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	if errno != 0 {
		return int(nwritten), errno
	}
	return int(nwritten), nil
}
