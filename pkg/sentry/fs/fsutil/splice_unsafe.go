// Copyright 2018 Google LLC
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

package fsutil

import (
	"syscall"
	"unsafe"
)

func tee(srcFD, dstFD int, length int64) (int64, error) {
	n, _, errno := syscall.Syscall(
		syscall.SYS_TEE,
		uintptr(srcFD),
		uintptr(dstFD),
		uintptr(length))
	if errno != 0 {
		return int64(n), errno
	}
	return int64(n), nil
}

func sendfile(dstFD, srcFD int, offset *int64, length int64) (int64, error) {
	n, _, errno := syscall.Syscall6(
		syscall.SYS_SENDFILE,
		uintptr(dstFD),
		uintptr(srcFD),
		uintptr(unsafe.Pointer(offset)),
		uintptr(length), 0, 0)
	if errno != 0 {
		return int64(n), errno
	}
	return int64(n), nil
}
