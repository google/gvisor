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

package filemem

import (
	"reflect"
	"syscall"
	"unsafe"
)

func unsafeSlice(addr uintptr, length int) (slice []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	sh.Data = addr
	sh.Len = length
	sh.Cap = length
	return
}

func mincore(s []byte, buf []byte) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_MINCORE,
		uintptr(unsafe.Pointer(&s[0])),
		uintptr(len(s)),
		uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return errno
	}
	return nil
}
