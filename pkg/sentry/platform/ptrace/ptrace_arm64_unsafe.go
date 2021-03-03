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

// +build arm64

package ptrace

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// getTLS gets the thread local storage register.
func (t *thread) getTLS(tls *uint64) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(tls)),
		Len:  uint64(unsafe.Sizeof(*tls)),
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_GETREGSET,
		uintptr(t.tid),
		linux.NT_ARM_TLS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setTLS sets the thread local storage register.
func (t *thread) setTLS(tls *uint64) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(tls)),
		Len:  uint64(unsafe.Sizeof(*tls)),
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_SETREGSET,
		uintptr(t.tid),
		linux.NT_ARM_TLS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
