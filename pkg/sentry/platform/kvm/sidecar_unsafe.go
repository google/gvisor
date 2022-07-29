// Copyright 2022 The gVisor Authors.
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

package kvm

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

//go:linkname cputicks runtime.cputicks
func cputicks() int64

//go:nosplit
func futexWakeUint32(addr *uint32) error {
	if _, _, e := unix.RawSyscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), linux.FUTEX_WAKE|linux.FUTEX_PRIVATE_FLAG, 1, 0, 0, 0); e != 0 {
		throw("FUTEX_WAKE")
	}
	return nil
}

//go:nosplit
func futexWaitWhileUint32(addr *atomicbitops.Uint32, oldValue uint32) {
	for {
		val := addr.Load()
		if val != oldValue {
			break
		}

		_, _, e := unix.RawSyscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr.Ptr())), linux.FUTEX_WAIT|linux.FUTEX_PRIVATE_FLAG, uintptr(val), 0, 0, 0)
		if e != 0 && e != unix.EAGAIN && e != unix.EINTR {
			throw("FUTEX_WAIT")
		}
	}
}
