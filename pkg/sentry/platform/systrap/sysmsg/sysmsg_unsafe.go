// Copyright 2023 The gVisor Authors.
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

package sysmsg

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// SleepOnState makes the caller sleep on the ThreadContext.State futex.
func (c *ThreadContext) SleepOnState(curState ContextState) {
	_, _, errno := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.State)),
		linux.FUTEX_WAIT, uintptr(curState), 0, 0, 0)
	if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
		panic(fmt.Sprintf("error waiting for state: %v", errno))
	}
}

// WakeSysmsgThread calls futex wake on Sysmsg.State.
func (m *Msg) WakeSysmsgThread() syscall.Errno {
	m.State.Set(ThreadStatePrep)
	_, _, e := unix.RawSyscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&m.State)), linux.FUTEX_WAKE, 1, 0, 0, 0)
	return e
}
