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

package flipcall

import (
	"syscall"
)

// Return a memory mapping of the pwd in memory that can be shared outside the sandbox.
func packetWindowMmap(pwd PacketWindowDescriptor) (uintptr, syscall.Errno) {
	m, _, err := syscall.RawSyscall6(syscall.SYS_MMAP, 0, uintptr(pwd.Length), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED, uintptr(pwd.FD), uintptr(pwd.Offset))
	return m, err
}
