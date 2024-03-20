// Copyright 2024 The gVisor Authors.
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
// limitations under the License

package tpuproxy

import (
	"unsafe"

	"golang.org/x/exp/constraints"
	"golang.org/x/sys/unix"
)

// IOCTLInvokePtrArg makes ioctl syscalls with the command of the integer type
// and the pointer to any given params.
func IOCTLInvokePtrArg[Cmd constraints.Integer, Params any](hostFd int32, cmd Cmd, params *Params) (uintptr, error) {
	return IOCTLInvoke[Cmd, uintptr](hostFd, cmd, uintptr(unsafe.Pointer(params)))
}

// IOCTLInvoke makes ioctl syscalls with the arg of the integer type.
func IOCTLInvoke[Cmd, Arg constraints.Integer](hostFd int32, cmd Cmd, arg Arg) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(hostFd), uintptr(cmd), uintptr(arg))
	if errno != 0 {
		return n, errno
	}
	return n, nil
}
