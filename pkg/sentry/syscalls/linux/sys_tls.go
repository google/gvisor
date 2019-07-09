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

//+build amd64

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// ArchPrctl implements linux syscall arch_prctl(2).
// It sets architecture-specific process or thread state for t.
func ArchPrctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	switch args[0].Int() {
	case linux.ARCH_GET_FS:
		addr := args[1].Pointer()
		fsbase := t.Arch().TLS()
		_, err := t.CopyOut(addr, uint64(fsbase))
		if err != nil {
			return 0, nil, err
		}

	case linux.ARCH_SET_FS:
		fsbase := args[1].Uint64()
		if !t.Arch().SetTLS(uintptr(fsbase)) {
			return 0, nil, syserror.EPERM
		}

	case linux.ARCH_GET_GS, linux.ARCH_SET_GS:
		t.Kernel().EmitUnimplementedEvent(t)
		fallthrough
	default:
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, nil
}
