// Copyright 2019 The gVisor Authors.
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

package ptrace

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// fpRegSet returns the GETREGSET/SETREGSET register set type to be used.
func fpRegSet(useXsave bool) uintptr {
	if useXsave {
		return linux.NT_X86_XSTATE
	}
	return linux.NT_PRFPREG
}

func stackPointer(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Rsp)
}
