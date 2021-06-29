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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// RSeq implements syscall rseq(2).
func RSeq(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].Uint()
	flags := args[2].Int()
	signature := args[3].Uint()

	if !t.RSeqAvailable() {
		// Event for applications that want rseq on a configuration
		// that doesn't support them.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, syserror.ENOSYS
	}

	switch flags {
	case 0:
		// Register.
		return 0, nil, t.SetRSeq(addr, length, signature)
	case linux.RSEQ_FLAG_UNREGISTER:
		return 0, nil, t.ClearRSeq(addr, length, signature)
	default:
		// Unknown flag.
		return 0, nil, linuxerr.EINVAL
	}
}
