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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Membarrier implements syscall membarrier(2).
func Membarrier(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	cmd := args[0].Int()
	flags := args[1].Uint()

	switch cmd {
	case linux.MEMBARRIER_CMD_QUERY:
		if flags != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		var supportedCommands uintptr
		if t.Kernel().Platform.HaveGlobalMemoryBarrier() {
			supportedCommands |= linux.MEMBARRIER_CMD_GLOBAL |
				linux.MEMBARRIER_CMD_GLOBAL_EXPEDITED |
				linux.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED |
				linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED |
				linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
		}
		if t.RSeqAvailable() {
			supportedCommands |= linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ |
				linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
		}
		return supportedCommands, nil, nil
	case linux.MEMBARRIER_CMD_GLOBAL, linux.MEMBARRIER_CMD_GLOBAL_EXPEDITED, linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED:
		if flags != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.Kernel().Platform.HaveGlobalMemoryBarrier() {
			return 0, nil, linuxerr.EINVAL
		}
		if cmd == linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED && !t.MemoryManager().IsMembarrierPrivateEnabled() {
			return 0, nil, syserror.EPERM
		}
		return 0, nil, t.Kernel().Platform.GlobalMemoryBarrier()
	case linux.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
		if flags != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.Kernel().Platform.HaveGlobalMemoryBarrier() {
			return 0, nil, linuxerr.EINVAL
		}
		// no-op
		return 0, nil, nil
	case linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
		if flags != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.Kernel().Platform.HaveGlobalMemoryBarrier() {
			return 0, nil, linuxerr.EINVAL
		}
		t.MemoryManager().EnableMembarrierPrivate()
		return 0, nil, nil
	case linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ:
		if flags&^linux.MEMBARRIER_CMD_FLAG_CPU != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.RSeqAvailable() {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.MemoryManager().IsMembarrierRSeqEnabled() {
			return 0, nil, syserror.EPERM
		}
		// MEMBARRIER_CMD_FLAG_CPU and cpu_id are ignored since we don't have
		// the ability to preempt specific CPUs.
		return 0, nil, t.Kernel().Platform.PreemptAllCPUs()
	case linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ:
		if flags != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if !t.RSeqAvailable() {
			return 0, nil, linuxerr.EINVAL
		}
		t.MemoryManager().EnableMembarrierRSeq()
		return 0, nil, nil
	default:
		// Probably a command we don't implement.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, linuxerr.EINVAL
	}
}
