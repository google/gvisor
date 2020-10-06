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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Membarrier implements syscall membarrier(2).
func Membarrier(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	cmd := args[0].Int()
	flags := args[1].Int()

	p := t.Kernel().Platform
	if !p.HaveGlobalMemoryBarrier() {
		// Event for applications that want membarrier on a configuration that
		// doesn't support them.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, syserror.ENOSYS
	}

	if flags != 0 {
		return 0, nil, syserror.EINVAL
	}

	switch cmd {
	case linux.MEMBARRIER_CMD_QUERY:
		const supportedCommands = linux.MEMBARRIER_CMD_GLOBAL |
			linux.MEMBARRIER_CMD_GLOBAL_EXPEDITED |
			linux.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED |
			linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED |
			linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
		return supportedCommands, nil, nil
	case linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED:
		if !t.MemoryManager().IsMembarrierPrivateEnabled() {
			return 0, nil, syserror.EPERM
		}
		fallthrough
	case linux.MEMBARRIER_CMD_GLOBAL, linux.MEMBARRIER_CMD_GLOBAL_EXPEDITED:
		return 0, nil, p.GlobalMemoryBarrier()
	case linux.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
		// no-op
		return 0, nil, nil
	case linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
		t.MemoryManager().EnableMembarrierPrivate()
		return 0, nil, nil
	case linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE:
		// We're aware of these, but they aren't implemented since no platform
		// supports them yet.
		t.Kernel().EmitUnimplementedEvent(t)
		fallthrough
	default:
		return 0, nil, syserror.EINVAL
	}
}
