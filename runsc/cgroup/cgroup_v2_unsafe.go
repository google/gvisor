// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"fmt"
	"math"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// cannotCloneIntoCgroupReason returns the reason why
// `clone3(CLONE_INTO_CGROUP)` doesn't work, if any.
// Returns empty string if it does work.
var cannotCloneIntoCgroupReason = sync.OnceValue(func() string {
	// This makes a `clone3` call that always fails, but can fail for
	// different reasons. See the `switch` below.
	args := linux.CloneArgs{
		// We use CLONE_VM here too because otherwise the kernel will copy the
		// process page table entries before it gets to the cgroup FD check
		// part, which can be expensive.
		Flags:      linux.CLONE_INTO_CGROUP | linux.CLONE_VM,
		ExitSignal: uint64(unix.SIGCHLD),
		Cgroup:     math.MaxInt32,
	}
	_, _, errno := unix.RawSyscall(unix.SYS_CLONE3, uintptr(unsafe.Pointer(&args)), unsafe.Sizeof(args), 0)
	switch errno {
	case unix.ENOSYS:
		// `clone3` doesn't exist, i.e. Linux 5.2 or lower.
		// This can also happen under Docker's default profile, which injects
		// ENOSYS as the return code for `clone3`.
		return "clone3 syscall not implemented (kernel too old, or clone3 denied by container runtime policy)"
	case unix.EPERM:
		// Seccomp denial as well, such as Docker's profile before it
		// explicitly injected `ENOSYS` for `clone3`.
		return "clone3 syscall denied (perhaps by container runtime policy)"
	case unix.E2BIG:
		// The `Cgroup` field is beyond the struct size that `clone3`
		// expects. So `clone3` exists, but `CLONE_INTO_CGROUP` does not.
		// Linux 5.3, 5.4, 5.5, or 5.6.
		return "kernel too old"
	case unix.EBADF:
		return "" // Happy case
	default:
		return fmt.Sprintf("clone3 probe returned errno %v", errno)
	}
})
