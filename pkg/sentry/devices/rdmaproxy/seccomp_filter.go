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
// limitations under the License.

package rdmaproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns seccomp-bpf filters for the RDMA proxy.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_OPENAT: seccomp.PerArg{
			seccomp.EqualTo(^uintptr(0)),
			seccomp.AnyValue{},
			seccomp.MaskedEqual(unix.O_CREAT|unix.O_NOFOLLOW, unix.O_NOFOLLOW),
			seccomp.AnyValue{},
		},
		unix.SYS_IOCTL: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.MaskedEqual(0xFF00, 0x1B00),
		},
		// write/read forward the legacy uverbs command interface and
		// async event reads to the host fd.
		unix.SYS_WRITE: seccomp.PerArg{
			seccomp.NonNegativeFD{},
		},
		unix.SYS_READ: seccomp.PerArg{
			seccomp.NonNegativeFD{},
		},
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		unix.SYS_MUNMAP: seccomp.MatchAll{},
		// mremap is used by mirrorSandboxPages to build contiguous
		// sentry-side mappings of sandbox memory for DMA pinning.
		unix.SYS_MREMAP: seccomp.MatchAll{},
		// madvise(MADV_POPULATE_WRITE) pre-faults pages to avoid
		// mmap_lock contention during pin_user_pages.
		unix.SYS_MADVISE: seccomp.MatchAll{},
		// setns switches to the host network namespace for RoCE ioctls
		// that require GID-to-netdev resolution.
		unix.SYS_SETNS: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.EqualTo(unix.CLONE_NEWNET),
		},
	})
}
