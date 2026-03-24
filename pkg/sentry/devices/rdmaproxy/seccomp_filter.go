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
	"gvisor.dev/gvisor/pkg/abi/linux"
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
		// uverbs ioctls: RDMA_VERBS_IOCTL (_IOWR('F', 0x1b, ...)) and
		// legacy write-interface commands (_IOW/_IOWR with type 'F').
		// Allow any ioctl with type byte 0x46 ('F') on valid FDs.
		unix.SYS_IOCTL: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.MaskedEqual(0xFF00, 0x4600),
		},
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.MaskedEqual(linux.MAP_SHARED, linux.MAP_SHARED),
			seccomp.NonNegativeFD{},
		},
		unix.SYS_MUNMAP: seccomp.MatchAll{},
	})
}
