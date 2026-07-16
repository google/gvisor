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
	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns the seccomp-bpf filters the RDMA proxy adds to the base
// sandbox filter.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.EqualTo(uintptr(ib.RDMAVerbsIoctl)),
		},
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0), // old_size
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		// The RDMA sysfs surface serves per-port dynamic state (the RoCE GID
		// table, link state, counters) by reading host sysfs at access time via
		// openat(-1, <absolute path>, O_RDONLY|O_NOFOLLOW) (see
		// sys.hostFile.Generate). Without this rule a guest reading e.g.
		// /sys/class/infiniband/*/ports/*/gids/* would SIGSYS-kill the sentry.
		// dirfd is -1 (paths are absolute) and O_CREAT is forbidden, matching
		// tpuproxy.
		unix.SYS_OPENAT: seccomp.PerArg{
			seccomp.EqualTo(^uintptr(0)),
			seccomp.AnyValue{},
			seccomp.MaskedEqual(unix.O_CREAT|unix.O_NOFOLLOW, unix.O_NOFOLLOW),
			seccomp.AnyValue{},
		},
	})
}
