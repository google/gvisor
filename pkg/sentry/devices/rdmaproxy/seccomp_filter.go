// Copyright 2026 The gVisor Authors.
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

// Filters returns seccomp-bpf filters for this package.
//
// SYS_MMAP (to reserve the sentry VA window) and SYS_MUNMAP are already
// covered by the base sentry filter; SYS_MREMAP is not, since it is not
// otherwise used by the sentry.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		// Used by pinMapAppRange (rdma_fd_pin.go) to mirror pinned
		// application memory into a contiguous sentry VA window for
		// REG_MR, by duplicating each MAP_SHARED MemoryFile mapping
		// (old_size == 0) into the window at a fixed destination.
		// Matches the identical use in tpuproxy's iommuMapDma
		// (pkg/sentry/devices/tpuproxy/vfio/vfio_fd.go).
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0), /* old_size */
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
	})
}
