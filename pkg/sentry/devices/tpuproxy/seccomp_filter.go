// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpuproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns seccomp-bpf filters for this package.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_OPENAT: seccomp.PerArg{
			// All paths that we openat() are absolute, so we pass a dirfd
			// of -1 (which is invalid for relative paths, but ignored for
			// absolute paths) to hedge against bugs involving AT_FDCWD or
			// real dirfds.
			seccomp.EqualTo(^uintptr(0)),
			seccomp.AnyValue{},
			seccomp.MaskedEqual(unix.O_CREAT|unix.O_NOFOLLOW, unix.O_NOFOLLOW),
			seccomp.AnyValue{},
		},
		unix.SYS_GETDENTS64: seccomp.MatchAll{},
		unix.SYS_EVENTFD2: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.EFD_NONBLOCK),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.EFD_NONBLOCK | linux.EFD_SEMAPHORE),
			},
		},
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0), /* old_size */
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.PROT_READ | linux.PROT_WRITE),
			seccomp.EqualTo(linux.MAP_SHARED | linux.MAP_LOCKED),
			seccomp.NonNegativeFD{},
		},
		unix.SYS_MUNMAP:   seccomp.MatchAll{},
		unix.SYS_PREAD64:  seccomp.MatchAll{},
		unix.SYS_PWRITE64: seccomp.MatchAll{},
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_CHECK_EXTENSION),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_DEVICE_GET_INFO),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_DEVICE_GET_REGION_INFO),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_DEVICE_GET_IRQ_INFO),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_DEVICE_SET_IRQS),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_GROUP_GET_DEVICE_FD),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_GROUP_SET_CONTAINER),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_IOMMU_MAP_DMA),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_IOMMU_UNMAP_DMA),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.VFIO_SET_IOMMU),
			},
		},
	})
}
