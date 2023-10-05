// Copyright 2023 The gVisor Authors.
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

package accel

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/gasket"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns seccomp-bpf filters for this package.
func Filters() seccomp.SyscallRules {
	nonNegativeFD := seccomp.NonNegativeFDCheck()
	return seccomp.SyscallRules{
		unix.SYS_OPENAT: []seccomp.Rule{
			{
				// All paths that we openat() are absolute, so we pass a dirfd
				// of -1 (which is invalid for relative paths, but ignored for
				// absolute paths) to hedge against bugs involving AT_FDCWD or
				// real dirfds.
				seccomp.EqualTo(^uintptr(0)),
				seccomp.AnyValue{},
				seccomp.MaskedEqual(unix.O_CREAT|unix.O_NOFOLLOW, unix.O_NOFOLLOW),
				seccomp.AnyValue{},
			},
		},
		unix.SYS_GETDENTS64: {},
		unix.SYS_IOCTL: []seccomp.Rule{
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_RESET),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_SET_EVENTFD),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_CLEAR_EVENTFD),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_NUMBER_PAGE_TABLES),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_PAGE_TABLE_SIZE),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_SIMPLE_PAGE_TABLE_SIZE),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_PARTITION_PAGE_TABLE),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_MAP_BUFFER),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_UNMAP_BUFFER),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_REGISTER_INTERRUPT),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_UNREGISTER_INTERRUPT),
			},
			{
				nonNegativeFD,
				seccomp.EqualTo(gasket.GASKET_IOCTL_MAP_DMA_BUF),
			},
		},
		unix.SYS_EVENTFD2: []seccomp.Rule{
			{
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.EFD_NONBLOCK),
			},
			{
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.EFD_NONBLOCK | linux.EFD_SEMAPHORE),
			},
		},
		unix.SYS_MREMAP: []seccomp.Rule{
			{
				seccomp.AnyValue{},
				seccomp.EqualTo(0), /* old_size */
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
				seccomp.AnyValue{},
				seccomp.EqualTo(0),
			},
		},
	}
}
