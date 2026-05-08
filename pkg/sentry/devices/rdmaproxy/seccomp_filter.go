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
//
// These filters are deliberately narrower than "any FD / any flags" on the
// syscalls the sentry forwards to the host kernel. Every constraint below
// matches the single concrete call shape used by this package (see the
// corresponding call sites in rdmaproxy.go and rdmaproxy_ioctl_unsafe.go);
// a future caller that needs broader semantics must relax the filter
// explicitly rather than silently inheriting a permissive default.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		// openHostDevice opens /dev/infiniband/uverbs* with
		//   flags = (caller_flags & O_ACCMODE) | O_NOFOLLOW
		// and no other bits. The MaskedEqual below requires exactly
		// O_NOFOLLOW outside the O_ACCMODE bits — this simultaneously
		// forbids O_CREAT, O_PATH, O_DIRECTORY, O_TMPFILE, O_CLOEXEC,
		// O_DIRECT, O_SYNC, O_NONBLOCK, O_ASYNC, etc.
		unix.SYS_OPENAT: seccomp.PerArg{
			seccomp.EqualTo(^uintptr(0)), // dirfd == AT_FDCWD
			seccomp.AnyValue{},           // path (opaque to seccomp)
			seccomp.MaskedEqual(^uintptr(unix.O_ACCMODE), unix.O_NOFOLLOW),
			seccomp.AnyValue{}, // mode (unused when O_CREAT is forbidden)
		},
		// Only RDMA_VERBS_IOCTL is ever issued by the sentry on behalf
		// of the sandbox. Tighter than a magic-byte match because a
		// non-uverbs subsystem could in principle register the same
		// 0x1B magic on a file the sentry happens to hold.
		unix.SYS_IOCTL: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.EqualTo(uintptr(rdmaVerbsIoctl)),
		},
		// Async event forwarding: read(asyncEventFD.hostFD, buf, len).
		// seccomp-bpf cannot validate the FD against the process's FD
		// table, so we match the gofer/hostinet precedent of allowing
		// any non-negative FD.
		unix.SYS_READ: seccomp.PerArg{
			seccomp.NonNegativeFD{},
		},
		// MirrorSandboxPages reserves a contiguous sentry-side range:
		//   mmap(NULL, len, PROT_NONE,
		//        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
		// Only `len` varies between calls.
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.EqualTo(0), // addr == NULL
			seccomp.AnyValue{}, // length
			seccomp.EqualTo(unix.PROT_NONE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
			seccomp.EqualTo(^uintptr(0)), // fd == -1
			seccomp.EqualTo(0),           // offset == 0
		},
		// munmap is only used to tear down the mirror range on cleanup.
		// munmap(2) takes two args; the 3rd syscall-register value is
		// runtime-dependent padding, so we don't constrain it.
		unix.SYS_MUNMAP: seccomp.MatchAll{},
		// MirrorSandboxPages remaps each per-page internal mapping into
		// the reserved range:
		//   mremap(old_addr, 0, new_len,
		//          MREMAP_MAYMOVE|MREMAP_FIXED, new_addr, 0)
		// old_size == 0 combined with MAYMOVE|FIXED asks the kernel to
		// *duplicate* the mapping rather than move it. Matches nvproxy.
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0), // old_size
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		// Best-effort pre-fault of the mirrored range. Only this one
		// advice value is ever issued.
		unix.SYS_MADVISE: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MADV_POPULATE_WRITE),
		},
	})
}
