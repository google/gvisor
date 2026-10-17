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

package config

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

var cgoFilters = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	// musl pthread_create uses legacy clone with TID pointers, unlike the
	// Go runtime's clone call. Keep this exact thread-only flag set in
	// the cgo policy; it cannot create a process or a new namespace.
	// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?id=9fa28ece7#n243
	unix.SYS_CLONE: seccomp.PerArg{
		seccomp.EqualTo(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
			unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
			unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID |
			unix.CLONE_CHILD_CLEARTID | unix.CLONE_DETACHED),
		seccomp.AnyValue{}, // stack
		seccomp.AnyValue{}, // parent_tid
		seccomp.AnyValue{}, // child_tid (amd64), tls (arm64)
		seccomp.AnyValue{}, // tls (amd64), child_tid (arm64)
	},
	unix.SYS_MMAP: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_NONE),
			seccomp.EqualTo(
				unix.MAP_PRIVATE |
					unix.MAP_ANONYMOUS |
					unix.MAP_NORESERVE),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(
				unix.MAP_PRIVATE |
					unix.MAP_ANONYMOUS |
					unix.MAP_STACK),
		},
	},
	// TODO(eperot): remove this syscall seccomp rule
	unix.SYS_SET_ROBUST_LIST: seccomp.MatchAll{},
	// TODO(eperot): remove this syscall seccomp rule
	unix.SYS_CLONE3: seccomp.MatchAll{},
	// TODO(eperot): remove this syscall seccomp rule
	unix.SYS_RSEQ: seccomp.MatchAll{},
})
