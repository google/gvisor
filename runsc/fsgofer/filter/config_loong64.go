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

//go:build loong64
// +build loong64

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func init() {
	allowedSyscalls.Set(unix.SYS_CLONE, seccomp.PerArg{
		// parent_tidptr and child_tidptr are always 0 because neither
		// CLONE_PARENT_SETTID nor CLONE_CHILD_SETTID are used.
		seccomp.EqualTo(
			unix.CLONE_VM |
				unix.CLONE_FS |
				unix.CLONE_FILES |
				unix.CLONE_SIGHAND |
				unix.CLONE_SYSVSEM |
				unix.CLONE_THREAD),
		seccomp.AnyValue{}, // newsp
		// Uninitialized by the Go runtime.
		seccomp.AnyValue{}, // parent_tidptr
		seccomp.AnyValue{}, // tls
		seccomp.AnyValue{}, // child_tidptr
	})
	allowedSyscalls.Set(unix.SYS_FSTATAT, seccomp.MatchAll{})
	// LoongArch is an asm-generic arch with no fstat(2); all stat operations
	// go through statx(2), so the gofer needs it allowed.
	allowedSyscalls.Set(unix.SYS_STATX, seccomp.MatchAll{})
}
