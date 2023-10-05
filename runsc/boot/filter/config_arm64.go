// Copyright 2019 The gVisor Authors.
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

//go:build arm64
// +build arm64

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func init() {
	allowedSyscalls[unix.SYS_CLONE] = []seccomp.Rule{
		{
			seccomp.EqualTo(
				unix.CLONE_VM |
					unix.CLONE_FS |
					unix.CLONE_FILES |
					unix.CLONE_SIGHAND |
					unix.CLONE_SYSVSEM |
					unix.CLONE_THREAD),
			seccomp.AnyValue{}, // newsp
			// These arguments are left uninitialized by the Go
			// runtime, so they may be anything (and are unused by
			// the host).
			seccomp.AnyValue{}, // parent_tidptr
			seccomp.AnyValue{}, // tls
			seccomp.AnyValue{}, // child_tidptr
		},
	}
}

func archFstatAtSysNo() uintptr {
	return unix.SYS_FSTATAT
}
