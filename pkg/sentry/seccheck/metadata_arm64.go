// Copyright 2022 The gVisor Authors.
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

package seccheck

// init registers syscall trace points metadata.
// Keep them sorted by syscall number.
func init() {
	addSyscallPoint(19, "eventfd2", nil)
	addSyscallPoint(23, "dup", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(24, "dup3", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(25, "fcntl", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})

	addSyscallPoint(26, "inotify_init1", nil)
	addSyscallPoint(27, "inotify_add_watch", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(28, "inotify_rm_watch", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(49, "chdir", nil)
	addSyscallPoint(50, "fchdir", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(51, "chroot", nil)
	addSyscallPoint(56, "openat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(57, "close", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(59, "pipe2", nil)
	addSyscallPoint(63, "read", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(64, "write", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(65, "readv", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(66, "writev", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(67, "pread64", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(68, "pwrite64", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(69, "preadv", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(70, "pwritev", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(74, "signalfd4", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(85, "timerfd_create", nil)
	addSyscallPoint(86, "timerfd_settime", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(87, "timerfd_gettime", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(144, "setgid", nil)
	addSyscallPoint(146, "setuid", nil)
	addSyscallPoint(147, "setresuid", nil)
	addSyscallPoint(149, "setresgid", nil)
	addSyscallPoint(157, "setsid", nil)
	addSyscallPoint(198, "socket", nil)
	addSyscallPoint(199, "socketpair", nil)
	addSyscallPoint(200, "bind", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(202, "accept", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(203, "connect", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(220, "clone", nil)
	addSyscallPoint(221, "execve", []FieldDesc{
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(242, "accept4", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(261, "prlimit64", nil)
	addSyscallPoint(281, "execveat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(286, "preadv2", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(287, "pwritev2", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})

	const lastSyscallInTable = 441
	for i := 0; i <= lastSyscallInTable; i++ {
		addRawSyscallPoint(uintptr(i))
	}
}
