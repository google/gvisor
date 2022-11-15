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

//go:build amd64
// +build amd64

package seccheck

// init registers syscall trace points metadata.
// Keep them sorted by syscall number.
func init() {
	addSyscallPoint(0, "read", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(1, "write", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(2, "open", nil)
	addSyscallPoint(3, "close", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(17, "pread64", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(18, "pwrite64", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(19, "readv", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(20, "writev", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(22, "pipe", nil)
	addSyscallPoint(32, "dup", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(33, "dup2", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(41, "socket", nil)
	addSyscallPoint(42, "connect", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(43, "accept", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(49, "bind", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(53, "socketpair", nil)
	addSyscallPoint(56, "clone", nil)
	addSyscallPoint(57, "fork", nil)
	addSyscallPoint(58, "vfork", nil)
	addSyscallPoint(59, "execve", []FieldDesc{
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(72, "fcntl", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(85, "creat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(80, "chdir", nil)
	addSyscallPoint(81, "fchdir", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(105, "setuid", nil)
	addSyscallPoint(106, "setgid", nil)
	addSyscallPoint(112, "setsid", nil)
	addSyscallPoint(117, "setresuid", nil)
	addSyscallPoint(119, "setresgid", nil)
	addSyscallPoint(161, "chroot", nil)
	addSyscallPoint(253, "inotify_init", nil)
	addSyscallPoint(254, "inotify_add_watch", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(255, "inotify_rm_watch", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(257, "openat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(282, "signalfd", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(283, "timerfd_create", nil)
	addSyscallPoint(284, "eventfd", nil)
	addSyscallPoint(286, "timerfd_settime", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(287, "timerfd_gettime", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(288, "accept4", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(289, "signalfd4", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(290, "eventfd2", nil)
	addSyscallPoint(292, "dup3", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(293, "pipe2", nil)
	addSyscallPoint(294, "inotify_init1", nil)
	addSyscallPoint(295, "preadv", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(296, "pwritev", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(302, "prlimit64", nil)
	addSyscallPoint(322, "execveat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(327, "preadv2", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(328, "pwritev2", []FieldDesc{
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
