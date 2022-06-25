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

func init() {
	addSyscallPoint(0, "read", []FieldDesc{
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
	addSyscallPoint(41, "socket", nil)
	addSyscallPoint(42, "connect", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(59, "execve", []FieldDesc{
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(85, "creat", []FieldDesc{
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
	addSyscallPoint(80, "chdir", nil)
	addSyscallPoint(81, "fchdir", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(22, "pipe", nil)
	addSyscallPoint(293, "pipe2", nil)
	addSyscallPoint(72, "fcntl", []FieldDesc{
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
	addSyscallPoint(302, "prlimit64", nil)
	addSyscallPoint(284, "eventfd", nil)
	addSyscallPoint(290, "eventfd2", nil)
	addSyscallPoint(282, "signalfd", []FieldDesc{
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
	addSyscallPoint(292, "dup3", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(56, "clone", nil)
	addSyscallPoint(49, "bind", []FieldDesc{
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
	addSyscallPoint(288, "accept4", []FieldDesc{
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
