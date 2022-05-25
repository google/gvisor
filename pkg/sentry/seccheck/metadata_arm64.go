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

func init() {
	addSyscallPoint(63, "read", []FieldDesc{
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
	addSyscallPoint(198, "socket", nil)
	addSyscallPoint(203, "connect", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(221, "execve", []FieldDesc{
		{
			ID:   FieldSyscallExecveEnvv,
			Name: "envv",
		},
	})
	addSyscallPoint(56, "openat", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
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
	addSyscallPoint(49, "chdir", nil)
	addSyscallPoint(50, "fchdir", []FieldDesc{
		{
			ID:   FieldSyscallPath,
			Name: "fd_path",
		},
	})
	addSyscallPoint(146, "setuid", nil)
	addSyscallPoint(144, "setgid", nil)
	addSyscallPoint(157, "setsid", nil)
	addSyscallPoint(147, "setresuid", nil)
	addSyscallPoint(149, "setresgid", nil)

	const lastSyscallInTable = 441
	for i := 0; i <= lastSyscallInTable; i++ {
		addRawSyscallPoint(uintptr(i))
	}
}
