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

package seccheck

// SyscallType is an enum that denotes different types of syscall points. There
// are 2 types of syscall point: fully-schematized and raw. Schematizes are
// points that have syscall specific format, e.g. open => {path, flags, mode}.
// Raw uses a generic schema that contains syscall number and 6 arguments. Each
// of these type have a corresponding enter and exit points. Exit points include
// return value and errno information.
type SyscallType int

const (
	// SyscallEnter represents schematized/enter syscall.
	SyscallEnter SyscallType = iota
	// SyscallExit represents schematized/exit syscall.
	SyscallExit
	// SyscallRawEnter represents raw/enter syscall.
	SyscallRawEnter
	// SyscallRawExit represents raw/exit syscall.
	SyscallRawExit

	syscallTypesCount
)

// SyscallFlagListener is an interface that is notified when syscall point enablement changes.
//
// It is used to notify the kernel's syscall table about syscall points, without introducing a
// direct dependency on it.
type SyscallFlagListener interface {
	// UpdateSecCheck is called each time the system call point enablement may have changed.
	// This is called with seccheck.State.mu held, so it is expected to be fast and not re-entrant
	// with seccheck.State functions that attempt to re-lock it.
	UpdateSecCheck(state *State)
}

const (
	// Copied from kernel.maxSyscallNum to avoid reverse dependency.
	syscallsMax   = 2000
	syscallPoints = syscallsMax * int(syscallTypesCount)
)

// Fields that are common for many syscalls.
const (
	// FieldSyscallPath is an optional field to collect path from an FD. Given
	// that many syscalls operate on FDs, this const is used across syscalls.
	FieldSyscallPath Field = iota
)

// Fields for execve*(2) syscalls.
const (
	// FieldSyscallExecveEnvv is an optional field to collect list of environment
	// variables. Start after FieldSyscallPath because execveat(2) can collect
	// path from FD.
	FieldSyscallExecveEnvv = FieldSyscallPath + 1
)

// GetPointForSyscall translates the syscall number to the corresponding Point.
func GetPointForSyscall(typ SyscallType, sysno uintptr) Point {
	return Point(sysno)*Point(syscallTypesCount) + Point(typ) + pointLengthBeforeSyscalls
}

// SyscallEnabled checks if the corresponding point for the syscall is enabled.
func (s *State) SyscallEnabled(typ SyscallType, sysno uintptr) bool {
	// Prevent overflow.
	if sysno >= syscallsMax {
		return false
	}
	return s.Enabled(GetPointForSyscall(typ, sysno))
}
