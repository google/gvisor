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

//go:build linux
// +build linux

// Package rawsyscall provides functions like unix.RawSyscall, but without the
// overhead of multiple stack frame allocations.
//
// This is mostly relevant for platform/kvm which needs to execute some function
// call chains in a go:nosplit environment. Debug builds specifically make using
// unix.RawSyscall variants infeasible.
package rawsyscall

import (
	"golang.org/x/sys/unix"
)

// Syscall6 is a copy of runtime.Syscall6.
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, errno uintptr)

// Variants of runtime.Syscall6 that use slightly less stack space by only
// returning errno.

// SyscallErrno6 is like Syscall6, but only returns errno, and 0 if successful.
func SyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) unix.Errno

// SyscallErrno is like Syscall6, but only returns errno, and 0 if successful.
func SyscallErrno(trap, a1, a2, a3 uintptr) unix.Errno
