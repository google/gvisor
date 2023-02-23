// Copyright 2021 The gVisor Authors.
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

// Package usertrap implements the library to replace syscall instructions with
// function calls.
//
// The most often used pattern of performing a system call is a sequence of two
// instruction: mov sysno, %eax; syscall.  The size of the mov instruction is 5
// bytes and the size of the syscall instruction is 2 bytes. These two
// instruction can be replaced with a single jmp instruction with an absolute
// address below 2 gigabytes.
//
// Here is a few tricks:
//   - The GS register is used to access a per-thread memory.
//   - The syscall instruction is replaced with the "jmp *%ds:offset" instruction.
//     On x86_64, ds is always zero. offset is a 32-bit signed integer. This
//     means that a service mapping for a table with syscall trampolines has to
//     be mapped below 2GB.
//   - We can't touch a process stack, so we have to use the jmp instruction
//     instead of callq and generate a new function call for each replaced
//     instruction. Each trampoline contains a syscall number and an return
//     address.
//   - The address for the syscall table is set so that the syscall instruction
//     is replaced on an invalid instruction. This allows us to handle races
//     when two threads are executing the same syscall concurrently. And this
//     allows us to restart a syscall if it has been interrupted by a signal.
//
// +checkalignedignore
package usertrap

import "fmt"

var (
	// ErrFaultRestart indicates that the current stub thread has to be restarted.
	ErrFaultRestart = fmt.Errorf("need to restart stub thread")
	// ErrFaultSyscall indicates that the current fault has to be handled as a system call.
	ErrFaultSyscall = fmt.Errorf("need to handle as syscall")
)
