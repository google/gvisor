// Copyright 2023 The gVisor Authors.
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

package secbenchdef

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// SpecialSyscall are syscalls which need special handling.
// This can be syscalls where the arguments must be valid references to user
// memory.
type SpecialSyscall string

const (
	// NanosleepZero calls nanosleep(2) to sleep for zero nanoseconds.
	NanosleepZero = SpecialSyscall("NanosleepZero")
	// PPollNonExistent calls ppoll(2) with a non-existent FD and a tiny timeout.
	PPollNonExistent = SpecialSyscall("PPollNonExistent")
	// RTSigreturn calls a system call that stands in the place of `rt_sigreturn(2)`.
	RTSigreturn = SpecialSyscall("RTSigreturn")
)

// Sys returns the Syscall struct for this special syscall.
func (s SpecialSyscall) Sys() Syscall {
	return Syscall{Special: s}
}

// Seq returns a one-item slice of the Syscall struct for this special syscall.
func (s SpecialSyscall) Seq() []Syscall {
	return []Syscall{s.Sys()}
}

// zeroNanoseconds is a timespec that represents zero nanoseconds.
var zeroNanosecond = &linux.Timespec{}

// oneNanosecond is a timespec that represents a single nanosecond.
var oneNanosecond = &linux.Timespec{Nsec: 1}

// ppollNonExistent is a PollFD struct with a non-existent FD and no events.
var ppollNonExistent = &linux.PollFD{FD: int32(NonExistentFD)}

// args returns the syscall number and arguments to call,
// along with an array of references that must be kept alive if the syscall
// arguments should refer to valid user memory.
func (s SpecialSyscall) args() (sysno uintptr, args [6]uintptr, refs [6]any) {
	switch s {
	case NanosleepZero:
		refs[0] = zeroNanosecond
		args[0] = uintptr(unsafe.Pointer(zeroNanosecond))
		return unix.SYS_NANOSLEEP, args, refs
	case PPollNonExistent:
		refs[0] = ppollNonExistent
		args[0] = uintptr(unsafe.Pointer(ppollNonExistent))
		args[1] = 1
		refs[2] = oneNanosecond
		args[2] = uintptr(unsafe.Pointer(oneNanosecond))
		return unix.SYS_PPOLL, args, refs
	case RTSigreturn:
		// We use `request_key(2)` as a stand-in for `rt_sigreturn(2)`.
		return unix.SYS_REQUEST_KEY, args, refs
	default:
		panic("invalid special syscall")
	}
}

// Data returns the seccomp data for this syscall.
func (s SpecialSyscall) Data(arch uint32) *linux.SeccompData {
	sysno, args, _ := s.args()
	return &linux.SeccompData{
		Nr:   int32(sysno),
		Arch: arch,
		Args: [6]uint64{
			uint64(args[0]),
			uint64(args[1]),
			uint64(args[2]),
			uint64(args[3]),
			uint64(args[4]),
			uint64(args[5]),
		},
	}
}

// Call calls this syscall.
func (s SpecialSyscall) Call() (r1 uintptr, r2 uintptr, err error) {
	sysno, args, refs := s.args()
	r1, r2, err = unix.Syscall6(sysno, args[0], args[1], args[2], args[3], args[4], args[5])
	runtime.KeepAlive(refs)
	return r1, r2, err
}
