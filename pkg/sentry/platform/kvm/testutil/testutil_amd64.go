// Copyright 2018 The gVisor Authors.
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

// +build amd64

package testutil

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// AddrOfTwiddleSegments return the address of a function that reads segments
// into known registers.
func AddrOfTwiddleSegments() uintptr
func twiddleSegments()

// SetTestTarget sets the rip appropriately.
func SetTestTarget(regs *arch.Registers, fn uintptr) {
	regs.Rip = uint64(fn)
}

// SetTouchTarget sets rax appropriately.
func SetTouchTarget(regs *arch.Registers, target *uintptr) {
	if target != nil {
		regs.Rax = uint64(reflect.ValueOf(target).Pointer())
	} else {
		regs.Rax = 0
	}
}

// RewindSyscall rewinds a syscall RIP.
func RewindSyscall(regs *arch.Registers) {
	regs.Rip -= 2
}

// SetTestRegs initializes registers to known values.
func SetTestRegs(regs *arch.Registers) {
	regs.R15 = 0x15
	regs.R14 = 0x14
	regs.R13 = 0x13
	regs.R12 = 0x12
	regs.Rbp = 0xb9
	regs.Rbx = 0xb4
	regs.R11 = 0x11
	regs.R10 = 0x10
	regs.R9 = 0x09
	regs.R8 = 0x08
	regs.Rax = 0x44
	regs.Rcx = 0xc4
	regs.Rdx = 0xd4
	regs.Rsi = 0x51
	regs.Rdi = 0xd1
	regs.Rsp = 0x59
}

// CheckTestRegs checks that registers were twiddled per TwiddleRegs.
func CheckTestRegs(regs *arch.Registers, full bool) (err error) {
	if need := ^uint64(0x15); regs.R15 != need {
		err = addRegisterMismatch(err, "R15", regs.R15, need)
	}
	if need := ^uint64(0x14); regs.R14 != need {
		err = addRegisterMismatch(err, "R14", regs.R14, need)
	}
	if need := ^uint64(0x13); regs.R13 != need {
		err = addRegisterMismatch(err, "R13", regs.R13, need)
	}
	if need := ^uint64(0x12); regs.R12 != need {
		err = addRegisterMismatch(err, "R12", regs.R12, need)
	}
	if need := ^uint64(0xb9); regs.Rbp != need {
		err = addRegisterMismatch(err, "Rbp", regs.Rbp, need)
	}
	if need := ^uint64(0xb4); regs.Rbx != need {
		err = addRegisterMismatch(err, "Rbx", regs.Rbx, need)
	}
	if need := ^uint64(0x10); regs.R10 != need {
		err = addRegisterMismatch(err, "R10", regs.R10, need)
	}
	if need := ^uint64(0x09); regs.R9 != need {
		err = addRegisterMismatch(err, "R9", regs.R9, need)
	}
	if need := ^uint64(0x08); regs.R8 != need {
		err = addRegisterMismatch(err, "R8", regs.R8, need)
	}
	if need := ^uint64(0x44); regs.Rax != need {
		err = addRegisterMismatch(err, "Rax", regs.Rax, need)
	}
	if need := ^uint64(0xd4); regs.Rdx != need {
		err = addRegisterMismatch(err, "Rdx", regs.Rdx, need)
	}
	if need := ^uint64(0x51); regs.Rsi != need {
		err = addRegisterMismatch(err, "Rsi", regs.Rsi, need)
	}
	if need := ^uint64(0xd1); regs.Rdi != need {
		err = addRegisterMismatch(err, "Rdi", regs.Rdi, need)
	}
	if need := ^uint64(0x59); regs.Rsp != need {
		err = addRegisterMismatch(err, "Rsp", regs.Rsp, need)
	}
	// Rcx & R11 are ignored if !full is set.
	if need := ^uint64(0x11); full && regs.R11 != need {
		err = addRegisterMismatch(err, "R11", regs.R11, need)
	}
	if need := ^uint64(0xc4); full && regs.Rcx != need {
		err = addRegisterMismatch(err, "Rcx", regs.Rcx, need)
	}
	return
}

var fsData uint64 = 0x55
var gsData uint64 = 0x85

// SetTestSegments initializes segments to known values.
func SetTestSegments(regs *arch.Registers) {
	regs.Fs_base = uint64(reflect.ValueOf(&fsData).Pointer())
	regs.Gs_base = uint64(reflect.ValueOf(&gsData).Pointer())
}

// CheckTestSegments checks that registers were twiddled per TwiddleSegments.
func CheckTestSegments(regs *arch.Registers) (err error) {
	if regs.Rax != fsData {
		err = addRegisterMismatch(err, "Rax", regs.Rax, fsData)
	}
	if regs.Rbx != gsData {
		err = addRegisterMismatch(err, "Rbx", regs.Rcx, gsData)
	}
	return
}
