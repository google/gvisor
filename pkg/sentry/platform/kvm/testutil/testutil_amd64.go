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

// TwiddleSegments reads segments into known registers.
func TwiddleSegments()

// SetTestTarget sets the rip appropriately.
func SetTestTarget(regs *arch.Registers, fn func()) {
	regs.PtraceRegs().Rip = uint64(reflect.ValueOf(fn).Pointer())
}

// SetTouchTarget sets rax appropriately.
func SetTouchTarget(regs *arch.Registers, target *uintptr) {
	if target != nil {
		regs.PtraceRegs().Rax = uint64(reflect.ValueOf(target).Pointer())
	} else {
		regs.PtraceRegs().Rax = 0
	}
}

// RewindSyscall rewinds a syscall RIP.
func RewindSyscall(regs *arch.Registers) {
	regs.PtraceRegs().Rip -= 2
}

// SetTestRegs initializes registers to known values.
func SetTestRegs(regs *arch.Registers) {
	ptRegs := regs.PtraceRegs()
	ptRegs.R15 = 0x15
	ptRegs.R14 = 0x14
	ptRegs.R13 = 0x13
	ptRegs.R12 = 0x12
	ptRegs.Rbp = 0xb9
	ptRegs.Rbx = 0xb4
	ptRegs.R11 = 0x11
	ptRegs.R10 = 0x10
	ptRegs.R9 = 0x09
	ptRegs.R8 = 0x08
	ptRegs.Rax = 0x44
	ptRegs.Rcx = 0xc4
	ptRegs.Rdx = 0xd4
	ptRegs.Rsi = 0x51
	ptRegs.Rdi = 0xd1
	ptRegs.Rsp = 0x59
}

// CheckTestRegs checks that registers were twiddled per TwiddleRegs.
func CheckTestRegs(regs *arch.Registers, full bool) (err error) {
	ptRegs := regs.PtraceRegs()
	if need := ^uint64(0x15); ptRegs.R15 != need {
		err = addRegisterMismatch(err, "R15", ptRegs.R15, need)
	}
	if need := ^uint64(0x14); ptRegs.R14 != need {
		err = addRegisterMismatch(err, "R14", ptRegs.R14, need)
	}
	if need := ^uint64(0x13); ptRegs.R13 != need {
		err = addRegisterMismatch(err, "R13", ptRegs.R13, need)
	}
	if need := ^uint64(0x12); ptRegs.R12 != need {
		err = addRegisterMismatch(err, "R12", ptRegs.R12, need)
	}
	if need := ^uint64(0xb9); ptRegs.Rbp != need {
		err = addRegisterMismatch(err, "Rbp", ptRegs.Rbp, need)
	}
	if need := ^uint64(0xb4); ptRegs.Rbx != need {
		err = addRegisterMismatch(err, "Rbx", ptRegs.Rbx, need)
	}
	if need := ^uint64(0x10); ptRegs.R10 != need {
		err = addRegisterMismatch(err, "R10", ptRegs.R10, need)
	}
	if need := ^uint64(0x09); ptRegs.R9 != need {
		err = addRegisterMismatch(err, "R9", ptRegs.R9, need)
	}
	if need := ^uint64(0x08); ptRegs.R8 != need {
		err = addRegisterMismatch(err, "R8", ptRegs.R8, need)
	}
	if need := ^uint64(0x44); ptRegs.Rax != need {
		err = addRegisterMismatch(err, "Rax", ptRegs.Rax, need)
	}
	if need := ^uint64(0xd4); ptRegs.Rdx != need {
		err = addRegisterMismatch(err, "Rdx", ptRegs.Rdx, need)
	}
	if need := ^uint64(0x51); ptRegs.Rsi != need {
		err = addRegisterMismatch(err, "Rsi", ptRegs.Rsi, need)
	}
	if need := ^uint64(0xd1); ptRegs.Rdi != need {
		err = addRegisterMismatch(err, "Rdi", ptRegs.Rdi, need)
	}
	if need := ^uint64(0x59); ptRegs.Rsp != need {
		err = addRegisterMismatch(err, "Rsp", ptRegs.Rsp, need)
	}
	// Rcx & R11 are ignored if !full is set.
	if need := ^uint64(0x11); full && ptRegs.R11 != need {
		err = addRegisterMismatch(err, "R11", ptRegs.R11, need)
	}
	if need := ^uint64(0xc4); full && ptRegs.Rcx != need {
		err = addRegisterMismatch(err, "Rcx", ptRegs.Rcx, need)
	}
	return
}

var fsData uint64 = 0x55
var gsData uint64 = 0x85

// SetTestSegments initializes segments to known values.
func SetTestSegments(regs *arch.Registers) {
	regs.PtraceRegs().Fs_base = uint64(reflect.ValueOf(&fsData).Pointer())
	regs.PtraceRegs().Gs_base = uint64(reflect.ValueOf(&gsData).Pointer())
}

// CheckTestSegments checks that registers were twiddled per TwiddleSegments.
func CheckTestSegments(regs *arch.Registers) (err error) {
	if regs.PtraceRegs().Rax != fsData {
		err = addRegisterMismatch(err, "Rax", regs.PtraceRegs().Rax, fsData)
	}
	if regs.PtraceRegs().Rbx != gsData {
		err = addRegisterMismatch(err, "Rbx", regs.PtraceRegs().Rcx, gsData)
	}
	return
}
