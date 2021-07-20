// Copyright 2019 The gVisor Authors.
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

package testutil

import (
	"fmt"
	"reflect"

	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// TLSWorks is a tls test.
//
// It returns true or false.
func TLSWorks() bool

// SetTestTarget sets the rip appropriately.
func SetTestTarget(regs *arch.Registers, fn func()) {
	regs.Pc = uint64(reflect.ValueOf(fn).Pointer())
}

// SetTouchTarget sets rax appropriately.
func SetTouchTarget(regs *arch.Registers, target *uintptr) {
	if target != nil {
		regs.Regs[8] = uint64(reflect.ValueOf(target).Pointer())
	} else {
		regs.Regs[8] = 0
	}
}

// RewindSyscall rewinds a syscall RIP.
func RewindSyscall(regs *arch.Registers) {
	regs.Pc -= 4
}

// SetTestRegs initializes registers to known values.
func SetTestRegs(regs *arch.Registers) {
	for i := 0; i <= 30; i++ {
		regs.Regs[i] = uint64(i) + 1
	}
}

// CheckTestRegs checks that registers were twiddled per TwiddleRegs.
func CheckTestRegs(regs *arch.Registers, full bool) (err error) {
	for i := 0; i <= 30; i++ {
		if need := ^uint64(i + 1); regs.Regs[i] != need {
			err = addRegisterMismatch(err, fmt.Sprintf("R%d", i), regs.Regs[i], need)
		}
	}
	// Check tls.
	if need := ^uint64(11); regs.TPIDR_EL0 != need {
		err = addRegisterMismatch(err, "tpdir_el0", regs.TPIDR_EL0, need)
	}
	return
}
