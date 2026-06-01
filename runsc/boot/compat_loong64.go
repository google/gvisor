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

package boot

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/strace"
)

const (
	// reportLimit is the max number of events that should be reported per
	// tracker.
	reportLimit = 100
	syscallLink = "https://gvisor.dev/c/linux/loong64"
)

// newRegs creates an empty Registers instance.
func newRegs() *rpb.Registers {
	return &rpb.Registers{
		Arch: &rpb.Registers_Loong64{
			Loong64: &rpb.LoongArch64Registers{},
		},
	}
}

// LoongArch syscall ABI: arguments live in $a0..$a5 ($r4..$r9).
func argVal(argIdx int, regs *rpb.Registers) uint64 {
	r := regs.GetArch().(*rpb.Registers_Loong64).Loong64
	switch argIdx {
	case 0:
		return r.R4
	case 1:
		return r.R5
	case 2:
		return r.R6
	case 3:
		return r.R7
	case 4:
		return r.R8
	case 5:
		return r.R9
	}
	panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
}

func setArgVal(argIdx int, argVal uint64, regs *rpb.Registers) {
	r := regs.GetArch().(*rpb.Registers_Loong64).Loong64
	switch argIdx {
	case 0:
		r.R4 = argVal
	case 1:
		r.R5 = argVal
	case 2:
		r.R6 = argVal
	case 3:
		r.R7 = argVal
	case 4:
		r.R8 = argVal
	case 5:
		r.R9 = argVal
	default:
		panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
	}
}

func getSyscallNameMap() (strace.SyscallMap, bool) {
	return strace.Lookup(abi.Linux, arch.LOONGARCH64)
}

// syscallNum returns the syscall number, held in $a7 ($r11) on LoongArch.
func syscallNum(regs *rpb.Registers) uint64 {
	return regs.GetArch().(*rpb.Registers_Loong64).Loong64.R11
}

func newArchArgsTracker(sysnr uint64) syscallTracker {
	// No LoongArch-specific syscalls need argument tracking today.
	return nil
}
