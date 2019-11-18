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

package boot

import (
	"fmt"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/strace"
)

// reportLimit is the max number of events that should be reported per tracker.
const reportLimit = 100

// newRegs create a empty Registers instance.
func newRegs() *rpb.Registers {
	return &rpb.Registers{
		Arch: &rpb.Registers_Arm64{
			Arm64: &rpb.ARM64Registers{},
		},
	}
}

func argVal(argIdx int, regs *rpb.Registers) uint32 {
	arm64Regs := regs.GetArch().(*rpb.Registers_Arm64).Arm64

	switch argIdx {
	case 0:
		return uint32(arm64Regs.R0)
	case 1:
		return uint32(arm64Regs.R1)
	case 2:
		return uint32(arm64Regs.R2)
	case 3:
		return uint32(arm64Regs.R3)
	case 4:
		return uint32(arm64Regs.R4)
	case 5:
		return uint32(arm64Regs.R5)
	}
	panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
}

func setArgVal(argIdx int, argVal uint64, regs *rpb.Registers) {
	arm64Regs := regs.GetArch().(*rpb.Registers_Arm64).Arm64

	switch argIdx {
	case 0:
		arm64Regs.R0 = argVal
	case 1:
		arm64Regs.R1 = argVal
	case 2:
		arm64Regs.R2 = argVal
	case 3:
		arm64Regs.R3 = argVal
	case 4:
		arm64Regs.R4 = argVal
	case 5:
		arm64Regs.R5 = argVal
	default:
		panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
	}
}

func getSyscallNameMap() (strace.SyscallMap, bool) {
	return strace.Lookup(abi.Linux, arch.ARM64)
}

func syscallNum(regs *rpb.Registers) uint64 {
	arm64Regs := regs.GetArch().(*rpb.Registers_Arm64).Arm64
	return arm64Regs.R8
}

func newArchArgsTracker(sysnr uint64) syscallTracker {

	switch sysnr {
	// currently, no arch specific syscalls need to be handled here.
	default:
		return &onceTracker{}
	}
}
