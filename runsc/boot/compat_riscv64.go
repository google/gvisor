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

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/strace"
)

const (
	// reportLimit is the max number of events that should be reported per
	// tracker.
	reportLimit = 100
	syscallLink = "https://gvisor.dev/c/linux/riscv64"
)

// newRegs create a empty Registers instance.
func newRegs() *rpb.Registers {
	return &rpb.Registers{
		Arch: &rpb.Registers_Riscv64{
			Riscv64: &rpb.RISCV64Registers{},
		},
	}
}

func argVal(argIdx int, regs *rpb.Registers) uint64 {
	riscv64Regs := regs.GetArch().(*rpb.Registers_Riscv64).Riscv64

	switch argIdx {
	case 0:
		return riscv64Regs.A0;
	case 1:
		return riscv64Regs.A1;
	case 2:
		return riscv64Regs.A2;
	case 3:
		return riscv64Regs.A3;
	case 4:
		return riscv64Regs.A4;
	case 5:
		return riscv64Regs.A5;
	}
	panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
}

func setArgVal(argIdx int, argVal uint64, regs *rpb.Registers) {
	riscv64Regs := regs.GetArch().(*rpb.Registers_Riscv64).Riscv64

	switch argIdx {
	case 0:
		riscv64Regs.A0 = argVal
	case 1:
		riscv64Regs.A1 = argVal
	case 2:
		riscv64Regs.A2 = argVal
	case 3:
		riscv64Regs.A3 = argVal
	case 4:
		riscv64Regs.A4 = argVal
	case 5:
		riscv64Regs.A5 = argVal
	default:
		panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
	}
}

func getSyscallNameMap() (strace.SyscallMap, bool) {
	return strace.Lookup(abi.Linux, arch.RISCV64)
}

func syscallNum(regs *rpb.Registers) uint64 {
	riscv64Regs := regs.GetArch().(*rpb.Registers_Riscv64).Riscv64
	return riscv64Regs.A7;
}

func newArchArgsTracker(sysnr uint64) syscallTracker {
	// currently, no arch specific syscalls need to be handled here.
	return nil
}
