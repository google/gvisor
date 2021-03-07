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

package boot

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/strace"
)

const (
	// reportLimit is the max number of events that should be reported per
	// tracker.
	reportLimit = 100
	syscallLink = "https://gvisor.dev/c/linux/amd64"
)

// newRegs create a empty Registers instance.
func newRegs() *rpb.Registers {
	return &rpb.Registers{
		Arch: &rpb.Registers_Amd64{
			Amd64: &rpb.AMD64Registers{},
		},
	}
}

func argVal(argIdx int, regs *rpb.Registers) uint64 {
	amd64Regs := regs.GetArch().(*rpb.Registers_Amd64).Amd64

	switch argIdx {
	case 0:
		return amd64Regs.Rdi
	case 1:
		return amd64Regs.Rsi
	case 2:
		return amd64Regs.Rdx
	case 3:
		return amd64Regs.R10
	case 4:
		return amd64Regs.R8
	case 5:
		return amd64Regs.R9
	}
	panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
}

func setArgVal(argIdx int, argVal uint64, regs *rpb.Registers) {
	amd64Regs := regs.GetArch().(*rpb.Registers_Amd64).Amd64

	switch argIdx {
	case 0:
		amd64Regs.Rdi = argVal
	case 1:
		amd64Regs.Rsi = argVal
	case 2:
		amd64Regs.Rdx = argVal
	case 3:
		amd64Regs.R10 = argVal
	case 4:
		amd64Regs.R8 = argVal
	case 5:
		amd64Regs.R9 = argVal
	default:
		panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
	}
}

func getSyscallNameMap() (strace.SyscallMap, bool) {
	return strace.Lookup(abi.Linux, arch.AMD64)
}

func syscallNum(regs *rpb.Registers) uint64 {
	amd64Regs := regs.GetArch().(*rpb.Registers_Amd64).Amd64
	return amd64Regs.OrigRax
}

func newArchArgsTracker(sysnr uint64) syscallTracker {
	switch sysnr {
	case unix.SYS_ARCH_PRCTL:
		// args: cmd, ...
		return newArgsTracker(0)
	}
	return nil
}
