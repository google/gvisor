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

// +build arm64

package ring0

import (
	"fmt"
	"io"
	"reflect"

	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// Emit prints architecture-specific offsets.
func Emit(w io.Writer) {
	fmt.Fprintf(w, "// Automatically generated, do not edit.\n")

	c := &CPU{}
	fmt.Fprintf(w, "\n// CPU offsets.\n")
	fmt.Fprintf(w, "#define CPU_SELF             0x%02x\n", reflect.ValueOf(&c.self).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_REGISTERS        0x%02x\n", reflect.ValueOf(&c.registers).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_STACK_TOP        0x%02x\n", reflect.ValueOf(&c.stack[0]).Pointer()-reflect.ValueOf(c).Pointer()+uintptr(len(c.stack)))
	fmt.Fprintf(w, "#define CPU_ERROR_CODE       0x%02x\n", reflect.ValueOf(&c.errorCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_ERROR_TYPE       0x%02x\n", reflect.ValueOf(&c.errorType).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_FAULT_ADDR       0x%02x\n", reflect.ValueOf(&c.faultAddr).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_FPSTATE_EL0      0x%02x\n", reflect.ValueOf(&c.el0Fp).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_TTBR0_KVM	     0x%02x\n", reflect.ValueOf(&c.ttbr0Kvm).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_TTBR0_APP        0x%02x\n", reflect.ValueOf(&c.ttbr0App).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_VECTOR_CODE      0x%02x\n", reflect.ValueOf(&c.vecCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_APP_ADDR         0x%02x\n", reflect.ValueOf(&c.appAddr).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_LAZY_VFP         0x%02x\n", reflect.ValueOf(&c.lazyVFP).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_APP_ASID         0x%02x\n", reflect.ValueOf(&c.appASID).Pointer()-reflect.ValueOf(c).Pointer())

	fmt.Fprintf(w, "\n// Bits.\n")
	fmt.Fprintf(w, "#define _KERNEL_FLAGS        0x%02x\n", KernelFlagsSet)

	fmt.Fprintf(w, "\n// Vectors.\n")

	fmt.Fprintf(w, "#define El1Sync 0x%02x\n", El1Sync)
	fmt.Fprintf(w, "#define El1Irq 0x%02x\n", El1Irq)
	fmt.Fprintf(w, "#define El1Fiq 0x%02x\n", El1Fiq)
	fmt.Fprintf(w, "#define El1Err 0x%02x\n", El1Err)

	fmt.Fprintf(w, "#define El0Sync 0x%02x\n", El0Sync)
	fmt.Fprintf(w, "#define El0Irq 0x%02x\n", El0Irq)
	fmt.Fprintf(w, "#define El0Fiq 0x%02x\n", El0Fiq)
	fmt.Fprintf(w, "#define El0Err 0x%02x\n", El0Err)

	fmt.Fprintf(w, "#define El1SyncDa 0x%02x\n", El1SyncDa)
	fmt.Fprintf(w, "#define El1SyncIa 0x%02x\n", El1SyncIa)
	fmt.Fprintf(w, "#define El1SyncSpPc 0x%02x\n", El1SyncSpPc)
	fmt.Fprintf(w, "#define El1SyncUndef 0x%02x\n", El1SyncUndef)
	fmt.Fprintf(w, "#define El1SyncDbg 0x%02x\n", El1SyncDbg)
	fmt.Fprintf(w, "#define El1SyncInv 0x%02x\n", El1SyncInv)

	fmt.Fprintf(w, "#define El0SyncSVC 0x%02x\n", El0SyncSVC)
	fmt.Fprintf(w, "#define El0SyncDa 0x%02x\n", El0SyncDa)
	fmt.Fprintf(w, "#define El0SyncIa 0x%02x\n", El0SyncIa)
	fmt.Fprintf(w, "#define El0SyncFpsimdAcc 0x%02x\n", El0SyncFpsimdAcc)
	fmt.Fprintf(w, "#define El0SyncSveAcc 0x%02x\n", El0SyncSveAcc)
	fmt.Fprintf(w, "#define El0SyncFpsimdExc 0x%02x\n", El0SyncFpsimdExc)
	fmt.Fprintf(w, "#define El0SyncSys 0x%02x\n", El0SyncSys)
	fmt.Fprintf(w, "#define El0SyncSpPc 0x%02x\n", El0SyncSpPc)
	fmt.Fprintf(w, "#define El0SyncUndef 0x%02x\n", El0SyncUndef)
	fmt.Fprintf(w, "#define El0SyncDbg 0x%02x\n", El0SyncDbg)
	fmt.Fprintf(w, "#define El0SyncWfx 0x%02x\n", El0SyncWfx)
	fmt.Fprintf(w, "#define El0SyncInv 0x%02x\n", El0SyncInv)

	fmt.Fprintf(w, "#define El0ErrNMI 0x%02x\n", El0ErrNMI)

	fmt.Fprintf(w, "#define PageFault 0x%02x\n", PageFault)
	fmt.Fprintf(w, "#define Syscall 0x%02x\n", Syscall)
	fmt.Fprintf(w, "#define VirtualizationException 0x%02x\n", VirtualizationException)

	p := &arch.Registers{}
	fmt.Fprintf(w, "\n// Ptrace registers.\n")
	fmt.Fprintf(w, "#define PTRACE_R0       0x%02x\n", reflect.ValueOf(&p.Regs[0]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R1       0x%02x\n", reflect.ValueOf(&p.Regs[1]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R2       0x%02x\n", reflect.ValueOf(&p.Regs[2]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R3       0x%02x\n", reflect.ValueOf(&p.Regs[3]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R4       0x%02x\n", reflect.ValueOf(&p.Regs[4]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R5       0x%02x\n", reflect.ValueOf(&p.Regs[5]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R6       0x%02x\n", reflect.ValueOf(&p.Regs[6]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R7       0x%02x\n", reflect.ValueOf(&p.Regs[7]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R8       0x%02x\n", reflect.ValueOf(&p.Regs[8]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R9       0x%02x\n", reflect.ValueOf(&p.Regs[9]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R10      0x%02x\n", reflect.ValueOf(&p.Regs[10]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R11      0x%02x\n", reflect.ValueOf(&p.Regs[11]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R12      0x%02x\n", reflect.ValueOf(&p.Regs[12]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R13      0x%02x\n", reflect.ValueOf(&p.Regs[13]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R14      0x%02x\n", reflect.ValueOf(&p.Regs[14]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R15      0x%02x\n", reflect.ValueOf(&p.Regs[15]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R16      0x%02x\n", reflect.ValueOf(&p.Regs[16]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R17      0x%02x\n", reflect.ValueOf(&p.Regs[17]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R18      0x%02x\n", reflect.ValueOf(&p.Regs[18]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R19      0x%02x\n", reflect.ValueOf(&p.Regs[19]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R20      0x%02x\n", reflect.ValueOf(&p.Regs[20]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R21      0x%02x\n", reflect.ValueOf(&p.Regs[21]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R22      0x%02x\n", reflect.ValueOf(&p.Regs[22]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R23      0x%02x\n", reflect.ValueOf(&p.Regs[23]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R24      0x%02x\n", reflect.ValueOf(&p.Regs[24]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R25      0x%02x\n", reflect.ValueOf(&p.Regs[25]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R26      0x%02x\n", reflect.ValueOf(&p.Regs[26]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R27      0x%02x\n", reflect.ValueOf(&p.Regs[27]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R28      0x%02x\n", reflect.ValueOf(&p.Regs[28]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R29      0x%02x\n", reflect.ValueOf(&p.Regs[29]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R30      0x%02x\n", reflect.ValueOf(&p.Regs[30]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_SP       0x%02x\n", reflect.ValueOf(&p.Sp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_PC       0x%02x\n", reflect.ValueOf(&p.Pc).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_PSTATE   0x%02x\n", reflect.ValueOf(&p.Pstate).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_TLS      0x%02x\n", reflect.ValueOf(&p.TPIDR_EL0).Pointer()-reflect.ValueOf(p).Pointer())
}
