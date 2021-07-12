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
	fmt.Fprintf(w, "#define CPU_REGISTERS        0x%02x\n", reflect.ValueOf(&c.registers).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_ERROR_CODE       0x%02x\n", reflect.ValueOf(&c.errorCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_ERROR_TYPE       0x%02x\n", reflect.ValueOf(&c.errorType).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_ENTRY            0x%02x\n", reflect.ValueOf(&c.kernelEntry).Pointer()-reflect.ValueOf(c).Pointer())

	e := &kernelEntry{}
	fmt.Fprintf(w, "\n// CPU entry offsets.\n")
	fmt.Fprintf(w, "#define ENTRY_SCRATCH0       0x%02x\n", reflect.ValueOf(&e.scratch0).Pointer()-reflect.ValueOf(e).Pointer())
	fmt.Fprintf(w, "#define ENTRY_STACK_TOP      0x%02x\n", reflect.ValueOf(&e.stackTop).Pointer()-reflect.ValueOf(e).Pointer())
	fmt.Fprintf(w, "#define ENTRY_CPU_SELF       0x%02x\n", reflect.ValueOf(&e.cpuSelf).Pointer()-reflect.ValueOf(e).Pointer())
	fmt.Fprintf(w, "#define ENTRY_KERNEL_CR3     0x%02x\n", reflect.ValueOf(&e.kernelCR3).Pointer()-reflect.ValueOf(e).Pointer())

	fmt.Fprintf(w, "\n// Bits.\n")
	fmt.Fprintf(w, "#define _RFLAGS_IF           0x%02x\n", _RFLAGS_IF)
	fmt.Fprintf(w, "#define _RFLAGS_IOPL0         0x%02x\n", _RFLAGS_IOPL0)
	fmt.Fprintf(w, "#define _KERNEL_FLAGS        0x%02x\n", KernelFlagsSet)

	fmt.Fprintf(w, "\n// Vectors.\n")
	fmt.Fprintf(w, "#define DivideByZero               0x%02x\n", DivideByZero)
	fmt.Fprintf(w, "#define Debug                      0x%02x\n", Debug)
	fmt.Fprintf(w, "#define NMI                        0x%02x\n", NMI)
	fmt.Fprintf(w, "#define Breakpoint                 0x%02x\n", Breakpoint)
	fmt.Fprintf(w, "#define Overflow                   0x%02x\n", Overflow)
	fmt.Fprintf(w, "#define BoundRangeExceeded         0x%02x\n", BoundRangeExceeded)
	fmt.Fprintf(w, "#define InvalidOpcode              0x%02x\n", InvalidOpcode)
	fmt.Fprintf(w, "#define DeviceNotAvailable         0x%02x\n", DeviceNotAvailable)
	fmt.Fprintf(w, "#define DoubleFault                0x%02x\n", DoubleFault)
	fmt.Fprintf(w, "#define CoprocessorSegmentOverrun  0x%02x\n", CoprocessorSegmentOverrun)
	fmt.Fprintf(w, "#define InvalidTSS                 0x%02x\n", InvalidTSS)
	fmt.Fprintf(w, "#define SegmentNotPresent          0x%02x\n", SegmentNotPresent)
	fmt.Fprintf(w, "#define StackSegmentFault          0x%02x\n", StackSegmentFault)
	fmt.Fprintf(w, "#define GeneralProtectionFault     0x%02x\n", GeneralProtectionFault)
	fmt.Fprintf(w, "#define PageFault                  0x%02x\n", PageFault)
	fmt.Fprintf(w, "#define X87FloatingPointException  0x%02x\n", X87FloatingPointException)
	fmt.Fprintf(w, "#define AlignmentCheck             0x%02x\n", AlignmentCheck)
	fmt.Fprintf(w, "#define MachineCheck               0x%02x\n", MachineCheck)
	fmt.Fprintf(w, "#define SIMDFloatingPointException 0x%02x\n", SIMDFloatingPointException)
	fmt.Fprintf(w, "#define VirtualizationException    0x%02x\n", VirtualizationException)
	fmt.Fprintf(w, "#define SecurityException          0x%02x\n", SecurityException)
	fmt.Fprintf(w, "#define SyscallInt80               0x%02x\n", SyscallInt80)
	fmt.Fprintf(w, "#define Syscall                    0x%02x\n", Syscall)

	p := &arch.Registers{}
	fmt.Fprintf(w, "\n// Ptrace registers.\n")
	fmt.Fprintf(w, "#define PTRACE_R15      0x%02x\n", reflect.ValueOf(&p.R15).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R14      0x%02x\n", reflect.ValueOf(&p.R14).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R13      0x%02x\n", reflect.ValueOf(&p.R13).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R12      0x%02x\n", reflect.ValueOf(&p.R12).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RBP      0x%02x\n", reflect.ValueOf(&p.Rbp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RBX      0x%02x\n", reflect.ValueOf(&p.Rbx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R11      0x%02x\n", reflect.ValueOf(&p.R11).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R10      0x%02x\n", reflect.ValueOf(&p.R10).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R9       0x%02x\n", reflect.ValueOf(&p.R9).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R8       0x%02x\n", reflect.ValueOf(&p.R8).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RAX      0x%02x\n", reflect.ValueOf(&p.Rax).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RCX      0x%02x\n", reflect.ValueOf(&p.Rcx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RDX      0x%02x\n", reflect.ValueOf(&p.Rdx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RSI      0x%02x\n", reflect.ValueOf(&p.Rsi).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RDI      0x%02x\n", reflect.ValueOf(&p.Rdi).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_ORIGRAX  0x%02x\n", reflect.ValueOf(&p.Orig_rax).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RIP      0x%02x\n", reflect.ValueOf(&p.Rip).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_CS       0x%02x\n", reflect.ValueOf(&p.Cs).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_FLAGS    0x%02x\n", reflect.ValueOf(&p.Eflags).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RSP      0x%02x\n", reflect.ValueOf(&p.Rsp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_SS       0x%02x\n", reflect.ValueOf(&p.Ss).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_FS_BASE  0x%02x\n", reflect.ValueOf(&p.Fs_base).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_GS_BASE  0x%02x\n", reflect.ValueOf(&p.Gs_base).Pointer()-reflect.ValueOf(p).Pointer())
}
