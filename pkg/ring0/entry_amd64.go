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

//go:build amd64
// +build amd64

package ring0

import (
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// This is an assembly function.
//
// The sysenter function is invoked in two situations:
//
//	(1) The guest kernel has executed a system call.
//	(2) The guest application has executed a system call.
//
// The interrupt flag is examined to determine whether the system call was
// executed from kernel mode or not and the appropriate stub is called.
func sysenter()

// addrOfSysenter returns the start address of sysenter.
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func addrOfSysenter() uintptr

// jumpToKernel jumps to the kernel version of the current RIP.
func jumpToKernel()

// jumpToUser jumps to the user version of the current RIP.
func jumpToUser()

// sysret returns to userspace from a system call.
//
// The return code is the vector that interrupted execution.
//
// See stubs.go for a note regarding the frame size of this function.
func sysret(cpu *CPU, regs *arch.Registers, userCR3 uintptr) Vector

// "iret is the cadillac of CPL switching."
//
//	-- Neel Natu
//
// iret is nearly identical to sysret, except an iret is used to fully restore
// all user state. This must be called in cases where all registers need to be
// restored.
func iret(cpu *CPU, regs *arch.Registers, userCR3 uintptr) Vector

// exception is the generic exception entry.
//
// This is called by the individual stub definitions.
func exception()

// resume is a stub that restores the CPU kernel registers.
//
// This is used when processing kernel exceptions and syscalls.
func resume()

// start is the CPU entrypoint.
//
// See requirements below.
func start()

// AddrOfStart return the address of the CPU entrypoint.
//
// The following start conditions must be satisfied:
//
//   - AX should contain the CPU pointer.
//   - c.GDT() should be loaded as the GDT.
//   - c.IDT() should be loaded as the IDT.
//   - c.CR0() should be the current CR0 value.
//   - c.CR3() should be set to the kernel PageTables.
//   - c.CR4() should be the current CR4 value.
//   - c.EFER() should be the current EFER value.
//
// The CPU state will be set to c.Registers().
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func AddrOfStart() uintptr

// Exception stubs.
func divideByZero()
func debug()
func nmi()
func breakpoint()
func overflow()
func boundRangeExceeded()
func invalidOpcode()
func deviceNotAvailable()
func doubleFault()
func coprocessorSegmentOverrun()
func invalidTSS()
func segmentNotPresent()
func stackSegmentFault()
func generalProtectionFault()
func pageFault()
func x87FloatingPointException()
func alignmentCheck()
func machineCheck()
func simdFloatingPointException()
func virtualizationException()
func securityException()
func syscallInt80()

// These returns the start address of the functions above.
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func addrOfDivideByZero() uintptr
func addrOfDebug() uintptr
func addrOfNMI() uintptr
func addrOfBreakpoint() uintptr
func addrOfOverflow() uintptr
func addrOfBoundRangeExceeded() uintptr
func addrOfInvalidOpcode() uintptr
func addrOfDeviceNotAvailable() uintptr
func addrOfDoubleFault() uintptr
func addrOfCoprocessorSegmentOverrun() uintptr
func addrOfInvalidTSS() uintptr
func addrOfSegmentNotPresent() uintptr
func addrOfStackSegmentFault() uintptr
func addrOfGeneralProtectionFault() uintptr
func addrOfPageFault() uintptr
func addrOfX87FloatingPointException() uintptr
func addrOfAlignmentCheck() uintptr
func addrOfMachineCheck() uintptr
func addrOfSimdFloatingPointException() uintptr
func addrOfVirtualizationException() uintptr
func addrOfSecurityException() uintptr
func addrOfSyscallInt80() uintptr

// Exception handler index.
var handlers = map[Vector]uintptr{
	DivideByZero:               addrOfDivideByZero(),
	Debug:                      addrOfDebug(),
	NMI:                        addrOfNMI(),
	Breakpoint:                 addrOfBreakpoint(),
	Overflow:                   addrOfOverflow(),
	BoundRangeExceeded:         addrOfBoundRangeExceeded(),
	InvalidOpcode:              addrOfInvalidOpcode(),
	DeviceNotAvailable:         addrOfDeviceNotAvailable(),
	DoubleFault:                addrOfDoubleFault(),
	CoprocessorSegmentOverrun:  addrOfCoprocessorSegmentOverrun(),
	InvalidTSS:                 addrOfInvalidTSS(),
	SegmentNotPresent:          addrOfSegmentNotPresent(),
	StackSegmentFault:          addrOfStackSegmentFault(),
	GeneralProtectionFault:     addrOfGeneralProtectionFault(),
	PageFault:                  addrOfPageFault(),
	X87FloatingPointException:  addrOfX87FloatingPointException(),
	AlignmentCheck:             addrOfAlignmentCheck(),
	MachineCheck:               addrOfMachineCheck(),
	SIMDFloatingPointException: addrOfSimdFloatingPointException(),
	VirtualizationException:    addrOfVirtualizationException(),
	SecurityException:          addrOfSecurityException(),
	SyscallInt80:               addrOfSyscallInt80(),
}
