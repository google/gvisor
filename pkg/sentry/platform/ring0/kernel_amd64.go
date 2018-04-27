// Copyright 2018 Google Inc.
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
	"encoding/binary"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
)

const (
	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _RFLAGS_RESERVED

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _RFLAGS_RESERVED | _RFLAGS_IF

	// KernelFlagsClear should always be clear in the kernel.
	KernelFlagsClear = _RFLAGS_IF | _RFLAGS_NT | _RFLAGS_IOPL

	// UserFlagsClear are always cleared in userspace.
	UserFlagsClear = _RFLAGS_NT | _RFLAGS_IOPL
)

// init initializes architecture-specific state.
func (k *Kernel) init(opts KernelOpts) {
	// Save the root page tables.
	k.PageTables = opts.PageTables

	// Setup the IDT, which is uniform.
	for v, handler := range handlers {
		// Note that we set all traps to use the interrupt stack, this
		// is defined below when setting up the TSS.
		k.globalIDT[v].setInterrupt(Kcode, uint64(kernelFunc(handler)), 0 /* dpl */, 1 /* ist */)
	}
}

// init initializes architecture-specific state.
func (c *CPU) init() {
	// Null segment.
	c.gdt[0].setNull()

	// Kernel & user segments.
	c.gdt[segKcode] = KernelCodeSegment
	c.gdt[segKdata] = KernelDataSegment
	c.gdt[segUcode32] = UserCodeSegment32
	c.gdt[segUdata] = UserDataSegment
	c.gdt[segUcode64] = UserCodeSegment64

	// The task segment, this spans two entries.
	tssBase, tssLimit, _ := c.TSS()
	c.gdt[segTss].set(
		uint32(tssBase),
		uint32(tssLimit),
		0, // Privilege level zero.
		SegmentDescriptorPresent|
			SegmentDescriptorAccess|
			SegmentDescriptorWrite|
			SegmentDescriptorExecute)
	c.gdt[segTssHi].setHi(uint32((tssBase) >> 32))

	// Set the kernel stack pointer in the TSS (virtual address).
	stackAddr := c.StackTop()
	c.tss.rsp0Lo = uint32(stackAddr)
	c.tss.rsp0Hi = uint32(stackAddr >> 32)
	c.tss.ist1Lo = uint32(stackAddr)
	c.tss.ist1Hi = uint32(stackAddr >> 32)

	// Permanently set the kernel segments.
	c.registers.Cs = uint64(Kcode)
	c.registers.Ds = uint64(Kdata)
	c.registers.Es = uint64(Kdata)
	c.registers.Ss = uint64(Kdata)
	c.registers.Fs = uint64(Kdata)
	c.registers.Gs = uint64(Kdata)
}

// StackTop returns the kernel's stack address.
//
//go:nosplit
func (c *CPU) StackTop() uint64 {
	return uint64(kernelAddr(&c.stack[0])) + uint64(len(c.stack))
}

// IDT returns the CPU's IDT base and limit.
//
//go:nosplit
func (c *CPU) IDT() (uint64, uint16) {
	return uint64(kernelAddr(&c.kernel.globalIDT[0])), uint16(binary.Size(&c.kernel.globalIDT) - 1)
}

// GDT returns the CPU's GDT base and limit.
//
//go:nosplit
func (c *CPU) GDT() (uint64, uint16) {
	return uint64(kernelAddr(&c.gdt[0])), uint16(8*segLast - 1)
}

// TSS returns the CPU's TSS base, limit and value.
//
//go:nosplit
func (c *CPU) TSS() (uint64, uint16, *SegmentDescriptor) {
	return uint64(kernelAddr(&c.tss)), uint16(binary.Size(&c.tss) - 1), &c.gdt[segTss]
}

// CR0 returns the CPU's CR0 value.
//
//go:nosplit
func (c *CPU) CR0() uint64 {
	return _CR0_PE | _CR0_PG | _CR0_ET
}

// CR4 returns the CPU's CR4 value.
//
//go:nosplit
func (c *CPU) CR4() uint64 {
	cr4 := uint64(_CR4_PAE | _CR4_PSE | _CR4_OSFXSR | _CR4_OSXMMEXCPT)
	if hasPCID {
		cr4 |= _CR4_PCIDE
	}
	if hasXSAVE {
		cr4 |= _CR4_OSXSAVE
	}
	if hasSMEP {
		cr4 |= _CR4_SMEP
	}
	if hasFSGSBASE {
		cr4 |= _CR4_FSGSBASE
	}
	return cr4
}

// EFER returns the CPU's EFER value.
//
//go:nosplit
func (c *CPU) EFER() uint64 {
	return _EFER_LME | _EFER_SCE | _EFER_NX
}

// IsCanonical indicates whether addr is canonical per the amd64 spec.
//
//go:nosplit
func IsCanonical(addr uint64) bool {
	return addr <= 0x00007fffffffffff || addr > 0xffff800000000000
}

// Flags contains flags related to switch.
type Flags uintptr

const (
	// FlagFull indicates that a full restore should be not, not a fast
	// restore (on the syscall return path.)
	FlagFull = 1 << iota

	// FlagFlush indicates that a full TLB flush is required.
	FlagFlush
)

// SwitchToUser performs either a sysret or an iret.
//
// The return value is the vector that interrupted execution.
//
// This function will not split the stack. Callers will probably want to call
// runtime.entersyscall (and pair with a call to runtime.exitsyscall) prior to
// calling this function.
//
// When this is done, this region is quite sensitive to things like system
// calls. After calling entersyscall, any memory used must have been allocated
// and no function calls without go:nosplit are permitted. Any calls made here
// are protected appropriately (e.g. IsCanonical and CR3).
//
// Also note that this function transitively depends on the compiler generating
// code that uses IP-relative addressing inside of absolute addresses. That's
// the case for amd64, but may not be the case for other architectures.
//
//go:nosplit
func (c *CPU) SwitchToUser(regs *syscall.PtraceRegs, fpState *byte, pt *pagetables.PageTables, flags Flags) (vector Vector) {
	// Check for canonical addresses.
	if !IsCanonical(regs.Rip) || !IsCanonical(regs.Rsp) || !IsCanonical(regs.Fs_base) || !IsCanonical(regs.Gs_base) {
		return GeneralProtectionFault
	}

	var (
		userCR3   uint64
		kernelCR3 uint64
	)

	// Sanitize registers.
	if flags&FlagFlush != 0 {
		userCR3 = pt.FlushCR3()
	} else {
		userCR3 = pt.CR3()
	}
	regs.Eflags &= ^uint64(UserFlagsClear)
	regs.Eflags |= UserFlagsSet
	regs.Cs = uint64(Ucode64) // Required for iret.
	regs.Ss = uint64(Udata)   // Ditto.
	kernelCR3 = c.kernel.PageTables.CR3()

	// Perform the switch.
	swapgs()                    // GS will be swapped on return.
	wrfs(uintptr(regs.Fs_base)) // Set application FS.
	wrgs(uintptr(regs.Gs_base)) // Set application GS.
	LoadFloatingPoint(fpState)  // Copy in floating point.
	jumpToKernel()              // Switch to upper half.
	writeCR3(uintptr(userCR3))  // Change to user address space.
	if flags&FlagFull != 0 {
		vector = iret(c, regs)
	} else {
		vector = sysret(c, regs)
	}
	writeCR3(uintptr(kernelCR3))       // Return to kernel address space.
	jumpToUser()                       // Return to lower half.
	SaveFloatingPoint(fpState)         // Copy out floating point.
	wrfs(uintptr(c.registers.Fs_base)) // Restore kernel FS.
	return
}

// start is the CPU entrypoint.
//
// This is called from the Start asm stub (see entry_amd64.go); on return the
// registers in c.registers will be restored (not segments).
//
//go:nosplit
func start(c *CPU) {
	// Save per-cpu & FS segment.
	wrgs(kernelAddr(c))
	wrfs(uintptr(c.Registers().Fs_base))

	// Initialize floating point.
	//
	// Note that on skylake, the valid XCR0 mask reported seems to be 0xff.
	// This breaks down as:
	//
	//	bit0   - x87
	//	bit1   - SSE
	//	bit2   - AVX
	//	bit3-4 - MPX
	//	bit5-7 - AVX512
	//
	// For some reason, enabled MPX & AVX512 on platforms that report them
	// seems to be cause a general protection fault. (Maybe there are some
	// virtualization issues and these aren't exported to the guest cpuid.)
	// This needs further investigation, but we can limit the floating
	// point operations to x87, SSE & AVX for now.
	fninit()
	xsetbv(0, validXCR0Mask&0x7)

	// Set the syscall target.
	wrmsr(_MSR_LSTAR, kernelFunc(sysenter))
	wrmsr(_MSR_SYSCALL_MASK, _RFLAGS_STEP|_RFLAGS_IF|_RFLAGS_DF|_RFLAGS_IOPL|_RFLAGS_AC|_RFLAGS_NT)

	// NOTE: This depends on having the 64-bit segments immediately
	// following the 32-bit user segments. This is simply the way the
	// sysret instruction is designed to work (it assumes they follow).
	wrmsr(_MSR_STAR, uintptr(uint64(Kcode)<<32|uint64(Ucode32)<<48))
	wrmsr(_MSR_CSTAR, kernelFunc(sysenter))
}

// ReadCR2 reads the current CR2 value.
//
//go:nosplit
func ReadCR2() uintptr {
	return readCR2()
}
