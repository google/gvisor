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
	"encoding/binary"
	"reflect"

	"gvisor.dev/gvisor/pkg/usermem"
)

// init initializes architecture-specific state.
func (k *Kernel) init(opts KernelOpts, maxCPUs int) {
	// Save the root page tables.
	k.PageTables = opts.PageTables

	entrySize := reflect.TypeOf(kernelEntry{}).Size()
	var (
		entries []kernelEntry
		padding = 1
	)
	for {
		entries = make([]kernelEntry, maxCPUs+padding-1)
		totalSize := entrySize * uintptr(maxCPUs+padding-1)
		addr := reflect.ValueOf(&entries[0]).Pointer()
		if addr&(usermem.PageSize-1) == 0 && totalSize >= usermem.PageSize {
			// The runtime forces power-of-2 alignment for allocations, and we are therefore
			// safe once the first address is aligned and the chunk is at least a full page.
			break
		}
		padding = padding << 1
	}
	k.cpuEntries = entries

	k.globalIDT = &idt64{}
	if reflect.TypeOf(idt64{}).Size() != usermem.PageSize {
		panic("Size of globalIDT should be PageSize")
	}
	if reflect.ValueOf(k.globalIDT).Pointer()&(usermem.PageSize-1) != 0 {
		panic("Allocated globalIDT should be page aligned")
	}

	// Setup the IDT, which is uniform.
	for v, handler := range handlers {
		// Allow Breakpoint and Overflow to be called from all
		// privilege levels.
		dpl := 0
		if v == Breakpoint || v == Overflow {
			dpl = 3
		}
		// Note that we set all traps to use the interrupt stack, this
		// is defined below when setting up the TSS.
		k.globalIDT[v].setInterrupt(Kcode, uint64(kernelFunc(handler)), dpl, 1 /* ist */)
	}
}

func (k *Kernel) EntryRegions() map[uintptr]uintptr {
	regions := make(map[uintptr]uintptr)

	addr := reflect.ValueOf(&k.cpuEntries[0]).Pointer()
	size := reflect.TypeOf(kernelEntry{}).Size() * uintptr(len(k.cpuEntries))
	end, _ := usermem.Addr(addr + size).RoundUp()
	regions[uintptr(usermem.Addr(addr).RoundDown())] = uintptr(end)

	addr = reflect.ValueOf(k.globalIDT).Pointer()
	size = reflect.TypeOf(idt64{}).Size()
	end, _ = usermem.Addr(addr + size).RoundUp()
	regions[uintptr(usermem.Addr(addr).RoundDown())] = uintptr(end)

	return regions
}

// init initializes architecture-specific state.
func (c *CPU) init(cpuID int) {
	c.kernelEntry = &c.kernel.cpuEntries[cpuID]
	c.cpuSelf = c
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
	c.stackTop = stackAddr
	c.tss.rsp0Lo = uint32(stackAddr)
	c.tss.rsp0Hi = uint32(stackAddr >> 32)
	c.tss.ist1Lo = uint32(stackAddr)
	c.tss.ist1Hi = uint32(stackAddr >> 32)

	// Set the I/O bitmap base address beyond the last byte in the TSS
	// to block access to the entire I/O address range.
	//
	// From section 18.5.2 "I/O Permission Bit Map" from Intel SDM vol1:
	// I/O addresses not spanned by the map are treated as if they had set
	// bits in the map.
	c.tss.ioPerm = tssLimit + 1

	// Permanently set the kernel segments.
	c.registers.Cs = uint64(Kcode)
	c.registers.Ds = uint64(Kdata)
	c.registers.Es = uint64(Kdata)
	c.registers.Ss = uint64(Kdata)
	c.registers.Fs = uint64(Kdata)
	c.registers.Gs = uint64(Kdata)

	// Set mandatory flags.
	c.registers.Eflags = KernelFlagsSet
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
	return _CR0_PE | _CR0_PG | _CR0_AM | _CR0_ET
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
	return _EFER_LME | _EFER_LMA | _EFER_SCE | _EFER_NX
}

// IsCanonical indicates whether addr is canonical per the amd64 spec.
//
//go:nosplit
func IsCanonical(addr uint64) bool {
	return addr <= 0x00007fffffffffff || addr > 0xffff800000000000
}

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
// Precondition: the Rip, Rsp, Fs and Gs registers must be canonical.
//
// +checkescape:all
//
//go:nosplit
func (c *CPU) SwitchToUser(switchOpts SwitchOpts) (vector Vector) {
	userCR3 := switchOpts.PageTables.CR3(!switchOpts.Flush, switchOpts.UserPCID)
	c.kernelCR3 = uintptr(c.kernel.PageTables.CR3(true, switchOpts.KernelPCID))

	// Sanitize registers.
	regs := switchOpts.Registers
	regs.Eflags &= ^uint64(UserFlagsClear)
	regs.Eflags |= UserFlagsSet
	regs.Cs = uint64(Ucode64) // Required for iret.
	regs.Ss = uint64(Udata)   // Ditto.

	// Perform the switch.
	swapgs()                                         // GS will be swapped on return.
	WriteFS(uintptr(regs.Fs_base))                   // escapes: no. Set application FS.
	WriteGS(uintptr(regs.Gs_base))                   // escapes: no. Set application GS.
	LoadFloatingPoint(switchOpts.FloatingPointState) // escapes: no. Copy in floating point.
	if switchOpts.FullRestore {
		vector = iret(c, regs, uintptr(userCR3))
	} else {
		vector = sysret(c, regs, uintptr(userCR3))
	}
	SaveFloatingPoint(switchOpts.FloatingPointState) // escapes: no. Copy out floating point.
	WriteFS(uintptr(c.registers.Fs_base))            // escapes: no. Restore kernel FS.
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
	WriteGS(kernelAddr(c.kernelEntry))
	WriteFS(uintptr(c.registers.Fs_base))

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
	wrmsr(_MSR_SYSCALL_MASK, KernelFlagsClear|_RFLAGS_DF)

	// NOTE: This depends on having the 64-bit segments immediately
	// following the 32-bit user segments. This is simply the way the
	// sysret instruction is designed to work (it assumes they follow).
	wrmsr(_MSR_STAR, uintptr(uint64(Kcode)<<32|uint64(Ucode32)<<48))
	wrmsr(_MSR_CSTAR, kernelFunc(sysenter))
}

// SetCPUIDFaulting sets CPUID faulting per the boolean value.
//
// True is returned if faulting could be set.
//
//go:nosplit
func SetCPUIDFaulting(on bool) bool {
	// Per the SDM (Vol 3, Table 2-43), PLATFORM_INFO bit 31 denotes support
	// for CPUID faulting, and we enable and disable via the MISC_FEATURES MSR.
	if rdmsr(_MSR_PLATFORM_INFO)&_PLATFORM_INFO_CPUID_FAULT != 0 {
		features := rdmsr(_MSR_MISC_FEATURES)
		if on {
			features |= _MISC_FEATURE_CPUID_TRAP
		} else {
			features &^= _MISC_FEATURE_CPUID_TRAP
		}
		wrmsr(_MSR_MISC_FEATURES, features)
		return true // Setting successful.
	}
	return false
}

// ReadCR2 reads the current CR2 value.
//
//go:nosplit
func ReadCR2() uintptr {
	return readCR2()
}
