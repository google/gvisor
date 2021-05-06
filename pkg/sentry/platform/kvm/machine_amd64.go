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

package kvm

import (
	"fmt"
	"math/big"
	"reflect"
	"runtime/debug"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
)

// initArchState initializes architecture-specific state.
func (m *machine) initArchState() error {
	// Set the legacy TSS address. This address is covered by the reserved
	// range (up to 4GB). In fact, this is a main reason it exists.
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_SET_TSS_ADDR,
		uintptr(reservedMemory-(3*hostarch.PageSize))); errno != 0 {
		return errno
	}

	// Enable CPUID faulting, if possible. Note that this also serves as a
	// basic platform sanity tests, since we will enter guest mode for the
	// first time here. The recovery is necessary, since if we fail to read
	// the platform info register, we will retry to host mode and
	// ultimately need to handle a segmentation fault.
	old := debug.SetPanicOnFault(true)
	defer func() {
		recover()
		debug.SetPanicOnFault(old)
	}()
	c := m.Get()
	defer m.Put(c)
	bluepill(c)
	ring0.SetCPUIDFaulting(true)

	return nil
}

type vCPUArchState struct {
	// PCIDs is the set of PCIDs for this vCPU.
	//
	// This starts above fixedKernelPCID.
	PCIDs *pagetables.PCIDs

	// floatingPointState is the floating point state buffer used in guest
	// to host transitions. See usage in bluepill_amd64.go.
	floatingPointState fpu.State
}

const (
	// fixedKernelPCID is a fixed kernel PCID used for the kernel page
	// tables. We must start allocating user PCIDs above this in order to
	// avoid any conflict (see below).
	fixedKernelPCID = 1

	// poolPCIDs is the number of PCIDs to record in the database. As this
	// grows, assignment can take longer, since it is a simple linear scan.
	// Beyond a relatively small number, there are likely few perform
	// benefits, since the TLB has likely long since lost any translations
	// from more than a few PCIDs past.
	poolPCIDs = 8
)

// initArchState initializes architecture-specific state.
func (c *vCPU) initArchState() error {
	var (
		kernelSystemRegs systemRegs
		kernelUserRegs   userRegs
	)

	// Set base control registers.
	kernelSystemRegs.CR0 = c.CR0()
	kernelSystemRegs.CR4 = c.CR4()
	kernelSystemRegs.EFER = c.EFER()

	// Set the IDT & GDT in the registers.
	kernelSystemRegs.IDT.base, kernelSystemRegs.IDT.limit = c.IDT()
	kernelSystemRegs.GDT.base, kernelSystemRegs.GDT.limit = c.GDT()
	kernelSystemRegs.CS.Load(&ring0.KernelCodeSegment, ring0.Kcode)
	kernelSystemRegs.DS.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.ES.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.SS.Load(&ring0.KernelDataSegment, ring0.Kdata)
	kernelSystemRegs.FS.Load(&ring0.UserDataSegment, ring0.Udata)
	kernelSystemRegs.GS.Load(&ring0.UserDataSegment, ring0.Udata)
	tssBase, tssLimit, tss := c.TSS()
	kernelSystemRegs.TR.Load(tss, ring0.Tss)
	kernelSystemRegs.TR.base = tssBase
	kernelSystemRegs.TR.limit = uint32(tssLimit)

	// Point to kernel page tables, with no initial PCID.
	kernelSystemRegs.CR3 = c.machine.kernel.PageTables.CR3(false, 0)

	// Initialize the PCID database.
	if hasGuestPCID {
		// Note that NewPCIDs may return a nil table here, in which
		// case we simply don't use PCID support (see below). In
		// practice, this should not happen, however.
		c.PCIDs = pagetables.NewPCIDs(fixedKernelPCID+1, poolPCIDs)
	}

	// Set the CPUID; this is required before setting system registers,
	// since KVM will reject several CR4 bits if the CPUID does not
	// indicate the support is available.
	if err := c.setCPUID(); err != nil {
		return err
	}

	// Set the entrypoint for the kernel.
	kernelUserRegs.RIP = uint64(reflect.ValueOf(ring0.Start).Pointer())
	kernelUserRegs.RAX = uint64(reflect.ValueOf(&c.CPU).Pointer())
	kernelUserRegs.RSP = c.StackTop()
	kernelUserRegs.RFLAGS = ring0.KernelFlagsSet

	// Set the system registers.
	if err := c.setSystemRegisters(&kernelSystemRegs); err != nil {
		return err
	}

	// Set the user registers.
	if errno := c.setUserRegisters(&kernelUserRegs); errno != 0 {
		return fmt.Errorf("error setting user registers: %v", errno)
	}

	// Allocate some floating point state save area for the local vCPU.
	// This will be saved prior to leaving the guest, and we restore from
	// this always. We cannot use the pointer in the context alone because
	// we don't know how large the area there is in reality.
	c.floatingPointState = fpu.NewState()

	// Set the time offset to the host native time.
	return c.setSystemTime()
}

// bitsForScaling returns the bits available for storing the fraction component
// of the TSC scaling ratio. This allows us to replicate the (bad) math done by
// the kernel below in scaledTSC, and ensure we can compute an exact zero
// offset in setSystemTime.
//
// These constants correspond to kvm_tsc_scaling_ratio_frac_bits.
var bitsForScaling = func() int64 {
	fs := cpuid.HostFeatureSet()
	if fs.Intel() {
		return 48 // See vmx.c (kvm sources).
	} else if fs.AMD() {
		return 32 // See svm.c (svm sources).
	} else {
		return 63 // Unknown: theoretical maximum.
	}
}()

// scaledTSC returns the host TSC scaled by the given frequency.
//
// This assumes a current frequency of 1. We require only the unitless ratio of
// rawFreq to some current frequency. See setSystemTime for context.
//
// The kernel math guarantees that all bits of the multiplication and division
// will be correctly preserved and applied. However, it is not possible to
// actually store the ratio correctly.  So we need to use the same schema in
// order to calculate the scaled frequency and get the same result.
//
// We can assume that the current frequency is (1), so we are calculating a
// strict inverse of this value. This simplifies this function considerably.
//
// Roughly, the returned value "scaledTSC" will have:
// 	scaledTSC/hostTSC == 1/rawFreq
//
//go:nosplit
func scaledTSC(rawFreq uintptr) int64 {
	scale := int64(1 << bitsForScaling)
	ratio := big.NewInt(scale / int64(rawFreq))
	ratio.Mul(ratio, big.NewInt(int64(ktime.Rdtsc())))
	ratio.Div(ratio, big.NewInt(scale))
	return ratio.Int64()
}

// setSystemTime sets the vCPU to the system time.
func (c *vCPU) setSystemTime() error {
	// First, scale down the clock frequency to the lowest value allowed by
	// the API itself.  How low we can go depends on the underlying
	// hardware, but it is typically ~1/2^48 for Intel, ~1/2^32 for AMD.
	// Even the lower bound here will take a 4GHz frequency down to 1Hz,
	// meaning that everything should be able to handle a Khz setting of 1
	// with bits to spare.
	//
	// Note that reducing the clock does not typically require special
	// capabilities as it is emulated in KVM. We don't actually use this
	// capability, but it means that this method should be robust to
	// different hardware configurations.

	// if tsc scaling is not supported, fallback to legacy mode
	if !c.machine.tscControl {
		return c.setSystemTimeLegacy()
	}
	rawFreq, err := c.getTSCFreq()
	if err != nil {
		return c.setSystemTimeLegacy()
	}
	if err := c.setTSCFreq(1); err != nil {
		return c.setSystemTimeLegacy()
	}

	// Always restore the original frequency.
	defer func() {
		if err := c.setTSCFreq(rawFreq); err != nil {
			panic(err.Error())
		}
	}()

	// Attempt to set the system time in this compressed world. The
	// calculation for offset normally looks like:
	//
	//	offset = target_tsc - kvm_scale_tsc(vcpu, rdtsc());
	//
	// So as long as the kvm_scale_tsc component is constant before and
	// after the call to set the TSC value (and it is passes as the
	// target_tsc), we will compute an offset value of zero.
	//
	// This is effectively cheating to make our "setSystemTime" call so
	// unbelievably, incredibly fast that we do it "instantly" and all the
	// calculations result in an offset of zero.
	lastTSC := scaledTSC(rawFreq)
	for {
		if err := c.setTSC(uint64(lastTSC)); err != nil {
			return err
		}
		nextTSC := scaledTSC(rawFreq)
		if lastTSC == nextTSC {
			return nil
		}
		lastTSC = nextTSC // Try again.
	}
}

// nonCanonical generates a canonical address return.
//
//go:nosplit
func nonCanonical(addr uint64, signal int32, info *arch.SignalInfo) (hostarch.AccessType, error) {
	*info = arch.SignalInfo{
		Signo: signal,
		Code:  arch.SignalInfoKernel,
	}
	info.SetAddr(addr) // Include address.
	return hostarch.NoAccess, platform.ErrContextSignal
}

// fault generates an appropriate fault return.
//
//go:nosplit
func (c *vCPU) fault(signal int32, info *arch.SignalInfo) (hostarch.AccessType, error) {
	bluepill(c) // Probably no-op, but may not be.
	faultAddr := ring0.ReadCR2()
	code, user := c.ErrorCode()
	if !user {
		// The last fault serviced by this CPU was not a user
		// fault, so we can't reliably trust the faultAddr or
		// the code provided here. We need to re-execute.
		return hostarch.NoAccess, platform.ErrContextInterrupt
	}
	// Reset the pointed SignalInfo.
	*info = arch.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))
	accessType := hostarch.AccessType{
		Read:    code&(1<<1) == 0,
		Write:   code&(1<<1) != 0,
		Execute: code&(1<<4) != 0,
	}
	if !accessType.Write && !accessType.Execute {
		info.Code = 1 // SEGV_MAPERR.
	} else {
		info.Code = 2 // SEGV_ACCERR.
	}
	return accessType, platform.ErrContextSignal
}

//go:nosplit
//go:noinline
func loadByte(ptr *byte) byte {
	return *ptr
}

// prefaultFloatingPointState touches each page of the floating point state to
// be sure that its physical pages are mapped.
//
// Otherwise the kernel can trigger KVM_EXIT_MMIO and an instruction that
// triggered a fault will be emulated by the kvm kernel code, but it can't
// emulate instructions like xsave and xrstor.
//
//go:nosplit
func prefaultFloatingPointState(data *fpu.State) {
	size := len(*data)
	for i := 0; i < size; i += hostarch.PageSize {
		loadByte(&(*data)[i])
	}
	loadByte(&(*data)[size-1])
}

//go:nosplit
func (c *vCPU) switchToUser(switchOpts *ring0.SwitchOpts) ring0.Vector {
	var vector ring0.Vector

	// Past this point, stack growth can cause system calls (and a break
	// from guest mode). So we need to ensure that between the bluepill
	// call here and the switch call immediately below, no additional
	// allocations occur.
	entersyscall()
	bluepill(c)
	// The root table physical page has to be mapped to not fault in iret
	// or sysret after switching into a user address space.  sysret and
	// iret are in the upper half that is global and already mapped.
	switchOpts.PageTables.PrefaultRootTable()
	prefaultFloatingPointState(switchOpts.FloatingPointState)
	vector = c.CPU.SwitchToUser(switchOpts)
	exitsyscall()

	return vector
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(switchOpts *ring0.SwitchOpts, info *arch.SignalInfo) (hostarch.AccessType, error) {
	// Check for canonical addresses.
	if regs := switchOpts.Registers; !ring0.IsCanonical(regs.Rip) {
		return nonCanonical(regs.Rip, int32(unix.SIGSEGV), info)
	} else if !ring0.IsCanonical(regs.Rsp) {
		return nonCanonical(regs.Rsp, int32(unix.SIGBUS), info)
	} else if !ring0.IsCanonical(regs.Fs_base) {
		return nonCanonical(regs.Fs_base, int32(unix.SIGBUS), info)
	} else if !ring0.IsCanonical(regs.Gs_base) {
		return nonCanonical(regs.Gs_base, int32(unix.SIGBUS), info)
	}

	// Assign PCIDs.
	if c.PCIDs != nil {
		var requireFlushPCID bool // Force a flush?
		switchOpts.UserPCID, requireFlushPCID = c.PCIDs.Assign(switchOpts.PageTables)
		switchOpts.KernelPCID = fixedKernelPCID
		switchOpts.Flush = switchOpts.Flush || requireFlushPCID
	}

	vector := c.switchToUser(switchOpts)

	switch vector {
	case ring0.Syscall, ring0.SyscallInt80:
		// Fast path: system call executed.
		return hostarch.NoAccess, nil

	case ring0.PageFault:
		return c.fault(int32(unix.SIGSEGV), info)

	case ring0.Debug, ring0.Breakpoint:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGTRAP),
			Code:  1, // TRAP_BRKPT (breakpoint).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.GeneralProtectionFault,
		ring0.SegmentNotPresent,
		ring0.BoundRangeExceeded,
		ring0.InvalidTSS,
		ring0.StackSegmentFault:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGSEGV),
			Code:  arch.SignalInfoKernel,
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		if vector == ring0.GeneralProtectionFault {
			// When CPUID faulting is enabled, we will generate a #GP(0) when
			// userspace executes a CPUID instruction. This is handled above,
			// because we need to be able to map and read user memory.
			return hostarch.AccessType{}, platform.ErrContextSignalCPUID
		}
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.InvalidOpcode:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGILL),
			Code:  1, // ILL_ILLOPC (illegal opcode).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.DivideByZero:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  1, // FPE_INTDIV (divide by zero).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Overflow:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  2, // FPE_INTOVF (integer overflow).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.X87FloatingPointException,
		ring0.SIMDFloatingPointException:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  7, // FPE_FLTINV (invalid operation).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Vector(bounce): // ring0.VirtualizationException
		return hostarch.NoAccess, platform.ErrContextInterrupt

	case ring0.AlignmentCheck:
		*info = arch.SignalInfo{
			Signo: int32(unix.SIGBUS),
			Code:  2, // BUS_ADRERR (physical address does not exist).
		}
		return hostarch.NoAccess, platform.ErrContextSignal

	case ring0.NMI:
		// An NMI is generated only when a fault is not servicable by
		// KVM itself, so we think some mapping is writeable but it's
		// really not. This could happen, e.g. if some file is
		// truncated (and would generate a SIGBUS) and we map it
		// directly into the instance.
		return c.fault(int32(unix.SIGBUS), info)

	case ring0.DeviceNotAvailable,
		ring0.DoubleFault,
		ring0.CoprocessorSegmentOverrun,
		ring0.MachineCheck,
		ring0.SecurityException:
		fallthrough
	default:
		panic(fmt.Sprintf("unexpected vector: 0x%x", vector))
	}
}

// On x86 platform, the flags for "setMemoryRegion" can always be set as 0.
// There is no need to return read-only physicalRegions.
func rdonlyRegionsForSetMem() (phyRegions []physicalRegion) {
	return nil
}

func availableRegionsForSetMem() (phyRegions []physicalRegion) {
	return physicalRegions
}

func (m *machine) mapUpperHalf(pageTable *pagetables.PageTables) {
	// Map all the executible regions so that all the entry functions
	// are mapped in the upper half.
	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) || vr.filename == "[vsyscall]" {
			return
		}

		if vr.accessType.Execute {
			r := vr.region
			physical, length, ok := translateToPhysical(r.virtual)
			if !ok || length < r.length {
				panic("impossible translation")
			}
			pageTable.Map(
				hostarch.Addr(ring0.KernelStartAddress|r.virtual),
				r.length,
				pagetables.MapOpts{AccessType: hostarch.Execute},
				physical)
		}
	})
	for start, end := range m.kernel.EntryRegions() {
		regionLen := end - start
		physical, length, ok := translateToPhysical(start)
		if !ok || length < regionLen {
			panic("impossible translation")
		}
		pageTable.Map(
			hostarch.Addr(ring0.KernelStartAddress|start),
			regionLen,
			pagetables.MapOpts{AccessType: hostarch.ReadWrite},
			physical)
	}
}
