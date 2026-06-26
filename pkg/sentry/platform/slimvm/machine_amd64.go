// Copyright 2026 The gVisor Authors.
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

package slimvm

import (
	"fmt"
	"reflect"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// initArchState initializes architecture-specific state.
func (m *machine) initArchState() error {
	// Set the legacy TSS address. This address is covered by the reserved
	// range (up to 4GB). In fact, this is a main reason it exists.
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		slimvmFD,
		_SLIMVM_SET_TSS_ADDR,
		uintptr(reservedMemory-(3*hostarch.PageSize))); errno != 0 {
		return errno
	}

	return nil
}

type vCPUArchState struct {
	// floatingPointState is the floating point state buffer used in guest
	// to host transitions. See usage in bluepill_amd64.go.
	floatingPointState fpu.State
}

// dropPageTables drops cached page table entries.
func (m *machine) dropPageTables(pcid uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear on all vCPUs.
	for _, c := range m.vCPUs {
		c.activePCIDs.clear(pcid)
	}
	dropPCID(pcid)
}

// getMaxVCPU sets m.maxVCPUs from GOMAXPROCS and the configured application
// cores, bounded by the _SLIMVM_NR_VCPUS hard cap.
func (m *machine) getMaxVCPU() {
	// Allow a CPU overcommit factor of ~3, but give explicitly-configured
	// application cores their own vCPU with room to spare (factor of 2).
	n := 3 * runtime.GOMAXPROCS(0)
	if d := 2 * m.applicationCores; n < d {
		n = d
	}
	if n > _SLIMVM_NR_VCPUS {
		n = _SLIMVM_NR_VCPUS
	}
	if n < 1 {
		n = 1
	}
	m.maxVCPUs = n
}

// initArchState initializes architecture-specific state.
func (c *vCPU) initArchState() error {
	var (
		kernelSystemRegs systemRegs
		kernelUserRegs   userRegs
	)

	// AMD and compatible CPUs do not support CPUID Faulting feature.
	// cpuidFaultingEnable will set to 1 to avoid setting the cpuidFaulting
	// function in SwitchToUser.
	fs := cpuid.HostFeatureSet()
	if fs.AMD() {
		ring0.CPUVendor = ring0.CPUAMD
		c.cpuidFaultingEnable = 1
	} else {
		ring0.CPUVendor = ring0.CPUIntel
		c.cpuidFaultingEnable = 0
	}

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

	kernelSystemRegs.LDT.base = 0
	kernelSystemRegs.LDT.limit = 0
	kernelSystemRegs.LDT.selector = 0
	kernelSystemRegs.LDT.typ = 0x2
	kernelSystemRegs.LDT.present = 0x1

	// Point to kernel page tables, with no initial PCID.
	kernelSystemRegs.CR3 = c.machine.kernel.PageTables.CR3(false, 0)

	if err := c.setCPUID(); err != nil {
		return err
	}

	// Set the entrypoint for the kernel.
	kernelUserRegs.RIP = uint64(ring0.AddrOfStart())
	kernelUserRegs.RAX = uint64(reflect.ValueOf(&c.CPU).Pointer())
	kernelUserRegs.RSP = c.StackTop()
	kernelUserRegs.RFLAGS = ring0.KernelFlagsSet

	// Set the system registers.
	if err := c.setSystemRegisters(&kernelSystemRegs); err != nil {
		return err
	}

	// Set the user registers.
	if err := c.setUserRegisters(&kernelUserRegs); err != nil {
		return err
	}

	// Allocate some floating point state save area for the local vCPU.
	// This will be saved prior to leaving the guest, and we restore from
	// this always. We cannot use the pointer in the context alone because
	// we don't know how large the area there is in reality.
	c.floatingPointState = fpu.NewState()

	// Set the time offset to the host native time.
	return c.setSystemTime()
}

// nonCanonical generates a canonical address return.
//
//go:nosplit
func nonCanonical(addr uint64, signal int32, info *linux.SignalInfo) (hostarch.AccessType, error) {
	*info = linux.SignalInfo{
		Signo: signal,
		Code:  linux.SI_KERNEL,
	}
	info.SetAddr(addr) // Include address.
	return hostarch.NoAccess, platform.ErrContextSignal
}

// fault generates an appropriate fault return.
//
//go:nosplit
func (c *vCPU) fault(signal int32, info *linux.SignalInfo) (hostarch.AccessType, error) {
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
	*info = linux.SignalInfo{Signo: signal}
	info.SetAddr(uint64(faultAddr))
	accessType := hostarch.AccessType{}
	if signal == int32(unix.SIGSEGV) {
		accessType = hostarch.AccessType{
			Read:    code&(1<<1) == 0,
			Write:   code&(1<<1) != 0,
			Execute: code&(1<<4) != 0,
		}
	}
	if !accessType.Write && !accessType.Execute {
		info.Code = 1 // SEGV_MAPERR.
	} else {
		info.Code = 2 // SEGV_ACCERR.
	}
	return accessType, platform.ErrContextSignal
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(switchOpts ring0.SwitchOpts, info *linux.SignalInfo) (hostarch.AccessType, error) {
	// Check for canonical addresses.
	if regs := switchOpts.Registers; !ring0.IsCanonical(regs.Rip) {
		return nonCanonical(regs.Rip, int32(syscall.SIGSEGV), info)
	} else if !ring0.IsCanonical(regs.Rsp) {
		return nonCanonical(regs.Rsp, int32(syscall.SIGBUS), info)
	} else if !ring0.IsCanonical(regs.Fs_base) {
		return nonCanonical(regs.Fs_base, int32(syscall.SIGBUS), info)
	} else if !ring0.IsCanonical(regs.Gs_base) {
		return nonCanonical(regs.Gs_base, int32(syscall.SIGBUS), info)
	}

	localAS := c.active.get()
	if hasGuestPCID && (localAS != nil) {
		pcid := localAS.pcid
		if pcid == 0 {
			// As an optimization, we use pcidMu to protect
			// the update of localAS.pcid.
			//
			// Note that, a snapshot of localAS.pcid is needed
			// as localAS.pcid can be modified by other vCPUs
			// when it is 0.
			pcid = assignPCID(&localAS.pcid)
		}
		if pcid != 0 && !c.activePCIDs.test(pcid) {
			switchOpts.Flush = true
			c.activePCIDs.set(pcid)
		}
		switchOpts.KernelPCID = fixedKernelPCID
		switchOpts.UserPCID = pcid
	}

	// See below.
	var vector ring0.Vector

	entersyscall()
	bluepill(c)

	// The root table physical page has to be mapped to not fault in iret
	// or sysret after switching into a user address space. sysret and iret
	// are in the upper half that is global and already mapped. PTEs come
	// from the runtime allocator's Go heap (no mlock / memfile pinning),
	// so the root page can be reclaimed under memory pressure and
	// re-faulting it from inside the iret/sysret window has been observed
	// to produce vCPU bounce stalls.
	switchOpts.PageTables.PrefaultRootTable()

	// Enable CPUID Faulting featue if the CPU supported.
	if c.cpuidFaultingEnable == 0 {
		ring0.SetCPUIDFaulting(true)
		c.cpuidFaultingEnable = 1
	}

	c.PrefaultIDT()
	vector = c.CPU.SwitchToUser(switchOpts)
	exitsyscall()

	switch vector {
	case ring0.Syscall, ring0.SyscallInt80:
		// Fast path: system call executed.
		return hostarch.NoAccess, nil

	case ring0.PageFault:
		return c.fault(int32(syscall.SIGSEGV), info)

	case ring0.Debug:
		// Vector #DB. SlimVM does not currently expose DR6 to the sentry, so
		// we can't distinguish single-step from hardware breakpoints. App-level
		// PTRACE_SINGLESTEP is the only path that should hit this in practice;
		// report TRAP_TRACE so ptrace observes the expected si_code.
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGTRAP),
			Code:  2, // TRAP_TRACE
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Breakpoint:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGTRAP),
			Code:  linux.SI_KERNEL,
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.GeneralProtectionFault,
		ring0.SegmentNotPresent,
		ring0.BoundRangeExceeded,
		ring0.InvalidTSS,
		ring0.StackSegmentFault:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGSEGV),
			Code:  linux.SI_KERNEL,
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		if vector == ring0.GeneralProtectionFault {
			// When CPUID faulting is enabled, we will generate a #GP(0) when
			// userspace executes a CPUID instruction. This is handled above,
			// because we need to be able to map and read user memory.
			return hostarch.AccessType{}, tryCPUIDError{}
		}
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.InvalidOpcode:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGILL),
			Code:  1, // ILL_ILLOPC (illegal opcode).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.DivideByZero:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGFPE),
			Code:  1, // FPE_INTDIV (divide by zero).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Overflow:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGFPE),
			Code:  1, // FPE_INTOVF (integer overflow).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.X87FloatingPointException,
		ring0.SIMDFloatingPointException:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGFPE),
			Code:  7, // FPE_FLTINV (invalid operation).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Vector(bounce): // ring0.VirtualizationException
		return hostarch.NoAccess, platform.ErrContextInterrupt

	case ring0.AlignmentCheck:
		c.FullRestore = true
		*info = linux.SignalInfo{
			Signo: int32(syscall.SIGBUS),
			Code:  2, // BUS_ADRERR (physical address does not exist).
		}
		return hostarch.NoAccess, platform.ErrContextSignal

	case ring0.NMI:
		// An NMI is generated only when a fault is not servicable by
		// SlimVM itself, so we think some mapping is writeable but it's
		// really not. This could happen, e.g. if some file is
		// truncated (and would generate a SIGBUS) and we map it
		// directly into the instance.
		c.FullRestore = true
		return c.fault(int32(syscall.SIGBUS), info)

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

func (m *machine) mapUpperHalf(pageTable *pagetables.PageTables) {
	applyPhysicalRegions(func(pr physicalRegion) bool {
		pageTable.Map(
			hostarch.Addr(ring0.KernelStartAddress|pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: hostarch.AnyAccess},
			pr.physical)

		return true // Keep iterating.
	})
}
