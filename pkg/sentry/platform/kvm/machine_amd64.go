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

package kvm

import (
	"fmt"
	"math/big"
	"reflect"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sync"
)

// initArchState initializes architecture-specific state.
func (m *machine) initArchState() error {
	// Set the legacy TSS address. This address is covered by the reserved
	// range (up to 4GB). In fact, this is a main reason it exists.
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(m.fd),
		KVM_SET_TSS_ADDR,
		uintptr(reservedMemory-(3*hostarch.PageSize))); errno != 0 {
		return errno
	}

	// Initialize all vCPUs to minimize kvm ioctl-s allowed by seccomp filters.
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < m.maxVCPUs; i++ {
		if _, err := m.createVCPU(i); err != nil {
			return err
		}
	}

	return nil
}

type vCPUArchState struct {
	// PCIDs is the set of PCIDs for this vCPU.
	//
	// This starts above fixedKernelPCID.
	PCIDs *pagetables.PCIDs

	// signalStack is the signal stack of the last thread bound to this vCPU.
	signalStack linux.SignalStack
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

var cpuidFaultingWarnOnce sync.Once

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

	// Set up the PAT as required by ring0/pagetables.
	if err := c.setPAT(); err != nil {
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
	if errno := c.setUserRegisters(&kernelUserRegs); errno != 0 {
		return fmt.Errorf("error setting user registers: %v", errno)
	}

	// Set the time offset to the host native time.
	if err := c.setSystemTime(); err != nil {
		return err
	}

	// Try to enable CPUID faulting. This is required to handle app CPUID
	// correctly, since we always pass the CPUID returned by
	// KVM_GET_SUPPORTED_CPUID to KVM_SET_CPUID2. Note that while hardware
	// support for CPUID faulting is inconsistent, KVM always supports it after
	// db2336a80489e ("KVM: x86: virtualize cpuid faulting"), Linux 4.12+.
	if err := c.enableCPUIDFaulting(); err != nil {
		cpuidFaultingWarnOnce.Do(func() {
			log.Warningf("Application CPUID will be incorrect: %v", err)
		})
	}

	return nil
}

// bitsForScaling returns the bits available for storing the fraction component
// of the TSC scaling ratio.
// It is set using getBitsForScaling when the KVM platform is initialized.
var bitsForScaling int64

// getBitsForScaling returns the bits available for storing the fraction component
// of the TSC scaling ratio. This allows us to replicate the (bad) math done by
// the kernel below in scaledTSC, and ensure we can compute an exact zero
// offset in setSystemTime.
//
// These constants correspond to kvm_tsc_scaling_ratio_frac_bits.
func getBitsForScaling() int64 {
	fs := cpuid.HostFeatureSet()
	if fs.Intel() {
		return 48 // See vmx.c (kvm sources).
	} else if fs.AMD() {
		return 32 // See svm.c (svm sources).
	} else {
		return 63 // Unknown: theoretical maximum.
	}
}

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
// scaledTSC/hostTSC == 1/rawFreq
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
	// Attempt to set the offset directly. This is supported as of Linux 5.16,
	// or commit 828ca89628bfcb1b8f27535025f69dd00eb55207.
	if err := c.setTSCOffset(); err == nil {
		return err
	}

	// If tsc scaling is not supported, fallback to legacy mode.
	if !c.machine.tscControl {
		return c.setSystemTimeLegacy()
	}

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

//go:nosplit
//go:noinline
func loadByte(ptr *byte) byte {
	return *ptr
}

func rdDR6() uint64
func wrDR6(val uint64)

const (
	// _DR6_RESERVED is a set of reserved bits in DR6 which are always set to 1
	_DR6_RESERVED = uint64(0xFFFF0FF0)

	_DR_TRAP0 = 0x1    // DR0
	_DR_TRAP1 = 0x2    // DR1
	_DR_TRAP2 = 0x4    // DR2
	_DR_TRAP3 = 0x8    // DR3
	_DR_STEP  = 0x4000 // single-step
)

//go:nosplit
func readAndResetDR6() uint64 {
	dr6 := rdDR6()
	wrDR6(_DR6_RESERVED)
	dr6 ^= _DR6_RESERVED
	return dr6
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(switchOpts ring0.SwitchOpts, info *linux.SignalInfo) (hostarch.AccessType, error) {
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

	// See below.
	var vector ring0.Vector

	// Past this point, stack growth can cause system calls (and a break
	// from guest mode). So we need to ensure that between the bluepill
	// call here and the switch call immediately below, no additional
	// allocations occur.
	entersyscall()
	bluepill(c)
	vector = c.CPU.SwitchToUser(switchOpts)
	exitsyscall()

	switch vector {
	case ring0.Syscall, ring0.SyscallInt80:
		// Fast path: system call executed.
		return hostarch.NoAccess, nil

	case ring0.PageFault:
		return c.fault(int32(unix.SIGSEGV), info)

	case ring0.Debug:
		bluepill(c)
		dr6 := readAndResetDR6()
		code := int32(linux.TRAP_BRKPT)
		if dr6&_DR_STEP != 0 {
			code = linux.TRAP_TRACE
		} else if dr6&(_DR_TRAP0|_DR_TRAP1|_DR_TRAP2|_DR_TRAP3) != 0 {
			code = linux.TRAP_HWBKPT
		}
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGTRAP),
			Code:  code,
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Breakpoint:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGTRAP),
			Code:  linux.SI_KERNEL,
		}
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.GeneralProtectionFault,
		ring0.SegmentNotPresent,
		ring0.BoundRangeExceeded,
		ring0.InvalidTSS,
		ring0.StackSegmentFault:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGSEGV),
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
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGILL),
			Code:  1, // ILL_ILLOPC (illegal opcode).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.DivideByZero:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  1, // FPE_INTDIV (divide by zero).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Overflow:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  2, // FPE_INTOVF (integer overflow).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.X87FloatingPointException,
		ring0.SIMDFloatingPointException:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGFPE),
			Code:  7, // FPE_FLTINV (invalid operation).
		}
		info.SetAddr(switchOpts.Registers.Rip) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal

	case ring0.Vector(bounce): // ring0.VirtualizationException
		return hostarch.NoAccess, platform.ErrContextInterrupt

	case ring0.AlignmentCheck:
		*info = linux.SignalInfo{
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

func (m *machine) mapUpperHalfRegion(
	pageTable *pagetables.PageTables,
	virtual uintptr, length uintptr,
	opts pagetables.MapOpts,
) {
	for length != 0 {
		physical, plength, ok := translateToPhysical(virtual)
		if !ok || plength == 0 {
			panic(fmt.Sprintf("impossible translation: virtual %x length %x", virtual, length))
		}
		if plength > length {
			plength = length
		}

		pageTable.Map(
			hostarch.Addr(ring0.KernelStartAddress|virtual),
			plength,
			opts,
			physical)

		length -= plength
		virtual += plength
	}
}

func (m *machine) mapUpperHalf(pageTable *pagetables.PageTables) {
	// Map all the executable regions so that all the entry functions
	// are mapped in the upper half.
	if err := applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) || vr.filename == "[vsyscall]" {
			return
		}

		if vr.accessType.Execute {
			r := vr.region
			m.mapUpperHalfRegion(pageTable, r.virtual, r.length,
				pagetables.MapOpts{AccessType: hostarch.Execute, Global: true})
		}
	}); err != nil {
		panic(fmt.Sprintf("error parsing /proc/self/maps: %v", err))
	}
	for start, end := range m.kernel.EntryRegions() {
		regionLen := end - start
		m.mapUpperHalfRegion(pageTable, start, regionLen,
			pagetables.MapOpts{AccessType: hostarch.ReadWrite, Global: true})
	}
}

// getMaxVCPU get max vCPU number
func (m *machine) getMaxVCPU() {
	maxVCPUs, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), KVM_CHECK_EXTENSION, _KVM_CAP_MAX_VCPUS)
	if errno != 0 {
		maxVCPUs = _KVM_NR_VCPUS
	}
	m.maxVCPUs = int(maxVCPUs)

	// The goal here is to avoid vCPU contentions for reasonable workloads.
	// But "reasonable" isn't defined well in this case. Let's say that CPU
	// overcommit with factor 2 is still acceptable. We allocate a set of
	// vCPU for each goruntime processor (P) and two sets of vCPUs to run
	// user code.
	rCPUs := runtime.GOMAXPROCS(0)
	if 3*rCPUs < m.maxVCPUs {
		m.maxVCPUs = 3 * rCPUs
	}
	// However if the sentry is explicitly configured to run more application
	// cores then we should try our best to give each application thread
	// its own vCPU, with some room to spare (like above, factor of 2).
	desiredAppCores := m.applicationCores * 2
	if m.maxVCPUs < desiredAppCores {
		if int(maxVCPUs) < desiredAppCores {
			log.Warningf("ApplicationCores is set too high: set to %d, max on this machine is %d. Your workload may experience unexpected timeouts.", desiredAppCores, maxVCPUs)
			m.maxVCPUs = int(maxVCPUs)
		} else {
			m.maxVCPUs = desiredAppCores
		}
	}
}

func archPhysicalRegions(physicalRegions []physicalRegion) []physicalRegion {
	return physicalRegions
}
