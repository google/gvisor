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

package kvm

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
)

type kvmVcpuInit struct {
	target   uint32
	features [7]uint32
}

var vcpuInit kvmVcpuInit

// initArchState initializes architecture-specific state.
func (m *machine) initArchState() error {
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_ARM_PREFERRED_TARGET,
		uintptr(unsafe.Pointer(&vcpuInit))); errno != 0 {
		panic(fmt.Sprintf("error setting KVM_ARM_PREFERRED_TARGET failed: %v", errno))
	}

	// Initialize all vCPUs on ARM64, while this does not happen on x86_64.
	// The reason for the difference is that ARM64 and x86_64 have different KVM timer mechanisms.
	// If we create vCPU dynamically on ARM64, the timer for vCPU would mess up for a short time.
	// For more detail, please refer to https://github.com/google/gvisor/issues/5739
	m.initialvCPUs = make(map[int]*vCPU)
	m.mu.Lock()
	for int(m.nextID) < m.maxVCPUs-1 {
		c := m.newVCPU()
		c.state = 0
		m.initialvCPUs[c.id] = c
	}
	m.mu.Unlock()
	return nil
}

// initArchState initializes architecture-specific state.
func (c *vCPU) initArchState() error {
	var (
		reg     kvmOneReg
		data    uint64
		regGet  kvmOneReg
		dataGet uint64
	)

	reg.addr = uint64(reflect.ValueOf(&data).Pointer())
	regGet.addr = uint64(reflect.ValueOf(&dataGet).Pointer())

	vcpuInit.features[0] |= (1 << _KVM_ARM_VCPU_PSCI_0_2)
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_ARM_VCPU_INIT,
		uintptr(unsafe.Pointer(&vcpuInit))); errno != 0 {
		panic(fmt.Sprintf("error setting KVM_ARM_VCPU_INIT failed: %v", errno))
	}

	// tcr_el1
	data = _TCR_TXSZ_VA48 | _TCR_CACHE_FLAGS | _TCR_SHARED | _TCR_TG_FLAGS | _TCR_ASID16 | _TCR_IPS_40BITS
	reg.id = _KVM_ARM64_REGS_TCR_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// mair_el1
	data = _MT_EL1_INIT
	reg.id = _KVM_ARM64_REGS_MAIR_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// ttbr0_el1
	data = c.machine.kernel.PageTables.TTBR0_EL1(false, 0)

	reg.id = _KVM_ARM64_REGS_TTBR0_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	c.SetTtbr0Kvm(uintptr(data))

	// ttbr1_el1
	data = c.machine.kernel.PageTables.TTBR1_EL1(false, 0)

	reg.id = _KVM_ARM64_REGS_TTBR1_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// sp_el1
	data = c.CPU.StackTop()
	reg.id = _KVM_ARM64_REGS_SP_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// pc
	reg.id = _KVM_ARM64_REGS_PC
	data = uint64(reflect.ValueOf(ring0.Start).Pointer())
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// r8
	reg.id = _KVM_ARM64_REGS_R8
	data = uint64(reflect.ValueOf(&c.CPU).Pointer())
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// vbar_el1
	reg.id = _KVM_ARM64_REGS_VBAR_EL1

	fromLocation := reflect.ValueOf(ring0.Vectors).Pointer()
	offset := fromLocation & (1<<11 - 1)
	if offset != 0 {
		offset = 1<<11 - offset
	}

	toLocation := fromLocation + offset
	data = uint64(ring0.KernelStartAddress | toLocation)
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// Use the address of the exception vector table as
	// the MMIO address base.
	arm64HypercallMMIOBase = toLocation

	// Initialize the PCID database.
	if hasGuestPCID {
		// Note that NewPCIDs may return a nil table here, in which
		// case we simply don't use PCID support (see below). In
		// practice, this should not happen, however.
		c.PCIDs = pagetables.NewPCIDs(fixedKernelPCID+1, poolPCIDs)
	}

	c.floatingPointState = fpu.NewState()

	return c.setSystemTime()
}

// setTSC sets the counter Virtual Offset.
func (c *vCPU) setTSC(value uint64) error {
	var (
		reg  kvmOneReg
		data uint64
	)

	reg.addr = uint64(reflect.ValueOf(&data).Pointer())
	reg.id = _KVM_ARM64_REGS_TIMER_CNT
	data = uint64(value)

	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	return nil
}

// getTSC gets the counter Physical Counter minus Virtual Offset.
func (c *vCPU) getTSC() error {
	var (
		reg  kvmOneReg
		data uint64
	)

	reg.addr = uint64(reflect.ValueOf(&data).Pointer())
	reg.id = _KVM_ARM64_REGS_TIMER_CNT

	if err := c.getOneRegister(&reg); err != nil {
		return err
	}

	return nil
}

// setSystemTime sets the vCPU to the system time.
func (c *vCPU) setSystemTime() error {
	const minIterations = 10
	minimum := uint64(0)
	for iter := 0; ; iter++ {
		// Use get the TSC to an estimate of where it will be
		// on the host during a "fast" system call iteration.
		// replace getTSC to another setOneRegister syscall can get more accurate value?
		start := uint64(ktime.Rdtsc())
		if err := c.getTSC(); err != nil {
			return err
		}
		// See if this is our new minimum call time. Note that this
		// serves two functions: one, we make sure that we are
		// accurately predicting the offset we need to set. Second, we
		// don't want to do the final set on a slow call, which could
		// produce a really bad result.
		end := uint64(ktime.Rdtsc())
		if end < start {
			continue // Totally bogus: unstable TSC?
		}
		current := end - start
		if current < minimum || iter == 0 {
			minimum = current // Set our new minimum.
		}
		// Is this past minIterations and within ~10% of minimum?
		upperThreshold := (((minimum << 3) + minimum) >> 3)
		if iter >= minIterations && (current <= upperThreshold || minimum < 50) {
			// Try to set the TSC
			if err := c.setTSC(end + (minimum / 2)); err != nil {
				return err
			}
			return nil
		}
	}
}

//go:nosplit
func (c *vCPU) loadSegments(tid uint64) {
	// TODO(gvisor.dev/issue/1238):  TLS is not supported.
	// Get TLS from tpidr_el0.
	atomic.StoreUint64(&c.tid, tid)
}

func (c *vCPU) setOneRegister(reg *kvmOneReg) error {
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_ONE_REG,
		uintptr(unsafe.Pointer(reg))); errno != 0 {
		return fmt.Errorf("error setting one register: %v", errno)
	}
	return nil
}

func (c *vCPU) getOneRegister(reg *kvmOneReg) error {
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_GET_ONE_REG,
		uintptr(unsafe.Pointer(reg))); errno != 0 {
		return fmt.Errorf("error getting one register: %v", errno)
	}
	return nil
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(switchOpts ring0.SwitchOpts, info *linux.SignalInfo) (hostarch.AccessType, error) {
	// Check for canonical addresses.
	if regs := switchOpts.Registers; !ring0.IsCanonical(regs.Pc) {
		return nonCanonical(regs.Pc, int32(unix.SIGSEGV), info)
	} else if !ring0.IsCanonical(regs.Sp) {
		return nonCanonical(regs.Sp, int32(unix.SIGSEGV), info)
	}

	// Assign PCIDs.
	if c.PCIDs != nil {
		var requireFlushPCID bool // Force a flush?
		switchOpts.UserASID, requireFlushPCID = c.PCIDs.Assign(switchOpts.PageTables)
		switchOpts.Flush = switchOpts.Flush || requireFlushPCID
	}

	var vector ring0.Vector
	ttbr0App := switchOpts.PageTables.TTBR0_EL1(false, 0)
	c.SetTtbr0App(uintptr(ttbr0App))

	// Full context-switch supporting for Arm64.
	// The Arm64 user-mode execution state consists of:
	// x0-x30
	// PC, SP, PSTATE
	// V0-V31: 32 128-bit registers for floating point, and simd
	// FPSR, FPCR
	// TPIDR_EL0, used for TLS
	appRegs := switchOpts.Registers
	c.SetAppAddr(ring0.KernelStartAddress | uintptr(unsafe.Pointer(appRegs)))

	entersyscall()
	bluepill(c)
	vector = c.CPU.SwitchToUser(switchOpts)
	exitsyscall()

	switch vector {
	case ring0.Syscall:
		// Fast path: system call executed.
		return hostarch.NoAccess, nil
	case ring0.PageFault:
		return c.fault(int32(unix.SIGSEGV), info)
	case ring0.El0ErrNMI:
		return c.fault(int32(unix.SIGBUS), info)
	case ring0.Vector(bounce): // ring0.VirtualizationException.
		return hostarch.NoAccess, platform.ErrContextInterrupt
	case ring0.El0SyncUndef:
		return c.fault(int32(unix.SIGILL), info)
	case ring0.El0SyncDbg:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGTRAP),
			Code:  1, // TRAP_BRKPT (breakpoint).
		}
		info.SetAddr(switchOpts.Registers.Pc) // Include address.
		return hostarch.AccessType{}, platform.ErrContextSignal
	case ring0.El0SyncSpPc:
		*info = linux.SignalInfo{
			Signo: int32(unix.SIGBUS),
			Code:  2, // BUS_ADRERR (physical address does not exist).
		}
		return hostarch.NoAccess, platform.ErrContextSignal
	case ring0.El0SyncSys,
		ring0.El0SyncWfx:
		return hostarch.NoAccess, nil // skip for now.
	default:
		panic(fmt.Sprintf("unexpected vector: 0x%x", vector))
	}

}
