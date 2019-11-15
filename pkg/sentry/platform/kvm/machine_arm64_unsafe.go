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
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// setMemoryRegion initializes a region.
//
// This may be called from bluepillHandler, and therefore returns an errno
// directly (instead of wrapping in an error) to avoid allocations.
//
//go:nosplit
func (m *machine) setMemoryRegion(slot int, physical, length, virtual uintptr) syscall.Errno {
	userRegion := userMemoryRegion{
		slot:          uint32(slot),
		flags:         0,
		guestPhysAddr: uint64(physical),
		memorySize:    uint64(length),
		userspaceAddr: uint64(virtual),
	}

	// Set the region.
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_SET_USER_MEMORY_REGION,
		uintptr(unsafe.Pointer(&userRegion)))
	return errno
}

type kvmVcpuInit struct {
	target   uint32
	features [7]uint32
}

var vcpuInit kvmVcpuInit

// initArchState initializes architecture-specific state.
func (m *machine) initArchState() error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_ARM_PREFERRED_TARGET,
		uintptr(unsafe.Pointer(&vcpuInit))); errno != 0 {
		panic(fmt.Sprintf("error setting KVM_ARM_PREFERRED_TARGET failed: %v", errno))
	}
	return nil
}

func getPageWithReflect(p uintptr) []byte {
	return (*(*[0xFFFFFF]byte)(unsafe.Pointer(p & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
}

// Work around: move ring0.Vectors() into a specific address with 11-bits alignment.
//
// According to the design documentation of Arm64,
// the start address of exception vector table should be 11-bits aligned.
// Please see the code in linux kernel as reference: arch/arm64/kernel/entry.S
// But, we can't align a function's start address to a specific address by using golang.
// We have raised this question in golang community:
// https://groups.google.com/forum/m/#!topic/golang-dev/RPj90l5x86I
// This function will be removed when golang supports this feature.
//
// There are 2 jobs were implemented in this function:
// 1, move the start address of exception vector table into the specific address.
// 2, modify the offset of each instruction.
func updateVectorTable() {
	fromLocation := reflect.ValueOf(ring0.Vectors).Pointer()
	offset := fromLocation & (1<<11 - 1)
	if offset != 0 {
		offset = 1<<11 - offset
	}

	toLocation := fromLocation + offset
	page := getPageWithReflect(toLocation)
	if err := syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC); err != nil {
		panic(err)
	}

	page = getPageWithReflect(toLocation + 4096)
	if err := syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC); err != nil {
		panic(err)
	}

	// Move exception-vector-table into the specific address.
	var entry *uint32
	var entry_from *uint32
	for i := 1; i <= 0x800; i++ {
		entry = (*uint32)(unsafe.Pointer(toLocation + 0x800 - uintptr(i)))
		entry_from = (*uint32)(unsafe.Pointer(fromLocation + 0x800 - uintptr(i)))
		*entry = *entry_from
	}

	// The offset from the address of each unconditionally branch is changed.
	// We should modify the offset of each instruction.
	nums := []uint32{0x0, 0x80, 0x100, 0x180, 0x200, 0x280, 0x300, 0x380, 0x400, 0x480, 0x500, 0x580, 0x600, 0x680, 0x700, 0x780}
	for _, num := range nums {
		entry = (*uint32)(unsafe.Pointer(toLocation + uintptr(num)))
		*entry = *entry - (uint32)(offset/4)
	}

	page = getPageWithReflect(toLocation)
	if err := syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		panic(err)
	}

	page = getPageWithReflect(toLocation + 4096)
	if err := syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		panic(err)
	}
}

// initArchState initializes architecture-specific state.
func (c *vCPU) initArchState() error {
	var (
		reg      kvmOneReg
		data     uint64
		reg_get  kvmOneReg
		data_get uint64
	)

	reg.addr = uint64(reflect.ValueOf(&data).Pointer())
	reg_get.addr = uint64(reflect.ValueOf(&data_get).Pointer())

	vcpuInit.features[0] |= (1 << _KVM_ARM_VCPU_PSCI_0_2)
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_ARM_VCPU_INIT,
		uintptr(unsafe.Pointer(&vcpuInit))); errno != 0 {
		panic(fmt.Sprintf("error setting KVM_ARM_VCPU_INIT failed: %v", errno))
	}

	// cpacr_el1
	reg.id = _KVM_ARM64_REGS_CPACR_EL1
	data = (_FPEN_NOTRAP << _FPEN_SHIFT)
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	// sctlr_el1
	reg_get.id = _KVM_ARM64_REGS_SCTLR_EL1
	if err := c.getOneRegister(&reg_get); err != nil {
		return err
	}

	data_get |= (_SCTLR_M | _SCTLR_C | _SCTLR_I)
	data = data_get
	reg.id = _KVM_ARM64_REGS_SCTLR_EL1
	if err := c.setOneRegister(&reg); err != nil {
		return err
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

	data = ring0.PsrDefaultSet | ring0.KernelFlagsSet
	reg.id = _KVM_ARM64_REGS_PSTATE
	if err := c.setOneRegister(&reg); err != nil {
		return err
	}

	return nil
}

//go:nosplit
func (c *vCPU) loadSegments(tid uint64) {
	// TODO(gvisor.dev/issue/1238):  TLS is not supported.
	// Get TLS from tpidr_el0.
	atomic.StoreUint64(&c.tid, tid)
}

func (c *vCPU) setOneRegister(reg *kvmOneReg) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_ONE_REG,
		uintptr(unsafe.Pointer(reg))); errno != 0 {
		return fmt.Errorf("error setting one register: %v", errno)
	}
	return nil
}

func (c *vCPU) getOneRegister(reg *kvmOneReg) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_GET_ONE_REG,
		uintptr(unsafe.Pointer(reg))); errno != 0 {
		return fmt.Errorf("error setting one register: %v", errno)
	}
	return nil
}

// setCPUID sets the CPUID to be used by the guest.
func (c *vCPU) setCPUID() error {
	return nil
}

// setSystemTime sets the TSC for the vCPU.
func (c *vCPU) setSystemTime() error {
	return nil
}

// setSignalMask sets the vCPU signal mask.
//
// This must be called prior to running the vCPU.
func (c *vCPU) setSignalMask() error {
	// The layout of this structure implies that it will not necessarily be
	// the same layout chosen by the Go compiler. It gets fudged here.
	var data struct {
		length uint32
		mask1  uint32
		mask2  uint32
		_      uint32
	}
	data.length = 8 // Fixed sigset size.
	data.mask1 = ^uint32(bounceSignalMask & 0xffffffff)
	data.mask2 = ^uint32(bounceSignalMask >> 32)
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_SIGNAL_MASK,
		uintptr(unsafe.Pointer(&data))); errno != 0 {
		return fmt.Errorf("error setting signal mask: %v", errno)
	}

	return nil
}

// SwitchToUser unpacks architectural-details.
func (c *vCPU) SwitchToUser(switchOpts ring0.SwitchOpts, info *arch.SignalInfo) (usermem.AccessType, error) {
	// Check for canonical addresses.
	if regs := switchOpts.Registers; !ring0.IsCanonical(regs.Pc) {
		return nonCanonical(regs.Pc, int32(syscall.SIGSEGV), info)
	} else if !ring0.IsCanonical(regs.Sp) {
		return nonCanonical(regs.Sp, int32(syscall.SIGBUS), info)
	}

	var vector ring0.Vector
	ttbr0_app := switchOpts.PageTables.TTBR0_EL1(false, 0)
	c.SetTtbr0App(uintptr(ttbr0_app))

	// TODO(gvisor.dev/issue/1238): full context-switch supporting for Arm64.
	// The Arm64 user-mode execution state consists of:
	// x0-x30
	// PC, SP, PSTATE
	// V0-V31: 32 128-bit registers for floating point, and simd
	// FPSR
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
		return usermem.NoAccess, nil

	case ring0.PageFault:
		return c.fault(int32(syscall.SIGSEGV), info)
	case 0xaa:
		return usermem.NoAccess, nil
	default:
		return usermem.NoAccess, platform.ErrContextSignal
	}

}
