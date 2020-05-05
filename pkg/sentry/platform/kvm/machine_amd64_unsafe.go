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
	"sync/atomic"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
)

// loadSegments copies the current segments.
//
// This may be called from within the signal context and throws on error.
//
//go:nosplit
func (c *vCPU) loadSegments(tid uint64) {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_ARCH_PRCTL,
		linux.ARCH_GET_FS,
		uintptr(unsafe.Pointer(&c.CPU.Registers().Fs_base)),
		0); errno != 0 {
		throw("getting FS segment")
	}
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_ARCH_PRCTL,
		linux.ARCH_GET_GS,
		uintptr(unsafe.Pointer(&c.CPU.Registers().Gs_base)),
		0); errno != 0 {
		throw("getting GS segment")
	}
	atomic.StoreUint64(&c.tid, tid)
}

// setCPUID sets the CPUID to be used by the guest.
func (c *vCPU) setCPUID() error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_CPUID2,
		uintptr(unsafe.Pointer(&cpuidSupported))); errno != 0 {
		return fmt.Errorf("error setting CPUID: %v", errno)
	}
	return nil
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
	const _MSR_IA32_TSC = 0x00000010
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_IA32_TSC

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
	rawFreq, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_GET_TSC_KHZ,
		0 /* ignored */)
	if errno != 0 {
		return fmt.Errorf("error getting tsc frequency: %v", errno)
	}
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_TSC_KHZ,
		1 /* khz */); errno != 0 {
		// This instance of KVM does not support TSC scaling.
		// Unfortunately, the API does not allow us to control the
		// offset directly. In order to minimize the drift from the
		// host time, we loop 5+ times, then accept the first set that
		// is within a tolerable threshold of the minimal set time.
		//
		// This will only be required on pre-Skylake machines.
		const (
			minLoopIterations = 5
			maxLoopIterations = 25
		)
		minSetTime := ^uint64(0)
		for i := 0; i < maxLoopIterations; i++ {
			// Take the halfway point for the settime.
			registers.entries[0].data = uint64(ktime.Rdtsc()) + minSetTime/2
			if _, _, errno := syscall.RawSyscall(
				syscall.SYS_IOCTL,
				uintptr(c.fd),
				_KVM_SET_MSRS,
				uintptr(unsafe.Pointer(&registers))); errno != 0 {
				return fmt.Errorf("error setting tsc: %v", errno)
			}
			// Did this set a new record?
			lastSetTime := uint64(ktime.Rdtsc()) - registers.entries[0].data
			if lastSetTime < minSetTime {
				minSetTime = lastSetTime
			}
			// Were we within 10%? Call it a day.
			if lastSetTime <= (minSetTime*11/10) && i >= minLoopIterations {
				break
			}
		}
		return nil
	}
	defer func() {
		// Always restore the original frequency.
		if _, _, errno := syscall.RawSyscall(
			syscall.SYS_IOCTL,
			uintptr(c.fd),
			_KVM_SET_TSC_KHZ,
			rawFreq); errno != 0 {
			panic(fmt.Errorf("error restoring tsc khz: %v", errno))
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
		registers.entries[0].data = uint64(lastTSC)
		if _, _, errno := syscall.RawSyscall(
			syscall.SYS_IOCTL,
			uintptr(c.fd),
			_KVM_SET_MSRS,
			uintptr(unsafe.Pointer(&registers))); errno != 0 {
			return fmt.Errorf("error setting tsc: %v", errno)
		}
		nextTSC := scaledTSC(rawFreq)
		if lastTSC == nextTSC {
			return nil
		}
		lastTSC = nextTSC // Try again.
	}
}

// setUserRegisters sets user registers in the vCPU.
func (c *vCPU) setUserRegisters(uregs *userRegs) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return fmt.Errorf("error setting user registers: %v", errno)
	}
	return nil
}

// getUserRegisters reloads user registers in the vCPU.
//
// This is safe to call from a nosplit context.
//
//go:nosplit
func (c *vCPU) getUserRegisters(uregs *userRegs) syscall.Errno {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_GET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return errno
	}
	return 0
}

// setSystemRegisters sets system registers.
func (c *vCPU) setSystemRegisters(sregs *systemRegs) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_SREGS,
		uintptr(unsafe.Pointer(sregs))); errno != 0 {
		return fmt.Errorf("error setting system registers: %v", errno)
	}
	return nil
}
