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

//go:build arm64
// +build arm64

package ring0

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

var (
	// UserspaceSize is the total size of userspace.
	UserspaceSize = uintptr(1) << (VirtualAddressBits())

	// MaximumUserAddress is the largest possible user address.
	MaximumUserAddress = (UserspaceSize - 1) & ^uintptr(hostarch.PageSize-1)

	// KernelStartAddress is the starting kernel address.
	KernelStartAddress = ^uintptr(0) - (UserspaceSize - 1)
)

// KernelArchState contains architecture-specific state.
type KernelArchState struct {
}

// CPUArchState contains CPU-specific arch state.
type CPUArchState struct {
	// stack is the stack used for interrupts on this CPU.
	stack [128]byte

	// errorCode is the error code from the last exception.
	errorCode uintptr

	// errorType indicates the type of error code here, it is always set
	// along with the errorCode value above.
	//
	// It will either by 1, which indicates a user error, or 0 indicating a
	// kernel error. If the error code below returns false (kernel error),
	// then it cannot provide relevant information about the last
	// exception.
	errorType uintptr

	// faultAddr is the value of far_el1.
	faultAddr uintptr

	// el0Fp is the address of application's fpstate.
	el0Fp uintptr

	// ttbr0Kvm is the value of ttbr0_el1 for sentry.
	ttbr0Kvm uintptr

	// ttbr0App is the value of ttbr0_el1 for applicaton.
	ttbr0App uintptr

	// exception vector.
	vecCode Vector

	// application context pointer.
	appAddr uintptr

	// lazyVFP is the value of cpacr_el1.
	lazyVFP uintptr

	// appASID is the asid value of guest application.
	appASID uintptr
}

// ErrorCode returns the last error code.
//
// The returned boolean indicates whether the error code corresponds to the
// last user error or not. If it does not, then fault information must be
// ignored. This is generally the result of a kernel fault while servicing a
// user fault.
//
//go:nosplit
func (c *CPU) ErrorCode() (value uintptr, user bool) {
	return c.errorCode, c.errorType != 0
}

// ClearErrorCode resets the error code.
//
//go:nosplit
func (c *CPU) ClearErrorCode() {
	c.errorCode = 0 // No code.
	c.errorType = 1 // User mode.
}

//go:nosplit
func (c *CPU) GetFaultAddr() (value uintptr) {
	return c.faultAddr
}

//go:nosplit
func (c *CPU) SetTtbr0Kvm(value uintptr) {
	c.ttbr0Kvm = value
}

//go:nosplit
func (c *CPU) SetTtbr0App(value uintptr) {
	c.ttbr0App = value
}

//go:nosplit
func (c *CPU) GetVector() (value Vector) {
	return c.vecCode
}

//go:nosplit
func (c *CPU) SetAppAddr(value uintptr) {
	c.appAddr = value
}

// GetLazyVFP returns the value of cpacr_el1.
//go:nosplit
func (c *CPU) GetLazyVFP() (value uintptr) {
	return c.lazyVFP
}

// SwitchArchOpts are embedded in SwitchOpts.
type SwitchArchOpts struct {
	// UserASID indicates that the application ASID to be used on switch,
	UserASID uint16

	// KernelASID indicates that the kernel ASID to be used on return,
	KernelASID uint16
}

func init() {
}
