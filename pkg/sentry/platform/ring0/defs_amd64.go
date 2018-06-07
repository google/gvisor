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
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
)

// Segment indices and Selectors.
const (
	// Index into GDT array.
	_          = iota // Null descriptor first.
	_                 // Reserved (Linux is kernel 32).
	segKcode          // Kernel code (64-bit).
	segKdata          // Kernel data.
	segUcode32        // User code (32-bit).
	segUdata          // User data.
	segUcode64        // User code (64-bit).
	segTss            // Task segment descriptor.
	segTssHi          // Upper bits for TSS.
	segLast           // Last segment (terminal, not included).
)

// Selectors.
const (
	Kcode   Selector = segKcode << 3
	Kdata   Selector = segKdata << 3
	Ucode32 Selector = (segUcode32 << 3) | 3
	Udata   Selector = (segUdata << 3) | 3
	Ucode64 Selector = (segUcode64 << 3) | 3
	Tss     Selector = segTss << 3
)

// Standard segments.
var (
	UserCodeSegment32 SegmentDescriptor
	UserDataSegment   SegmentDescriptor
	UserCodeSegment64 SegmentDescriptor
	KernelCodeSegment SegmentDescriptor
	KernelDataSegment SegmentDescriptor
)

// KernelOpts has initialization options for the kernel.
type KernelOpts struct {
	// PageTables are the kernel pagetables; this must be provided.
	PageTables *pagetables.PageTables
}

// KernelArchState contains architecture-specific state.
type KernelArchState struct {
	KernelOpts

	// globalIDT is our set of interrupt gates.
	globalIDT idt64
}

// CPUArchState contains CPU-specific arch state.
type CPUArchState struct {
	// stack is the stack used for interrupts on this CPU.
	stack [256]byte

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

	// gdt is the CPU's descriptor table.
	gdt descriptorTable

	// tss is the CPU's task state.
	tss TaskState64
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

// SwitchArchOpts are embedded in SwitchOpts.
type SwitchArchOpts struct {
	// UserPCID indicates that the application PCID to be used on switch,
	// assuming that PCIDs are supported.
	//
	// Per pagetables_x86.go, a zero PCID implies a flush.
	UserPCID uint16

	// KernelPCID indicates that the kernel PCID to be used on return,
	// assuming that PCIDs are supported.
	//
	// Per pagetables_x86.go, a zero PCID implies a flush.
	KernelPCID uint16
}

func init() {
	KernelCodeSegment.setCode64(0, 0, 0)
	KernelDataSegment.setData(0, 0xffffffff, 0)
	UserCodeSegment32.setCode64(0, 0, 3)
	UserDataSegment.setData(0, 0xffffffff, 3)
	UserCodeSegment64.setCode64(0, 0, 3)
}
