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

package ring0

var (
	// VirtualAddressBits is the number of bits available in the virtual
	// address space.
	//
	// Initialized by ring0.Init.
	VirtualAddressBits uintptr

	// PhysicalAddressBits is the number of bits available in the physical
	// address space.
	//
	// Initialized by ring0.Init.
	PhysicalAddressBits uintptr

	// UserspaceSize is the total size of userspace.
	//
	// Initialized by ring0.Init.
	UserspaceSize uintptr

	// MaximumUserAddress is the largest possible user address.
	//
	// Initialized by ring0.Init.
	MaximumUserAddress uintptr

	// KernelStartAddress is the starting kernel address.
	//
	// Initialized by ring0.Init.
	KernelStartAddress uintptr
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

// KernelArchState contains architecture-specific state.
type KernelArchState struct {
	// cpuEntries is array of kernelEntry for all cpus.
	cpuEntries []kernelEntry

	// globalIDT is our set of interrupt gates.
	globalIDT *idt64
}

// kernelEntry contains minimal CPU-specific arch state
// that can be mapped at the upper of the address space.
// Malicious APP might steal info from it via CPU bugs.
type kernelEntry struct {
	// stack is the stack used for interrupts on this CPU.
	stack [256]byte

	// scratch space for temporary usage.
	scratch0 uint64

	// stackTop is the top of the stack.
	stackTop uint64

	// cpuSelf is back reference to CPU.
	cpuSelf *CPU

	// kernelCR3 is the cr3 used for sentry kernel.
	kernelCR3 uintptr

	// gdt is the CPU's descriptor table.
	gdt descriptorTable

	// tss is the CPU's task state.
	tss TaskState64
}

// CPUArchState contains CPU-specific arch state.
type CPUArchState struct {
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

	// vector is the vector of the last exception.
	vector uintptr

	// faultAddr is the value of the cr2 register.
	faultAddr uintptr

	*kernelEntry

	// Copies of global variables, stored in CPU so that they can be used by
	// syscall and exception handlers (in the upper address space).
	hasXSAVE    bool
	hasXSAVEOPT bool
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

// Vector returns the vector of the last exception.
//
//go:nosplit
func (c *CPU) Vector() uintptr {
	return c.vector
}

// FaultAddr returns the last fault address.
//
//go:nosplit
func (c *CPU) FaultAddr() uintptr {
	return c.faultAddr
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
