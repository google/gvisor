package ring0

import (
	"fmt"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"io"
	"reflect"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

var (
	// UserspaceSize is the total size of userspace.
	UserspaceSize = uintptr(1) << (VirtualAddressBits() - 1)

	// MaximumUserAddress is the largest possible user address.
	MaximumUserAddress = (UserspaceSize - 1) & ^uintptr(usermem.PageSize-1)

	// KernelStartAddress is the starting kernel address.
	KernelStartAddress = ^uintptr(0) - (UserspaceSize - 1)
)

// Kernel is a global kernel object.
//
// This contains global state, shared by multiple CPUs.
type Kernel struct {
	KernelArchState
}

// Hooks are hooks for kernel functions.
type Hooks interface {
	// KernelSyscall is called for kernel system calls.
	//
	// Return from this call will restore registers and return to the kernel: the
	// registers must be modified directly.
	//
	// If this function is not provided, a kernel exception results in halt.
	//
	// This must be go:nosplit, as this will be on the interrupt stack.
	// Closures are permitted, as the pointer to the closure frame is not
	// passed on the stack.
	KernelSyscall()

	// KernelException handles an exception during kernel execution.
	//
	// Return from this call will restore registers and return to the kernel: the
	// registers must be modified directly.
	//
	// If this function is not provided, a kernel exception results in halt.
	//
	// This must be go:nosplit, as this will be on the interrupt stack.
	// Closures are permitted, as the pointer to the closure frame is not
	// passed on the stack.
	KernelException(Vector)
}

// CPU is the per-CPU struct.
type CPU struct {
	// self is a self reference.
	//
	// This is always guaranteed to be at offset zero.
	self *CPU

	// kernel is reference to the kernel that this CPU was initialized
	// with. This reference is kept for garbage collection purposes: CPU
	// registers may refer to objects within the Kernel object that cannot
	// be safely freed.
	kernel *Kernel

	// CPUArchState is architecture-specific state.
	CPUArchState

	// registers is a set of registers; these may be used on kernel system
	// calls and exceptions via the Registers function.
	registers syscall.PtraceRegs

	// hooks are kernel hooks.
	hooks Hooks
}

// Registers returns a modifiable-copy of the kernel registers.
//
// This is explicitly safe to call during KernelException and KernelSyscall.
//
//go:nosplit
func (c *CPU) Registers() *syscall.PtraceRegs {
	return &c.registers
}

// SwitchOpts are passed to the Switch function.
type SwitchOpts struct {
	// Registers are the user register state.
	Registers *syscall.PtraceRegs

	// FloatingPointState is a byte pointer where floating point state is
	// saved and restored.
	FloatingPointState *byte

	// PageTables are the application page tables.
	PageTables *pagetables.PageTables

	// Flush indicates that a TLB flush should be forced on switch.
	Flush bool

	// FullRestore indicates that an iret-based restore should be used.
	FullRestore bool

	// SwitchArchOpts are architecture-specific options.
	SwitchArchOpts
}

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

// ClearErrorCode resets the error code.
//
//go:nosplit
func (c *CPU) ClearErrorCode() {
	c.errorCode = 0
	c.errorType = 1
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

// Emit prints architecture-specific offsets.
func Emit(w io.Writer) {
	fmt.Fprintf(w, "// Automatically generated, do not edit.\n")

	c := &CPU{}
	fmt.Fprintf(w, "\n// CPU offsets.\n")
	fmt.Fprintf(w, "#define CPU_SELF             0x%02x\n", reflect.ValueOf(&c.self).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_REGISTERS        0x%02x\n", reflect.ValueOf(&c.registers).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_STACK_TOP        0x%02x\n", reflect.ValueOf(&c.stack[0]).Pointer()-reflect.ValueOf(c).Pointer()+uintptr(len(c.stack)))
	fmt.Fprintf(w, "#define CPU_ERROR_CODE       0x%02x\n", reflect.ValueOf(&c.errorCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_ERROR_TYPE       0x%02x\n", reflect.ValueOf(&c.errorType).Pointer()-reflect.ValueOf(c).Pointer())

	fmt.Fprintf(w, "\n// Bits.\n")
	fmt.Fprintf(w, "#define _RFLAGS_IF           0x%02x\n", _RFLAGS_IF)
	fmt.Fprintf(w, "#define _KERNEL_FLAGS        0x%02x\n", KernelFlagsSet)

	fmt.Fprintf(w, "\n// Vectors.\n")
	fmt.Fprintf(w, "#define DivideByZero               0x%02x\n", DivideByZero)
	fmt.Fprintf(w, "#define Debug                      0x%02x\n", Debug)
	fmt.Fprintf(w, "#define NMI                        0x%02x\n", NMI)
	fmt.Fprintf(w, "#define Breakpoint                 0x%02x\n", Breakpoint)
	fmt.Fprintf(w, "#define Overflow                   0x%02x\n", Overflow)
	fmt.Fprintf(w, "#define BoundRangeExceeded         0x%02x\n", BoundRangeExceeded)
	fmt.Fprintf(w, "#define InvalidOpcode              0x%02x\n", InvalidOpcode)
	fmt.Fprintf(w, "#define DeviceNotAvailable         0x%02x\n", DeviceNotAvailable)
	fmt.Fprintf(w, "#define DoubleFault                0x%02x\n", DoubleFault)
	fmt.Fprintf(w, "#define CoprocessorSegmentOverrun  0x%02x\n", CoprocessorSegmentOverrun)
	fmt.Fprintf(w, "#define InvalidTSS                 0x%02x\n", InvalidTSS)
	fmt.Fprintf(w, "#define SegmentNotPresent          0x%02x\n", SegmentNotPresent)
	fmt.Fprintf(w, "#define StackSegmentFault          0x%02x\n", StackSegmentFault)
	fmt.Fprintf(w, "#define GeneralProtectionFault     0x%02x\n", GeneralProtectionFault)
	fmt.Fprintf(w, "#define PageFault                  0x%02x\n", PageFault)
	fmt.Fprintf(w, "#define X87FloatingPointException  0x%02x\n", X87FloatingPointException)
	fmt.Fprintf(w, "#define AlignmentCheck             0x%02x\n", AlignmentCheck)
	fmt.Fprintf(w, "#define MachineCheck               0x%02x\n", MachineCheck)
	fmt.Fprintf(w, "#define SIMDFloatingPointException 0x%02x\n", SIMDFloatingPointException)
	fmt.Fprintf(w, "#define VirtualizationException    0x%02x\n", VirtualizationException)
	fmt.Fprintf(w, "#define SecurityException          0x%02x\n", SecurityException)
	fmt.Fprintf(w, "#define SyscallInt80               0x%02x\n", SyscallInt80)
	fmt.Fprintf(w, "#define Syscall                    0x%02x\n", Syscall)

	p := &syscall.PtraceRegs{}
	fmt.Fprintf(w, "\n// Ptrace registers.\n")
	fmt.Fprintf(w, "#define PTRACE_R15      0x%02x\n", reflect.ValueOf(&p.R15).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R14      0x%02x\n", reflect.ValueOf(&p.R14).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R13      0x%02x\n", reflect.ValueOf(&p.R13).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R12      0x%02x\n", reflect.ValueOf(&p.R12).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RBP      0x%02x\n", reflect.ValueOf(&p.Rbp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RBX      0x%02x\n", reflect.ValueOf(&p.Rbx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R11      0x%02x\n", reflect.ValueOf(&p.R11).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R10      0x%02x\n", reflect.ValueOf(&p.R10).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R9       0x%02x\n", reflect.ValueOf(&p.R9).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R8       0x%02x\n", reflect.ValueOf(&p.R8).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RAX      0x%02x\n", reflect.ValueOf(&p.Rax).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RCX      0x%02x\n", reflect.ValueOf(&p.Rcx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RDX      0x%02x\n", reflect.ValueOf(&p.Rdx).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RSI      0x%02x\n", reflect.ValueOf(&p.Rsi).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RDI      0x%02x\n", reflect.ValueOf(&p.Rdi).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_ORIGRAX  0x%02x\n", reflect.ValueOf(&p.Orig_rax).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RIP      0x%02x\n", reflect.ValueOf(&p.Rip).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_CS       0x%02x\n", reflect.ValueOf(&p.Cs).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_FLAGS    0x%02x\n", reflect.ValueOf(&p.Eflags).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_RSP      0x%02x\n", reflect.ValueOf(&p.Rsp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_SS       0x%02x\n", reflect.ValueOf(&p.Ss).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_FS       0x%02x\n", reflect.ValueOf(&p.Fs_base).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_GS       0x%02x\n", reflect.ValueOf(&p.Gs_base).Pointer()-reflect.ValueOf(p).Pointer())
}

// Useful bits.
const (
	_CR0_PE = 1 << 0
	_CR0_ET = 1 << 4
	_CR0_AM = 1 << 18
	_CR0_PG = 1 << 31

	_CR4_PSE        = 1 << 4
	_CR4_PAE        = 1 << 5
	_CR4_PGE        = 1 << 7
	_CR4_OSFXSR     = 1 << 9
	_CR4_OSXMMEXCPT = 1 << 10
	_CR4_FSGSBASE   = 1 << 16
	_CR4_PCIDE      = 1 << 17
	_CR4_OSXSAVE    = 1 << 18
	_CR4_SMEP       = 1 << 20

	_RFLAGS_AC       = 1 << 18
	_RFLAGS_NT       = 1 << 14
	_RFLAGS_IOPL     = 3 << 12
	_RFLAGS_DF       = 1 << 10
	_RFLAGS_IF       = 1 << 9
	_RFLAGS_STEP     = 1 << 8
	_RFLAGS_RESERVED = 1 << 1

	_EFER_SCE = 0x001
	_EFER_LME = 0x100
	_EFER_LMA = 0x400
	_EFER_NX  = 0x800

	_MSR_STAR          = 0xc0000081
	_MSR_LSTAR         = 0xc0000082
	_MSR_CSTAR         = 0xc0000083
	_MSR_SYSCALL_MASK  = 0xc0000084
	_MSR_PLATFORM_INFO = 0xce
	_MSR_MISC_FEATURES = 0x140

	_PLATFORM_INFO_CPUID_FAULT = 1 << 31

	_MISC_FEATURE_CPUID_TRAP = 0x1
)

const (
	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _RFLAGS_RESERVED

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _RFLAGS_RESERVED | _RFLAGS_IF

	// KernelFlagsClear should always be clear in the kernel.
	KernelFlagsClear = _RFLAGS_STEP | _RFLAGS_IF | _RFLAGS_IOPL | _RFLAGS_AC | _RFLAGS_NT

	// UserFlagsClear are always cleared in userspace.
	UserFlagsClear = _RFLAGS_NT | _RFLAGS_IOPL
)

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
const (
	DivideByZero Vector = iota
	Debug
	NMI
	Breakpoint
	Overflow
	BoundRangeExceeded
	InvalidOpcode
	DeviceNotAvailable
	DoubleFault
	CoprocessorSegmentOverrun
	InvalidTSS
	SegmentNotPresent
	StackSegmentFault
	GeneralProtectionFault
	PageFault
	_
	X87FloatingPointException
	AlignmentCheck
	MachineCheck
	SIMDFloatingPointException
	VirtualizationException
	SecurityException = 0x1e
	SyscallInt80      = 0x80
	_NR_INTERRUPTS    = SyscallInt80 + 1
)

// System call vectors.
const (
	Syscall Vector = _NR_INTERRUPTS
)

// VirtualAddressBits returns the number bits available for virtual addresses.
//
// Note that sign-extension semantics apply to the highest order bit.
//
// FIXME(b/69382326): This should use the cpuid passed to Init.
func VirtualAddressBits() uint32 {
	ax, _, _, _ := cpuid.HostID(0x80000008, 0)
	return (ax >> 8) & 0xff
}

// PhysicalAddressBits returns the number of bits available for physical addresses.
//
// FIXME(b/69382326): This should use the cpuid passed to Init.
func PhysicalAddressBits() uint32 {
	ax, _, _, _ := cpuid.HostID(0x80000008, 0)
	return ax & 0xff
}

// Selector is a segment Selector.
type Selector uint16

// SegmentDescriptor is a segment descriptor.
type SegmentDescriptor struct {
	bits [2]uint32
}

// descriptorTable is a collection of descriptors.
type descriptorTable [32]SegmentDescriptor

// SegmentDescriptorFlags are typed flags within a descriptor.
type SegmentDescriptorFlags uint32

// SegmentDescriptorFlag declarations.
const (
	SegmentDescriptorAccess     SegmentDescriptorFlags = 1 << 8  // Access bit (always set).
	SegmentDescriptorWrite                             = 1 << 9  // Write permission.
	SegmentDescriptorExpandDown                        = 1 << 10 // Grows down, not used.
	SegmentDescriptorExecute                           = 1 << 11 // Execute permission.
	SegmentDescriptorSystem                            = 1 << 12 // Zero => system, 1 => user code/data.
	SegmentDescriptorPresent                           = 1 << 15 // Present.
	SegmentDescriptorAVL                               = 1 << 20 // Available.
	SegmentDescriptorLong                              = 1 << 21 // Long mode.
	SegmentDescriptorDB                                = 1 << 22 // 16 or 32-bit.
	SegmentDescriptorG                                 = 1 << 23 // Granularity: page or byte.
)

// Base returns the descriptor's base linear address.
func (d *SegmentDescriptor) Base() uint32 {
	return d.bits[1]&0xFF000000 | (d.bits[1]&0x000000FF)<<16 | d.bits[0]>>16
}

// Limit returns the descriptor size.
func (d *SegmentDescriptor) Limit() uint32 {
	l := d.bits[0]&0xFFFF | d.bits[1]&0xF0000
	if d.bits[1]&uint32(SegmentDescriptorG) != 0 {
		l <<= 12
		l |= 0xFFF
	}
	return l
}

// Flags returns descriptor flags.
func (d *SegmentDescriptor) Flags() SegmentDescriptorFlags {
	return SegmentDescriptorFlags(d.bits[1] & 0x00F09F00)
}

// DPL returns the descriptor privilege level.
func (d *SegmentDescriptor) DPL() int {
	return int((d.bits[1] >> 13) & 3)
}

func (d *SegmentDescriptor) setNull() {
	d.bits[0] = 0
	d.bits[1] = 0
}

func (d *SegmentDescriptor) set(base, limit uint32, dpl int, flags SegmentDescriptorFlags) {
	flags |= SegmentDescriptorPresent
	if limit>>12 != 0 {
		limit >>= 12
		flags |= SegmentDescriptorG
	}
	d.bits[0] = base<<16 | limit&0xFFFF
	d.bits[1] = base&0xFF000000 | (base>>16)&0xFF | limit&0x000F0000 | uint32(flags) | uint32(dpl)<<13
}

func (d *SegmentDescriptor) setCode32(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorDB|
			SegmentDescriptorExecute|
			SegmentDescriptorSystem)
}

func (d *SegmentDescriptor) setCode64(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorG|
			SegmentDescriptorLong|
			SegmentDescriptorExecute|
			SegmentDescriptorSystem)
}

func (d *SegmentDescriptor) setData(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorWrite|
			SegmentDescriptorSystem)
}

// setHi is only used for the TSS segment, which is magically 64-bits.
func (d *SegmentDescriptor) setHi(base uint32) {
	d.bits[0] = base
	d.bits[1] = 0
}

// Gate64 is a 64-bit task, trap, or interrupt gate.
type Gate64 struct {
	bits [4]uint32
}

// idt64 is a 64-bit interrupt descriptor table.
type idt64 [_NR_INTERRUPTS]Gate64

func (g *Gate64) setInterrupt(cs Selector, rip uint64, dpl int, ist int) {
	g.bits[0] = uint32(cs)<<16 | uint32(rip)&0xFFFF
	g.bits[1] = uint32(rip)&0xFFFF0000 | SegmentDescriptorPresent | uint32(dpl)<<13 | 14<<8 | uint32(ist)&0x7
	g.bits[2] = uint32(rip >> 32)
}

func (g *Gate64) setTrap(cs Selector, rip uint64, dpl int, ist int) {
	g.setInterrupt(cs, rip, dpl, ist)
	g.bits[1] |= 1 << 8
}

// TaskState64 is a 64-bit task state structure.
type TaskState64 struct {
	_              uint32
	rsp0Lo, rsp0Hi uint32
	rsp1Lo, rsp1Hi uint32
	rsp2Lo, rsp2Hi uint32
	_              [2]uint32
	ist1Lo, ist1Hi uint32
	ist2Lo, ist2Hi uint32
	ist3Lo, ist3Hi uint32
	ist4Lo, ist4Hi uint32
	ist5Lo, ist5Hi uint32
	ist6Lo, ist6Hi uint32
	ist7Lo, ist7Hi uint32
	_              [2]uint32
	_              uint16
	ioPerm         uint16
}
