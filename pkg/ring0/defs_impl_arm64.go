//go:build arm64 && arm64 && arm64
// +build arm64,arm64,arm64

package ring0

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"io"
	"reflect"
)

// Useful bits.
const (
	_PGD_PGT_BASE = 0x1000
	_PGD_PGT_SIZE = 0x1000
	_PUD_PGT_BASE = 0x2000
	_PUD_PGT_SIZE = 0x1000
	_PMD_PGT_BASE = 0x3000
	_PMD_PGT_SIZE = 0x4000
	_PTE_PGT_BASE = 0x7000
	_PTE_PGT_SIZE = 0x1000
)

const (
	// DAIF bits:debug, sError, IRQ, FIQ.
	_PSR_D_BIT      = 0x00000200
	_PSR_A_BIT      = 0x00000100
	_PSR_I_BIT      = 0x00000080
	_PSR_F_BIT      = 0x00000040
	_PSR_DAIF_SHIFT = 6
	_PSR_DAIF_MASK  = 0xf << _PSR_DAIF_SHIFT

	// PSR bits.
	_PSR_MODE_EL0t = 0x00000000
	_PSR_MODE_EL1t = 0x00000004
	_PSR_MODE_EL1h = 0x00000005
	_PSR_MODE_MASK = 0x0000000f

	PsrFlagsClear = _PSR_MODE_MASK | _PSR_DAIF_MASK
	PsrModeMask   = _PSR_MODE_MASK

	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _PSR_MODE_EL1h | _PSR_D_BIT | _PSR_A_BIT | _PSR_I_BIT | _PSR_F_BIT

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _PSR_MODE_EL0t
)

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
const (
	El1InvSync = iota
	El1InvIrq
	El1InvFiq
	El1InvError

	El1Sync
	El1Irq
	El1Fiq
	El1Err

	El0Sync
	El0Irq
	El0Fiq
	El0Err

	El0InvSync
	El0InvIrq
	El0InvFiq
	El0InvErr

	El1SyncDa
	El1SyncIa
	El1SyncSpPc
	El1SyncUndef
	El1SyncDbg
	El1SyncInv

	El0SyncSVC
	El0SyncDa
	El0SyncIa
	El0SyncFpsimdAcc
	El0SyncSveAcc
	El0SyncFpsimdExc
	El0SyncSys
	El0SyncSpPc
	El0SyncUndef
	El0SyncDbg
	El0SyncWfx
	El0SyncInv

	El0ErrNMI
	El0ErrBounce

	_NR_INTERRUPTS
)

// System call vectors.
const (
	Syscall                 Vector = El0SyncSVC
	PageFault               Vector = El0SyncDa
	VirtualizationException Vector = El0ErrBounce
)

// VirtualAddressBits returns the number bits available for virtual addresses.
func VirtualAddressBits() uint32 {
	return 48
}

// PhysicalAddressBits returns the number of bits available for physical addresses.
func PhysicalAddressBits() uint32 {
	return 40
}

// Kernel is a global kernel object.
//
// This contains global state, shared by multiple CPUs.
type Kernel struct {
	// PageTables are the kernel pagetables; this must be provided.
	PageTables *pagetables.PageTables

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
	registers arch.Registers

	// hooks are kernel hooks.
	hooks Hooks
}

// Registers returns a modifiable-copy of the kernel registers.
//
// This is explicitly safe to call during KernelException and KernelSyscall.
//
//go:nosplit
func (c *CPU) Registers() *arch.Registers {
	return &c.registers
}

// SwitchOpts are passed to the Switch function.
type SwitchOpts struct {
	// Registers are the user register state.
	Registers *arch.Registers

	// FloatingPointState is a byte pointer where floating point state is
	// saved and restored.
	FloatingPointState *fpu.State

	// PageTables are the application page tables.
	PageTables *pagetables.PageTables

	// Flush indicates that a TLB flush should be forced on switch.
	Flush bool

	// FullRestore indicates that an iret-based restore should be used.
	FullRestore bool

	// SwitchArchOpts are architecture-specific options.
	SwitchArchOpts
}

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
	c.errorCode = 0
	c.errorType = 1
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
	fmt.Fprintf(w, "#define CPU_FAULT_ADDR       0x%02x\n", reflect.ValueOf(&c.faultAddr).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_FPSTATE_EL0      0x%02x\n", reflect.ValueOf(&c.el0Fp).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_TTBR0_KVM	     0x%02x\n", reflect.ValueOf(&c.ttbr0Kvm).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_TTBR0_APP        0x%02x\n", reflect.ValueOf(&c.ttbr0App).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_VECTOR_CODE      0x%02x\n", reflect.ValueOf(&c.vecCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_APP_ADDR         0x%02x\n", reflect.ValueOf(&c.appAddr).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_LAZY_VFP         0x%02x\n", reflect.ValueOf(&c.lazyVFP).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_APP_ASID         0x%02x\n", reflect.ValueOf(&c.appASID).Pointer()-reflect.ValueOf(c).Pointer())

	fmt.Fprintf(w, "\n// Bits.\n")
	fmt.Fprintf(w, "#define _KERNEL_FLAGS        0x%02x\n", KernelFlagsSet)

	fmt.Fprintf(w, "\n// Vectors.\n")

	fmt.Fprintf(w, "#define El1Sync 0x%02x\n", El1Sync)
	fmt.Fprintf(w, "#define El1Irq 0x%02x\n", El1Irq)
	fmt.Fprintf(w, "#define El1Fiq 0x%02x\n", El1Fiq)
	fmt.Fprintf(w, "#define El1Err 0x%02x\n", El1Err)

	fmt.Fprintf(w, "#define El0Sync 0x%02x\n", El0Sync)
	fmt.Fprintf(w, "#define El0Irq 0x%02x\n", El0Irq)
	fmt.Fprintf(w, "#define El0Fiq 0x%02x\n", El0Fiq)
	fmt.Fprintf(w, "#define El0Err 0x%02x\n", El0Err)

	fmt.Fprintf(w, "#define El1SyncDa 0x%02x\n", El1SyncDa)
	fmt.Fprintf(w, "#define El1SyncIa 0x%02x\n", El1SyncIa)
	fmt.Fprintf(w, "#define El1SyncSpPc 0x%02x\n", El1SyncSpPc)
	fmt.Fprintf(w, "#define El1SyncUndef 0x%02x\n", El1SyncUndef)
	fmt.Fprintf(w, "#define El1SyncDbg 0x%02x\n", El1SyncDbg)
	fmt.Fprintf(w, "#define El1SyncInv 0x%02x\n", El1SyncInv)

	fmt.Fprintf(w, "#define El0SyncSVC 0x%02x\n", El0SyncSVC)
	fmt.Fprintf(w, "#define El0SyncDa 0x%02x\n", El0SyncDa)
	fmt.Fprintf(w, "#define El0SyncIa 0x%02x\n", El0SyncIa)
	fmt.Fprintf(w, "#define El0SyncFpsimdAcc 0x%02x\n", El0SyncFpsimdAcc)
	fmt.Fprintf(w, "#define El0SyncSveAcc 0x%02x\n", El0SyncSveAcc)
	fmt.Fprintf(w, "#define El0SyncFpsimdExc 0x%02x\n", El0SyncFpsimdExc)
	fmt.Fprintf(w, "#define El0SyncSys 0x%02x\n", El0SyncSys)
	fmt.Fprintf(w, "#define El0SyncSpPc 0x%02x\n", El0SyncSpPc)
	fmt.Fprintf(w, "#define El0SyncUndef 0x%02x\n", El0SyncUndef)
	fmt.Fprintf(w, "#define El0SyncDbg 0x%02x\n", El0SyncDbg)
	fmt.Fprintf(w, "#define El0SyncWfx 0x%02x\n", El0SyncWfx)
	fmt.Fprintf(w, "#define El0SyncInv 0x%02x\n", El0SyncInv)

	fmt.Fprintf(w, "#define El0ErrNMI 0x%02x\n", El0ErrNMI)

	fmt.Fprintf(w, "#define PageFault 0x%02x\n", PageFault)
	fmt.Fprintf(w, "#define Syscall 0x%02x\n", Syscall)
	fmt.Fprintf(w, "#define VirtualizationException 0x%02x\n", VirtualizationException)

	p := &arch.Registers{}
	fmt.Fprintf(w, "\n// Ptrace registers.\n")
	fmt.Fprintf(w, "#define PTRACE_R0       0x%02x\n", reflect.ValueOf(&p.Regs[0]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R1       0x%02x\n", reflect.ValueOf(&p.Regs[1]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R2       0x%02x\n", reflect.ValueOf(&p.Regs[2]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R3       0x%02x\n", reflect.ValueOf(&p.Regs[3]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R4       0x%02x\n", reflect.ValueOf(&p.Regs[4]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R5       0x%02x\n", reflect.ValueOf(&p.Regs[5]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R6       0x%02x\n", reflect.ValueOf(&p.Regs[6]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R7       0x%02x\n", reflect.ValueOf(&p.Regs[7]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R8       0x%02x\n", reflect.ValueOf(&p.Regs[8]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R9       0x%02x\n", reflect.ValueOf(&p.Regs[9]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R10      0x%02x\n", reflect.ValueOf(&p.Regs[10]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R11      0x%02x\n", reflect.ValueOf(&p.Regs[11]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R12      0x%02x\n", reflect.ValueOf(&p.Regs[12]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R13      0x%02x\n", reflect.ValueOf(&p.Regs[13]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R14      0x%02x\n", reflect.ValueOf(&p.Regs[14]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R15      0x%02x\n", reflect.ValueOf(&p.Regs[15]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R16      0x%02x\n", reflect.ValueOf(&p.Regs[16]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R17      0x%02x\n", reflect.ValueOf(&p.Regs[17]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R18      0x%02x\n", reflect.ValueOf(&p.Regs[18]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R19      0x%02x\n", reflect.ValueOf(&p.Regs[19]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R20      0x%02x\n", reflect.ValueOf(&p.Regs[20]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R21      0x%02x\n", reflect.ValueOf(&p.Regs[21]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R22      0x%02x\n", reflect.ValueOf(&p.Regs[22]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R23      0x%02x\n", reflect.ValueOf(&p.Regs[23]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R24      0x%02x\n", reflect.ValueOf(&p.Regs[24]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R25      0x%02x\n", reflect.ValueOf(&p.Regs[25]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R26      0x%02x\n", reflect.ValueOf(&p.Regs[26]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R27      0x%02x\n", reflect.ValueOf(&p.Regs[27]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R28      0x%02x\n", reflect.ValueOf(&p.Regs[28]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R29      0x%02x\n", reflect.ValueOf(&p.Regs[29]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_R30      0x%02x\n", reflect.ValueOf(&p.Regs[30]).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_SP       0x%02x\n", reflect.ValueOf(&p.Sp).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_PC       0x%02x\n", reflect.ValueOf(&p.Pc).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_PSTATE   0x%02x\n", reflect.ValueOf(&p.Pstate).Pointer()-reflect.ValueOf(p).Pointer())
	fmt.Fprintf(w, "#define PTRACE_TLS      0x%02x\n", reflect.ValueOf(&p.TPIDR_EL0).Pointer()-reflect.ValueOf(p).Pointer())
}
