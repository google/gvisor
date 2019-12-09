package ring0

import (
	"reflect"
	"syscall"

	"fmt"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"io"
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

	_PSR_MODE_EL0t = 0x0
	_PSR_MODE_EL1t = 0x4
	_PSR_MODE_EL1h = 0x5
	_PSR_EL_MASK   = 0xf

	_PSR_D_BIT = 0x200
	_PSR_A_BIT = 0x100
	_PSR_I_BIT = 0x80
	_PSR_F_BIT = 0x40
)

const (
	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _PSR_MODE_EL1h

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _PSR_MODE_EL0t

	KernelFlagsClear = _PSR_EL_MASK
	UserFlagsClear   = _PSR_EL_MASK

	PsrDefaultSet = _PSR_D_BIT | _PSR_A_BIT | _PSR_I_BIT | _PSR_F_BIT
)

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
const (
	El1SyncInvalid = iota
	El1IrqInvalid
	El1FiqInvalid
	El1ErrorInvalid
	El1Sync
	El1Irq
	El1Fiq
	El1Error
	El0Sync
	El0Irq
	El0Fiq
	El0Error
	El0Sync_invalid
	El0Irq_invalid
	El0Fiq_invalid
	El0Error_invalid
	El1Sync_da
	El1Sync_ia
	El1Sync_sp_pc
	El1Sync_undef
	El1Sync_dbg
	El1Sync_inv
	El0Sync_svc
	El0Sync_da
	El0Sync_ia
	El0Sync_fpsimd_acc
	El0Sync_sve_acc
	El0Sync_sys
	El0Sync_sp_pc
	El0Sync_undef
	El0Sync_dbg
	El0Sync_inv
	VirtualizationException
	_NR_INTERRUPTS
)

// System call vectors.
const (
	Syscall   Vector = El0Sync_svc
	PageFault Vector = El0Sync_da
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

var (
	// UserspaceSize is the total size of userspace.
	UserspaceSize = uintptr(1) << (VirtualAddressBits())

	// MaximumUserAddress is the largest possible user address.
	MaximumUserAddress = (UserspaceSize - 1) & ^uintptr(usermem.PageSize-1)

	// KernelStartAddress is the starting kernel address.
	KernelStartAddress = ^uintptr(0) - (UserspaceSize - 1)
)

// KernelOpts has initialization options for the kernel.
type KernelOpts struct {
	// PageTables are the kernel pagetables; this must be provided.
	PageTables *pagetables.PageTables
}

// KernelArchState contains architecture-specific state.
type KernelArchState struct {
	KernelOpts
}

// CPUArchState contains CPU-specific arch state.
type CPUArchState struct {
	// stack is the stack used for interrupts on this CPU.
	stack [512]byte

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

	// ttbr0Kvm is the value of ttbr0_el1 for sentry.
	ttbr0Kvm uintptr

	// ttbr0App is the value of ttbr0_el1 for applicaton.
	ttbr0App uintptr

	// exception vector.
	vecCode Vector

	// application context pointer.
	appAddr uintptr
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
	fmt.Fprintf(w, "#define CPU_TTBR0_KVM	     0x%02x\n", reflect.ValueOf(&c.ttbr0Kvm).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_TTBR0_APP        0x%02x\n", reflect.ValueOf(&c.ttbr0App).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_VECTOR_CODE      0x%02x\n", reflect.ValueOf(&c.vecCode).Pointer()-reflect.ValueOf(c).Pointer())
	fmt.Fprintf(w, "#define CPU_APP_ADDR         0x%02x\n", reflect.ValueOf(&c.appAddr).Pointer()-reflect.ValueOf(c).Pointer())

	fmt.Fprintf(w, "\n// Bits.\n")
	fmt.Fprintf(w, "#define _KERNEL_FLAGS        0x%02x\n", KernelFlagsSet)

	fmt.Fprintf(w, "\n// Vectors.\n")
	fmt.Fprintf(w, "#define El1SyncInvalid  0x%02x\n", El1SyncInvalid)
	fmt.Fprintf(w, "#define El1IrqInvalid 0x%02x\n", El1IrqInvalid)
	fmt.Fprintf(w, "#define El1FiqInvalid 0x%02x\n", El1FiqInvalid)
	fmt.Fprintf(w, "#define El1ErrorInvalid 0x%02x\n", El1ErrorInvalid)

	fmt.Fprintf(w, "#define El1Sync 0x%02x\n", El1Sync)
	fmt.Fprintf(w, "#define El1Irq 0x%02x\n", El1Irq)
	fmt.Fprintf(w, "#define El1Fiq 0x%02x\n", El1Fiq)
	fmt.Fprintf(w, "#define El1Error 0x%02x\n", El1Error)

	fmt.Fprintf(w, "#define El0Sync 0x%02x\n", El0Sync)
	fmt.Fprintf(w, "#define El0Irq 0x%02x\n", El0Irq)
	fmt.Fprintf(w, "#define El0Fiq 0x%02x\n", El0Fiq)
	fmt.Fprintf(w, "#define El0Error 0x%02x\n", El0Error)

	fmt.Fprintf(w, "#define El0Sync_invalid 0x%02x\n", El0Sync_invalid)
	fmt.Fprintf(w, "#define El0Irq_invalid 0x%02x\n", El0Irq_invalid)
	fmt.Fprintf(w, "#define El0Fiq_invalid 0x%02x\n", El0Fiq_invalid)
	fmt.Fprintf(w, "#define El0Error_invalid 0x%02x\n", El0Error_invalid)

	fmt.Fprintf(w, "#define El1Sync_da 0x%02x\n", El1Sync_da)
	fmt.Fprintf(w, "#define El1Sync_ia 0x%02x\n", El1Sync_ia)
	fmt.Fprintf(w, "#define El1Sync_sp_pc 0x%02x\n", El1Sync_sp_pc)
	fmt.Fprintf(w, "#define El1Sync_undef 0x%02x\n", El1Sync_undef)
	fmt.Fprintf(w, "#define El1Sync_dbg 0x%02x\n", El1Sync_dbg)
	fmt.Fprintf(w, "#define El1Sync_inv 0x%02x\n", El1Sync_inv)

	fmt.Fprintf(w, "#define El0Sync_svc 0x%02x\n", El0Sync_svc)
	fmt.Fprintf(w, "#define El0Sync_da 0x%02x\n", El0Sync_da)
	fmt.Fprintf(w, "#define El0Sync_ia 0x%02x\n", El0Sync_ia)
	fmt.Fprintf(w, "#define El0Sync_fpsimd_acc 0x%02x\n", El0Sync_fpsimd_acc)
	fmt.Fprintf(w, "#define El0Sync_sve_acc 0x%02x\n", El0Sync_sve_acc)
	fmt.Fprintf(w, "#define El0Sync_sys 0x%02x\n", El0Sync_sys)
	fmt.Fprintf(w, "#define El0Sync_sp_pc 0x%02x\n", El0Sync_sp_pc)
	fmt.Fprintf(w, "#define El0Sync_undef 0x%02x\n", El0Sync_undef)
	fmt.Fprintf(w, "#define El0Sync_dbg 0x%02x\n", El0Sync_dbg)
	fmt.Fprintf(w, "#define El0Sync_inv 0x%02x\n", El0Sync_inv)

	fmt.Fprintf(w, "#define PageFault 0x%02x\n", PageFault)
	fmt.Fprintf(w, "#define Syscall 0x%02x\n", Syscall)

	p := &syscall.PtraceRegs{}
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
}
