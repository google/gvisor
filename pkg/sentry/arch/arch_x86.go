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

// +build amd64 i386

package arch

import (
	"fmt"
	"io"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/log"
	rpb "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// System-related constants for x86.
const (
	// SyscallWidth is the width of syscall, sysenter, and int 80 insturctions.
	SyscallWidth = 2
)

// EFLAGS register bits.
const (
	// eflagsCF is the mask for the carry flag.
	eflagsCF = uint64(1) << 0
	// eflagsPF is the mask for the parity flag.
	eflagsPF = uint64(1) << 2
	// eflagsAF is the mask for the auxiliary carry flag.
	eflagsAF = uint64(1) << 4
	// eflagsZF is the mask for the zero flag.
	eflagsZF = uint64(1) << 6
	// eflagsSF is the mask for the sign flag.
	eflagsSF = uint64(1) << 7
	// eflagsTF is the mask for the trap flag.
	eflagsTF = uint64(1) << 8
	// eflagsIF is the mask for the interrupt flag.
	eflagsIF = uint64(1) << 9
	// eflagsDF is the mask for the direction flag.
	eflagsDF = uint64(1) << 10
	// eflagsOF is the mask for the overflow flag.
	eflagsOF = uint64(1) << 11
	// eflagsIOPL is the mask for the I/O privilege level.
	eflagsIOPL = uint64(3) << 12
	// eflagsNT is the mask for the nested task bit.
	eflagsNT = uint64(1) << 14
	// eflagsRF is the mask for the resume flag.
	eflagsRF = uint64(1) << 16
	// eflagsVM is the mask for the virtual mode bit.
	eflagsVM = uint64(1) << 17
	// eflagsAC is the mask for the alignment check / access control bit.
	eflagsAC = uint64(1) << 18
	// eflagsVIF is the mask for the virtual interrupt flag.
	eflagsVIF = uint64(1) << 19
	// eflagsVIP is the mask for the virtual interrupt pending bit.
	eflagsVIP = uint64(1) << 20
	// eflagsID is the mask for the CPUID detection bit.
	eflagsID = uint64(1) << 21

	// eflagsPtraceMutable is the mask for the set of EFLAGS that may be
	// changed by ptrace(PTRACE_SETREGS). eflagsPtraceMutable is analogous to
	// Linux's FLAG_MASK.
	eflagsPtraceMutable = eflagsCF | eflagsPF | eflagsAF | eflagsZF | eflagsSF | eflagsTF | eflagsDF | eflagsOF | eflagsRF | eflagsAC | eflagsNT

	// eflagsRestorable is the mask for the set of EFLAGS that may be changed by
	// SignalReturn. eflagsRestorable is analogous to Linux's FIX_EFLAGS.
	eflagsRestorable = eflagsAC | eflagsOF | eflagsDF | eflagsTF | eflagsSF | eflagsZF | eflagsAF | eflagsPF | eflagsCF | eflagsRF
)

// Segment selectors. See arch/x86/include/asm/segment.h.
const (
	userCS   = 0x33 // guest ring 3 code selector
	user32CS = 0x23 // guest ring 3 32 bit code selector
	userDS   = 0x2b // guest ring 3 data selector

	_FS_TLS_SEL = 0x63 // Linux FS thread-local storage selector
	_GS_TLS_SEL = 0x6b // Linux GS thread-local storage selector
)

var (
	// TrapInstruction is the x86 trap instruction.
	TrapInstruction = [1]byte{0xcc}

	// CPUIDInstruction is the x86 CPUID instruction.
	CPUIDInstruction = [2]byte{0xf, 0xa2}

	// X86TrapFlag is an exported const for use by other packages.
	X86TrapFlag uint64 = (1 << 8)
)

// x86FPState is x86 floating point state.
type x86FPState []byte

// initX86FPState (defined in asm files) sets up initial state.
func initX86FPState(data *FloatingPointData, useXsave bool)

func newX86FPStateSlice() []byte {
	size, align := cpuid.HostFeatureSet().ExtendedStateSize()
	capacity := size
	// Always use at least 4096 bytes.
	if capacity < 4096 {
		capacity = 4096
	}
	return alignedBytes(capacity, align)[:size]
}

// newX86FPState returns an initialized floating point state.
//
// The returned state is large enough to store all floating point state
// supported by host, even if the app won't use much of it due to a restricted
// FeatureSet. Since they may still be able to see state not advertised by
// CPUID we must ensure it does not contain any sentry state.
func newX86FPState() x86FPState {
	f := x86FPState(newX86FPStateSlice())
	initX86FPState(f.FloatingPointData(), cpuid.HostFeatureSet().UseXsave())
	return f
}

// fork creates and returns an identical copy of the x86 floating point state.
func (f x86FPState) fork() x86FPState {
	n := x86FPState(newX86FPStateSlice())
	copy(n, f)
	return n
}

// FloatingPointData returns the raw data pointer.
func (f x86FPState) FloatingPointData() *FloatingPointData {
	return (*FloatingPointData)(&f[0])
}

// NewFloatingPointData returns a new floating point data blob.
//
// This is primarily for use in tests.
func NewFloatingPointData() *FloatingPointData {
	return (*FloatingPointData)(&(newX86FPState()[0]))
}

// State contains the common architecture bits for X86 (the build tag of this
// file ensures it's only built on x86).
//
// +stateify savable
type State struct {
	// The system registers.
	Regs syscall.PtraceRegs `state:".(syscallPtraceRegs)"`

	// Our floating point state.
	x86FPState `state:"wait"`

	// FeatureSet is a pointer to the currently active feature set.
	FeatureSet *cpuid.FeatureSet
}

// Proto returns a protobuf representation of the system registers in State.
func (s State) Proto() *rpb.Registers {
	regs := &rpb.AMD64Registers{
		Rax:     s.Regs.Rax,
		Rbx:     s.Regs.Rbx,
		Rcx:     s.Regs.Rcx,
		Rdx:     s.Regs.Rdx,
		Rsi:     s.Regs.Rsi,
		Rdi:     s.Regs.Rdi,
		Rsp:     s.Regs.Rsp,
		Rbp:     s.Regs.Rbp,
		R8:      s.Regs.R8,
		R9:      s.Regs.R9,
		R10:     s.Regs.R10,
		R11:     s.Regs.R11,
		R12:     s.Regs.R12,
		R13:     s.Regs.R13,
		R14:     s.Regs.R14,
		R15:     s.Regs.R15,
		Rip:     s.Regs.Rip,
		Rflags:  s.Regs.Eflags,
		OrigRax: s.Regs.Orig_rax,
		Cs:      s.Regs.Cs,
		Ds:      s.Regs.Ds,
		Es:      s.Regs.Es,
		Fs:      s.Regs.Fs,
		Gs:      s.Regs.Gs,
		Ss:      s.Regs.Ss,
		FsBase:  s.Regs.Fs_base,
		GsBase:  s.Regs.Gs_base,
	}
	return &rpb.Registers{Arch: &rpb.Registers_Amd64{Amd64: regs}}
}

// Fork creates and returns an identical copy of the state.
func (s *State) Fork() State {
	return State{
		Regs:       s.Regs,
		x86FPState: s.x86FPState.fork(),
		FeatureSet: s.FeatureSet,
	}
}

// StateData implements Context.StateData.
func (s *State) StateData() *State {
	return s
}

// CPUIDEmulate emulates a cpuid instruction.
func (s *State) CPUIDEmulate(l log.Logger) {
	argax := uint32(s.Regs.Rax)
	argcx := uint32(s.Regs.Rcx)
	ax, bx, cx, dx := s.FeatureSet.EmulateID(argax, argcx)
	s.Regs.Rax = uint64(ax)
	s.Regs.Rbx = uint64(bx)
	s.Regs.Rcx = uint64(cx)
	s.Regs.Rdx = uint64(dx)
	l.Debugf("CPUID(%x,%x): %x %x %x %x", argax, argcx, ax, bx, cx, dx)
}

// SingleStep implements Context.SingleStep.
func (s *State) SingleStep() bool {
	return s.Regs.Eflags&X86TrapFlag != 0
}

// SetSingleStep enables single stepping.
func (s *State) SetSingleStep() {
	// Set the trap flag.
	s.Regs.Eflags |= X86TrapFlag
}

// ClearSingleStep enables single stepping.
func (s *State) ClearSingleStep() {
	// Clear the trap flag.
	s.Regs.Eflags &= ^X86TrapFlag
}

// RegisterMap returns a map of all registers.
func (s *State) RegisterMap() (map[string]uintptr, error) {
	return map[string]uintptr{
		"R15":      uintptr(s.Regs.R15),
		"R14":      uintptr(s.Regs.R14),
		"R13":      uintptr(s.Regs.R13),
		"R12":      uintptr(s.Regs.R12),
		"Rbp":      uintptr(s.Regs.Rbp),
		"Rbx":      uintptr(s.Regs.Rbx),
		"R11":      uintptr(s.Regs.R11),
		"R10":      uintptr(s.Regs.R10),
		"R9":       uintptr(s.Regs.R9),
		"R8":       uintptr(s.Regs.R8),
		"Rax":      uintptr(s.Regs.Rax),
		"Rcx":      uintptr(s.Regs.Rcx),
		"Rdx":      uintptr(s.Regs.Rdx),
		"Rsi":      uintptr(s.Regs.Rsi),
		"Rdi":      uintptr(s.Regs.Rdi),
		"Orig_rax": uintptr(s.Regs.Orig_rax),
		"Rip":      uintptr(s.Regs.Rip),
		"Cs":       uintptr(s.Regs.Cs),
		"Eflags":   uintptr(s.Regs.Eflags),
		"Rsp":      uintptr(s.Regs.Rsp),
		"Ss":       uintptr(s.Regs.Ss),
		"Fs_base":  uintptr(s.Regs.Fs_base),
		"Gs_base":  uintptr(s.Regs.Gs_base),
		"Ds":       uintptr(s.Regs.Ds),
		"Es":       uintptr(s.Regs.Es),
		"Fs":       uintptr(s.Regs.Fs),
		"Gs":       uintptr(s.Regs.Gs),
	}, nil
}

// PtraceGetRegs implements Context.PtraceGetRegs.
func (s *State) PtraceGetRegs(dst io.Writer) (int, error) {
	return dst.Write(binary.Marshal(nil, usermem.ByteOrder, s.ptraceGetRegs()))
}

func (s *State) ptraceGetRegs() syscall.PtraceRegs {
	regs := s.Regs
	// These may not be initialized.
	if regs.Cs == 0 || regs.Ss == 0 || regs.Eflags == 0 {
		regs.Eflags = eflagsIF
		regs.Cs = userCS
		regs.Ss = userDS
	}
	// As an optimization, Linux <4.7 implements 32-bit fs_base/gs_base
	// addresses using reserved descriptors in the GDT instead of the MSRs,
	// with selector values FS_TLS_SEL and GS_TLS_SEL respectively. These
	// values are actually visible in struct user_regs_struct::fs/gs;
	// arch/x86/kernel/ptrace.c:getreg() doesn't attempt to sanitize struct
	// thread_struct::fsindex/gsindex.
	//
	// We always use fs == gs == 0 when fs_base/gs_base is in use, for
	// simplicity.
	//
	// Luckily, Linux <4.7 silently ignores setting fs/gs to 0 via
	// arch/x86/kernel/ptrace.c:set_segment_reg() when fs_base/gs_base is a
	// 32-bit value and fsindex/gsindex indicates that this optimization is
	// in use, as well as the reverse case of setting fs/gs to
	// FS/GS_TLS_SEL when fs_base/gs_base is a 64-bit value. (We do the
	// same in PtraceSetRegs.)
	//
	// TODO: Remove this fixup since newer Linux doesn't have
	// this behavior anymore.
	if regs.Fs == 0 && regs.Fs_base <= 0xffffffff {
		regs.Fs = _FS_TLS_SEL
	}
	if regs.Gs == 0 && regs.Gs_base <= 0xffffffff {
		regs.Gs = _GS_TLS_SEL
	}
	return regs
}

var ptraceRegsSize = int(binary.Size(syscall.PtraceRegs{}))

// PtraceSetRegs implements Context.PtraceSetRegs.
func (s *State) PtraceSetRegs(src io.Reader) (int, error) {
	var regs syscall.PtraceRegs
	buf := make([]byte, ptraceRegsSize)
	if _, err := io.ReadFull(src, buf); err != nil {
		return 0, err
	}
	binary.Unmarshal(buf, usermem.ByteOrder, &regs)
	// Truncate segment registers to 16 bits.
	regs.Cs = uint64(uint16(regs.Cs))
	regs.Ds = uint64(uint16(regs.Ds))
	regs.Es = uint64(uint16(regs.Es))
	regs.Fs = uint64(uint16(regs.Fs))
	regs.Gs = uint64(uint16(regs.Gs))
	regs.Ss = uint64(uint16(regs.Ss))
	// In Linux this validation is via arch/x86/kernel/ptrace.c:putreg().
	if !isUserSegmentSelector(regs.Cs) {
		return 0, syscall.EIO
	}
	if regs.Ds != 0 && !isUserSegmentSelector(regs.Ds) {
		return 0, syscall.EIO
	}
	if regs.Es != 0 && !isUserSegmentSelector(regs.Es) {
		return 0, syscall.EIO
	}
	if regs.Fs != 0 && !isUserSegmentSelector(regs.Fs) {
		return 0, syscall.EIO
	}
	if regs.Gs != 0 && !isUserSegmentSelector(regs.Gs) {
		return 0, syscall.EIO
	}
	if !isUserSegmentSelector(regs.Ss) {
		return 0, syscall.EIO
	}
	if regs.Fs_base >= uint64(maxAddr64) {
		return 0, syscall.EIO
	}
	if regs.Gs_base >= uint64(maxAddr64) {
		return 0, syscall.EIO
	}
	// CS and SS are validated, but changes to them are otherwise silently
	// ignored on amd64.
	regs.Cs = s.Regs.Cs
	regs.Ss = s.Regs.Ss
	// fs_base/gs_base changes reset fs/gs via do_arch_prctl() on Linux.
	if regs.Fs_base != s.Regs.Fs_base {
		regs.Fs = 0
	}
	if regs.Gs_base != s.Regs.Gs_base {
		regs.Gs = 0
	}
	// Ignore "stale" TLS segment selectors for FS and GS. See comment in
	// ptraceGetRegs.
	if regs.Fs == _FS_TLS_SEL && regs.Fs_base != 0 {
		regs.Fs = 0
	}
	if regs.Gs == _GS_TLS_SEL && regs.Gs_base != 0 {
		regs.Gs = 0
	}
	regs.Eflags = (s.Regs.Eflags &^ eflagsPtraceMutable) | (regs.Eflags & eflagsPtraceMutable)
	s.Regs = regs
	return ptraceRegsSize, nil
}

// isUserSegmentSelector returns true if the given segment selector specifies a
// privilege level of 3 (USER_RPL).
func isUserSegmentSelector(reg uint64) bool {
	return reg&3 == 3
}

// ptraceFPRegsSize is the size in bytes of Linux's user_i387_struct, the type
// manipulated by PTRACE_GETFPREGS and PTRACE_SETFPREGS on x86. Equivalently,
// ptraceFPRegsSize is the size in bytes of the x86 FXSAVE area.
const ptraceFPRegsSize = 512

// PtraceGetFPRegs implements Context.PtraceGetFPRegs.
func (s *State) PtraceGetFPRegs(dst io.Writer) (int, error) {
	return dst.Write(s.x86FPState[:ptraceFPRegsSize])
}

// PtraceSetFPRegs implements Context.PtraceSetFPRegs.
func (s *State) PtraceSetFPRegs(src io.Reader) (int, error) {
	var f [ptraceFPRegsSize]byte
	n, err := io.ReadFull(src, f[:])
	if err != nil {
		return 0, err
	}
	// Force reserved bits in MXCSR to 0. This is consistent with Linux.
	sanitizeMXCSR(x86FPState(f[:]))
	// N.B. this only copies the beginning of the FP state, which
	// corresponds to the FXSAVE area.
	copy(s.x86FPState, f[:])
	return n, nil
}

const (
	// mxcsrOffset is the offset in bytes of the MXCSR field from the start of
	// the FXSAVE area. (Intel SDM Vol. 1, Table 10-2 "Format of an FXSAVE
	// Area")
	mxcsrOffset = 24

	// mxcsrMaskOffset is the offset in bytes of the MXCSR_MASK field from the
	// start of the FXSAVE area.
	mxcsrMaskOffset = 28
)

var (
	mxcsrMask     uint32
	initMXCSRMask sync.Once
)

// sanitizeMXCSR coerces reserved bits in the MXCSR field of f to 0. ("FXRSTOR
// generates a general-protection fault (#GP) in response to an attempt to set
// any of the reserved bits of the MXCSR register." - Intel SDM Vol. 1, Section
// 10.5.1.2 "SSE State")
func sanitizeMXCSR(f x86FPState) {
	mxcsr := usermem.ByteOrder.Uint32(f[mxcsrOffset:])
	initMXCSRMask.Do(func() {
		temp := x86FPState(alignedBytes(uint(ptraceFPRegsSize), 16))
		initX86FPState(temp.FloatingPointData(), false /* useXsave */)
		mxcsrMask = usermem.ByteOrder.Uint32(temp[mxcsrMaskOffset:])
		if mxcsrMask == 0 {
			// "If the value of the MXCSR_MASK field is 00000000H, then the
			// MXCSR_MASK value is the default value of 0000FFBFH." - Intel SDM
			// Vol. 1, Section 11.6.6 "Guidelines for Writing to the MXCSR
			// Register"
			mxcsrMask = 0xffbf
		}
	})
	mxcsr &= mxcsrMask
	usermem.ByteOrder.PutUint32(f[mxcsrOffset:], mxcsr)
}

const (
	// minXstateBytes is the minimum size in bytes of an x86 XSAVE area, equal
	// to the size of the XSAVE legacy area (512 bytes) plus the size of the
	// XSAVE header (64 bytes). Equivalently, minXstateBytes is GDB's
	// X86_XSTATE_SSE_SIZE.
	minXstateBytes = 512 + 64

	// userXstateXCR0Offset is the offset in bytes of the USER_XSTATE_XCR0_WORD
	// field in Linux's struct user_xstateregs, which is the type manipulated
	// by ptrace(PTRACE_GET/SETREGSET, NT_X86_XSTATE). Equivalently,
	// userXstateXCR0Offset is GDB's I386_LINUX_XSAVE_XCR0_OFFSET.
	userXstateXCR0Offset = 464

	// xstateBVOffset is the offset in bytes of the XSTATE_BV field in an x86
	// XSAVE area.
	xstateBVOffset = 512

	// xsaveHeaderZeroedOffset and xsaveHeaderZeroedBytes indicate parts of the
	// XSAVE header that we coerce to zero: "Bytes 15:8 of the XSAVE header is
	// a state-component bitmap called XCOMP_BV. ... Bytes 63:16 of the XSAVE
	// header are reserved." - Intel SDM Vol. 1, Section 13.4.2 "XSAVE Header".
	// Linux ignores XCOMP_BV, but it's able to recover from XRSTOR #GP
	// exceptions resulting from invalid values; we aren't. Linux also never
	// uses the compacted format when doing XSAVE and doesn't even define the
	// compaction extensions to XSAVE as a CPU feature, so for simplicity we
	// assume no one is using them.
	xsaveHeaderZeroedOffset = 512 + 8
	xsaveHeaderZeroedBytes  = 64 - 8
)

func (s *State) ptraceGetXstateRegs(dst io.Writer, maxlen int) (int, error) {
	// N.B. s.x86FPState may contain more state than the application
	// expects. We only copy the subset that would be in their XSAVE area.
	ess, _ := s.FeatureSet.ExtendedStateSize()
	f := make([]byte, ess)
	copy(f, s.x86FPState)
	// "The XSAVE feature set does not use bytes 511:416; bytes 463:416 are
	// reserved." - Intel SDM Vol 1., Section 13.4.1 "Legacy Region of an XSAVE
	// Area". Linux uses the first 8 bytes of this area to store the OS XSTATE
	// mask. GDB relies on this: see
	// gdb/x86-linux-nat.c:x86_linux_read_description().
	usermem.ByteOrder.PutUint64(f[userXstateXCR0Offset:], s.FeatureSet.ValidXCR0Mask())
	if len(f) > maxlen {
		f = f[:maxlen]
	}
	return dst.Write(f)
}

func (s *State) ptraceSetXstateRegs(src io.Reader, maxlen int) (int, error) {
	// Allow users to pass an xstate register set smaller than ours (they can
	// mask bits out of XSTATE_BV), as long as it's at least minXstateBytes.
	// Also allow users to pass a register set larger than ours; anything after
	// their ExtendedStateSize will be ignored. (I think Linux technically
	// permits setting a register set smaller than minXstateBytes, but it has
	// the same silent truncation behavior in kernel/ptrace.c:ptrace_regset().)
	if maxlen < minXstateBytes {
		return 0, syscall.EFAULT
	}
	ess, _ := s.FeatureSet.ExtendedStateSize()
	if maxlen > int(ess) {
		maxlen = int(ess)
	}
	f := make([]byte, maxlen)
	if _, err := io.ReadFull(src, f); err != nil {
		return 0, err
	}
	// Force reserved bits in MXCSR to 0. This is consistent with Linux.
	sanitizeMXCSR(x86FPState(f))
	// Users can't enable *more* XCR0 bits than what we, and the CPU, support.
	xstateBV := usermem.ByteOrder.Uint64(f[xstateBVOffset:])
	xstateBV &= s.FeatureSet.ValidXCR0Mask()
	usermem.ByteOrder.PutUint64(f[xstateBVOffset:], xstateBV)
	// Force XCOMP_BV and reserved bytes in the XSAVE header to 0.
	reserved := f[xsaveHeaderZeroedOffset : xsaveHeaderZeroedOffset+xsaveHeaderZeroedBytes]
	for i := range reserved {
		reserved[i] = 0
	}
	return copy(s.x86FPState, f), nil
}

// Register sets defined in include/uapi/linux/elf.h.
const (
	_NT_PRSTATUS   = 1
	_NT_PRFPREG    = 2
	_NT_X86_XSTATE = 0x202
)

// PtraceGetRegSet implements Context.PtraceGetRegSet.
func (s *State) PtraceGetRegSet(regset uintptr, dst io.Writer, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < ptraceRegsSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceGetRegs(dst)
	case _NT_PRFPREG:
		if maxlen < ptraceFPRegsSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceGetFPRegs(dst)
	case _NT_X86_XSTATE:
		return s.ptraceGetXstateRegs(dst, maxlen)
	default:
		return 0, syserror.EINVAL
	}
}

// PtraceSetRegSet implements Context.PtraceSetRegSet.
func (s *State) PtraceSetRegSet(regset uintptr, src io.Reader, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < ptraceRegsSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceSetRegs(src)
	case _NT_PRFPREG:
		if maxlen < ptraceFPRegsSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceSetFPRegs(src)
	case _NT_X86_XSTATE:
		return s.ptraceSetXstateRegs(src, maxlen)
	default:
		return 0, syserror.EINVAL
	}
}

// FullRestore indicates whether a full restore is required.
func (s *State) FullRestore() bool {
	// A fast system call return is possible only if
	//
	// * RCX matches the instruction pointer.
	// * R11 matches our flags value.
	// * Usermode does not expect to set either the resume flag or the
	//   virtual mode flags (unlikely.)
	// * CS and SS are set to the standard selectors.
	//
	// That is, SYSRET results in the correct final state.
	fastRestore := s.Regs.Rcx == s.Regs.Rip &&
		s.Regs.Eflags == s.Regs.R11 &&
		(s.Regs.Eflags&eflagsRF == 0) &&
		(s.Regs.Eflags&eflagsVM == 0) &&
		s.Regs.Cs == userCS &&
		s.Regs.Ss == userDS
	return !fastRestore
}

// New returns a new architecture context.
func New(arch Arch, fs *cpuid.FeatureSet) Context {
	switch arch {
	case AMD64:
		return &context64{
			State{
				x86FPState: newX86FPState(),
				FeatureSet: fs,
			},
			[]x86FPState(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}
