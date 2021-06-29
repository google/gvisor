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

// +build amd64 386

package arch

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Registers represents the CPU registers for this architecture.
//
// +stateify savable
type Registers struct {
	linux.PtraceRegs
}

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
		fpState:    s.fpState.Fork(),
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
	regs := s.ptraceGetRegs()
	n, err := regs.WriteTo(dst)
	return int(n), err
}

func (s *State) ptraceGetRegs() Registers {
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
	// TODO(gvisor.dev/issue/168): Remove this fixup since newer Linux
	// doesn't have this behavior anymore.
	if regs.Fs == 0 && regs.Fs_base <= 0xffffffff {
		regs.Fs = _FS_TLS_SEL
	}
	if regs.Gs == 0 && regs.Gs_base <= 0xffffffff {
		regs.Gs = _GS_TLS_SEL
	}
	return regs
}

var ptraceRegistersSize = (*linux.PtraceRegs)(nil).SizeBytes()

// PtraceSetRegs implements Context.PtraceSetRegs.
func (s *State) PtraceSetRegs(src io.Reader) (int, error) {
	var regs Registers
	buf := make([]byte, ptraceRegistersSize)
	if _, err := io.ReadFull(src, buf); err != nil {
		return 0, err
	}
	regs.UnmarshalUnsafe(buf)
	// Truncate segment registers to 16 bits.
	regs.Cs = uint64(uint16(regs.Cs))
	regs.Ds = uint64(uint16(regs.Ds))
	regs.Es = uint64(uint16(regs.Es))
	regs.Fs = uint64(uint16(regs.Fs))
	regs.Gs = uint64(uint16(regs.Gs))
	regs.Ss = uint64(uint16(regs.Ss))
	// In Linux this validation is via arch/x86/kernel/ptrace.c:putreg().
	if !isUserSegmentSelector(regs.Cs) {
		return 0, unix.EIO
	}
	if regs.Ds != 0 && !isUserSegmentSelector(regs.Ds) {
		return 0, unix.EIO
	}
	if regs.Es != 0 && !isUserSegmentSelector(regs.Es) {
		return 0, unix.EIO
	}
	if regs.Fs != 0 && !isUserSegmentSelector(regs.Fs) {
		return 0, unix.EIO
	}
	if regs.Gs != 0 && !isUserSegmentSelector(regs.Gs) {
		return 0, unix.EIO
	}
	if !isUserSegmentSelector(regs.Ss) {
		return 0, unix.EIO
	}
	if !isValidSegmentBase(regs.Fs_base) {
		return 0, unix.EIO
	}
	if !isValidSegmentBase(regs.Gs_base) {
		return 0, unix.EIO
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
	return ptraceRegistersSize, nil
}

// isUserSegmentSelector returns true if the given segment selector specifies a
// privilege level of 3 (USER_RPL).
func isUserSegmentSelector(reg uint64) bool {
	return reg&3 == 3
}

// isValidSegmentBase returns true if the given segment base specifies a
// canonical user address.
func isValidSegmentBase(reg uint64) bool {
	return reg < uint64(maxAddr64)
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
		if maxlen < ptraceRegistersSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceGetRegs(dst)
	case _NT_PRFPREG:
		return s.fpState.PtraceGetFPRegs(dst, maxlen)
	case _NT_X86_XSTATE:
		return s.fpState.PtraceGetXstateRegs(dst, maxlen, s.FeatureSet)
	default:
		return 0, linuxerr.EINVAL
	}
}

// PtraceSetRegSet implements Context.PtraceSetRegSet.
func (s *State) PtraceSetRegSet(regset uintptr, src io.Reader, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < ptraceRegistersSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceSetRegs(src)
	case _NT_PRFPREG:
		return s.fpState.PtraceSetFPRegs(src, maxlen)
	case _NT_X86_XSTATE:
		return s.fpState.PtraceSetXstateRegs(src, maxlen, s.FeatureSet)
	default:
		return 0, linuxerr.EINVAL
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
				fpState:    fpu.NewState(),
				FeatureSet: fs,
			},
			[]fpu.State(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}
