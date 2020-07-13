// Copyright 2020 The gVisor Authors.
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

package arch

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/log"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Registers represents the CPU registers for this architecture.
type Registers struct {
	ptRegs    linux.PtraceRegs
	TPIDR_EL0 uint64
}

func (r *Registers) PtraceRegs() *linux.PtraceRegs {
	return &r.ptRegs
}

func (r *Registers) TlsRegs() *uint64 {
	return &r.TPIDR_EL0
}

const (
	// SyscallWidth is the width of insturctions.
	SyscallWidth = 4

	// fpsimdMagic is the magic number which is used in fpsimd_context.
	fpsimdMagic = 0x46508001

	// fpsimdContextSize is the size of fpsimd_context.
	fpsimdContextSize = 0x210
)

// ARMTrapFlag is the mask for the trap flag.
const ARMTrapFlag = uint64(1) << 21

// aarch64FPState is aarch64 floating point state.
type aarch64FPState []byte

// initAarch64FPState sets up initial state.
//
// Related code in Linux kernel: fpsimd_flush_thread().
// FPCR = FPCR_RM_RN (0x0 << 22).
//
// Currently, aarch64FPState is only a space of 0x210 length for fpstate.
// The fp head is useless in sentry/ptrace/kvm.
//
func initAarch64FPState(data aarch64FPState) {
}

func newAarch64FPStateSlice() []byte {
	return alignedBytes(4096, 16)[:fpsimdContextSize]
}

// newAarch64FPState returns an initialized floating point state.
//
// The returned state is large enough to store all floating point state
// supported by host, even if the app won't use much of it due to a restricted
// FeatureSet.
func newAarch64FPState() aarch64FPState {
	f := aarch64FPState(newAarch64FPStateSlice())
	initAarch64FPState(f)
	return f
}

// fork creates and returns an identical copy of the aarch64 floating point state.
func (f aarch64FPState) fork() aarch64FPState {
	n := aarch64FPState(newAarch64FPStateSlice())
	copy(n, f)
	return n
}

// FloatingPointData returns the raw data pointer.
func (f aarch64FPState) FloatingPointData() *FloatingPointData {
	return (*FloatingPointData)(&f[0])
}

// NewFloatingPointData returns a new floating point data blob.
//
// This is primarily for use in tests.
func NewFloatingPointData() *FloatingPointData {
	return (*FloatingPointData)(&(newAarch64FPState()[0]))
}

// State contains the common architecture bits for aarch64 (the build tag of this
// file ensures it's only built on aarch64).
type State struct {
	// The system registers.
	Regs Registers

	// Our floating point state.
	aarch64FPState `state:"wait"`

	// FeatureSet is a pointer to the currently active feature set.
	FeatureSet *cpuid.FeatureSet

	// OrigR0 stores the value of register R0.
	OrigR0 uint64
}

// Proto returns a protobuf representation of the system registers in State.
func (s State) Proto() *rpb.Registers {
	ptRegs := s.Regs.PtraceRegs()
	regs := &rpb.ARM64Registers{
		R0:     ptRegs.Regs[0],
		R1:     ptRegs.Regs[1],
		R2:     ptRegs.Regs[2],
		R3:     ptRegs.Regs[3],
		R4:     ptRegs.Regs[4],
		R5:     ptRegs.Regs[5],
		R6:     ptRegs.Regs[6],
		R7:     ptRegs.Regs[7],
		R8:     ptRegs.Regs[8],
		R9:     ptRegs.Regs[9],
		R10:    ptRegs.Regs[10],
		R11:    ptRegs.Regs[11],
		R12:    ptRegs.Regs[12],
		R13:    ptRegs.Regs[13],
		R14:    ptRegs.Regs[14],
		R15:    ptRegs.Regs[15],
		R16:    ptRegs.Regs[16],
		R17:    ptRegs.Regs[17],
		R18:    ptRegs.Regs[18],
		R19:    ptRegs.Regs[19],
		R20:    ptRegs.Regs[20],
		R21:    ptRegs.Regs[21],
		R22:    ptRegs.Regs[22],
		R23:    ptRegs.Regs[23],
		R24:    ptRegs.Regs[24],
		R25:    ptRegs.Regs[25],
		R26:    ptRegs.Regs[26],
		R27:    ptRegs.Regs[27],
		R28:    ptRegs.Regs[28],
		R29:    ptRegs.Regs[29],
		R30:    ptRegs.Regs[30],
		Sp:     ptRegs.Sp,
		Pc:     ptRegs.Pc,
		Pstate: ptRegs.Pstate,
	}
	return &rpb.Registers{Arch: &rpb.Registers_Arm64{Arm64: regs}}
}

// Fork creates and returns an identical copy of the state.
func (s *State) Fork() State {
	return State{
		Regs:           s.Regs,
		aarch64FPState: s.aarch64FPState.fork(),
		FeatureSet:     s.FeatureSet,
		OrigR0:         s.OrigR0,
	}
}

// StateData implements Context.StateData.
func (s *State) StateData() *State {
	return s
}

// CPUIDEmulate emulates a cpuid instruction.
func (s *State) CPUIDEmulate(l log.Logger) {
	// TODO(gvisor.dev/issue/1255): cpuid is not supported.
}

// SingleStep implements Context.SingleStep.
func (s *State) SingleStep() bool {
	return false
}

// SetSingleStep enables single stepping.
func (s *State) SetSingleStep() {
	// Set the trap flag.
	// TODO(gvisor.dev/issue/1239): ptrace single-step is not supported.
}

// ClearSingleStep enables single stepping.
func (s *State) ClearSingleStep() {
	// Clear the trap flag.
	// TODO(gvisor.dev/issue/1239): ptrace single-step is not supported.
}

// RegisterMap returns a map of all registers.
func (s *State) RegisterMap() (map[string]uintptr, error) {
	ptRegs := s.Regs.PtraceRegs()
	return map[string]uintptr{
		"R0":     uintptr(ptRegs.Regs[0]),
		"R1":     uintptr(ptRegs.Regs[1]),
		"R2":     uintptr(ptRegs.Regs[2]),
		"R3":     uintptr(ptRegs.Regs[3]),
		"R4":     uintptr(ptRegs.Regs[4]),
		"R5":     uintptr(ptRegs.Regs[5]),
		"R6":     uintptr(ptRegs.Regs[6]),
		"R7":     uintptr(ptRegs.Regs[7]),
		"R8":     uintptr(ptRegs.Regs[8]),
		"R9":     uintptr(ptRegs.Regs[9]),
		"R10":    uintptr(ptRegs.Regs[10]),
		"R11":    uintptr(ptRegs.Regs[11]),
		"R12":    uintptr(ptRegs.Regs[12]),
		"R13":    uintptr(ptRegs.Regs[13]),
		"R14":    uintptr(ptRegs.Regs[14]),
		"R15":    uintptr(ptRegs.Regs[15]),
		"R16":    uintptr(ptRegs.Regs[16]),
		"R17":    uintptr(ptRegs.Regs[17]),
		"R18":    uintptr(ptRegs.Regs[18]),
		"R19":    uintptr(ptRegs.Regs[19]),
		"R20":    uintptr(ptRegs.Regs[20]),
		"R21":    uintptr(ptRegs.Regs[21]),
		"R22":    uintptr(ptRegs.Regs[22]),
		"R23":    uintptr(ptRegs.Regs[23]),
		"R24":    uintptr(ptRegs.Regs[24]),
		"R25":    uintptr(ptRegs.Regs[25]),
		"R26":    uintptr(ptRegs.Regs[26]),
		"R27":    uintptr(ptRegs.Regs[27]),
		"R28":    uintptr(ptRegs.Regs[28]),
		"R29":    uintptr(ptRegs.Regs[29]),
		"R30":    uintptr(ptRegs.Regs[30]),
		"Sp":     uintptr(ptRegs.Sp),
		"Pc":     uintptr(ptRegs.Pc),
		"Pstate": uintptr(ptRegs.Pstate),
	}, nil
}

// PtraceGetRegs implements Context.PtraceGetRegs.
func (s *State) PtraceGetRegs(dst io.Writer) (int, error) {
	regs := s.ptraceGetRegs()
	n, err := regs.WriteTo(dst)
	return int(n), err
}

func (s *State) ptraceGetRegs() linux.PtraceRegs {
	regs := s.Regs.PtraceRegs()
	return *regs
}

var registersSize = (*linux.PtraceRegs)(nil).SizeBytes()

// PtraceSetRegs implements Context.PtraceSetRegs.
func (s *State) PtraceSetRegs(src io.Reader) (int, error) {
	var regs linux.PtraceRegs
	buf := make([]byte, registersSize)
	if _, err := io.ReadFull(src, buf); err != nil {
		return 0, err
	}
	regs.UnmarshalUnsafe(buf)
	s.Regs.ptRegs = regs
	return registersSize, nil
}

// PtraceGetFPRegs implements Context.PtraceGetFPRegs.
func (s *State) PtraceGetFPRegs(dst io.Writer) (int, error) {
	// TODO(gvisor.dev/issue/1238): floating-point is not supported.
	return 0, nil
}

// PtraceSetFPRegs implements Context.PtraceSetFPRegs.
func (s *State) PtraceSetFPRegs(src io.Reader) (int, error) {
	// TODO(gvisor.dev/issue/1238): floating-point is not supported.
	return 0, nil
}

// Register sets defined in include/uapi/linux/elf.h.
const (
	_NT_PRSTATUS = 1
	_NT_PRFPREG  = 2
	_NT_ARM_TLS  = 0x401
)

// PtraceGetRegSet implements Context.PtraceGetRegSet.
func (s *State) PtraceGetRegSet(regset uintptr, dst io.Writer, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < registersSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceGetRegs(dst)
	default:
		return 0, syserror.EINVAL
	}
}

// PtraceSetRegSet implements Context.PtraceSetRegSet.
func (s *State) PtraceSetRegSet(regset uintptr, src io.Reader, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < registersSize {
			return 0, syserror.EFAULT
		}
		return s.PtraceSetRegs(src)
	default:
		return 0, syserror.EINVAL
	}
}

// FullRestore indicates whether a full restore is required.
func (s *State) FullRestore() bool {
	return false
}

// New returns a new architecture context.
func New(arch Arch, fs *cpuid.FeatureSet) Context {
	switch arch {
	case ARM64:
		return &context64{
			State{
				aarch64FPState: newAarch64FPState(),
				FeatureSet:     fs,
			},
			[]aarch64FPState(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}
