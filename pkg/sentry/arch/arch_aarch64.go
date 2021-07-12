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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
)

// Registers represents the CPU registers for this architecture.
//
// +stateify savable
type Registers struct {
	linux.PtraceRegs

	// TPIDR_EL0 is the EL0 Read/Write Software Thread ID Register.
	TPIDR_EL0 uint64
}

const (
	// SyscallWidth is the width of insturctions.
	SyscallWidth = 4
)

// ARMTrapFlag is the mask for the trap flag.
const ARMTrapFlag = uint64(1) << 21

// State contains the common architecture bits for aarch64 (the build tag of this
// file ensures it's only built on aarch64).
//
// +stateify savable
type State struct {
	// The system registers.
	Regs Registers

	// Our floating point state.
	fpState fpu.State `state:"wait"`

	// FeatureSet is a pointer to the currently active feature set.
	FeatureSet *cpuid.FeatureSet

	// OrigR0 stores the value of register R0.
	OrigR0 uint64
}

// Proto returns a protobuf representation of the system registers in State.
func (s State) Proto() *rpb.Registers {
	regs := &rpb.ARM64Registers{
		R0:     s.Regs.Regs[0],
		R1:     s.Regs.Regs[1],
		R2:     s.Regs.Regs[2],
		R3:     s.Regs.Regs[3],
		R4:     s.Regs.Regs[4],
		R5:     s.Regs.Regs[5],
		R6:     s.Regs.Regs[6],
		R7:     s.Regs.Regs[7],
		R8:     s.Regs.Regs[8],
		R9:     s.Regs.Regs[9],
		R10:    s.Regs.Regs[10],
		R11:    s.Regs.Regs[11],
		R12:    s.Regs.Regs[12],
		R13:    s.Regs.Regs[13],
		R14:    s.Regs.Regs[14],
		R15:    s.Regs.Regs[15],
		R16:    s.Regs.Regs[16],
		R17:    s.Regs.Regs[17],
		R18:    s.Regs.Regs[18],
		R19:    s.Regs.Regs[19],
		R20:    s.Regs.Regs[20],
		R21:    s.Regs.Regs[21],
		R22:    s.Regs.Regs[22],
		R23:    s.Regs.Regs[23],
		R24:    s.Regs.Regs[24],
		R25:    s.Regs.Regs[25],
		R26:    s.Regs.Regs[26],
		R27:    s.Regs.Regs[27],
		R28:    s.Regs.Regs[28],
		R29:    s.Regs.Regs[29],
		R30:    s.Regs.Regs[30],
		Sp:     s.Regs.Sp,
		Pc:     s.Regs.Pc,
		Pstate: s.Regs.Pstate,
		Tls:    s.Regs.TPIDR_EL0,
	}
	return &rpb.Registers{Arch: &rpb.Registers_Arm64{Arm64: regs}}
}

// Fork creates and returns an identical copy of the state.
func (s *State) Fork() State {
	return State{
		Regs:       s.Regs,
		fpState:    s.fpState.Fork(),
		FeatureSet: s.FeatureSet,
		OrigR0:     s.OrigR0,
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
	return map[string]uintptr{
		"R0":     uintptr(s.Regs.Regs[0]),
		"R1":     uintptr(s.Regs.Regs[1]),
		"R2":     uintptr(s.Regs.Regs[2]),
		"R3":     uintptr(s.Regs.Regs[3]),
		"R4":     uintptr(s.Regs.Regs[4]),
		"R5":     uintptr(s.Regs.Regs[5]),
		"R6":     uintptr(s.Regs.Regs[6]),
		"R7":     uintptr(s.Regs.Regs[7]),
		"R8":     uintptr(s.Regs.Regs[8]),
		"R9":     uintptr(s.Regs.Regs[9]),
		"R10":    uintptr(s.Regs.Regs[10]),
		"R11":    uintptr(s.Regs.Regs[11]),
		"R12":    uintptr(s.Regs.Regs[12]),
		"R13":    uintptr(s.Regs.Regs[13]),
		"R14":    uintptr(s.Regs.Regs[14]),
		"R15":    uintptr(s.Regs.Regs[15]),
		"R16":    uintptr(s.Regs.Regs[16]),
		"R17":    uintptr(s.Regs.Regs[17]),
		"R18":    uintptr(s.Regs.Regs[18]),
		"R19":    uintptr(s.Regs.Regs[19]),
		"R20":    uintptr(s.Regs.Regs[20]),
		"R21":    uintptr(s.Regs.Regs[21]),
		"R22":    uintptr(s.Regs.Regs[22]),
		"R23":    uintptr(s.Regs.Regs[23]),
		"R24":    uintptr(s.Regs.Regs[24]),
		"R25":    uintptr(s.Regs.Regs[25]),
		"R26":    uintptr(s.Regs.Regs[26]),
		"R27":    uintptr(s.Regs.Regs[27]),
		"R28":    uintptr(s.Regs.Regs[28]),
		"R29":    uintptr(s.Regs.Regs[29]),
		"R30":    uintptr(s.Regs.Regs[30]),
		"Sp":     uintptr(s.Regs.Sp),
		"Pc":     uintptr(s.Regs.Pc),
		"Pstate": uintptr(s.Regs.Pstate),
		"Tls":    uintptr(s.Regs.TPIDR_EL0),
	}, nil
}

// PtraceGetRegs implements Context.PtraceGetRegs.
func (s *State) PtraceGetRegs(dst io.Writer) (int, error) {
	regs := s.ptraceGetRegs()
	n, err := regs.WriteTo(dst)
	return int(n), err
}

func (s *State) ptraceGetRegs() Registers {
	return s.Regs
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
	s.Regs = regs
	return ptraceRegistersSize, nil
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
		if maxlen < ptraceRegistersSize {
			return 0, linuxerr.EFAULT
		}
		return s.PtraceGetRegs(dst)
	default:
		return 0, linuxerr.EINVAL
	}
}

// PtraceSetRegSet implements Context.PtraceSetRegSet.
func (s *State) PtraceSetRegSet(regset uintptr, src io.Reader, maxlen int) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < ptraceRegistersSize {
			return 0, linuxerr.EFAULT
		}
		return s.PtraceSetRegs(src)
	default:
		return 0, linuxerr.EINVAL
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
				fpState:    fpu.NewState(),
				FeatureSet: fs,
			},
			[]fpu.State(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}
