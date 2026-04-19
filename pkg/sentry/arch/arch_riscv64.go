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

//go:build riscv64
// +build riscv64

package arch

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
)

// Host specifies the host architecture.
const Host = RISCV64

// These constants come directly from Linux.
const (
	// maxAddr64 is the maximum userspace address. It is TASK_SIZE in Linux
	// for a 64-bit process.
	maxAddr64 hostarch.Addr = (1 << 48)

	// maxStackRand64 is the maximum randomization to apply to the stack.
	// It is defined by mm/mmap.c:(STACK_RND_MASK << PAGE_SHIFT) in Linux.
	// STACK_RND_MASK defined by arch/riscv/include/asm/elf.h
	maxStackRand64 = 0x3ffff << 12 // 16 GB

	// maxMmapRand64 is the maximum randomization to apply to the mmap
	// layout. It is defined by arch/arm64/mm/mmap.c:arch_mmap_rnd in Linux.
	maxMmapRand64 = (1 << 24) * hostarch.PageSize

	// minGap64 is the minimum gap to leave at the top of the address space
	// for the stack. It is defined by mm/util.c:MIN_GAP in Linux.
	minGap64 = (128 << 20) + maxStackRand64

	// preferredPIELoadAddr is the standard Linux position-independent
	// executable base load address. It is ELF_ET_DYN_BASE in Linux.
	//
	// The Platform {Min,Max}UserAddress() may preclude loading at this
	// address. See other preferredFoo comments below.
	preferredPIELoadAddr hostarch.Addr = maxAddr64 / 6 * 5
)

var (
	// CPUIDInstruction doesn't exist on ARM64.
	CPUIDInstruction = []byte{}
)

// These constants are selected as heuristics to help make the Platform's
// potentially limited address space conform as closely to Linux as possible.
// TODO: better constants for riscv64?
const (
	preferredTopDownAllocMin hostarch.Addr = 0x7e8000000000
	preferredAllocationGap                 = 128 << 30 // 128 GB
	preferredTopDownBaseMin                = preferredTopDownAllocMin + preferredAllocationGap

	// minMmapRand64 is the smallest we are willing to make the
	// randomization to stay above preferredTopDownBaseMin.
	minMmapRand64 = (1 << 18) * hostarch.PageSize
)

// Context64 represents an RISCV64 context.
//
// +stateify savable
type Context64 struct {
	State
	sigFPState []fpu.State // fpstate to be restored on sigreturn.
}

// Arch implements Context.Arch.
func (c *Context64) Arch() Arch {
	return RISCV64
}

func (c *Context64) copySigFPState() []fpu.State {
	var sigfps []fpu.State
	for _, s := range c.sigFPState {
		sigfps = append(sigfps, s.Fork())
	}
	return sigfps
}

// Fork returns an exact copy of this context.
func (c *Context64) Fork() *Context64 {
	return &Context64{
		State:      c.State.Fork(),
		sigFPState: c.copySigFPState(),
	}
}

// General purpose registers usage on Riscv64:

// Return returns the current syscall return value.
func (c *Context64) Return() uintptr {
	return uintptr(c.Regs.Regs[10])
}

// SetReturn sets the syscall return value.
func (c *Context64) SetReturn(value uintptr) {
	c.Regs.Regs[10] = uint64(value)
}

// IP returns the current instruction pointer.
func (c *Context64) IP() uintptr {
	return uintptr(c.Regs.Regs[0])
}

// SetIP sets the current instruction pointer.
func (c *Context64) SetIP(value uintptr) {
	c.Regs.Regs[0] = uint64(value)
}

// Stack returns the current stack pointer.
func (c *Context64) Stack() uintptr {
	return uintptr(c.Regs.Regs[2])
}

// SetStack sets the current stack pointer.
func (c *Context64) SetStack(value uintptr) {
	c.Regs.Regs[2] = uint64(value)
}

// TLS returns the current TLS pointer.
func (c *Context64) TLS() uintptr {
	return uintptr(c.Regs.Regs[4])
}

// SetTLS sets the current TLS pointer. Returns false if value is invalid.
func (c *Context64) SetTLS(value uintptr) bool {
	// TODO: figure out why we get zero when it is non-zero
	if c.Regs.Regs[4] != 0 && value == 0 {
		return true
	}
	if value >= uintptr(maxAddr64) {
		return false
	}

	c.Regs.Regs[4] = uint64(value)
	return true
}

// SetOldRSeqInterruptedIP implements Context.SetOldRSeqInterruptedIP.
func (c *Context64) SetOldRSeqInterruptedIP(value uintptr) {
	c.Regs.Regs[13] = uint64(value)
}

// Native returns the native type for the given val.
func (c *Context64) Native(val uintptr) marshal.Marshallable {
	v := primitive.Uint64(val)
	return &v
}

// Value returns the generic val for the given native type.
func (c *Context64) Value(val marshal.Marshallable) uintptr {
	return uintptr(*val.(*primitive.Uint64))
}

// Width returns the byte width of this architecture.
func (c *Context64) Width() uint {
	return 8
}

// mmapRand returns a random adjustment for randomizing an mmap layout.
func mmapRand(max uint64) hostarch.Addr {
	return hostarch.Addr(rand.Int63n(int64(max))).RoundDown()
}

// NewMmapLayout implements Context.NewMmapLayout consistently with Linux.
func (c *Context64) NewMmapLayout(min, max hostarch.Addr, r *limits.LimitSet) (MmapLayout, error) {
	min, ok := min.RoundUp()
	if !ok {
		return MmapLayout{}, unix.EINVAL
	}
	if max > maxAddr64 {
		max = maxAddr64
	}
	max = max.RoundDown()

	if min > max {
		return MmapLayout{}, unix.EINVAL
	}

	stackSize := r.Get(limits.Stack)

	// MAX_GAP in Linux.
	maxGap := (max / 6) * 5
	gap := hostarch.Addr(stackSize.Cur)
	if gap < minGap64 {
		gap = minGap64
	}
	if gap > maxGap {
		gap = maxGap
	}
	defaultDir := MmapTopDown
	if stackSize.Cur == limits.Infinity {
		defaultDir = MmapBottomUp
	}

	topDownMin := max - gap - maxMmapRand64
	maxRand := hostarch.Addr(maxMmapRand64)
	if topDownMin < preferredTopDownBaseMin {
		// Try to keep TopDownBase above preferredTopDownBaseMin by
		// shrinking maxRand.
		maxAdjust := maxRand - minMmapRand64
		needAdjust := preferredTopDownBaseMin - topDownMin
		if needAdjust <= maxAdjust {
			maxRand -= needAdjust
		}
	}

	rnd := mmapRand(uint64(maxRand))
	l := MmapLayout{
		MinAddr: min,
		MaxAddr: max,
		// TASK_UNMAPPED_BASE in Linux.
		BottomUpBase:     (max/3 + rnd).RoundDown(),
		TopDownBase:      (max - gap - rnd).RoundDown(),
		DefaultDirection: defaultDir,
		// We may have reduced the maximum randomization to keep
		// TopDownBase above preferredTopDownBaseMin while maintaining
		// our stack gap. Stack allocations must use that max
		// randomization to avoiding eating into the gap.
		MaxStackRand: uint64(maxRand),
	}

	// Final sanity check on the layout.
	if !l.Valid() {
		panic(fmt.Sprintf("Invalid MmapLayout: %+v", l))
	}

	return l, nil
}

// PIELoadAddress implements Context.PIELoadAddress.
func (c *Context64) PIELoadAddress(l MmapLayout) hostarch.Addr {
	base := preferredPIELoadAddr
	max, ok := base.AddLength(maxMmapRand64)
	if !ok {
		panic(fmt.Sprintf("preferredPIELoadAddr %#x too large", base))
	}

	if max > l.MaxAddr {
		// preferredPIELoadAddr won't fit; fall back to the standard
		// Linux behavior of 2/3 of TopDownBase. TSAN won't like this.
		//
		// Don't bother trying to shrink the randomization for now.
		base = l.TopDownBase / 3 * 2
	}

	return base + mmapRand(maxMmapRand64)
}

// PtracePeekUser implements Context.PtracePeekUser.
func (c *Context64) PtracePeekUser(addr uintptr) (marshal.Marshallable, error) {
	// TODO(gvisor.dev/issue/1239): Full ptrace supporting for Arm64.
	return c.Native(0), nil
}

// PtracePokeUser implements Context.PtracePokeUser.
func (c *Context64) PtracePokeUser(addr, data uintptr) error {
	// TODO(gvisor.dev/issue/1239): Full ptrace supporting for Arm64.
	return nil
}

// FloatingPointData returns the state of the floating-point unit.
func (c *Context64) FloatingPointData() *fpu.State {
	return &c.State.fpState
}

// Registers represents the CPU registers for this architecture.
//
// +stateify savable
type Registers struct {
	linux.PtraceRegs
}

const (
	// SyscallWidth is the width of insturctions.
	SyscallWidth = 4
)

// State contains the common architecture bits for riscv64 (the build tag of this
// file ensures it's only built on riscv64).
//
// +stateify savable
type State struct {
	// The system registers.
	Regs Registers

	// Our floating point state.
	fpState fpu.State `state:"wait"`

	// OrigA0 stores the value of register A0
	OrigA0 uint64

	// determine if we need to execute riscv_flush_icache syscall
	FlushIcache bool
}

// Proto returns a protobuf representation of the system registers in State.
func (s State) Proto() *rpb.Registers {
	regs := &rpb.RISCV64Registers{
		Pc:     s.Regs.Regs[0],
		Ra:     s.Regs.Regs[1],
		Sp:     s.Regs.Regs[2],
		Gp:     s.Regs.Regs[3],
		Tp:     s.Regs.Regs[4],
		T0:     s.Regs.Regs[5],
		T1:     s.Regs.Regs[6],
		T2:     s.Regs.Regs[7],
		S0:     s.Regs.Regs[8],
		S1:     s.Regs.Regs[9],
		A0:    s.Regs.Regs[10],
		A1:    s.Regs.Regs[11],
		A2:    s.Regs.Regs[12],
		A3:    s.Regs.Regs[13],
		A4:    s.Regs.Regs[14],
		A5:    s.Regs.Regs[15],
		A6:    s.Regs.Regs[16],
		A7:    s.Regs.Regs[17],
		S2:    s.Regs.Regs[18],
		S3:    s.Regs.Regs[19],
		S4:    s.Regs.Regs[20],
		S5:    s.Regs.Regs[21],
		S6:    s.Regs.Regs[22],
		S7:    s.Regs.Regs[23],
		S8:    s.Regs.Regs[24],
		S9:    s.Regs.Regs[25],
		S10:    s.Regs.Regs[26],
		S11:    s.Regs.Regs[27],
		T3:    s.Regs.Regs[28],
		T4:    s.Regs.Regs[29],
		T5:    s.Regs.Regs[30],
		T6:    s.Regs.Regs[31],
		OrigA0:s.Regs.Regs[32],
		//Pstate: s.Regs.Sstatus,
		//Tls:    s.Regs.Tp,
	}
	return &rpb.Registers{Arch: &rpb.Registers_Riscv64{Riscv64: regs}}
}

// Fork creates and returns an identical copy of the state.
func (s *State) Fork() State {
	return State{
		Regs:    s.Regs,
		fpState: s.fpState.Fork(),
		OrigA0:  s.OrigA0,
	}
}

// StateData implements Context.StateData.
func (s *State) StateData() *State {
	return s
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
		"Pc":     uintptr(s.Regs.Regs[0]),
		"Ra":     uintptr(s.Regs.Regs[1]),
		"Sp":     uintptr(s.Regs.Regs[2]),
		"Gp":     uintptr(s.Regs.Regs[3]),
		"Tp":     uintptr(s.Regs.Regs[4]),
		"T0":     uintptr(s.Regs.Regs[5]),
		"T1":     uintptr(s.Regs.Regs[6]),
		"T2":     uintptr(s.Regs.Regs[7]),
		"S0":     uintptr(s.Regs.Regs[8]),
		"S1":     uintptr(s.Regs.Regs[9]),
		"A0":    uintptr(s.Regs.Regs[10]),
		"A1":    uintptr(s.Regs.Regs[11]),
		"A2":    uintptr(s.Regs.Regs[12]),
		"A3":    uintptr(s.Regs.Regs[13]),
		"A4":    uintptr(s.Regs.Regs[14]),
		"A5":    uintptr(s.Regs.Regs[15]),
		"A6":    uintptr(s.Regs.Regs[16]),
		"A7":    uintptr(s.Regs.Regs[17]),
		"S2":    uintptr(s.Regs.Regs[18]),
		"S3":    uintptr(s.Regs.Regs[19]),
		"S4":    uintptr(s.Regs.Regs[20]),
		"S5":    uintptr(s.Regs.Regs[21]),
		"S6":    uintptr(s.Regs.Regs[22]),
		"S7":    uintptr(s.Regs.Regs[23]),
		"S8":    uintptr(s.Regs.Regs[24]),
		"S9":    uintptr(s.Regs.Regs[25]),
		"S10":    uintptr(s.Regs.Regs[26]),
		"S11":    uintptr(s.Regs.Regs[27]),
		"T3":    uintptr(s.Regs.Regs[28]),
		"T4":    uintptr(s.Regs.Regs[29]),
		"T5":    uintptr(s.Regs.Regs[30]),
		"T6":     uintptr(s.Regs.Regs[31]),
		"OrigA0":     uintptr(s.Regs.Regs[32]),
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
	/*
	if !regs.validRegs() {
		return 0, linuxerr.EINVAL
	}
	*/
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
	//_NT_ARM_TLS  = 0x401
)

// PtraceGetRegSet implements Context.PtraceGetRegSet.
func (s *State) PtraceGetRegSet(regset uintptr, dst io.Writer, maxlen int, _ cpuid.FeatureSet) (int, error) {
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
func (s *State) PtraceSetRegSet(regset uintptr, src io.Reader, maxlen int, _ cpuid.FeatureSet) (int, error) {
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
func New(arch Arch) *Context64 {
	switch arch {
	case RISCV64:
		return &Context64{
			State{
				fpState: fpu.NewState(),
			},
			[]fpu.State(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}
