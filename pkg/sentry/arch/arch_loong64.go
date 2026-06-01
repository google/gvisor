// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package arch

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
)

// Host specifies the host architecture.
const Host = LOONGARCH64

// LoongArch64 register-index aliases used throughout this package. These
// match the LoongArch psABI v2: $r0 is hard-wired zero, $r1 is the return
// address, $r2 is the thread pointer (TLS), $r3 is the stack pointer,
// $r4..$r11 are a0..a7 (the syscall ABI uses a0..a5 for arguments, a7 for
// the syscall number, and a0 for the return value).
const (
	regZero = 0  // $r0  : always zero
	regRA   = 1  // $r1  : return address
	regTP   = 2  // $r2  : thread pointer (TLS)
	regSP   = 3  // $r3  : stack pointer
	regA0   = 4  // $r4  : syscall arg 0 / return
	regA1   = 5
	regA2   = 6
	regA3   = 7
	regA4   = 8
	regA5   = 9
	regA6   = 10
	regA7   = 11 // $r11 : syscall number
	regT0   = 12 // first temporary, used here for SetOldRSeqInterruptedIP
)

// SyscallWidth is the width of LoongArch's `syscall 0` instruction (4 bytes).
const SyscallWidth = 4

// LoongArch (mainline Linux) uses a single 48-bit user VA window with 4-level
// page tables and 16K pages, so unlike arm64 we have just one configuration.
const (
	maxAddr64                hostarch.Addr = 1 << 48
	maxMmapRand64            hostarch.Addr = 1 << 30 // 1 GiB, conservative
	minMmapRand64            hostarch.Addr = 1 << 18 // 256 KiB
	maxStackRand64           hostarch.Addr = 0x3ffff << hostarch.PageShift
	preferredTopDownAllocMin hostarch.Addr = 0x7e8000000000
	preferredAllocationGap   hostarch.Addr = 128 << 30 // 128 GiB
	preferredPIELoadAddr     hostarch.Addr = maxAddr64 / 6 * 5
)

var (
	// minGap64 is the minimum gap reserved at the top of the address space
	// for the stack.
	minGap64 hostarch.Addr = hostarch.Addr(128<<20) + maxStackRand64

	// preferredTopDownBaseMin is derived from the constants above.
	preferredTopDownBaseMin hostarch.Addr = preferredTopDownAllocMin + preferredAllocationGap

	// CPUIDInstruction has no equivalent on LoongArch (the CPUCFG
	// instruction is used instead, but it is not exposed here).
	CPUIDInstruction = []byte{}
)

// ConfigureAddressSpace is a no-op on LoongArch64 because we only support
// the canonical 48-bit task layout. Provided for interface parity with arm64.
func ConfigureAddressSpace(taskSize uintptr) {
	if taskSize != 1<<48 {
		panic(fmt.Sprintf("unsupported LoongArch64 task size: %#x", taskSize))
	}
}

// Registers represents the CPU registers visible at EL0 on LoongArch64.
// PtraceRegs already carries the 32 GPRs (including $r2=tp and $r3=sp),
// OrigA0, Era (CSR.ERA) and Badv (CSR.BADV), so no extra fields are needed.
//
// +stateify savable
type Registers struct {
	linux.PtraceRegs
}

// State is the LoongArch64 user-mode CPU state.
//
// +stateify savable
type State struct {
	// Regs holds the integer registers.
	Regs Registers

	// fpState holds the floating-point unit state.
	fpState fpu.State `state:"wait"`

	// OrigA0 is the saved original $a0. It is a sentry-private copy (NOT
	// part of PtraceRegs / user_pt_regs) so that a ptrace GETREGSET does
	// not clobber it. Mirrors arm64's State.OrigR0.
	OrigA0 uint64
}

// Proto returns a protobuf representation of the integer registers.
func (s State) Proto() *rpb.Registers {
	regs := &rpb.LoongArch64Registers{
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
		R31:    s.Regs.Regs[31],
		OrigA0: s.Regs.OrigA0,
		Era:    s.Regs.Era,
		Badv:   s.Regs.Badv,
	}
	return &rpb.Registers{Arch: &rpb.Registers_Loong64{Loong64: regs}}
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
func (s *State) StateData() *State { return s }

// SingleStep implements Context.SingleStep.
func (s *State) SingleStep() bool { return false }

// SetSingleStep enables single stepping. TODO: not yet supported.
func (s *State) SetSingleStep() {}

// ClearSingleStep disables single stepping.
func (s *State) ClearSingleStep() {}

// RegisterMap returns all registers in a map keyed by canonical name.
func (s *State) RegisterMap() (map[string]uintptr, error) {
	m := make(map[string]uintptr, 36)
	for i := 0; i < 32; i++ {
		m[fmt.Sprintf("R%d", i)] = uintptr(s.Regs.Regs[i])
	}
	m["OrigA0"] = uintptr(s.Regs.OrigA0)
	m["Era"] = uintptr(s.Regs.Era)
	m["Badv"] = uintptr(s.Regs.Badv)
	return m, nil
}

// PtraceGetRegs implements Context.PtraceGetRegs.
func (s *State) PtraceGetRegs(dst io.Writer) (int, error) {
	regs := s.ptraceGetRegs()
	n, err := regs.WriteTo(dst)
	return int(n), err
}

func (s *State) ptraceGetRegs() Registers { return s.Regs }

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
// TODO: not yet wired up — Sentry FPU restore on LoongArch is minimal.
func (s *State) PtraceGetFPRegs(dst io.Writer) (int, error) { return 0, nil }

// PtraceSetFPRegs implements Context.PtraceSetFPRegs.
func (s *State) PtraceSetFPRegs(src io.Reader) (int, error) { return 0, nil }

// ELF note types defined in include/uapi/linux/elf.h.
const (
	_NT_PRSTATUS = 1
	_NT_PRFPREG  = 2
)

// PtraceGetRegSet implements Context.PtraceGetRegSet.
func (s *State) PtraceGetRegSet(regset uintptr, dst io.Writer, maxlen int, _ cpuid.FeatureSet) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen <= 0 {
			return 0, linuxerr.EFAULT
		}
		if maxlen >= ptraceRegistersSize {
			return s.PtraceGetRegs(dst)
		}
		regs := s.ptraceGetRegs()
		buf := make([]byte, regs.SizeBytes())
		regs.MarshalBytes(buf)
		return dst.Write(buf[:maxlen])
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

// FullRestore indicates whether a full restore is required. LoongArch64
// does not require it — same as arm64.
func (s *State) FullRestore() bool { return false }

// New returns a new architecture context.
func New(arch Arch) *Context64 {
	switch arch {
	case LOONGARCH64:
		return &Context64{
			State{
				fpState: fpu.NewState(),
			},
			[]fpu.State(nil),
		}
	}
	panic(fmt.Sprintf("unknown architecture %v", arch))
}

// Context64 represents a LoongArch64 user context.
//
// +stateify savable
type Context64 struct {
	State
	sigFPState []fpu.State // FP state stack saved across nested signals.
}

// Arch implements Context.Arch.
func (c *Context64) Arch() Arch { return LOONGARCH64 }

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

// Return returns the syscall return value (in $a0 = $r4).
func (c *Context64) Return() uintptr { return uintptr(c.Regs.Regs[regA0]) }

// SetReturn sets the syscall return value.
func (c *Context64) SetReturn(value uintptr) { c.Regs.Regs[regA0] = uint64(value) }

// IP returns the program counter (CSR.ERA on LoongArch).
func (c *Context64) IP() uintptr { return uintptr(c.Regs.Era) }

// SetIP sets the program counter.
func (c *Context64) SetIP(value uintptr) { c.Regs.Era = uint64(value) }

// Stack returns the stack pointer ($r3).
func (c *Context64) Stack() uintptr { return uintptr(c.Regs.Regs[regSP]) }

// SetStack sets the stack pointer.
func (c *Context64) SetStack(value uintptr) { c.Regs.Regs[regSP] = uint64(value) }

// TLS returns the thread pointer ($r2). Unlike arm64, where TLS lives in the
// EL0 CSR TPIDR_EL0, LoongArch keeps it in the regular GPR file.
func (c *Context64) TLS() uintptr { return uintptr(c.Regs.Regs[regTP]) }

// SetTLS sets the thread pointer.
func (c *Context64) SetTLS(value uintptr) bool {
	if value >= uintptr(maxAddr64) {
		return false
	}
	c.Regs.Regs[regTP] = uint64(value)
	return true
}

// SetOldRSeqInterruptedIP stashes the interrupted-IP for rseq into a
// scratch temporary register ($t0 = $r12). $r3 (arm64's pick) is the stack
// pointer on LoongArch and must not be clobbered.
func (c *Context64) SetOldRSeqInterruptedIP(value uintptr) {
	c.Regs.Regs[regT0] = uint64(value)
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
func (c *Context64) Width() uint { return 8 }

// mmapRand returns a random adjustment for the mmap layout.
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
	maxRand := maxMmapRand64
	if topDownMin < preferredTopDownBaseMin {
		maxAdjust := maxRand - minMmapRand64
		needAdjust := preferredTopDownBaseMin - topDownMin
		if needAdjust <= maxAdjust {
			maxRand -= needAdjust
		}
	}

	rnd := mmapRand(uint64(maxRand))
	l := MmapLayout{
		MinAddr:          min,
		MaxAddr:          max,
		BottomUpBase:     (max/3 + rnd).RoundDown(),
		TopDownBase:      (max - gap - rnd).RoundDown(),
		DefaultDirection: defaultDir,
		MaxStackRand:     uint64(maxStackRand64),
	}

	if !l.Valid() {
		panic(fmt.Sprintf("Invalid MmapLayout: %+v", l))
	}
	return l, nil
}

// PIELoadAddress implements Context.PIELoadAddress.
func (c *Context64) PIELoadAddress(l MmapLayout) hostarch.Addr {
	base := preferredPIELoadAddr
	max, ok := base.AddLength(uint64(maxMmapRand64))
	if !ok {
		panic(fmt.Sprintf("preferredPIELoadAddr %#x too large", base))
	}
	if max > l.MaxAddr {
		base = l.TopDownBase / 3 * 2
	}
	return base + mmapRand(uint64(maxMmapRand64))
}

// PtracePeekUser is a stub. Full PEEKUSER support is out of scope for the
// LoongArch64 port (matches arm64's behavior in upstream).
func (c *Context64) PtracePeekUser(addr uintptr) (marshal.Marshallable, error) {
	return c.Native(0), nil
}

// PtracePokeUser is a stub for the same reason.
func (c *Context64) PtracePokeUser(addr, data uintptr) error { return nil }

// FloatingPointData returns the state of the floating-point unit.
func (c *Context64) FloatingPointData() *fpu.State { return &c.State.fpState }
