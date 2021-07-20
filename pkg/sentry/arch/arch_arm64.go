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

//go:build arm64
// +build arm64

package arch

import (
	"fmt"
	"math/rand"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/limits"
)

// Host specifies the host architecture.
const Host = ARM64

// These constants come directly from Linux.
const (
	// maxAddr64 is the maximum userspace address. It is TASK_SIZE in Linux
	// for a 64-bit process.
	maxAddr64 hostarch.Addr = (1 << 48)

	// maxStackRand64 is the maximum randomization to apply to the stack.
	// It is defined by arch/arm64/mm/mmap.c:(STACK_RND_MASK << PAGE_SHIFT) in Linux.
	maxStackRand64 = 0x3ffff << 12 // 16 GB

	// maxMmapRand64 is the maximum randomization to apply to the mmap
	// layout. It is defined by arch/arm64/mm/mmap.c:arch_mmap_rnd in Linux.
	maxMmapRand64 = (1 << 33) * hostarch.PageSize

	// minGap64 is the minimum gap to leave at the top of the address space
	// for the stack. It is defined by arch/arm64/mm/mmap.c:MIN_GAP in Linux.
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
const (
	preferredTopDownAllocMin hostarch.Addr = 0x7e8000000000
	preferredAllocationGap                 = 128 << 30 // 128 GB
	preferredTopDownBaseMin                = preferredTopDownAllocMin + preferredAllocationGap

	// minMmapRand64 is the smallest we are willing to make the
	// randomization to stay above preferredTopDownBaseMin.
	minMmapRand64 = (1 << 18) * hostarch.PageSize
)

// context64 represents an ARM64 context.
//
// +stateify savable
type context64 struct {
	State
	sigFPState []fpu.State // fpstate to be restored on sigreturn.
}

// Arch implements Context.Arch.
func (c *context64) Arch() Arch {
	return ARM64
}

func (c *context64) copySigFPState() []fpu.State {
	var sigfps []fpu.State
	for _, s := range c.sigFPState {
		sigfps = append(sigfps, s.Fork())
	}
	return sigfps
}

// Fork returns an exact copy of this context.
func (c *context64) Fork() Context {
	return &context64{
		State:      c.State.Fork(),
		sigFPState: c.copySigFPState(),
	}
}

// General purpose registers usage on Arm64:
// R0...R7: parameter/result registers.
// R8: indirect result location register.
// R9...R15: temporary rgisters.
// R16: the first intra-procedure-call scratch register.
// R17: the second intra-procedure-call scratch register.
// R18: the platform register.
// R19...R28: callee-saved registers.
// R29: the frame pointer.
// R30: the link register.

// Return returns the current syscall return value.
func (c *context64) Return() uintptr {
	return uintptr(c.Regs.Regs[0])
}

// SetReturn sets the syscall return value.
func (c *context64) SetReturn(value uintptr) {
	c.Regs.Regs[0] = uint64(value)
}

// IP returns the current instruction pointer.
func (c *context64) IP() uintptr {
	return uintptr(c.Regs.Pc)
}

// SetIP sets the current instruction pointer.
func (c *context64) SetIP(value uintptr) {
	c.Regs.Pc = uint64(value)
}

// Stack returns the current stack pointer.
func (c *context64) Stack() uintptr {
	return uintptr(c.Regs.Sp)
}

// SetStack sets the current stack pointer.
func (c *context64) SetStack(value uintptr) {
	c.Regs.Sp = uint64(value)
}

// TLS returns the current TLS pointer.
func (c *context64) TLS() uintptr {
	return uintptr(c.Regs.TPIDR_EL0)
}

// SetTLS sets the current TLS pointer. Returns false if value is invalid.
func (c *context64) SetTLS(value uintptr) bool {
	if value >= uintptr(maxAddr64) {
		return false
	}

	c.Regs.TPIDR_EL0 = uint64(value)
	return true
}

// SetOldRSeqInterruptedIP implements Context.SetOldRSeqInterruptedIP.
func (c *context64) SetOldRSeqInterruptedIP(value uintptr) {
	c.Regs.Regs[3] = uint64(value)
}

// Native returns the native type for the given val.
func (c *context64) Native(val uintptr) marshal.Marshallable {
	v := primitive.Uint64(val)
	return &v
}

// Value returns the generic val for the given native type.
func (c *context64) Value(val marshal.Marshallable) uintptr {
	return uintptr(*val.(*primitive.Uint64))
}

// Width returns the byte width of this architecture.
func (c *context64) Width() uint {
	return 8
}

// FeatureSet returns the FeatureSet in use.
func (c *context64) FeatureSet() *cpuid.FeatureSet {
	return c.State.FeatureSet
}

// mmapRand returns a random adjustment for randomizing an mmap layout.
func mmapRand(max uint64) hostarch.Addr {
	return hostarch.Addr(rand.Int63n(int64(max))).RoundDown()
}

// NewMmapLayout implements Context.NewMmapLayout consistently with Linux.
func (c *context64) NewMmapLayout(min, max hostarch.Addr, r *limits.LimitSet) (MmapLayout, error) {
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
func (c *context64) PIELoadAddress(l MmapLayout) hostarch.Addr {
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
func (c *context64) PtracePeekUser(addr uintptr) (marshal.Marshallable, error) {
	// TODO(gvisor.dev/issue/1239): Full ptrace supporting for Arm64.
	return c.Native(0), nil
}

// PtracePokeUser implements Context.PtracePokeUser.
func (c *context64) PtracePokeUser(addr, data uintptr) error {
	// TODO(gvisor.dev/issue/1239): Full ptrace supporting for Arm64.
	return nil
}

func (c *context64) FloatingPointData() *fpu.State {
	return &c.State.fpState
}
