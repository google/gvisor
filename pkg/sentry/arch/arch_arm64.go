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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
	"gvisor.dev/gvisor/pkg/sentry/limits"
)

// Host specifies the host architecture.
const Host = ARM64

// --- 39-bit VA (3-level page tables, 512 GB) ---
const (
	maxAddr64VA39                hostarch.Addr = 1 << 39
	maxMmapRand64VA39            hostarch.Addr = (1 << 24) * hostarch.PageSize // ARCH_MMAP_RND_BITS_MAX=24
	minMmapRand64VA39            hostarch.Addr = (1 << 18) * hostarch.PageSize // ARCH_MMAP_RND_BITS_MIN=18
	preferredTopDownAllocMinVA39 hostarch.Addr = 0x5800000000                  // ~352 GB, ~68.8%
	preferredAllocationGapVA39   hostarch.Addr = 16 << 30                      // 16 GB
	preferredPIELoadAddrVA39     hostarch.Addr = maxAddr64VA39 / 6 * 5
)

// --- 48-bit VA (4-level page tables, 256 TB) ---
const (
	maxAddr64VA48 hostarch.Addr = 1 << 48
	// The following 2 value is synced from 2bdc95b
	maxMmapRand64VA48            hostarch.Addr = 1 << 45 // ARCH_MMAP_RND_BITS_MAX=33
	minMmapRand64VA48            hostarch.Addr = 1 << 30
	preferredTopDownAllocMinVA48 hostarch.Addr = 0x7e8000000000
	preferredAllocationGapVA48   hostarch.Addr = 128 << 30 // 128 GB
	preferredPIELoadAddrVA48     hostarch.Addr = maxAddr64VA48 / 6 * 5
)

// --- 52-bit VA (5-level page tables, 4 PB) ---
//
// Critical notes:
//
//  1. PIE: Linux uses DEFAULT_MAP_WINDOW_64 (= 1<<48) rather than
//     TASK_SIZE_64 (= 1<<52) for ELF_ET_DYN_BASE when
//     CONFIG_ARM64_FORCE_52BIT is not set. Most processes do not
//     need addresses above 48-bit; keeping PIE in the 48-bit
//     window avoids compatibility issues with userspace code.
//
//  2. MMAP randomization: ARCH_MMAP_RND_BITS_MAX for 52-bit VA
//     is 33 (same as 48-bit), NOT 37 as the formula would suggest.
//     This is because mmap_rnd_bits is a global sysctl and the
//     same process can mix 48-bit and 52-bit mmap calls.
const (
	maxAddr64VA52                hostarch.Addr = 1 << 52
	maxMmapRand64VA52            hostarch.Addr = 1 << 45 // same as 48-bit
	minMmapRand64VA52            hostarch.Addr = 1 << 30
	preferredTopDownAllocMinVA52 hostarch.Addr = 0x7e80000000000 // ~2024 TB
	preferredAllocationGapVA52   hostarch.Addr = 128 << 30
	preferredPIELoadAddrVA52     hostarch.Addr = maxAddr64VA52 / 6 * 5
)

// --- VA-width independent constants ---
const (
	// maxStackRand64 is the maximum randomization to apply to the stack.
	// It is defined by arch/arm64/mm/mmap.c:(STACK_RND_MASK << PAGE_SHIFT) in Linux.
	// Fixed across all VA widths on ARM64.
	maxStackRand64 hostarch.Addr = 0x3ffff << hostarch.PageShift
)

var (
	// maxAddr64 is the maximum userspace address. It is TASK_SIZE in Linux
	// for a 64-bit process.
	maxAddr64 hostarch.Addr = maxAddr64VA48

	// maxMmapRand64 is the maximum randomization to apply to the mmap
	// layout. It is defined by arch/arm64/mm/mmap.c:arch_mmap_rnd in Linux.
	// For 4K pages (PageShift=12): 1 << 45 = 32TB
	// For 64K pages (PageShift=16): 1 << 45 = 32TB (same)
	// We use a fixed value to avoid exceeding the 48-bit address space.
	maxMmapRand64 hostarch.Addr = maxMmapRand64VA48

	// minGap64 is the minimum gap to leave at the top of the address space
	// for the stack. It is defined by arch/arm64/mm/mmap.c:MIN_GAP in Linux.
	minGap64 hostarch.Addr = hostarch.Addr(128<<20) + maxStackRand64

	// preferredPIELoadAddr is the standard Linux position-independent
	// executable base load address. It is ELF_ET_DYN_BASE in Linux.
	//
	// The Platform {Min,Max}UserAddress() may preclude loading at this
	// address. See other preferredFoo comments below.
	preferredPIELoadAddr hostarch.Addr = preferredPIELoadAddrVA48

	// These defaults are selected as heuristics to help make the Platform's
	// potentially limited address space conform as closely to Linux as possible.
	// They can be overridden via ConfigureAddressSpace().
	preferredTopDownAllocMin hostarch.Addr = preferredTopDownAllocMinVA48
	preferredAllocationGap   hostarch.Addr = preferredAllocationGapVA48
	preferredTopDownBaseMin  hostarch.Addr = preferredTopDownAllocMinVA48 + preferredAllocationGapVA48

	// minMmapRand64 is the smallest we are willing to make the
	// randomization to stay above preferredTopDownBaseMin.
	minMmapRand64 hostarch.Addr = minMmapRand64VA48
)

var (
	// CPUIDInstruction doesn't exist on ARM64.
	CPUIDInstruction = []byte{}
)

// ConfigureAddressSpace sets the active address space layout parameters
// based on the host virtual address space size (taskSize).
//
// Every platform MUST call this function exactly once during initialization,
// before any Context64 is created.
//
//   - systrap: ConfigureAddressSpace(uintptr(linux.TaskSize))
//   - KVM:     ConfigureAddressSpace(1 << 48)
func ConfigureAddressSpace(taskSize uintptr) {
	switch taskSize {
	case 1 << 39:
		maxAddr64 = maxAddr64VA39
		maxMmapRand64 = maxMmapRand64VA39
		minMmapRand64 = minMmapRand64VA39
		preferredTopDownAllocMin = preferredTopDownAllocMinVA39
		preferredAllocationGap = preferredAllocationGapVA39
		preferredPIELoadAddr = preferredPIELoadAddrVA39
	case 1 << 48:
		maxAddr64 = maxAddr64VA48
		maxMmapRand64 = maxMmapRand64VA48
		minMmapRand64 = minMmapRand64VA48
		preferredTopDownAllocMin = preferredTopDownAllocMinVA48
		preferredAllocationGap = preferredAllocationGapVA48
		preferredPIELoadAddr = preferredPIELoadAddrVA48
	case 1 << 52:
		maxAddr64 = maxAddr64VA52
		maxMmapRand64 = maxMmapRand64VA52
		minMmapRand64 = minMmapRand64VA52
		preferredTopDownAllocMin = preferredTopDownAllocMinVA52
		preferredAllocationGap = preferredAllocationGapVA52
		preferredPIELoadAddr = preferredPIELoadAddrVA52
	default:
		panic(fmt.Sprintf("unsupported ARM64 task size: %#x", taskSize))
	}
	preferredTopDownBaseMin = preferredTopDownAllocMin + preferredAllocationGap
}

// Context64 represents an ARM64 context.
//
// +stateify savable
type Context64 struct {
	State
	sigFPState []fpu.State // fpstate to be restored on sigreturn.
}

// Arch implements Context.Arch.
func (c *Context64) Arch() Arch {
	return ARM64
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
func (c *Context64) Return() uintptr {
	return uintptr(c.Regs.Regs[0])
}

// SetReturn sets the syscall return value.
func (c *Context64) SetReturn(value uintptr) {
	c.Regs.Regs[0] = uint64(value)
}

// IP returns the current instruction pointer.
func (c *Context64) IP() uintptr {
	return uintptr(c.Regs.Pc)
}

// SetIP sets the current instruction pointer.
func (c *Context64) SetIP(value uintptr) {
	c.Regs.Pc = uint64(value)
}

// Stack returns the current stack pointer.
func (c *Context64) Stack() uintptr {
	return uintptr(c.Regs.Sp)
}

// SetStack sets the current stack pointer.
func (c *Context64) SetStack(value uintptr) {
	c.Regs.Sp = uint64(value)
}

// TLS returns the current TLS pointer.
func (c *Context64) TLS() uintptr {
	return uintptr(c.Regs.TPIDR_EL0)
}

// SetTLS sets the current TLS pointer. Returns false if value is invalid.
func (c *Context64) SetTLS(value uintptr) bool {
	if value >= uintptr(maxAddr64) {
		return false
	}

	c.Regs.TPIDR_EL0 = uint64(value)
	return true
}

// SetOldRSeqInterruptedIP implements Context.SetOldRSeqInterruptedIP.
func (c *Context64) SetOldRSeqInterruptedIP(value uintptr) {
	c.Regs.Regs[3] = uint64(value)
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
	maxRand := maxMmapRand64
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
		// Stack randomization uses STACK_RND_MASK (maxStackRand64),
		// which is independent of mmap randomization (maxMmapRand64).
		// On ARM64, STACK_RND_MASK is fixed at ~1 GB across all VA widths.
		MaxStackRand: uint64(maxStackRand64),
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
	max, ok := base.AddLength(uint64(maxMmapRand64))
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

	return base + mmapRand(uint64(maxMmapRand64))
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
