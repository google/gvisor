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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// LoongArch extended-context magic numbers, from
// arch/loongarch/include/uapi/asm/sigcontext.h.
const (
	_FPU_CTX_MAGIC = 0x46505501
	_END_CTX_MAGIC = 0
)

// SctxInfo is the header preceding each entry in sigcontext.sc_extcontext.
// Layout matches `struct sctx_info`: { __u32 magic; __u32 size; __u64 _pad; }.
//
// +marshal
type SctxInfo struct {
	Magic   uint32
	Size    uint32
	Padding uint64
}

// FpuContext is the per-task floating-point save area, identified by
// FPU_CTX_MAGIC. Matches `struct fpu_context`: 32 doubles + FCC + FCSR
// (rounded up to 8-byte alignment with an explicit pad).
//
// We do NOT save LSX/LASX/LBT state — those magic values are filtered out
// of FeatureSet.AllowedHWCap1, so a sandboxed program should not rely on
// them. If it does, the kernel will fail to restore them, which is
// acceptable for the OJ workload.
//
// +marshal
type FpuContext struct {
	Regs [32]uint64
	Fcc  uint64
	Fcsr uint32
	_    uint32 // explicit pad to align next ext-context
}

// SignalContext64 is `struct sigcontext` for LoongArch64. The fixed prefix
// is { pc, regs[32], flags, pad[4] } at 272 bytes (16-byte aligned), after
// which we inline a single FPU extended context plus the END terminator.
//
// +marshal
type SignalContext64 struct {
	Pc    uint64
	Regs  [32]uint64
	Flags uint32
	_     [4]byte // pad so the extended-context area is 16-byte aligned

	// Inlined extended context: FPU, then END.
	FpuInfo SctxInfo
	Fpu     FpuContext
	EndInfo SctxInfo
}

// UContext64 is `struct ucontext` for LoongArch64. Layout:
//
//	uc_flags : 8 bytes
//	uc_link  : 8 bytes
//	uc_stack : 24 bytes (linux.SignalStack)
//	uc_sigmask : 8 bytes (linux.SignalSet, sigset_t)
//	unused  : (1024/8) - 8 = 120 bytes
//	pad     : 8 bytes (so uc_mcontext is 16-byte aligned)
//	uc_mcontext : SignalContext64
//
// +marshal
type UContext64 struct {
	Flags    uint64
	Link     uint64
	Stack    linux.SignalStack
	Sigset   linux.SignalSet
	_        [120]byte
	_        [8]byte
	MContext SignalContext64
}

// validRegs vets a set of registers loaded from userspace via PtraceSetRegs
// or sigreturn. LoongArch does not surface privilege-level bits to userspace
// the way arm64 does (PSTATE), so the policy here is very permissive: we
// only ensure $r0 stays zero. Anything else could be deliberate.
func (regs *Registers) validRegs() bool {
	regs.Regs[0] = 0
	return true
}

// SignalSetup implements Context.SignalSetup. It pushes a siginfo_t followed
// by a ucontext_t onto the signal stack, then redirects execution to the
// user-installed handler with the LoongArch-mandated argument convention:
//
//	$a0 = signo
//	$a1 = &siginfo
//	$a2 = &ucontext
//	$ra = restorer (rt_sigreturn trampoline)
//	$sp = signal frame top
func (c *Context64) SignalSetup(st *Stack, act *linux.SigAction, info *linux.SignalInfo, alt *linux.SignalStack, sigset linux.SignalSet, featureSet cpuid.FeatureSet) error {
	sp := st.Bottom

	uc := &UContext64{
		Flags: 0,
		Stack: *alt,
		MContext: SignalContext64{
			Pc:      c.Regs.Era,
			Regs:    c.Regs.Regs,
			FpuInfo: SctxInfo{Magic: _FPU_CTX_MAGIC, Size: uint32(16 + 272)},
			EndInfo: SctxInfo{Magic: _END_CTX_MAGIC, Size: 0},
		},
		Sigset: sigset,
	}

	ucSize := uc.SizeBytes()

	// Stack frame layout (high to low): [ucontext | siginfo].
	// sizeof(siginfo) == 128.
	frameSize := ucSize + 128
	frameBottom := (sp - hostarch.Addr(frameSize)) & ^hostarch.Addr(15)
	sp = frameBottom + hostarch.Addr(frameSize)
	st.Bottom = sp

	if act.Flags&linux.SA_ONSTACK != 0 && alt.IsEnabled() && !alt.Contains(frameBottom) {
		return unix.EFAULT
	}

	info.FixSignalCodeForUser()

	if _, err := info.CopyOut(st, StackBottomMagic); err != nil {
		return err
	}
	infoAddr := st.Bottom
	if _, err := uc.CopyOut(st, StackBottomMagic); err != nil {
		return err
	}
	ucAddr := st.Bottom

	// Redirect execution to the handler.
	c.Regs.Regs[regSP] = uint64(st.Bottom)
	c.Regs.Era = act.Handler
	c.Regs.Regs[regA0] = uint64(info.Signo)
	c.Regs.Regs[regA1] = uint64(infoAddr)
	c.Regs.Regs[regA2] = uint64(ucAddr)
	c.Regs.Regs[regRA] = act.Restorer

	// Save and reset FP state for the handler.
	c.sigFPState = append(c.sigFPState, c.fpState)
	c.fpState = fpu.NewState()
	return nil
}

// SignalRestore implements Context.SignalRestore (rt_sigreturn).
func (c *Context64) SignalRestore(st *Stack, rt bool, featureSet cpuid.FeatureSet) (linux.SignalSet, linux.SignalStack, error) {
	var uc UContext64
	if _, err := uc.CopyIn(st, StackBottomMagic); err != nil {
		return 0, linux.SignalStack{}, err
	}
	var info linux.SignalInfo
	if _, err := info.CopyIn(st, StackBottomMagic); err != nil {
		return 0, linux.SignalStack{}, err
	}

	// Restore integer registers from the saved sigcontext.
	c.Regs.Regs = uc.MContext.Regs
	c.Regs.Era = uc.MContext.Pc

	if !c.Regs.validRegs() {
		return 0, linux.SignalStack{}, unix.EFAULT
	}

	// Pop FP state.
	l := len(c.sigFPState)
	if l > 0 {
		c.fpState = c.sigFPState[l-1]
		c.sigFPState[l-1] = nil
		c.sigFPState = c.sigFPState[0 : l-1]
	} else {
		// Unbalanced sigreturn — leave FP state alone, but warn.
		log.Warningf("sigreturn unable to restore application fpstate")
		return 0, linux.SignalStack{}, unix.EFAULT
	}

	return uc.Sigset, uc.Stack, nil
}
