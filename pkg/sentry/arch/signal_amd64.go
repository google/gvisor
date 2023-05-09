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

//go:build amd64
// +build amd64

package arch

import (
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/usermem"
)

// SignalContext64 is equivalent to struct sigcontext, the type passed as the
// second argument to signal handlers set by signal(2).
//
// +marshal
type SignalContext64 struct {
	R8      uint64
	R9      uint64
	R10     uint64
	R11     uint64
	R12     uint64
	R13     uint64
	R14     uint64
	R15     uint64
	Rdi     uint64
	Rsi     uint64
	Rbp     uint64
	Rbx     uint64
	Rdx     uint64
	Rax     uint64
	Rcx     uint64
	Rsp     uint64
	Rip     uint64
	Eflags  uint64
	Cs      uint16
	Gs      uint16 // always 0 on amd64.
	Fs      uint16 // always 0 on amd64.
	Ss      uint16 // only restored if _UC_STRICT_RESTORE_SS (unsupported).
	Err     uint64
	Trapno  uint64
	Oldmask linux.SignalSet
	Cr2     uint64
	// Pointer to a struct _fpstate.
	Fpstate  uint64
	Reserved [8]uint64
}

// Flags for UContext64.Flags.
const (
	_UC_FP_XSTATE         = 1
	_UC_SIGCONTEXT_SS     = 2
	_UC_STRICT_RESTORE_SS = 4
)

// UContext64 is equivalent to ucontext_t on 64-bit x86.
//
// +marshal
type UContext64 struct {
	Flags    uint64
	Link     uint64
	Stack    linux.SignalStack
	MContext SignalContext64
	Sigset   linux.SignalSet
}

// FPSoftwareFrame is equivalent to struct _fpx_sw_bytes, the data stored by
// Linux in bytes 464:511 of the fxsave/xsave frame.
//
// +marshal
type FPSoftwareFrame struct {
	Magic1       uint32
	ExtendedSize uint32
	Xfeatures    uint64
	XstateSize   uint32
	Padding      [7]uint32
}

// From Linux's arch/x86/include/uapi/asm/sigcontext.h.
const (
	// Value of FPSoftwareFrame.Magic1.
	_FP_XSTATE_MAGIC1 = 0x46505853

	// Value written to the 4 bytes inserted by Linux after the fxsave/xsave
	// area in the signal frame.
	_FP_XSTATE_MAGIC2      = 0x46505845
	_FP_XSTATE_MAGIC2_SIZE = 4
)

// From Linux's arch/x86/include/asm/fpu/types.h.
const (
	// xsave features that are always enabled in signal frame fpstate.
	_XFEATURE_MASK_FPSSE = 0x3
)

// SignalSetup implements Context.SignalSetup. (Compare to Linux's
// arch/x86/kernel/signal.c:__setup_rt_frame().)
func (c *Context64) SignalSetup(st *Stack, act *linux.SigAction, info *linux.SignalInfo, alt *linux.SignalStack, sigset linux.SignalSet, featureSet cpuid.FeatureSet) error {
	// "The 128-byte area beyond the location pointed to by %rsp is considered
	// to be reserved and shall not be modified by signal or interrupt
	// handlers. ... leaf functions may use this area for their entire stack
	// frame, rather than adjusting the stack pointer in the prologue and
	// epilogue." - AMD64 ABI
	//
	// (But this doesn't apply if we're starting at the top of the signal
	// stack, in which case there is no following stack frame.)
	sp := st.Bottom
	if !(alt.IsEnabled() && sp == alt.Top()) {
		sp -= 128
	}

	// Allocate space for floating point state on the stack.
	fpSize, fpAlign := featureSet.ExtendedStateSize()
	if fpSize < 512 {
		// We expect support for at least FXSAVE.
		fpSize = 512
	}
	fpSize += _FP_XSTATE_MAGIC2_SIZE
	fpStart := (sp - hostarch.Addr(fpSize)) & ^hostarch.Addr(fpAlign-1)

	// Construct the UContext64 now since we need its size.
	uc := &UContext64{
		// No _UC_STRICT_RESTORE_SS: we don't allow SS changes.
		Flags: _UC_SIGCONTEXT_SS,
		Stack: *alt,
		MContext: SignalContext64{
			R8:      c.Regs.R8,
			R9:      c.Regs.R9,
			R10:     c.Regs.R10,
			R11:     c.Regs.R11,
			R12:     c.Regs.R12,
			R13:     c.Regs.R13,
			R14:     c.Regs.R14,
			R15:     c.Regs.R15,
			Rdi:     c.Regs.Rdi,
			Rsi:     c.Regs.Rsi,
			Rbp:     c.Regs.Rbp,
			Rbx:     c.Regs.Rbx,
			Rdx:     c.Regs.Rdx,
			Rax:     c.Regs.Rax,
			Rcx:     c.Regs.Rcx,
			Rsp:     c.Regs.Rsp,
			Rip:     c.Regs.Rip,
			Eflags:  c.Regs.Eflags,
			Cs:      uint16(c.Regs.Cs),
			Ss:      uint16(c.Regs.Ss),
			Oldmask: sigset,
			Fpstate: uint64(fpStart),
		},
		Sigset: sigset,
	}
	if featureSet.UseXsave() {
		uc.Flags |= _UC_FP_XSTATE
	}

	// TODO(gvisor.dev/issue/159): Set SignalContext64.Err, Trapno, and Cr2
	// based on the fault that caused the signal. For now, leave Err and
	// Trapno unset and assume CR2 == info.Addr() for SIGSEGVs and
	// SIGBUSes.
	if linux.Signal(info.Signo) == linux.SIGSEGV || linux.Signal(info.Signo) == linux.SIGBUS {
		uc.MContext.Cr2 = info.Addr()
	}

	// "... the value (%rsp+8) is always a multiple of 16 (...) when
	// control is transferred to the function entry point." - AMD64 ABI
	ucSize := uc.SizeBytes()
	// st.Arch.Width() is for the restorer address. sizeof(siginfo) == 128.
	frameSize := int(st.Arch.Width()) + ucSize + 128
	frameStart := (fpStart-hostarch.Addr(frameSize)) & ^hostarch.Addr(15) - 8
	frameEnd := frameStart + hostarch.Addr(frameSize)

	// Prior to proceeding, figure out if the frame will exhaust the range
	// for the signal stack. This is not allowed, and should immediately
	// force signal delivery (reverting to the default handler).
	if act.Flags&linux.SA_ONSTACK != 0 && alt.IsEnabled() && !alt.Contains(frameStart) {
		return unix.EFAULT
	}

	// Set up floating point state on the stack. Compare Linux's
	// arch/x86/kernel/fpu/signal.c:copy_fpstate_to_sigframe().
	if _, err := st.IO.CopyOut(context.Background(), fpStart, c.fpState[:464], usermem.IOOpts{}); err != nil {
		return err
	}
	fpsw := FPSoftwareFrame{
		Magic1:       _FP_XSTATE_MAGIC1,
		ExtendedSize: uint32(fpSize),
		Xfeatures:    _XFEATURE_MASK_FPSSE | featureSet.ValidXCR0Mask(),
		XstateSize:   uint32(fpSize) - _FP_XSTATE_MAGIC2_SIZE,
	}
	st.Bottom = fpStart + 512
	if _, err := fpsw.CopyOut(st, StackBottomMagic); err != nil {
		return err
	}
	if len(c.fpState) > 512 {
		if _, err := st.IO.CopyOut(context.Background(), fpStart+512, c.fpState[512:], usermem.IOOpts{}); err != nil {
			return err
		}
	}
	st.Bottom = fpStart + hostarch.Addr(fpSize)
	if _, err := primitive.CopyUint32Out(st, StackBottomMagic, _FP_XSTATE_MAGIC2); err != nil {
		return err
	}

	// Adjust the code.
	info.FixSignalCodeForUser()

	// Set up the stack frame.
	st.Bottom = frameEnd
	if _, err := info.CopyOut(st, StackBottomMagic); err != nil {
		return err
	}
	infoAddr := st.Bottom
	if _, err := uc.CopyOut(st, StackBottomMagic); err != nil {
		return err
	}
	ucAddr := st.Bottom
	if act.Flags&linux.SA_RESTORER != 0 {
		// Push the restorer return address.
		// Note that this doesn't need to be popped.
		if _, err := primitive.CopyUint64Out(st, StackBottomMagic, act.Restorer); err != nil {
			return err
		}
	} else {
		// amd64 requires a restorer.
		return unix.EFAULT
	}

	// Set up registers.
	c.Regs.Rip = act.Handler
	c.Regs.Rsp = uint64(st.Bottom)
	c.Regs.Rdi = uint64(info.Signo)
	c.Regs.Rsi = uint64(infoAddr)
	c.Regs.Rdx = uint64(ucAddr)
	c.Regs.Rax = 0
	c.Regs.Eflags &^= eflagsDF | eflagsRF | eflagsTF
	c.Regs.Ds = userDS
	c.Regs.Es = userDS
	c.Regs.Cs = userCS
	c.Regs.Ss = userDS

	// Clear floating point registers.
	c.fpState.Reset()

	return nil
}

// SignalRestore implements Context.SignalRestore. (Compare to Linux's
// arch/x86/kernel/signal.c:sys_rt_sigreturn().)
func (c *Context64) SignalRestore(st *Stack, rt bool, featureSet cpuid.FeatureSet) (linux.SignalSet, linux.SignalStack, error) {
	// Copy out the stack frame.
	var uc UContext64
	if _, err := uc.CopyIn(st, StackBottomMagic); err != nil {
		return 0, linux.SignalStack{}, err
	}
	var info linux.SignalInfo
	if _, err := info.CopyIn(st, StackBottomMagic); err != nil {
		return 0, linux.SignalStack{}, err
	}

	// Restore registers.
	c.Regs.R8 = uc.MContext.R8
	c.Regs.R9 = uc.MContext.R9
	c.Regs.R10 = uc.MContext.R10
	c.Regs.R11 = uc.MContext.R11
	c.Regs.R12 = uc.MContext.R12
	c.Regs.R13 = uc.MContext.R13
	c.Regs.R14 = uc.MContext.R14
	c.Regs.R15 = uc.MContext.R15
	c.Regs.Rdi = uc.MContext.Rdi
	c.Regs.Rsi = uc.MContext.Rsi
	c.Regs.Rbp = uc.MContext.Rbp
	c.Regs.Rbx = uc.MContext.Rbx
	c.Regs.Rdx = uc.MContext.Rdx
	c.Regs.Rax = uc.MContext.Rax
	c.Regs.Rcx = uc.MContext.Rcx
	c.Regs.Rsp = uc.MContext.Rsp
	c.Regs.Rip = uc.MContext.Rip
	c.Regs.Eflags = (c.Regs.Eflags & ^eflagsRestorable) | (uc.MContext.Eflags & eflagsRestorable)
	c.Regs.Cs = uint64(uc.MContext.Cs) | 3
	// N.B. _UC_STRICT_RESTORE_SS not supported.
	c.Regs.Orig_rax = math.MaxUint64

	// Restore floating point state. Compare Linux's
	// arch/x86/kernel/fpu/signal.c:fpu__restore_sig().
	if uc.MContext.Fpstate == 0 {
		c.fpState.Reset()
	} else {
		if _, err := st.IO.CopyIn(context.Background(), hostarch.Addr(uc.MContext.Fpstate), c.fpState, usermem.IOOpts{}); err != nil {
			c.fpState.Reset()
			return 0, linux.SignalStack{}, err
		}
		c.fpState.SanitizeUser(featureSet)
	}

	return uc.Sigset, uc.Stack, nil
}
