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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
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
	// Pointer to a struct _fpstate. See b/33003106#comment8.
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

// From Linux 'arch/x86/include/uapi/asm/sigcontext.h' the following is the
// size of the magic cookie at the end of the xsave frame.
//
// NOTE(b/33003106#comment11): Currently we don't actually populate the fpstate
// on the signal stack.
const _FP_XSTATE_MAGIC2_SIZE = 4

func (c *context64) fpuFrameSize() (size int, useXsave bool) {
	size = len(c.fpState)
	if size > 512 {
		// Make room for the magic cookie at the end of the xsave frame.
		size += _FP_XSTATE_MAGIC2_SIZE
		useXsave = true
	}
	return size, useXsave
}

// SignalSetup implements Context.SignalSetup. (Compare to Linux's
// arch/x86/kernel/signal.c:__setup_rt_frame().)
func (c *context64) SignalSetup(st *Stack, act *linux.SigAction, info *linux.SignalInfo, alt *linux.SignalStack, sigset linux.SignalSet) error {
	sp := st.Bottom

	// "The 128-byte area beyond the location pointed to by %rsp is considered
	// to be reserved and shall not be modified by signal or interrupt
	// handlers. ... leaf functions may use this area for their entire stack
	// frame, rather than adjusting the stack pointer in the prologue and
	// epilogue." - AMD64 ABI
	//
	// (But this doesn't apply if we're starting at the top of the signal
	// stack, in which case there is no following stack frame.)
	if !(alt.IsEnabled() && sp == alt.Top()) {
		sp -= 128
	}

	// Allocate space for floating point state on the stack.
	//
	// This isn't strictly necessary because we don't actually populate
	// the fpstate. However we do store the floating point state of the
	// interrupted thread inside the sentry. Simply accounting for this
	// space on the user stack naturally caps the amount of memory the
	// sentry will allocate for this purpose.
	fpSize, _ := c.fpuFrameSize()
	sp = (sp - hostarch.Addr(fpSize)) & ^hostarch.Addr(63)

	// Construct the UContext64 now since we need its size.
	uc := &UContext64{
		// No _UC_FP_XSTATE: see Fpstate above.
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
		},
		Sigset: sigset,
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
	frameBottom := (sp-hostarch.Addr(frameSize)) & ^hostarch.Addr(15) - 8
	sp = frameBottom + hostarch.Addr(frameSize)
	st.Bottom = sp

	// Prior to proceeding, figure out if the frame will exhaust the range
	// for the signal stack. This is not allowed, and should immediately
	// force signal delivery (reverting to the default handler).
	if act.Flags&linux.SA_ONSTACK != 0 && alt.IsEnabled() && !alt.Contains(frameBottom) {
		return unix.EFAULT
	}

	// Adjust the code.
	info.FixSignalCodeForUser()

	// Set up the stack frame.
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
	c.Regs.Ds = userDS
	c.Regs.Es = userDS
	c.Regs.Cs = userCS
	c.Regs.Ss = userDS

	// Save the thread's floating point state.
	c.sigFPState = append(c.sigFPState, c.fpState)

	// Signal handler gets a clean floating point state.
	c.fpState = fpu.NewState()

	return nil
}

// SignalRestore implements Context.SignalRestore. (Compare to Linux's
// arch/x86/kernel/signal.c:sys_rt_sigreturn().)
func (c *context64) SignalRestore(st *Stack, rt bool) (linux.SignalSet, linux.SignalStack, error) {
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

	// Restore floating point state.
	l := len(c.sigFPState)
	if l > 0 {
		c.fpState = c.sigFPState[l-1]
		// NOTE(cl/133042258): State save requires that any slice
		// elements from '[len:cap]' to be zero value.
		c.sigFPState[l-1] = nil
		c.sigFPState = c.sigFPState[0 : l-1]
	} else {
		// This might happen if sigreturn(2) calls are unbalanced with
		// respect to signal handler entries. This is not expected so
		// don't bother to do anything fancy with the floating point
		// state.
		log.Infof("sigreturn unable to restore application fpstate")
	}

	return uc.Sigset, uc.Stack, nil
}
