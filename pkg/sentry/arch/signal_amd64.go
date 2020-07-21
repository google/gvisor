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

// +build amd64

package arch

import (
	"encoding/binary"
	"math"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/usermem"
)

// SignalContext64 is equivalent to struct sigcontext, the type passed as the
// second argument to signal handlers set by signal(2).
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
type UContext64 struct {
	Flags    uint64
	Link     uint64
	Stack    SignalStack
	MContext SignalContext64
	Sigset   linux.SignalSet
}

// NewSignalAct implements Context.NewSignalAct.
func (c *context64) NewSignalAct() NativeSignalAct {
	return &SignalAct{}
}

// NewSignalStack implements Context.NewSignalStack.
func (c *context64) NewSignalStack() NativeSignalStack {
	return &SignalStack{}
}

// From Linux 'arch/x86/include/uapi/asm/sigcontext.h' the following is the
// size of the magic cookie at the end of the xsave frame.
//
// NOTE(b/33003106#comment11): Currently we don't actually populate the fpstate
// on the signal stack.
const _FP_XSTATE_MAGIC2_SIZE = 4

func (c *context64) fpuFrameSize() (size int, useXsave bool) {
	size = len(c.x86FPState)
	if size > 512 {
		// Make room for the magic cookie at the end of the xsave frame.
		size += _FP_XSTATE_MAGIC2_SIZE
		useXsave = true
	}
	return size, useXsave
}

// SignalSetup implements Context.SignalSetup. (Compare to Linux's
// arch/x86/kernel/signal.c:__setup_rt_frame().)
func (c *context64) SignalSetup(st *Stack, act *SignalAct, info *SignalInfo, alt *SignalStack, sigset linux.SignalSet) error {
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
	sp = (sp - usermem.Addr(fpSize)) & ^usermem.Addr(63)

	ptRegs := c.Regs.PtraceRegs()
	// Construct the UContext64 now since we need its size.
	uc := &UContext64{
		// No _UC_FP_XSTATE: see Fpstate above.
		// No _UC_STRICT_RESTORE_SS: we don't allow SS changes.
		Flags: _UC_SIGCONTEXT_SS,
		Stack: *alt,
		MContext: SignalContext64{
			R8:      ptRegs.R8,
			R9:      ptRegs.R9,
			R10:     ptRegs.R10,
			R11:     ptRegs.R11,
			R12:     ptRegs.R12,
			R13:     ptRegs.R13,
			R14:     ptRegs.R14,
			R15:     ptRegs.R15,
			Rdi:     ptRegs.Rdi,
			Rsi:     ptRegs.Rsi,
			Rbp:     ptRegs.Rbp,
			Rbx:     ptRegs.Rbx,
			Rdx:     ptRegs.Rdx,
			Rax:     ptRegs.Rax,
			Rcx:     ptRegs.Rcx,
			Rsp:     ptRegs.Rsp,
			Rip:     ptRegs.Rip,
			Eflags:  ptRegs.Eflags,
			Cs:      uint16(ptRegs.Cs),
			Ss:      uint16(ptRegs.Ss),
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
	ucSize := binary.Size(uc)
	if ucSize < 0 {
		// This can only happen if we've screwed up the definition of
		// UContext64.
		panic("can't get size of UContext64")
	}
	// st.Arch.Width() is for the restorer address. sizeof(siginfo) == 128.
	frameSize := int(st.Arch.Width()) + ucSize + 128
	frameBottom := (sp-usermem.Addr(frameSize)) & ^usermem.Addr(15) - 8
	sp = frameBottom + usermem.Addr(frameSize)
	st.Bottom = sp

	// Prior to proceeding, figure out if the frame will exhaust the range
	// for the signal stack. This is not allowed, and should immediately
	// force signal delivery (reverting to the default handler).
	if act.IsOnStack() && alt.IsEnabled() && !alt.Contains(frameBottom) {
		return syscall.EFAULT
	}

	// Adjust the code.
	info.FixSignalCodeForUser()

	// Set up the stack frame.
	infoAddr, err := st.Push(info)
	if err != nil {
		return err
	}
	ucAddr, err := st.Push(uc)
	if err != nil {
		return err
	}
	if act.HasRestorer() {
		// Push the restorer return address.
		// Note that this doesn't need to be popped.
		if _, err := st.Push(usermem.Addr(act.Restorer)); err != nil {
			return err
		}
	} else {
		// amd64 requires a restorer.
		return syscall.EFAULT
	}

	// Set up registers.
	ptRegs.Rip = act.Handler
	ptRegs.Rsp = uint64(st.Bottom)
	ptRegs.Rdi = uint64(info.Signo)
	ptRegs.Rsi = uint64(infoAddr)
	ptRegs.Rdx = uint64(ucAddr)
	ptRegs.Rax = 0
	ptRegs.Ds = userDS
	ptRegs.Es = userDS
	ptRegs.Cs = userCS
	ptRegs.Ss = userDS

	// Save the thread's floating point state.
	c.sigFPState = append(c.sigFPState, c.x86FPState)

	// Signal handler gets a clean floating point state.
	c.x86FPState = newX86FPState()

	return nil
}

// SignalRestore implements Context.SignalRestore. (Compare to Linux's
// arch/x86/kernel/signal.c:sys_rt_sigreturn().)
func (c *context64) SignalRestore(st *Stack, rt bool) (linux.SignalSet, SignalStack, error) {
	// Copy out the stack frame.
	var uc UContext64
	if _, err := st.Pop(&uc); err != nil {
		return 0, SignalStack{}, err
	}
	var info SignalInfo
	if _, err := st.Pop(&info); err != nil {
		return 0, SignalStack{}, err
	}

	ptRegs := c.Regs.PtraceRegs()
	// Restore registers.
	ptRegs.R8 = uc.MContext.R8
	ptRegs.R9 = uc.MContext.R9
	ptRegs.R10 = uc.MContext.R10
	ptRegs.R11 = uc.MContext.R11
	ptRegs.R12 = uc.MContext.R12
	ptRegs.R13 = uc.MContext.R13
	ptRegs.R14 = uc.MContext.R14
	ptRegs.R15 = uc.MContext.R15
	ptRegs.Rdi = uc.MContext.Rdi
	ptRegs.Rsi = uc.MContext.Rsi
	ptRegs.Rbp = uc.MContext.Rbp
	ptRegs.Rbx = uc.MContext.Rbx
	ptRegs.Rdx = uc.MContext.Rdx
	ptRegs.Rax = uc.MContext.Rax
	ptRegs.Rcx = uc.MContext.Rcx
	ptRegs.Rsp = uc.MContext.Rsp
	ptRegs.Rip = uc.MContext.Rip
	ptRegs.Eflags = (ptRegs.Eflags & ^eflagsRestorable) | (uc.MContext.Eflags & eflagsRestorable)
	ptRegs.Cs = uint64(uc.MContext.Cs) | 3
	// N.B. _UC_STRICT_RESTORE_SS not supported.
	ptRegs.Orig_rax = math.MaxUint64

	// Restore floating point state.
	l := len(c.sigFPState)
	if l > 0 {
		c.x86FPState = c.sigFPState[l-1]
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
