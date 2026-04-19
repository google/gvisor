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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// SignalContext64 is equivalent to struct sigcontext, the type passed as the
// second argument to signal handlers set by signal(2).
//
// +marshal
type SignalContext64 struct {
	Regs      [33]uint64
	_	  uint64
	FpRegs    FpState 
}

// FpregsContext is equivalent to union __riscv_fp_state on riscv64
// compat_restore_fp_state() only support d extenstion at this time
// (arch/riscv/include/uapi/asm/sigcontext.h).
//
// +marshal
type FpState struct {
	_ [528]byte
}

type DState struct {
	// d extension
	Regs [32]uint64
	Fcsr  uint32
	_     uint32
}

// UContext64 is equivalent to ucontext on riscv64(arch/riscv/include/uapi/asm/ucontext.h).
//
// +marshal
type UContext64 struct {
	Flags  uint64
	Link   uint64
	Stack  linux.SignalStack
	Sigset linux.SignalSet
	// glibc uses a 1024-bit sigset_t
	_pad [120]byte // (1024 - 64) / 8 = 120
	// sigcontext must be aligned to 16-byte
	_pad2 [8]byte
	// last for future expansion
	MContext SignalContext64
}

// SignalSetup implements Context.SignalSetup. (Compare to Linux's
// arch/riscv64/kernel/signal.c:setup_rt_frame().)
func (c *Context64) SignalSetup(st *Stack, act *linux.SigAction, info *linux.SignalInfo, alt *linux.SignalStack, sigset linux.SignalSet, featureSet cpuid.FeatureSet) error {
	sp := st.Bottom

	// Construct the UContext64 now since we need its size.
	uc := &UContext64{
		Flags: 0,
		Stack: *alt,
		MContext: SignalContext64{
			Regs:   c.Regs.Regs,
		},
		Sigset: sigset,
	}

	ucSize := uc.SizeBytes()

	// frameSize = ucSize + sizeof(siginfo).
	// sizeof(siginfo) == 128.
	// R30 stores the restorer address.
	frameSize := ucSize + 128
	frameBottom := (sp - hostarch.Addr(frameSize)) & ^hostarch.Addr(15)
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

	// Set up registers.
	c.Regs.Regs[2] = uint64(st.Bottom)
	c.Regs.Regs[0] = act.Handler
	c.Regs.Regs[10] = uint64(info.Signo)
	c.Regs.Regs[11] = uint64(infoAddr)
	c.Regs.Regs[12] = uint64(ucAddr)
	c.Regs.Regs[1] = act.Restorer

	// Save the thread's floating point state.
	c.sigFPState = append(c.sigFPState, c.fpState)
	// Signal handler gets a clean floating point state.
	c.fpState = fpu.NewState()
	return nil
}

// SignalRestore implements Context.SignalRestore. (Compare to Linux's
// arch/riscv64/kernel/signal.c:sys_rt_sigreturn().)
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
	c.Regs.Regs = uc.MContext.Regs

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
		log.Warningf("sigreturn unable to restore application fpstate")
		return 0, linux.SignalStack{}, unix.EFAULT
	}

	return uc.Sigset, uc.Stack, nil
}
