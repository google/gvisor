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

package arch

import (
	"encoding/binary"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/usermem"
)

// SignalContext64 is equivalent to struct sigcontext, the type passed as the
// second argument to signal handlers set by signal(2).
type SignalContext64 struct {
	FaultAddr uint64
	Regs      [31]uint64
	Sp        uint64
	Pc        uint64
	Pstate    uint64
	_pad      [8]byte       // __attribute__((__aligned__(16)))
	Fpsimd64  FpsimdContext // size = 528
	Reserved  [3568]uint8
}

type aarch64Ctx struct {
	Magic uint32
	Size  uint32
}

type FpsimdContext struct {
	Head  aarch64Ctx
	Fpsr  uint32
	Fpcr  uint32
	Vregs [64]uint64 // actually [32]uint128
}

// UContext64 is equivalent to ucontext on arm64(arch/arm64/include/uapi/asm/ucontext.h).
type UContext64 struct {
	Flags  uint64
	Link   uint64
	Stack  SignalStack
	Sigset linux.SignalSet
	// glibc uses a 1024-bit sigset_t
	_pad [(1024 - 64) / 8]byte
	// sigcontext must be aligned to 16-byte
	_pad2 [8]byte
	// last for future expansion
	MContext SignalContext64
}

// NewSignalAct implements Context.NewSignalAct.
func (c *context64) NewSignalAct() NativeSignalAct {
	return &SignalAct{}
}

// NewSignalStack implements Context.NewSignalStack.
func (c *context64) NewSignalStack() NativeSignalStack {
	return &SignalStack{}
}

// SignalSetup implements Context.SignalSetup.
func (c *context64) SignalSetup(st *Stack, act *SignalAct, info *SignalInfo, alt *SignalStack, sigset linux.SignalSet) error {
	sp := st.Bottom

	if !(alt.IsEnabled() && sp == alt.Top()) {
		sp -= 128
	}

	// Construct the UContext64 now since we need its size.
	uc := &UContext64{
		Flags: 0,
		Stack: *alt,
		MContext: SignalContext64{
			Regs:   c.Regs.Regs,
			Sp:     c.Regs.Sp,
			Pc:     c.Regs.Pc,
			Pstate: c.Regs.Pstate,
		},
		Sigset: sigset,
	}

	ucSize := binary.Size(uc)
	if ucSize < 0 {
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

	// Set up registers.
	c.Regs.Sp = uint64(st.Bottom)
	c.Regs.Pc = act.Handler
	c.Regs.Regs[0] = uint64(info.Signo)
	c.Regs.Regs[1] = uint64(infoAddr)
	c.Regs.Regs[2] = uint64(ucAddr)

	return nil
}

// SignalRestore implements Context.SignalRestore.
// Only used on intel.
func (c *context64) SignalRestore(st *Stack, rt bool) (linux.SignalSet, SignalStack, error) {
	return 0, SignalStack{}, nil
}
