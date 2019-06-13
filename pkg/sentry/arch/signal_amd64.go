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
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// SignalAct represents the action that should be taken when a signal is
// delivered, and is equivalent to struct sigaction on 64-bit x86.
//
// +stateify savable
type SignalAct struct {
	Handler  uint64
	Flags    uint64
	Restorer uint64
	Mask     linux.SignalSet
}

// SerializeFrom implements NativeSignalAct.SerializeFrom.
func (s *SignalAct) SerializeFrom(other *SignalAct) {
	*s = *other
}

// DeserializeTo implements NativeSignalAct.DeserializeTo.
func (s *SignalAct) DeserializeTo(other *SignalAct) {
	*other = *s
}

// SignalStack represents information about a user stack, and is equivalent to
// stack_t on 64-bit x86.
//
// +stateify savable
type SignalStack struct {
	Addr  uint64
	Flags uint32
	_     uint32
	Size  uint64
}

// SerializeFrom implements NativeSignalStack.SerializeFrom.
func (s *SignalStack) SerializeFrom(other *SignalStack) {
	*s = *other
}

// DeserializeTo implements NativeSignalStack.DeserializeTo.
func (s *SignalStack) DeserializeTo(other *SignalStack) {
	*other = *s
}

// SignalInfo represents information about a signal being delivered, and is
// equivalent to struct siginfo on 64-bit x86.
//
// +stateify savable
type SignalInfo struct {
	Signo int32 // Signal number
	Errno int32 // Errno value
	Code  int32 // Signal code
	_     uint32

	// struct siginfo::_sifields is a union. In SignalInfo, fields in the union
	// are accessed through methods.
	//
	// For reference, here is the definition of _sifields: (_sigfault._trapno,
	// which does not exist on x86, omitted for clarity)
	//
	// union {
	// 	int _pad[SI_PAD_SIZE];
	//
	// 	/* kill() */
	// 	struct {
	// 		__kernel_pid_t _pid;	/* sender's pid */
	// 		__ARCH_SI_UID_T _uid;	/* sender's uid */
	// 	} _kill;
	//
	// 	/* POSIX.1b timers */
	// 	struct {
	// 		__kernel_timer_t _tid;	/* timer id */
	// 		int _overrun;		/* overrun count */
	// 		char _pad[sizeof( __ARCH_SI_UID_T) - sizeof(int)];
	// 		sigval_t _sigval;	/* same as below */
	// 		int _sys_private;       /* not to be passed to user */
	// 	} _timer;
	//
	// 	/* POSIX.1b signals */
	// 	struct {
	// 		__kernel_pid_t _pid;	/* sender's pid */
	// 		__ARCH_SI_UID_T _uid;	/* sender's uid */
	// 		sigval_t _sigval;
	// 	} _rt;
	//
	// 	/* SIGCHLD */
	// 	struct {
	// 		__kernel_pid_t _pid;	/* which child */
	// 		__ARCH_SI_UID_T _uid;	/* sender's uid */
	// 		int _status;		/* exit code */
	// 		__ARCH_SI_CLOCK_T _utime;
	// 		__ARCH_SI_CLOCK_T _stime;
	// 	} _sigchld;
	//
	// 	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
	// 	struct {
	// 		void *_addr; /* faulting insn/memory ref. */
	// 		short _addr_lsb; /* LSB of the reported address */
	// 	} _sigfault;
	//
	// 	/* SIGPOLL */
	// 	struct {
	// 		__ARCH_SI_BAND_T _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
	// 		int _fd;
	// 	} _sigpoll;
	//
	// 	/* SIGSYS */
	// 	struct {
	// 		void *_call_addr; /* calling user insn */
	// 		int _syscall;	/* triggering system call number */
	// 		unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
	// 	} _sigsys;
	// } _sifields;
	//
	// _sifields is padded so that the size of siginfo is SI_MAX_SIZE = 128
	// bytes.
	Fields [128 - 16]byte
}

// FixSignalCodeForUser fixes up si_code.
//
// The si_code we get from Linux may contain the kernel-specific code in the
// top 16 bits if it's positive (e.g., from ptrace). Linux's
// copy_siginfo_to_user does
//     err |= __put_user((short)from->si_code, &to->si_code);
// to mask out those bits and we need to do the same.
func (s *SignalInfo) FixSignalCodeForUser() {
	if s.Code > 0 {
		s.Code &= 0x0000ffff
	}
}

// Pid returns the si_pid field.
func (s *SignalInfo) Pid() int32 {
	return int32(usermem.ByteOrder.Uint32(s.Fields[0:4]))
}

// SetPid mutates the si_pid field.
func (s *SignalInfo) SetPid(val int32) {
	usermem.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

// Uid returns the si_uid field.
func (s *SignalInfo) Uid() int32 {
	return int32(usermem.ByteOrder.Uint32(s.Fields[4:8]))
}

// SetUid mutates the si_uid field.
func (s *SignalInfo) SetUid(val int32) {
	usermem.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

// Sigval returns the sigval field, which is aliased to both si_int and si_ptr.
func (s *SignalInfo) Sigval() uint64 {
	return usermem.ByteOrder.Uint64(s.Fields[8:16])
}

// SetSigval mutates the sigval field.
func (s *SignalInfo) SetSigval(val uint64) {
	usermem.ByteOrder.PutUint64(s.Fields[8:16], val)
}

// TimerID returns the si_timerid field.
func (s *SignalInfo) TimerID() linux.TimerID {
	return linux.TimerID(usermem.ByteOrder.Uint32(s.Fields[0:4]))
}

// SetTimerID sets the si_timerid field.
func (s *SignalInfo) SetTimerID(val linux.TimerID) {
	usermem.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

// Overrun returns the si_overrun field.
func (s *SignalInfo) Overrun() int32 {
	return int32(usermem.ByteOrder.Uint32(s.Fields[4:8]))
}

// SetOverrun sets the si_overrun field.
func (s *SignalInfo) SetOverrun(val int32) {
	usermem.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

// Addr returns the si_addr field.
func (s *SignalInfo) Addr() uint64 {
	return usermem.ByteOrder.Uint64(s.Fields[0:8])
}

// SetAddr sets the si_addr field.
func (s *SignalInfo) SetAddr(val uint64) {
	usermem.ByteOrder.PutUint64(s.Fields[0:8], val)
}

// Status returns the si_status field.
func (s *SignalInfo) Status() int32 {
	return int32(usermem.ByteOrder.Uint32(s.Fields[8:12]))
}

// SetStatus mutates the si_status field.
func (s *SignalInfo) SetStatus(val int32) {
	usermem.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

// CallAddr returns the si_call_addr field.
func (s *SignalInfo) CallAddr() uint64 {
	return usermem.ByteOrder.Uint64(s.Fields[0:8])
}

// SetCallAddr mutates the si_call_addr field.
func (s *SignalInfo) SetCallAddr(val uint64) {
	usermem.ByteOrder.PutUint64(s.Fields[0:8], val)
}

// Syscall returns the si_syscall field.
func (s *SignalInfo) Syscall() int32 {
	return int32(usermem.ByteOrder.Uint32(s.Fields[8:12]))
}

// SetSyscall mutates the si_syscall field.
func (s *SignalInfo) SetSyscall(val int32) {
	usermem.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

// Arch returns the si_arch field.
func (s *SignalInfo) Arch() uint32 {
	return usermem.ByteOrder.Uint32(s.Fields[12:16])
}

// SetArch mutates the si_arch field.
func (s *SignalInfo) SetArch(val uint32) {
	usermem.ByteOrder.PutUint32(s.Fields[12:16], val)
}

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
