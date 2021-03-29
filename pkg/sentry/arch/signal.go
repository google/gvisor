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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// SignalAct represents the action that should be taken when a signal is
// delivered, and is equivalent to struct sigaction.
//
// +marshal
// +stateify savable
type SignalAct struct {
	Handler  uint64
	Flags    uint64
	Restorer uint64 // Only used on amd64.
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
// stack_t.
//
// +marshal
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
// equivalent to struct siginfo in linux kernel(linux/include/uapi/asm-generic/siginfo.h).
//
// +marshal
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

// PID returns the si_pid field.
func (s *SignalInfo) PID() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[0:4]))
}

// SetPID mutates the si_pid field.
func (s *SignalInfo) SetPID(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

// UID returns the si_uid field.
func (s *SignalInfo) UID() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[4:8]))
}

// SetUID mutates the si_uid field.
func (s *SignalInfo) SetUID(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

// Sigval returns the sigval field, which is aliased to both si_int and si_ptr.
func (s *SignalInfo) Sigval() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[8:16])
}

// SetSigval mutates the sigval field.
func (s *SignalInfo) SetSigval(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[8:16], val)
}

// TimerID returns the si_timerid field.
func (s *SignalInfo) TimerID() linux.TimerID {
	return linux.TimerID(hostarch.ByteOrder.Uint32(s.Fields[0:4]))
}

// SetTimerID sets the si_timerid field.
func (s *SignalInfo) SetTimerID(val linux.TimerID) {
	hostarch.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

// Overrun returns the si_overrun field.
func (s *SignalInfo) Overrun() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[4:8]))
}

// SetOverrun sets the si_overrun field.
func (s *SignalInfo) SetOverrun(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

// Addr returns the si_addr field.
func (s *SignalInfo) Addr() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[0:8])
}

// SetAddr sets the si_addr field.
func (s *SignalInfo) SetAddr(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], val)
}

// Status returns the si_status field.
func (s *SignalInfo) Status() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[8:12]))
}

// SetStatus mutates the si_status field.
func (s *SignalInfo) SetStatus(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

// CallAddr returns the si_call_addr field.
func (s *SignalInfo) CallAddr() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[0:8])
}

// SetCallAddr mutates the si_call_addr field.
func (s *SignalInfo) SetCallAddr(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], val)
}

// Syscall returns the si_syscall field.
func (s *SignalInfo) Syscall() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[8:12]))
}

// SetSyscall mutates the si_syscall field.
func (s *SignalInfo) SetSyscall(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

// Arch returns the si_arch field.
func (s *SignalInfo) Arch() uint32 {
	return hostarch.ByteOrder.Uint32(s.Fields[12:16])
}

// SetArch mutates the si_arch field.
func (s *SignalInfo) SetArch(val uint32) {
	hostarch.ByteOrder.PutUint32(s.Fields[12:16], val)
}

// Band returns the si_band field.
func (s *SignalInfo) Band() int64 {
	return int64(hostarch.ByteOrder.Uint64(s.Fields[0:8]))
}

// SetBand mutates the si_band field.
func (s *SignalInfo) SetBand(val int64) {
	// Note: this assumes the platform uses `long` as `__ARCH_SI_BAND_T`.
	// On some platforms, which gVisor doesn't support, `__ARCH_SI_BAND_T` is
	// `int`. See siginfo.h.
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], uint64(val))
}

// FD returns the si_fd field.
func (s *SignalInfo) FD() uint32 {
	return hostarch.ByteOrder.Uint32(s.Fields[8:12])
}

// SetFD mutates the si_fd field.
func (s *SignalInfo) SetFD(val uint32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], val)
}
