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

package linux

import (
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	// SignalMaximum is the highest valid signal number.
	SignalMaximum = 64

	// FirstStdSignal is the lowest standard signal number.
	FirstStdSignal = 1

	// LastStdSignal is the highest standard signal number.
	LastStdSignal = 31

	// FirstRTSignal is the lowest real-time signal number.
	//
	// 32 (SIGCANCEL) and 33 (SIGSETXID) are used internally by glibc.
	FirstRTSignal = 32

	// LastRTSignal is the highest real-time signal number.
	LastRTSignal = 64

	// NumStdSignals is the number of standard signals.
	NumStdSignals = LastStdSignal - FirstStdSignal + 1

	// NumRTSignals is the number of realtime signals.
	NumRTSignals = LastRTSignal - FirstRTSignal + 1
)

// Signal is a signal number.
type Signal int

// IsValid returns true if s is a valid standard or realtime signal. (0 is not
// considered valid; interfaces special-casing signal number 0 should check for
// 0 first before asserting validity.)
func (s Signal) IsValid() bool {
	return s > 0 && s <= SignalMaximum
}

// IsStandard returns true if s is a standard signal.
//
// Preconditions: s.IsValid().
func (s Signal) IsStandard() bool {
	return s <= LastStdSignal
}

// IsRealtime returns true if s is a realtime signal.
//
// Preconditions: s.IsValid().
func (s Signal) IsRealtime() bool {
	return s >= FirstRTSignal
}

// Index returns the index for signal s into arrays of both standard and
// realtime signals (e.g. signal masks).
//
// Preconditions: s.IsValid().
func (s Signal) Index() int {
	return int(s - 1)
}

// Signals.
const (
	SIGABRT   = Signal(6)
	SIGALRM   = Signal(14)
	SIGBUS    = Signal(7)
	SIGCHLD   = Signal(17)
	SIGCLD    = Signal(17)
	SIGCONT   = Signal(18)
	SIGFPE    = Signal(8)
	SIGHUP    = Signal(1)
	SIGILL    = Signal(4)
	SIGINT    = Signal(2)
	SIGIO     = Signal(29)
	SIGIOT    = Signal(6)
	SIGKILL   = Signal(9)
	SIGPIPE   = Signal(13)
	SIGPOLL   = Signal(29)
	SIGPROF   = Signal(27)
	SIGPWR    = Signal(30)
	SIGQUIT   = Signal(3)
	SIGSEGV   = Signal(11)
	SIGSTKFLT = Signal(16)
	SIGSTOP   = Signal(19)
	SIGSYS    = Signal(31)
	SIGTERM   = Signal(15)
	SIGTRAP   = Signal(5)
	SIGTSTP   = Signal(20)
	SIGTTIN   = Signal(21)
	SIGTTOU   = Signal(22)
	SIGUNUSED = Signal(31)
	SIGURG    = Signal(23)
	SIGUSR1   = Signal(10)
	SIGUSR2   = Signal(12)
	SIGVTALRM = Signal(26)
	SIGWINCH  = Signal(28)
	SIGXCPU   = Signal(24)
	SIGXFSZ   = Signal(25)
)

// SignalSet is a signal mask with a bit corresponding to each signal.
//
// +marshal
type SignalSet uint64

// SignalSetSize is the size in bytes of a SignalSet.
const SignalSetSize = 8

// MakeSignalSet returns SignalSet with the bit corresponding to each of the
// given signals set.
func MakeSignalSet(sigs ...Signal) SignalSet {
	indices := make([]int, len(sigs))
	for i, sig := range sigs {
		indices[i] = sig.Index()
	}
	return SignalSet(bits.Mask64(indices...))
}

// SignalSetOf returns a SignalSet with a single signal set.
func SignalSetOf(sig Signal) SignalSet {
	return SignalSet(bits.MaskOf64(sig.Index()))
}

// ForEachSignal invokes f for each signal set in the given mask.
func ForEachSignal(mask SignalSet, f func(sig Signal)) {
	bits.ForEachSetBit64(uint64(mask), func(i int) {
		f(Signal(i + 1))
	})
}

// 'how' values for rt_sigprocmask(2).
const (
	// SIG_BLOCK blocks the signals in the set.
	SIG_BLOCK = 0

	// SIG_UNBLOCK blocks the signals in the set.
	SIG_UNBLOCK = 1

	// SIG_SETMASK sets the signal mask to set.
	SIG_SETMASK = 2
)

// Signal actions for rt_sigaction(2), from uapi/asm-generic/signal-defs.h.
const (
	// SIG_DFL performs the default action.
	SIG_DFL = 0

	// SIG_IGN ignores the signal.
	SIG_IGN = 1
)

// Signal action flags for rt_sigaction(2), from uapi/asm-generic/signal.h.
const (
	SA_NOCLDSTOP = 0x00000001
	SA_NOCLDWAIT = 0x00000002
	SA_SIGINFO   = 0x00000004
	SA_RESTORER  = 0x04000000
	SA_ONSTACK   = 0x08000000
	SA_RESTART   = 0x10000000
	SA_NODEFER   = 0x40000000
	SA_RESETHAND = 0x80000000
	SA_NOMASK    = SA_NODEFER
	SA_ONESHOT   = SA_RESETHAND
)

// Signal stack flags for signalstack(2), from include/uapi/linux/signal.h.
const (
	SS_ONSTACK = 1
	SS_DISABLE = 2
)

// SIGPOLL si_codes.
const (
	// SI_POLL is defined as __SI_POLL in Linux 2.6.
	SI_POLL = 2 << 16

	// POLL_IN indicates that data input available.
	POLL_IN = SI_POLL | 1

	// POLL_OUT indicates that output buffers available.
	POLL_OUT = SI_POLL | 2

	// POLL_MSG indicates that an input message available.
	POLL_MSG = SI_POLL | 3

	// POLL_ERR indicates that there was an i/o error.
	POLL_ERR = SI_POLL | 4

	// POLL_PRI indicates that a high priority input available.
	POLL_PRI = SI_POLL | 5

	// POLL_HUP indicates that a device disconnected.
	POLL_HUP = SI_POLL | 6
)

// Possible values for si_code.
const (
	// SI_USER is sent by kill, sigsend, raise.
	SI_USER = 0

	// SI_KERNEL is sent by the kernel from somewhere.
	SI_KERNEL = 0x80

	// SI_QUEUE is sent by sigqueue.
	SI_QUEUE = -1

	// SI_TIMER is sent by timer expiration.
	SI_TIMER = -2

	// SI_MESGQ is sent by real time mesq state change.
	SI_MESGQ = -3

	// SI_ASYNCIO is sent by AIO completion.
	SI_ASYNCIO = -4

	// SI_SIGIO is sent by queued SIGIO.
	SI_SIGIO = -5

	// SI_TKILL is sent by tkill system call.
	SI_TKILL = -6

	// SI_DETHREAD is sent by execve() killing subsidiary threads.
	SI_DETHREAD = -7

	// SI_ASYNCNL is sent by glibc async name lookup completion.
	SI_ASYNCNL = -60
)

// CLD_* codes are only meaningful for SIGCHLD.
const (
	// CLD_EXITED indicates that a task exited.
	CLD_EXITED = 1

	// CLD_KILLED indicates that a task was killed by a signal.
	CLD_KILLED = 2

	// CLD_DUMPED indicates that a task was killed by a signal and then dumped
	// core.
	CLD_DUMPED = 3

	// CLD_TRAPPED indicates that a task was stopped by ptrace.
	CLD_TRAPPED = 4

	// CLD_STOPPED indicates that a thread group completed a group stop.
	CLD_STOPPED = 5

	// CLD_CONTINUED indicates that a group-stopped thread group was continued.
	CLD_CONTINUED = 6
)

// SYS_* codes are only meaningful for SIGSYS.
const (
	// SYS_SECCOMP indicates that a signal originates from seccomp.
	SYS_SECCOMP = 1
)

// Possible values for Sigevent.Notify, aka struct sigevent::sigev_notify.
const (
	SIGEV_SIGNAL    = 0
	SIGEV_NONE      = 1
	SIGEV_THREAD    = 2
	SIGEV_THREAD_ID = 4
)

// Sigevent represents struct sigevent.
//
// +marshal
type Sigevent struct {
	Value  uint64 // union sigval {int, void*}
	Signo  int32
	Notify int32

	// struct sigevent here contains 48-byte union _sigev_un. However, only
	// member _tid is significant to the kernel.
	Tid         int32
	UnRemainder [44]byte
}

// SigAction represents struct sigaction.
//
// +marshal
// +stateify savable
type SigAction struct {
	Handler  uint64
	Flags    uint64
	Restorer uint64
	Mask     SignalSet
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

// Contains checks if the stack pointer is within this stack.
func (s *SignalStack) Contains(sp hostarch.Addr) bool {
	return hostarch.Addr(s.Addr) < sp && sp <= hostarch.Addr(s.Addr+s.Size)
}

// Top returns the stack's top address.
func (s *SignalStack) Top() hostarch.Addr {
	return hostarch.Addr(s.Addr + s.Size)
}

// IsEnabled returns true iff this signal stack is marked as enabled.
func (s *SignalStack) IsEnabled() bool {
	return s.Flags&SS_DISABLE == 0
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
func (s *SignalInfo) TimerID() TimerID {
	return TimerID(hostarch.ByteOrder.Uint32(s.Fields[0:4]))
}

// SetTimerID sets the si_timerid field.
func (s *SignalInfo) SetTimerID(val TimerID) {
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
//
//go:nosplit
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
