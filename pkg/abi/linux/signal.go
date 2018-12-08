// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/bits"
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

// Signal action flags for rt_sigaction(2), from uapi/asm-generic/signal.h
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

// Signal info types.
const (
	SI_MASK  = 0xffff0000
	SI_KILL  = 0 << 16
	SI_TIMER = 1 << 16
	SI_POLL  = 2 << 16
	SI_FAULT = 3 << 16
	SI_CHLD  = 4 << 16
	SI_RT    = 5 << 16
	SI_MESGQ = 6 << 16
	SI_SYS   = 7 << 16
)

// SIGPOLL si_codes.
const (
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

// Sigevent represents struct sigevent.
type Sigevent struct {
	Value  uint64 // union sigval {int, void*}
	Signo  int32
	Notify int32

	// struct sigevent here contains 48-byte union _sigev_un. However, only
	// member _tid is significant to the kernel.
	Tid         int32
	UnRemainder [44]byte
}

// Possible values for Sigevent.Notify, aka struct sigevent::sigev_notify.
const (
	SIGEV_SIGNAL    = 0
	SIGEV_NONE      = 1
	SIGEV_THREAD    = 2
	SIGEV_THREAD_ID = 4
)
