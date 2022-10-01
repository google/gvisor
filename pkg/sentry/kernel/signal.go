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

package kernel

import (
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
)

// SignalPanic is used to panic the running threads. It is a signal which
// cannot be used by the application: it must be caught and ignored by the
// runtime (in order to catch possible races).
const SignalPanic = linux.SIGUSR2

// sendExternalSignal is called when an asynchronous signal is sent to the
// sentry ("in sentry context"). On some platforms, it may also be called when
// an asynchronous signal is sent to sandboxed application threads ("in
// application context").
//
// context is used only for debugging to differentiate these cases.
//
// Preconditions: Kernel must have an init process.
func (k *Kernel) sendExternalSignal(info *linux.SignalInfo, context string) {
	switch linux.Signal(info.Signo) {
	case linux.SIGURG:
		// Sent by the Go 1.14+ runtime for asynchronous goroutine preemption.

	case platform.SignalInterrupt:
		// Assume that a call to platform.Context.Interrupt() misfired.

	case SignalInterruptSyscall:
		// Expected.

	case SignalPanic:
		// SignalPanic is also specially handled in sentry setup to ensure that
		// it causes a panic even after tasks exit, but SignalPanic may also
		// be sent here if it is received while in app context.
		panic("Signal-induced panic")

	default:
		log.Infof("Received external signal %d in %s context", info.Signo, context)
		if k.globalInit == nil {
			panic(fmt.Sprintf("Received external signal %d before init created", info.Signo))
		}
		k.globalInit.SendSignal(info)
	}
}

// SignalInfoPriv returns a SignalInfo equivalent to Linux's SEND_SIG_PRIV.
func SignalInfoPriv(sig linux.Signal) *linux.SignalInfo {
	return &linux.SignalInfo{
		Signo: int32(sig),
		Code:  linux.SI_KERNEL,
	}
}

// SignalInfoNoInfo returns a SignalInfo equivalent to Linux's SEND_SIG_NOINFO.
func SignalInfoNoInfo(sig linux.Signal, sender, receiver *Task) *linux.SignalInfo {
	info := &linux.SignalInfo{
		Signo: int32(sig),
		Code:  linux.SI_USER,
	}
	info.SetPID(int32(receiver.tg.pidns.IDOfThreadGroup(sender.tg)))
	info.SetUID(int32(sender.Credentials().RealKUID.In(receiver.UserNamespace()).OrOverflow()))
	return info
}

// SignalInterruptSyscall is sent by Task.interrupt() to task goroutine threads
// in host syscalls that have atomically unmasked SignalInterruptSyscall.
// Threads whose IDs may be stored in Task.syscallTID have
// SignalInterruptSyscall masked when not in said syscalls, ensuring that
// signal delivery does not occur unless it would interrupt a syscall.
const SignalInterruptSyscall = linux.SIGPWR

var (
	// interruptSyscallReadyTIDs stores thread IDs for which
	// interruptibleSyscallSignalMask has already been called. (This is feasible
	// because the Go runtime never destroys threads, so thread IDs are never
	// reused.)
	interruptSyscallReadyTIDs tidsetAtomicPtrMap

	interruptSyscallInitOnce sync.Once
	interruptSyscallSigmask  linux.SignalSet // SignalInterruptSyscall is unmasked
)

// interruptibleSyscallSignalMask ensures that SignalInterruptSyscall is
// masked by the calling thread, then returns a signal mask not containing
// SignalInterruptSyscall, for use by the interruptible syscall.
//
// Preconditions:
//   - runtime.LockOSThread() is in effect.
//   - tid is the caller's thread ID.
func interruptibleSyscallSignalMask(tid int32) linux.SignalSet {
	if interruptSyscallReadyTIDs.Load(tid) != nil {
		return interruptSyscallSigmask
	}
	interruptSyscallInitOnce.Do(func() {
		// Get the current signal mask, assuming that it's the correct signal mask
		// for all threads on which task goroutines can run.
		var sigmask linux.SignalSet
		if err := sigprocmask(0, nil, &sigmask); err != nil {
			panic(fmt.Sprintf("sigprocmask(0, nil, %p) failed: %v", &sigmask, err))
		}
		interruptSyscallSigmask = sigmask &^ linux.SignalSetOf(SignalInterruptSyscall)
		// SignalInterruptSyscall must be handled by a userspace signal handler to
		// prevent ppoll(2) from being automatically restarted. The easiest way to
		// ensure this is to require Go to install a signal handler.
		// signal.Notify() will perform a non-blocking send to whatever channel we
		// provide, and we don't actually care about being notified about the
		// signal, so pass it an unbuffered channel that will never have a
		// receiver.
		signal.Notify(make(chan os.Signal), unix.Signal(SignalInterruptSyscall))
	})
	sigmask := linux.SignalSetOf(SignalInterruptSyscall)
	if err := sigprocmask(linux.SIG_BLOCK, &sigmask, nil); err != nil {
		panic(fmt.Sprintf("sigprocmask(SIG_BLOCK, %p, nil) failed: %v", &sigmask, err))
	}
	interruptSyscallReadyTIDs.Store(tid, &tidsetValue{})
	return interruptSyscallSigmask
}

type tidsetValue struct{}

type tidsetHasher struct{}

// Init implements generic_atomicptrmap.Hasher.Init.
func (tidsetHasher) Init() {
}

// Hash implements generic_atomicptrmap.Hasher.Hash.
func (tidsetHasher) Hash(tid int32) uintptr {
	// This hash function is the linear congruential generator defined as
	// nrand48() by POSIX, with the constant addition removed (since, with
	// overwhelming probability, it doesn't affect the output due to the bit
	// shift).
	return uintptr(uint64(tid) * 0x5deece66d >> 16)
}
