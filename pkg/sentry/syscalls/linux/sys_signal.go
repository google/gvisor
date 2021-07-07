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
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/signalfd"
	"gvisor.dev/gvisor/pkg/syserr"
)

// "For a process to have permission to send a signal it must
// - either be privileged (CAP_KILL), or
// - the real or effective user ID of the sending process must be equal to the
// real or saved set-user-ID of the target process.
//
// In the case of SIGCONT it suffices when the sending and receiving processes
// belong to the same session." - kill(2)
//
// Equivalent to kernel/signal.c:check_kill_permission.
func mayKill(t *kernel.Task, target *kernel.Task, sig linux.Signal) bool {
	// kernel/signal.c:check_kill_permission also allows a signal if the
	// sending and receiving tasks share a thread group, which is not
	// mentioned in kill(2) since kill does not allow task-level
	// granularity in signal sending.
	if t.ThreadGroup() == target.ThreadGroup() {
		return true
	}

	if t.HasCapabilityIn(linux.CAP_KILL, target.UserNamespace()) {
		return true
	}

	creds := t.Credentials()
	tcreds := target.Credentials()
	if creds.EffectiveKUID == tcreds.SavedKUID ||
		creds.EffectiveKUID == tcreds.RealKUID ||
		creds.RealKUID == tcreds.SavedKUID ||
		creds.RealKUID == tcreds.RealKUID {
		return true
	}

	if sig == linux.SIGCONT && target.ThreadGroup().Session() == t.ThreadGroup().Session() {
		return true
	}
	return false
}

// Kill implements linux syscall kill(2).
func Kill(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pid := kernel.ThreadID(args[0].Int())
	sig := linux.Signal(args[1].Int())

	switch {
	case pid > 0:
		// "If pid is positive, then signal sig is sent to the process with the
		// ID specified by pid." - kill(2)
		// This loops to handle races with execve where target dies between
		// TaskWithID and SendGroupSignal. Compare Linux's
		// kernel/signal.c:kill_pid_info().
		for {
			target := t.PIDNamespace().TaskWithID(pid)
			if target == nil {
				return 0, nil, linuxerr.ESRCH
			}
			if !mayKill(t, target, sig) {
				return 0, nil, linuxerr.EPERM
			}
			info := &linux.SignalInfo{
				Signo: int32(sig),
				Code:  linux.SI_USER,
			}
			info.SetPID(int32(target.PIDNamespace().IDOfTask(t)))
			info.SetUID(int32(t.Credentials().RealKUID.In(target.UserNamespace()).OrOverflow()))
			if err := target.SendGroupSignal(info); !linuxerr.Equals(linuxerr.ESRCH, err) {
				return 0, nil, err
			}
		}
	case pid == -1:
		// "If pid equals -1, then sig is sent to every process for which the
		// calling process has permission to send signals, except for process 1
		// (init), but see below. ... POSIX.1-2001 requires that kill(-1,sig)
		// send sig to all processes that the calling process may send signals
		// to, except possibly for some implementation-defined system
		// processes. Linux allows a process to signal itself, but on Linux the
		// call kill(-1,sig) does not signal the calling process."
		var (
			lastErr   error
			delivered int
		)
		for _, tg := range t.PIDNamespace().ThreadGroups() {
			if tg == t.ThreadGroup() {
				continue
			}
			if t.PIDNamespace().IDOfThreadGroup(tg) == kernel.InitTID {
				continue
			}

			// If pid == -1, the returned error is the last non-EPERM error
			// from any call to group_send_sig_info.
			if !mayKill(t, tg.Leader(), sig) {
				continue
			}
			// Here and below, whether or not kill returns an error may
			// depend on the iteration order. We at least implement the
			// semantics documented by the man page: "On success (at least
			// one signal was sent), zero is returned."
			info := &linux.SignalInfo{
				Signo: int32(sig),
				Code:  linux.SI_USER,
			}
			info.SetPID(int32(tg.PIDNamespace().IDOfTask(t)))
			info.SetUID(int32(t.Credentials().RealKUID.In(tg.Leader().UserNamespace()).OrOverflow()))
			err := tg.SendSignal(info)
			if linuxerr.Equals(linuxerr.ESRCH, err) {
				// ESRCH is ignored because it means the task
				// exited while we were iterating.  This is a
				// race which would not normally exist on
				// Linux, so we suppress it.
				continue
			}
			delivered++
			if err != nil {
				lastErr = err
			}
		}
		if delivered > 0 {
			return 0, nil, lastErr
		}
		return 0, nil, linuxerr.ESRCH
	default:
		// "If pid equals 0, then sig is sent to every process in the process
		// group of the calling process."
		//
		// "If pid is less than -1, then sig is sent to every process
		// in the process group whose ID is -pid."
		pgid := kernel.ProcessGroupID(-pid)
		if pgid == 0 {
			pgid = t.PIDNamespace().IDOfProcessGroup(t.ThreadGroup().ProcessGroup())
		}

		// If pid != -1 (i.e. signalling a process group), the returned error
		// is the last error from any call to group_send_sig_info.
		lastErr := error(linuxerr.ESRCH)
		for _, tg := range t.PIDNamespace().ThreadGroups() {
			if t.PIDNamespace().IDOfProcessGroup(tg.ProcessGroup()) == pgid {
				if !mayKill(t, tg.Leader(), sig) {
					lastErr = linuxerr.EPERM
					continue
				}

				info := &linux.SignalInfo{
					Signo: int32(sig),
					Code:  linux.SI_USER,
				}
				info.SetPID(int32(tg.PIDNamespace().IDOfTask(t)))
				info.SetUID(int32(t.Credentials().RealKUID.In(tg.Leader().UserNamespace()).OrOverflow()))
				// See note above regarding ESRCH race above.
				if err := tg.SendSignal(info); !linuxerr.Equals(linuxerr.ESRCH, err) {
					lastErr = err
				}
			}
		}

		return 0, nil, lastErr
	}
}

func tkillSigInfo(sender, receiver *kernel.Task, sig linux.Signal) *linux.SignalInfo {
	info := &linux.SignalInfo{
		Signo: int32(sig),
		Code:  linux.SI_TKILL,
	}
	info.SetPID(int32(receiver.PIDNamespace().IDOfThreadGroup(sender.ThreadGroup())))
	info.SetUID(int32(sender.Credentials().RealKUID.In(receiver.UserNamespace()).OrOverflow()))
	return info
}

// Tkill implements linux syscall tkill(2).
func Tkill(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tid := kernel.ThreadID(args[0].Int())
	sig := linux.Signal(args[1].Int())

	// N.B. Inconsistent with man page, linux actually rejects calls with
	// tid <=0 by EINVAL. This isn't the same for all signal calls.
	if tid <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	target := t.PIDNamespace().TaskWithID(tid)
	if target == nil {
		return 0, nil, linuxerr.ESRCH
	}

	if !mayKill(t, target, sig) {
		return 0, nil, linuxerr.EPERM
	}
	return 0, nil, target.SendSignal(tkillSigInfo(t, target, sig))
}

// Tgkill implements linux syscall tgkill(2).
func Tgkill(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tgid := kernel.ThreadID(args[0].Int())
	tid := kernel.ThreadID(args[1].Int())
	sig := linux.Signal(args[2].Int())

	// N.B. Inconsistent with man page, linux actually rejects calls with
	// tgid/tid <=0 by EINVAL. This isn't the same for all signal calls.
	if tgid <= 0 || tid <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	targetTG := t.PIDNamespace().ThreadGroupWithID(tgid)
	target := t.PIDNamespace().TaskWithID(tid)
	if targetTG == nil || target == nil || target.ThreadGroup() != targetTG {
		return 0, nil, linuxerr.ESRCH
	}

	if !mayKill(t, target, sig) {
		return 0, nil, linuxerr.EPERM
	}
	return 0, nil, target.SendSignal(tkillSigInfo(t, target, sig))
}

// RtSigaction implements linux syscall rt_sigaction(2).
func RtSigaction(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sig := linux.Signal(args[0].Int())
	newactarg := args[1].Pointer()
	oldactarg := args[2].Pointer()
	sigsetsize := args[3].SizeT()

	if sigsetsize != linux.SignalSetSize {
		return 0, nil, linuxerr.EINVAL
	}

	var newactptr *linux.SigAction
	if newactarg != 0 {
		var newact linux.SigAction
		if _, err := newact.CopyIn(t, newactarg); err != nil {
			return 0, nil, err
		}
		newactptr = &newact
	}
	oldact, err := t.ThreadGroup().SetSigAction(sig, newactptr)
	if err != nil {
		return 0, nil, err
	}
	if oldactarg != 0 {
		if _, err := oldact.CopyOut(t, oldactarg); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, nil
}

// Sigreturn implements linux syscall sigreturn(2).
func Sigreturn(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ctrl, err := t.SignalReturn(false)
	return 0, ctrl, err
}

// RtSigreturn implements linux syscall rt_sigreturn(2).
func RtSigreturn(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ctrl, err := t.SignalReturn(true)
	return 0, ctrl, err
}

// RtSigprocmask implements linux syscall rt_sigprocmask(2).
func RtSigprocmask(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	how := args[0].Int()
	setaddr := args[1].Pointer()
	oldaddr := args[2].Pointer()
	sigsetsize := args[3].SizeT()

	if sigsetsize != linux.SignalSetSize {
		return 0, nil, linuxerr.EINVAL
	}
	oldmask := t.SignalMask()
	if setaddr != 0 {
		mask, err := CopyInSigSet(t, setaddr, sigsetsize)
		if err != nil {
			return 0, nil, err
		}

		switch how {
		case linux.SIG_BLOCK:
			t.SetSignalMask(oldmask | mask)
		case linux.SIG_UNBLOCK:
			t.SetSignalMask(oldmask &^ mask)
		case linux.SIG_SETMASK:
			t.SetSignalMask(mask)
		default:
			return 0, nil, linuxerr.EINVAL
		}
	}
	if oldaddr != 0 {
		return 0, nil, copyOutSigSet(t, oldaddr, oldmask)
	}

	return 0, nil, nil
}

// Sigaltstack implements linux syscall sigaltstack(2).
func Sigaltstack(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	setaddr := args[0].Pointer()
	oldaddr := args[1].Pointer()

	alt := t.SignalStack()
	if oldaddr != 0 {
		if _, err := alt.CopyOut(t, oldaddr); err != nil {
			return 0, nil, err
		}
	}
	if setaddr != 0 {
		if _, err := alt.CopyIn(t, setaddr); err != nil {
			return 0, nil, err
		}
		// The signal stack cannot be changed if the task is currently
		// on the stack. This is enforced at the lowest level because
		// these semantics apply to changing the signal stack via a
		// ucontext during a signal handler.
		if !t.SetSignalStack(alt) {
			return 0, nil, linuxerr.EPERM
		}
	}

	return 0, nil, nil
}

// Pause implements linux syscall pause(2).
func Pause(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserr.ConvertIntr(t.Block(nil), linuxerr.ERESTARTNOHAND)
}

// RtSigpending implements linux syscall rt_sigpending(2).
func RtSigpending(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	pending := t.PendingSignals()
	_, err := pending.CopyOut(t, addr)
	return 0, nil, err
}

// RtSigtimedwait implements linux syscall rt_sigtimedwait(2).
func RtSigtimedwait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sigset := args[0].Pointer()
	siginfo := args[1].Pointer()
	timespec := args[2].Pointer()
	sigsetsize := args[3].SizeT()

	mask, err := CopyInSigSet(t, sigset, sigsetsize)
	if err != nil {
		return 0, nil, err
	}

	var timeout time.Duration
	if timespec != 0 {
		d, err := copyTimespecIn(t, timespec)
		if err != nil {
			return 0, nil, err
		}
		if !d.Valid() {
			return 0, nil, linuxerr.EINVAL
		}
		timeout = time.Duration(d.ToNsecCapped())
	} else {
		timeout = time.Duration(math.MaxInt64)
	}

	si, err := t.Sigtimedwait(mask, timeout)
	if err != nil {
		return 0, nil, err
	}

	if siginfo != 0 {
		si.FixSignalCodeForUser()
		if _, err := si.CopyOut(t, siginfo); err != nil {
			return 0, nil, err
		}
	}
	return uintptr(si.Signo), nil, nil
}

// RtSigqueueinfo implements linux syscall rt_sigqueueinfo(2).
func RtSigqueueinfo(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pid := kernel.ThreadID(args[0].Int())
	sig := linux.Signal(args[1].Int())
	infoAddr := args[2].Pointer()

	// Copy in the info.
	//
	// We must ensure that the Signo is set (Linux overrides this in the
	// same way), and that the code is in the allowed set. This same logic
	// appears below in RtSigtgqueueinfo and should be kept in sync.
	var info linux.SignalInfo
	if _, err := info.CopyIn(t, infoAddr); err != nil {
		return 0, nil, err
	}
	info.Signo = int32(sig)

	// This must loop to handle the race with execve described in Kill.
	for {
		// Deliver to the given task's thread group.
		target := t.PIDNamespace().TaskWithID(pid)
		if target == nil {
			return 0, nil, linuxerr.ESRCH
		}

		// If the sender is not the receiver, it can't use si_codes used by the
		// kernel or SI_TKILL.
		if (info.Code >= 0 || info.Code == linux.SI_TKILL) && target != t {
			return 0, nil, linuxerr.EPERM
		}

		if !mayKill(t, target, sig) {
			return 0, nil, linuxerr.EPERM
		}

		if err := target.SendGroupSignal(&info); !linuxerr.Equals(linuxerr.ESRCH, err) {
			return 0, nil, err
		}
	}
}

// RtTgsigqueueinfo implements linux syscall rt_tgsigqueueinfo(2).
func RtTgsigqueueinfo(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tgid := kernel.ThreadID(args[0].Int())
	tid := kernel.ThreadID(args[1].Int())
	sig := linux.Signal(args[2].Int())
	infoAddr := args[3].Pointer()

	// N.B. Inconsistent with man page, linux actually rejects calls with
	// tgid/tid <=0 by EINVAL. This isn't the same for all signal calls.
	if tgid <= 0 || tid <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Copy in the info. See RtSigqueueinfo above.
	var info linux.SignalInfo
	if _, err := info.CopyIn(t, infoAddr); err != nil {
		return 0, nil, err
	}
	info.Signo = int32(sig)

	// Deliver to the given task.
	targetTG := t.PIDNamespace().ThreadGroupWithID(tgid)
	target := t.PIDNamespace().TaskWithID(tid)
	if targetTG == nil || target == nil || target.ThreadGroup() != targetTG {
		return 0, nil, linuxerr.ESRCH
	}

	// If the sender is not the receiver, it can't use si_codes used by the
	// kernel or SI_TKILL.
	if (info.Code >= 0 || info.Code == linux.SI_TKILL) && target != t {
		return 0, nil, linuxerr.EPERM
	}

	if !mayKill(t, target, sig) {
		return 0, nil, linuxerr.EPERM
	}
	return 0, nil, target.SendSignal(&info)
}

// RtSigsuspend implements linux syscall rt_sigsuspend(2).
func RtSigsuspend(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sigset := args[0].Pointer()

	// Copy in the signal mask.
	var mask linux.SignalSet
	if _, err := mask.CopyIn(t, sigset); err != nil {
		return 0, nil, err
	}
	mask &^= kernel.UnblockableSignals

	// Swap the mask.
	oldmask := t.SignalMask()
	t.SetSignalMask(mask)
	t.SetSavedSignalMask(oldmask)

	// Perform the wait.
	return 0, nil, syserr.ConvertIntr(t.Block(nil), linuxerr.ERESTARTNOHAND)
}

// RestartSyscall implements the linux syscall restart_syscall(2).
func RestartSyscall(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	if r := t.SyscallRestartBlock(); r != nil {
		n, err := r.Restart(t)
		return n, nil, err
	}
	// The restart block should never be nil here, but it's possible
	// ERESTART_RESTARTBLOCK was set by ptrace without the current syscall
	// setting up a restart block. If ptrace didn't manipulate the return value,
	// finding a nil restart block is a bug. Linux ensures that the restart
	// function is never null by (re)initializing it with one that translates
	// the restart into EINTR. We'll emulate that behaviour.
	t.Debugf("Restart block missing in restart_syscall(2). Did ptrace inject a return value of ERESTART_RESTARTBLOCK?")
	return 0, nil, linuxerr.EINTR
}

// sharedSignalfd is shared between the two calls.
func sharedSignalfd(t *kernel.Task, fd int32, sigset hostarch.Addr, sigsetsize uint, flags int32) (uintptr, *kernel.SyscallControl, error) {
	// Copy in the signal mask.
	mask, err := CopyInSigSet(t, sigset, sigsetsize)
	if err != nil {
		return 0, nil, err
	}

	// Always check for valid flags, even if not creating.
	if flags&^(linux.SFD_NONBLOCK|linux.SFD_CLOEXEC) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Is this a change to an existing signalfd?
	//
	// The spec indicates that this should adjust the mask.
	if fd != -1 {
		file := t.GetFile(fd)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)

		// Is this a signalfd?
		if s, ok := file.FileOperations.(*signalfd.SignalOperations); ok {
			s.SetMask(mask)
			return 0, nil, nil
		}

		// Not a signalfd.
		return 0, nil, linuxerr.EINVAL
	}

	// Create a new file.
	file, err := signalfd.New(t, mask)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	// Set appropriate flags.
	file.SetFlags(fs.SettableFileFlags{
		NonBlocking: flags&linux.SFD_NONBLOCK != 0,
	})

	// Create a new descriptor.
	fd, err = t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.SFD_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}

	// Done.
	return uintptr(fd), nil, nil
}

// Signalfd implements the linux syscall signalfd(2).
func Signalfd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	sigset := args[1].Pointer()
	sigsetsize := args[2].SizeT()
	return sharedSignalfd(t, fd, sigset, sigsetsize, 0)
}

// Signalfd4 implements the linux syscall signalfd4(2).
func Signalfd4(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	sigset := args[1].Pointer()
	sigsetsize := args[2].SizeT()
	flags := args[3].Int()
	return sharedSignalfd(t, fd, sigset, sigsetsize, flags)
}
