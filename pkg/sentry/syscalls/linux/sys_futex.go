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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
)

// futexWaitRestartBlock encapsulates the state required to restart futex(2)
// via restart_syscall(2).
//
// +stateify savable
type futexWaitRestartBlock struct {
	duration time.Duration

	// addr stored as uint64 since uintptr is not save-able.
	addr    uint64
	private bool
	val     uint32
	mask    uint32
}

// Restart implements kernel.SyscallRestartBlock.Restart.
func (f *futexWaitRestartBlock) Restart(t *kernel.Task) (uintptr, error) {
	return futexWaitDuration(t, f.duration, false, hostarch.Addr(f.addr), f.private, f.val, f.mask)
}

// futexWaitAbsolute performs a FUTEX_WAIT_BITSET, blocking until the wait is
// complete.
//
// The wait blocks forever if forever is true, otherwise it blocks until ts.
//
// If blocking is interrupted, the syscall is restarted with the original
// arguments.
func futexWaitAbsolute(t *kernel.Task, clockRealtime bool, ts linux.Timespec, forever bool, addr hostarch.Addr, private bool, val, mask uint32) (uintptr, error) {
	w := t.FutexWaiter()
	err := t.Futex().WaitPrepare(w, t, addr, private, val, mask)
	if err != nil {
		return 0, err
	}

	if forever {
		err = t.Block(w.C)
	} else if clockRealtime {
		err = t.BlockWithDeadlineFrom(w.C, t.Kernel().RealtimeClock(), true, ktime.FromTimespec(ts))
	} else {
		err = t.BlockWithDeadline(w.C, true, ktime.FromTimespec(ts))
	}

	t.Futex().WaitComplete(w, t)
	return 0, linuxerr.ConvertIntr(err, linuxerr.ERESTARTSYS)
}

// futexWaitDuration performs a FUTEX_WAIT, blocking until the wait is
// complete.
//
// The wait blocks forever if forever is true, otherwise is blocks for
// duration.
//
// If blocking is interrupted, forever determines how to restart the
// syscall. If forever is true, the syscall is restarted with the original
// arguments. If forever is false, duration is a relative timeout and the
// syscall is restarted with the remaining timeout.
func futexWaitDuration(t *kernel.Task, duration time.Duration, forever bool, addr hostarch.Addr, private bool, val, mask uint32) (uintptr, error) {
	w := t.FutexWaiter()
	err := t.Futex().WaitPrepare(w, t, addr, private, val, mask)
	if err != nil {
		return 0, err
	}

	remaining, err := t.BlockWithTimeout(w.C, !forever, duration)
	t.Futex().WaitComplete(w, t)
	if err == nil {
		return 0, nil
	}

	// The wait was unsuccessful for some reason other than interruption. Simply
	// forward the error.
	if err != linuxerr.ErrInterrupted {
		return 0, err
	}

	// The wait was interrupted and we need to restart. Decide how.

	// The wait duration was absolute, restart with the original arguments.
	if forever {
		return 0, linuxerr.ERESTARTSYS
	}

	// The wait duration was relative, restart with the remaining duration.
	t.SetSyscallRestartBlock(&futexWaitRestartBlock{
		duration: remaining,
		addr:     uint64(addr),
		private:  private,
		val:      val,
		mask:     mask,
	})
	return 0, linuxerr.ERESTART_RESTARTBLOCK
}

func futexLockPI(t *kernel.Task, ts linux.Timespec, forever bool, addr hostarch.Addr, private bool) error {
	w := t.FutexWaiter()
	locked, err := t.Futex().LockPI(w, t, addr, uint32(t.ThreadID()), private, false)
	if err != nil {
		return err
	}
	if locked {
		// Futex acquired, we're done!
		return nil
	}

	if forever {
		err = t.Block(w.C)
	} else {
		err = t.BlockWithDeadlineFrom(w.C, t.Kernel().RealtimeClock(), true, ktime.FromTimespec(ts))
	}

	t.Futex().WaitComplete(w, t)
	return linuxerr.ConvertIntr(err, linuxerr.ERESTARTSYS)
}

func tryLockPI(t *kernel.Task, addr hostarch.Addr, private bool) error {
	w := t.FutexWaiter()
	locked, err := t.Futex().LockPI(w, t, addr, uint32(t.ThreadID()), private, true)
	if err != nil {
		return err
	}
	if !locked {
		return linuxerr.EWOULDBLOCK
	}
	return nil
}

// Futex implements linux syscall futex(2).
// It provides a method for a program to wait for a value at a given address to
// change, and a method to wake up anyone waiting on a particular address.
func Futex(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	futexOp := args[1].Int()
	val := int(args[2].Int())
	nreq := int(args[3].Int())
	timeout := args[3].Pointer()
	naddr := args[4].Pointer()
	val3 := args[5].Int()

	cmd := futexOp &^ (linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_CLOCK_REALTIME)
	private := (futexOp & linux.FUTEX_PRIVATE_FLAG) != 0
	clockRealtime := (futexOp & linux.FUTEX_CLOCK_REALTIME) == linux.FUTEX_CLOCK_REALTIME
	mask := uint32(val3)

	switch cmd {
	case linux.FUTEX_WAIT, linux.FUTEX_WAIT_BITSET:
		// WAIT{_BITSET} wait forever if the timeout isn't passed.
		forever := (timeout == 0)

		var timespec linux.Timespec
		if !forever {
			var err error
			timespec, err = copyTimespecIn(t, timeout)
			if err != nil {
				return 0, nil, err
			}
		}

		switch cmd {
		case linux.FUTEX_WAIT:
			// WAIT uses a relative timeout.
			mask = linux.FUTEX_BITSET_MATCH_ANY
			var timeoutDur time.Duration
			if !forever {
				timeoutDur = time.Duration(timespec.ToNsecCapped()) * time.Nanosecond
			}
			n, err := futexWaitDuration(t, timeoutDur, forever, addr, private, uint32(val), mask)
			return n, nil, err

		case linux.FUTEX_WAIT_BITSET:
			// WAIT_BITSET uses an absolute timeout which is either
			// CLOCK_MONOTONIC or CLOCK_REALTIME.
			if mask == 0 {
				return 0, nil, linuxerr.EINVAL
			}
			n, err := futexWaitAbsolute(t, clockRealtime, timespec, forever, addr, private, uint32(val), mask)
			return n, nil, err
		default:
			panic("unreachable")
		}

	case linux.FUTEX_WAKE:
		mask = ^uint32(0)
		fallthrough

	case linux.FUTEX_WAKE_BITSET:
		if mask == 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if val <= 0 {
			// The Linux kernel wakes one waiter even if val is
			// non-positive.
			val = 1
		}
		n, err := t.Futex().Wake(t, addr, private, mask, val)
		return uintptr(n), nil, err

	case linux.FUTEX_REQUEUE:
		n, err := t.Futex().Requeue(t, addr, naddr, private, val, nreq)
		return uintptr(n), nil, err

	case linux.FUTEX_CMP_REQUEUE:
		// 'val3' contains the value to be checked at 'addr' and
		// 'val' is the number of waiters that should be woken up.
		nval := uint32(val3)
		n, err := t.Futex().RequeueCmp(t, addr, naddr, private, nval, val, nreq)
		return uintptr(n), nil, err

	case linux.FUTEX_WAKE_OP:
		op := uint32(val3)
		if val <= 0 {
			// The Linux kernel wakes one waiter even if val is
			// non-positive.
			val = 1
		}
		n, err := t.Futex().WakeOp(t, addr, naddr, private, val, nreq, op)
		return uintptr(n), nil, err

	case linux.FUTEX_LOCK_PI:
		forever := (timeout == 0)

		var timespec linux.Timespec
		if !forever {
			var err error
			timespec, err = copyTimespecIn(t, timeout)
			if err != nil {
				return 0, nil, err
			}
		}
		err := futexLockPI(t, timespec, forever, addr, private)
		return 0, nil, err

	case linux.FUTEX_TRYLOCK_PI:
		err := tryLockPI(t, addr, private)
		return 0, nil, err

	case linux.FUTEX_UNLOCK_PI:
		err := t.Futex().UnlockPI(t, addr, uint32(t.ThreadID()), private)
		return 0, nil, err

	case linux.FUTEX_WAIT_REQUEUE_PI, linux.FUTEX_CMP_REQUEUE_PI:
		t.Kernel().EmitUnimplementedEvent(t, sysno)
		return 0, nil, linuxerr.ENOSYS

	default:
		// We don't even know about this command.
		return 0, nil, linuxerr.ENOSYS
	}
}

// FutexWaitv implements Linux syscall futex_waitv(2).
func FutexWaitv(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	waitersAddr := args[0].Pointer()
	nrFutexes := args[1].Uint()
	flags := args[2].Uint()
	timeoutAddr := args[3].Pointer()
	clockID := args[4].Int()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if nrFutexes == 0 || nrFutexes > linux.FUTEX_WAITV_MAX || waitersAddr == 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// The timeout is absolute, on the clock named by clockID.
	forever := timeoutAddr == 0
	var clock ktime.Clock
	var deadline ktime.Time
	if !forever {
		switch clockID {
		case linux.CLOCK_REALTIME:
			clock = t.Kernel().RealtimeClock()
		case linux.CLOCK_MONOTONIC:
			clock = t.Kernel().MonotonicClock()
		default:
			return 0, nil, linuxerr.EINVAL
		}
		ts, err := copyTimespecIn(t, timeoutAddr)
		if err != nil {
			return 0, nil, err
		}
		if !ts.Valid() {
			return 0, nil, linuxerr.EINVAL
		}
		deadline = ktime.FromTimespec(ts)
	}

	waitv := make([]linux.FutexWaitv, nrFutexes)
	if _, err := linux.CopyFutexWaitvSliceIn(t, waitersAddr, waitv); err != nil {
		return 0, nil, err
	}
	fs := make([]futex.WaitvFutex, nrFutexes)
	for i := range waitv {
		wv := &waitv[i]
		// Only 32-bit futexes are supported, as in Linux.
		if wv.Flags&^(linux.FUTEX2_SIZE_MASK|linux.FUTEX2_PRIVATE) != 0 || wv.Reserved != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if wv.Flags&linux.FUTEX2_SIZE_MASK != linux.FUTEX2_SIZE_U32 || wv.Val > math.MaxUint32 {
			return 0, nil, linuxerr.EINVAL
		}
		fs[i] = futex.WaitvFutex{
			Addr:    hostarch.Addr(wv.Uaddr),
			Val:     uint32(wv.Val),
			Private: wv.Flags&linux.FUTEX2_PRIVATE != 0,
		}
	}

	ws := t.FutexWaiters(len(fs))
	for {
		woken, err := t.Futex().WaitMultiplePrepare(ws, t, fs)
		if err != nil {
			return 0, nil, err
		}
		if woken >= 0 {
			return uintptr(woken), nil, nil
		}

		if forever {
			err = t.Block(ws[0].C)
		} else {
			err = t.BlockWithDeadlineFrom(ws[0].C, clock, true, deadline)
		}

		if woken := t.Futex().WaitMultipleComplete(ws, t); woken >= 0 {
			return uintptr(woken), nil, nil
		}
		if err != nil {
			// The timeout is absolute, so an interrupted wait restarts with
			// the original arguments.
			return 0, nil, linuxerr.ConvertIntr(err, linuxerr.ERESTARTSYS)
		}
		// A wakeup arrived without any Waiter having been woken. Wait again,
		// as Linux does.
	}
}

// SetRobustList implements linux syscall set_robust_list(2).
func SetRobustList(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// Despite the syscall using the name 'pid' for this variable, it is
	// very much a tid.
	head := args[0].Pointer()
	length := args[1].SizeT()

	if length != uint(linux.SizeOfRobustListHead) {
		return 0, nil, linuxerr.EINVAL
	}
	t.SetRobustList(head)
	return 0, nil, nil
}

// GetRobustList implements linux syscall get_robust_list(2).
func GetRobustList(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// Despite the syscall using the name 'pid' for this variable, it is
	// very much a tid.
	tid := args[0].Int()
	headAddr := args[1].Pointer()
	sizeAddr := args[2].Pointer()

	if tid < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ot := t
	if tid != 0 {
		if ot = t.PIDNamespace().TaskWithID(kernel.ThreadID(tid)); ot == nil {
			return 0, nil, linuxerr.ESRCH
		}
	}

	// Copy out head pointer.
	head := t.Arch().Native(uintptr(ot.GetRobustList()))
	if _, err := head.CopyOut(t, headAddr); err != nil {
		return 0, nil, err
	}

	// Copy out size, which is a constant. Note that while size isn't
	// an address, it is defined as the arch-dependent size_t, so it
	// needs to be converted to a native-sized int.
	size := t.Arch().Native(uintptr(linux.SizeOfRobustListHead))
	if _, err := size.CopyOut(t, sizeAddr); err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}
