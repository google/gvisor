// Copyright 2018 Google Inc.
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
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// futexChecker is a futex.Checker that uses a Task's MemoryManager.
type futexChecker struct {
	t *kernel.Task
}

// Check checks if the address contains the given value, and returns
// syserror.EAGAIN if it doesn't. See Checker interface in futex package
// for more information.
func (f futexChecker) Check(addr uintptr, val uint32) error {
	in := f.t.CopyScratchBuffer(4)
	_, err := f.t.CopyInBytes(usermem.Addr(addr), in)
	if err != nil {
		return err
	}
	nval := usermem.ByteOrder.Uint32(in)
	if val != nval {
		return syserror.EAGAIN
	}
	return nil
}

func (f futexChecker) atomicOp(addr uintptr, op func(uint32) uint32) (uint32, error) {
	in := f.t.CopyScratchBuffer(4)
	_, err := f.t.CopyInBytes(usermem.Addr(addr), in)
	if err != nil {
		return 0, err
	}
	o := usermem.ByteOrder.Uint32(in)
	mm := f.t.MemoryManager()
	for {
		n := op(o)
		r, err := mm.CompareAndSwapUint32(f.t, usermem.Addr(addr), o, n, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		if err != nil {
			return 0, err
		}

		if r == o {
			return o, nil
		}
		o = r
	}
}

// Op performs an operation on addr and returns a result based on the operation.
func (f futexChecker) Op(addr uintptr, opIn uint32) (bool, error) {
	op := (opIn >> 28) & 0xf
	cmp := (opIn >> 24) & 0xf
	opArg := (opIn >> 12) & 0xfff
	cmpArg := opIn & 0xfff

	if op&linux.FUTEX_OP_OPARG_SHIFT != 0 {
		opArg = 1 << opArg
		op &^= linux.FUTEX_OP_OPARG_SHIFT // clear flag
	}

	var oldVal uint32
	var err error
	switch op {
	case linux.FUTEX_OP_SET:
		oldVal, err = f.t.MemoryManager().SwapUint32(f.t, usermem.Addr(addr), opArg, usermem.IOOpts{
			AddressSpaceActive: true,
		})
	case linux.FUTEX_OP_ADD:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a + opArg
		})
	case linux.FUTEX_OP_OR:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a | opArg
		})
	case linux.FUTEX_OP_ANDN:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a & ^opArg
		})
	case linux.FUTEX_OP_XOR:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a ^ opArg
		})
	default:
		return false, syserror.ENOSYS
	}
	if err != nil {
		return false, err
	}

	switch cmp {
	case linux.FUTEX_OP_CMP_EQ:
		return oldVal == cmpArg, nil
	case linux.FUTEX_OP_CMP_NE:
		return oldVal != cmpArg, nil
	case linux.FUTEX_OP_CMP_LT:
		return oldVal < cmpArg, nil
	case linux.FUTEX_OP_CMP_LE:
		return oldVal <= cmpArg, nil
	case linux.FUTEX_OP_CMP_GT:
		return oldVal > cmpArg, nil
	case linux.FUTEX_OP_CMP_GE:
		return oldVal >= cmpArg, nil
	default:
		return false, syserror.ENOSYS
	}
}

// futexWaitRestartBlock encapsulates the state required to restart futex(2)
// via restart_syscall(2).
//
// +stateify savable
type futexWaitRestartBlock struct {
	duration time.Duration

	// addr stored as uint64 since uintptr is not save-able.
	addr uint64

	val  uint32
	mask uint32
}

// Restart implements kernel.SyscallRestartBlock.Restart.
func (f *futexWaitRestartBlock) Restart(t *kernel.Task) (uintptr, error) {
	return futexWaitDuration(t, f.duration, false, uintptr(f.addr), f.val, f.mask)
}

// futexWaitAbsolute performs a FUTEX_WAIT_BITSET, blocking until the wait is
// complete.
//
// The wait blocks forever if forever is true, otherwise it blocks until ts.
//
// If blocking is interrupted, the syscall is restarted with the original
// arguments.
func futexWaitAbsolute(t *kernel.Task, clockRealtime bool, ts linux.Timespec, forever bool, addr uintptr, val, mask uint32) (uintptr, error) {
	w := t.FutexWaiter()
	err := t.Futex().WaitPrepare(w, futexChecker{t}, addr, val, mask)
	if err != nil {
		return 0, err
	}

	if forever {
		err = t.Block(w.C)
	} else if clockRealtime {
		notifier, tchan := ktime.NewChannelNotifier()
		timer := ktime.NewTimer(t.Kernel().RealtimeClock(), notifier)
		timer.Swap(ktime.Setting{
			Enabled: true,
			Next:    ktime.FromTimespec(ts),
		})
		err = t.BlockWithTimer(w.C, tchan)
		timer.Destroy()
	} else {
		err = t.BlockWithDeadline(w.C, true, ktime.FromTimespec(ts))
	}

	t.Futex().WaitComplete(w)
	return 0, syserror.ConvertIntr(err, kernel.ERESTARTSYS)
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
func futexWaitDuration(t *kernel.Task, duration time.Duration, forever bool, addr uintptr, val, mask uint32) (uintptr, error) {
	w := t.FutexWaiter()
	err := t.Futex().WaitPrepare(w, futexChecker{t}, addr, val, mask)
	if err != nil {
		return 0, err
	}

	remaining, err := t.BlockWithTimeout(w.C, !forever, duration)
	t.Futex().WaitComplete(w)
	if err == nil {
		return 0, nil
	}

	// The wait was unsuccessful for some reason other than interruption. Simply
	// forward the error.
	if err != syserror.ErrInterrupted {
		return 0, err
	}

	// The wait was interrupted and we need to restart. Decide how.

	// The wait duration was absolute, restart with the original arguments.
	if forever {
		return 0, kernel.ERESTARTSYS
	}

	// The wait duration was relative, restart with the remaining duration.
	t.SetSyscallRestartBlock(&futexWaitRestartBlock{
		duration: remaining,
		addr:     uint64(addr),
		val:      val,
		mask:     mask,
	})
	return 0, kernel.ERESTART_RESTARTBLOCK
}

// Futex implements linux syscall futex(2).
// It provides a method for a program to wait for a value at a given address to
// change, and a method to wake up anyone waiting on a particular address.
func Futex(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	uaddr := args[0].Pointer()
	futexOp := args[1].Int()
	val := int(args[2].Int())
	nreq := int(args[3].Int())
	timeout := args[3].Pointer()
	uaddr2 := args[4].Pointer()
	val3 := args[5].Int()

	addr := uintptr(uaddr)
	naddr := uintptr(uaddr2)
	cmd := futexOp &^ (linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_CLOCK_REALTIME)
	clockRealtime := (futexOp & linux.FUTEX_CLOCK_REALTIME) == linux.FUTEX_CLOCK_REALTIME
	mask := uint32(val3)

	switch cmd {
	case linux.FUTEX_WAIT, linux.FUTEX_WAIT_BITSET:
		// WAIT{_BITSET} wait forever if the timeout isn't passed.
		forever := timeout == 0

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
			mask = ^uint32(0)
			var timeoutDur time.Duration
			if !forever {
				timeoutDur = time.Duration(timespec.ToNsecCapped()) * time.Nanosecond
			}
			n, err := futexWaitDuration(t, timeoutDur, forever, addr, uint32(val), mask)
			return n, nil, err

		case linux.FUTEX_WAIT_BITSET:
			// WAIT_BITSET uses an absolute timeout which is either
			// CLOCK_MONOTONIC or CLOCK_REALTIME.
			if mask == 0 {
				return 0, nil, syserror.EINVAL
			}
			n, err := futexWaitAbsolute(t, clockRealtime, timespec, forever, addr, uint32(val), mask)
			return n, nil, err
		default:
			panic("unreachable")
		}

	case linux.FUTEX_WAKE:
		mask = ^uint32(0)
		fallthrough

	case linux.FUTEX_WAKE_BITSET:
		if mask == 0 {
			return 0, nil, syserror.EINVAL
		}
		n, err := t.Futex().Wake(addr, mask, val)
		return uintptr(n), nil, err

	case linux.FUTEX_REQUEUE:
		n, err := t.Futex().Requeue(addr, naddr, val, nreq)
		return uintptr(n), nil, err

	case linux.FUTEX_CMP_REQUEUE:
		// 'val3' contains the value to be checked at 'addr' and
		// 'val' is the number of waiters that should be woken up.
		nval := uint32(val3)
		n, err := t.Futex().RequeueCmp(futexChecker{t}, addr, nval, naddr, val, nreq)
		return uintptr(n), nil, err

	case linux.FUTEX_WAKE_OP:
		op := uint32(val3)
		n, err := t.Futex().WakeOp(futexChecker{t}, addr, naddr, val, nreq, op)
		return uintptr(n), nil, err

	case linux.FUTEX_LOCK_PI, linux.FUTEX_UNLOCK_PI, linux.FUTEX_TRYLOCK_PI, linux.FUTEX_WAIT_REQUEUE_PI, linux.FUTEX_CMP_REQUEUE_PI:
		// We don't support any priority inversion futexes.
		return 0, nil, syserror.ENOSYS

	default:
		// We don't even know about this command.
		return 0, nil, syserror.ENOSYS
	}
}
