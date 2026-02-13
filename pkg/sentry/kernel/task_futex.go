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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Futex returns t's futex manager.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Futex() *futex.Manager {
	return t.image.fu
}

// SwapUint32 implements futex.Target.SwapUint32.
func (t *Task) SwapUint32(addr hostarch.Addr, new uint32) (uint32, error) {
	return t.MemoryManager().SwapUint32(t, addr, new, usermem.IOOpts{})
}

// CompareAndSwapUint32 implements futex.Target.CompareAndSwapUint32.
func (t *Task) CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error) {
	return t.MemoryManager().CompareAndSwapUint32(t, addr, old, new, usermem.IOOpts{})
}

// LoadUint32 implements futex.Target.LoadUint32.
func (t *Task) LoadUint32(addr hostarch.Addr) (uint32, error) {
	return t.MemoryManager().LoadUint32(t, addr, usermem.IOOpts{})
}

// GetSharedKey implements futex.Target.GetSharedKey.
func (t *Task) GetSharedKey(addr hostarch.Addr) (futex.Key, error) {
	return t.MemoryManager().GetSharedFutexKey(t, addr)
}

// GetRobustList sets the robust futex list for the task.
func (t *Task) GetRobustList() hostarch.Addr {
	t.mu.Lock()
	addr := t.robustList
	t.mu.Unlock()
	return addr
}

// SetRobustList sets the robust futex list for the task.
func (t *Task) SetRobustList(addr hostarch.Addr) {
	t.mu.Lock()
	t.robustList = addr
	t.mu.Unlock()
}

// exitRobustList walks the robust futex list, marking locks dead and notifying
// wakers. It corresponds to Linux's exit_robust_list(). Following Linux,
// errors are silently ignored.
func (t *Task) exitRobustList() {
	t.mu.Lock()
	addr := t.robustList
	t.robustList = 0
	t.mu.Unlock()

	if addr == 0 {
		return
	}

	var rl linux.RobustListHead
	if _, err := rl.CopyIn(t, hostarch.Addr(addr)); err != nil {
		return
	}

	next := primitive.Uint64(rl.List)
	done := 0
	var pendingLockAddr hostarch.Addr
	if rl.ListOpPending != 0 {
		pendingLockAddr = hostarch.Addr(rl.ListOpPending + rl.FutexOffset)
	}

	// Wake up normal elements.
	for hostarch.Addr(next) != addr {
		// We traverse to the next element of the list before we
		// actually wake anything. This prevents the race where waking
		// this futex causes a modification of the list.
		thisLockAddr := hostarch.Addr(uint64(next) + rl.FutexOffset)

		// Try to decode the next element in the list before waking the
		// current futex. But don't check the error until after we've
		// woken the current futex. Linux does it in this order too
		_, nextErr := next.CopyIn(t, hostarch.Addr(next))

		// Wakeup the current futex if it's not pending.
		if thisLockAddr != pendingLockAddr {
			t.wakeRobustListOne(thisLockAddr)
		}

		// If there was an error copying the next futex, we must bail.
		if nextErr != nil {
			break
		}

		// This is a user structure, so it could be a massive list, or
		// even contain a loop if they are trying to mess with us. We
		// cap traversal to prevent that.
		done++
		if done >= linux.ROBUST_LIST_LIMIT {
			break
		}
	}

	// Is there a pending entry to wake?
	if pendingLockAddr != 0 {
		t.wakeRobustListOne(pendingLockAddr)
	}
}

// wakeRobustListOne wakes a single futex from the robust list.
func (t *Task) wakeRobustListOne(addr hostarch.Addr) {
	// Bit 0 in address signals PI futex.
	pi := addr&1 == 1
	addr = addr &^ 1

	// Load the futex.
	f, err := t.LoadUint32(addr)
	if err != nil {
		// Can't read this single value? Ignore the problem.
		// We can wake the other futexes in the list.
		return
	}

	tid := uint32(t.ThreadID())
	for {
		// Is this held by someone else?
		if f&linux.FUTEX_TID_MASK != tid {
			return
		}

		// This thread is dying and it's holding this futex. We need to
		// set the owner died bit and wake up any waiters.
		newF := (f & linux.FUTEX_WAITERS) | linux.FUTEX_OWNER_DIED
		if curF, err := t.CompareAndSwapUint32(addr, f, newF); err != nil {
			return
		} else if curF != f {
			// Futex changed out from under us. Try again...
			f = curF
			continue
		}

		// Wake waiters if there are any.
		if f&linux.FUTEX_WAITERS != 0 {
			private := f&linux.FUTEX_PRIVATE_FLAG != 0
			if pi {
				t.Futex().UnlockPI(t, addr, tid, private)
				return
			}
			t.Futex().Wake(t, addr, private, linux.FUTEX_BITSET_MATCH_ANY, 1)
		}

		// Done.
		return
	}
}
