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

package syncevent

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sync"
)

// Waiter allows a goroutine to block on pending events received by a Receiver.
//
// Waiter.Init() must be called before first use.
type Waiter struct {
	r Receiver

	// g is one of:
	//
	// - 0: No goroutine is blocking in Wait.
	//
	// - preparingG: A goroutine is in Wait preparing to sleep, but hasn't yet
	// completed waiterUnlock(). Thus the wait can only be interrupted by
	// replacing the value of g with 0 (the G may not be in state Gwaiting yet,
	// so we can't call goready.)
	//
	// - Otherwise: g is a pointer to the runtime.g in state Gwaiting for the
	// goroutine blocked in Wait, which can only be woken by calling goready.
	//
	// +checkatomic
	g unsafe.Pointer `state:"zerovalue"`
}

const preparingG = 1

// Init must be called before first use of w.
func (w *Waiter) Init() {
	w.r.Init(w)
}

// Receiver returns the Receiver that receives events that unblock calls to
// w.Wait().
func (w *Waiter) Receiver() *Receiver {
	return &w.r
}

// Pending returns the set of pending events.
func (w *Waiter) Pending() Set {
	return w.r.Pending()
}

// Wait blocks until at least one event is pending, then returns the set of
// pending events. It does not affect the set of pending events; callers must
// call w.Ack() to do so, or use w.WaitAndAck() instead.
//
// Precondition: Only one goroutine may call any Wait* method at a time.
func (w *Waiter) Wait() Set {
	return w.WaitFor(AllEvents)
}

// WaitFor blocks until at least one event in es is pending, then returns the
// set of pending events (including those not in es). It does not affect the
// set of pending events; callers must call w.Ack() to do so.
//
// Precondition: Only one goroutine may call any Wait* method at a time.
func (w *Waiter) WaitFor(es Set) Set {
	for {
		// Optimization: Skip the atomic store to w.g if an event is already
		// pending.
		if p := w.r.Pending(); p&es != NoEvents {
			return p
		}

		// Indicate that we're preparing to go to sleep.
		atomic.StoreUintptr(&w.g, preparingG)

		// If an event is pending, abort the sleep.
		if p := w.r.Pending(); p&es != NoEvents {
			atomic.StoreUintptr(&w.g, 0)
			return p
		}

		// If w.g is still preparingG (i.e. w.NotifyPending() has not been
		// called or has not reached atomic.SwapUintptr()), go to sleep until
		// w.NotifyPending() => goready().
		sync.Gopark(waiterCommit, unsafe.Pointer(&w.g), sync.WaitReasonSelect, sync.TraceEvGoBlockSelect, 0) // checkatomic: safe.
	}
}

//go:norace
//go:nosplit
func waiterCommit(g uintptr, wg unsafe.Pointer) bool {
	// The only way this CAS can fail is if a call to Waiter.NotifyPending()
	// has replaced *wg with nil, in which case we should not sleep.
	return sync.RaceUncheckedAtomicCompareAndSwapUintptr((*uintptr)(wg), preparingG, g)
}

// Ack marks the given events as not pending.
func (w *Waiter) Ack(es Set) {
	w.r.Ack(es)
}

// WaitAndAckAll blocks until at least one event is pending, then marks all
// events as not pending and returns the set of previously-pending events.
//
// Precondition: Only one goroutine may call any Wait* method at a time.
func (w *Waiter) WaitAndAckAll() Set {
	// Optimization: Skip the atomic store to w.g if an event is already
	// pending. Call Pending() first since, in the common case that events are
	// not yet pending, this skips an atomic swap on w.r.pending.
	if w.r.Pending() != NoEvents {
		if p := w.r.PendingAndAckAll(); p != NoEvents {
			return p
		}
	}

	for {
		// Indicate that we're preparing to go to sleep.
		atomic.StoreUintptr(&w.g, preparingG)

		// If an event is pending, abort the sleep.
		if w.r.Pending() != NoEvents {
			if p := w.r.PendingAndAckAll(); p != NoEvents {
				atomic.StoreUintptr(&w.g, 0)
				return p
			}
		}

		// If w.g is still preparingG (i.e. w.NotifyPending() has not been
		// called or has not reached atomic.SwapUintptr()), go to sleep until
		// w.NotifyPending() => goready().
		sync.Gopark(waiterCommit, unsafe.Pointer(&w.g), sync.WaitReasonSelect, sync.TraceEvGoBlockSelect, 0) // checkatomic: safe.

		// Check for pending events. We call PendingAndAckAll() directly now since
		// we only expect to be woken after events become pending.
		if p := w.r.PendingAndAckAll(); p != NoEvents {
			return p
		}
	}
}

// Notify marks the given events as pending, possibly unblocking concurrent
// calls to w.Wait() or w.WaitFor().
func (w *Waiter) Notify(es Set) {
	w.r.Notify(es)
}

// NotifyPending implements ReceiverCallback.NotifyPending. Users of Waiter
// should not call NotifyPending.
func (w *Waiter) NotifyPending() {
	// Optimization: Skip the atomic swap on w.g if there is no sleeping
	// goroutine. NotifyPending is called after w.r.Pending() is updated, so
	// concurrent and future calls to w.Wait() will observe pending events and
	// abort sleeping.
	if atomic.LoadUintptr(&w.g) == 0 {
		return
	}
	// Wake a sleeping G, or prevent a G that is preparing to sleep from doing
	// so. Swap is needed here to ensure that only one call to NotifyPending
	// calls goready.
	if g := atomic.SwapUintptr(&w.g, 0); g > preparingG {
		sync.Goready(g, 0)
	}
}

var waiterPool = sync.Pool{
	New: func() interface{} {
		w := &Waiter{}
		w.Init()
		return w
	},
}

// GetWaiter returns an unused Waiter. PutWaiter should be called to release
// the Waiter once it is no longer needed.
//
// Where possible, users should prefer to associate each goroutine that calls
// Waiter.Wait() with a distinct pre-allocated Waiter to avoid allocation of
// Waiters in hot paths.
func GetWaiter() *Waiter {
	return waiterPool.Get().(*Waiter)
}

// PutWaiter releases an unused Waiter previously returned by GetWaiter.
func PutWaiter(w *Waiter) {
	waiterPool.Put(w)
}
