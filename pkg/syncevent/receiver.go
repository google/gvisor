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
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// Receiver is an event sink that holds pending events and invokes a callback
// whenever new events become pending. Receiver's methods may be called
// concurrently from multiple goroutines.
//
// Receiver.Init() must be called before first use.
type Receiver struct {
	// pending is the set of pending events. pending is accessed using atomic
	// memory operations.
	pending atomicbitops.Uint64

	// cb is notified when new events become pending. cb is immutable after
	// Init().
	cb ReceiverCallback
}

// ReceiverCallback receives callbacks from a Receiver.
type ReceiverCallback interface {
	// NotifyPending is called when the corresponding Receiver has new pending
	// events.
	//
	// NotifyPending is called synchronously from Receiver.Notify(), so
	// implementations must not take locks that may be held by callers of
	// Receiver.Notify(). NotifyPending may be called concurrently from
	// multiple goroutines.
	NotifyPending()
}

// Init must be called before first use of r.
func (r *Receiver) Init(cb ReceiverCallback) {
	r.cb = cb
}

// Pending returns the set of pending events.
func (r *Receiver) Pending() Set {
	return Set(r.pending.Load())
}

// Notify sets the given events as pending.
func (r *Receiver) Notify(es Set) {
	p := Set(r.pending.Load())
	// Optimization: Skip the atomic CAS on r.pending if all events are
	// already pending.
	if p&es == es {
		return
	}
	// When this is uncontended (the common case), CAS is faster than
	// atomic-OR because the former is inlined and the latter (which we
	// implement in assembly ourselves) is not.
	if !r.pending.CompareAndSwap(uint64(p), uint64(p|es)) {
		// If the CAS fails, fall back to atomic-OR.
		atomicbitops.OrUint64(&r.pending, uint64(es))
	}
	r.cb.NotifyPending()
}

// Ack unsets the given events as pending.
func (r *Receiver) Ack(es Set) {
	p := Set(r.pending.Load())
	// Optimization: Skip the atomic CAS on r.pending if all events are
	// already not pending.
	if p&es == 0 {
		return
	}
	// When this is uncontended (the common case), CAS is faster than
	// atomic-AND because the former is inlined and the latter (which we
	// implement in assembly ourselves) is not.
	if !r.pending.CompareAndSwap(uint64(p), uint64(p&^es)) {
		// If the CAS fails, fall back to atomic-AND.
		atomicbitops.AndUint64(&r.pending, ^uint64(es))
	}
}

// PendingAndAckAll unsets all events as pending and returns the set of
// previously-pending events.
//
// PendingAndAckAll should only be used in preference to a call to Pending
// followed by a conditional call to Ack when the caller expects events to be
// pending (e.g. after a call to ReceiverCallback.NotifyPending()).
func (r *Receiver) PendingAndAckAll() Set {
	return Set(r.pending.Swap(0))
}
