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
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

func Example_ioReadinessInterrputible() {
	const (
		evReady = Set(1 << iota)
		evInterrupt
	)
	errNotReady := fmt.Errorf("not ready for I/O")

	// State of some I/O object.
	var (
		br    Broadcaster
		ready atomicbitops.Uint32
	)
	doIO := func() error {
		if ready.Load() == 0 {
			return errNotReady
		}
		return nil
	}
	go func() {
		// The I/O object eventually becomes ready for I/O.
		time.Sleep(100 * time.Millisecond)
		// When it does, it first ensures that future calls to isReady() return
		// true, then broadcasts the readiness event to Receivers.
		ready.Store(1)
		br.Broadcast(evReady)
	}()

	// Each user of the I/O object owns a Waiter.
	var w Waiter
	w.Init()
	// The Waiter may be asynchronously interruptible, e.g. for signal
	// handling in the sentry.
	go func() {
		time.Sleep(200 * time.Millisecond)
		w.Receiver().Notify(evInterrupt)
	}()

	// To use the I/O object:
	//
	// Optionally, if the I/O object is likely to be ready, attempt I/O first.
	err := doIO()
	if err == nil {
		// Success, we're done.
		return /* nil */
	}
	if err != errNotReady {
		// Failure, I/O failed for some reason other than readiness.
		return /* err */
	}
	// Subscribe for readiness events from the I/O object.
	id := br.SubscribeEvents(w.Receiver(), evReady)
	// When we are finished blocking, unsubscribe from readiness events and
	// remove readiness events from the pending event set.
	defer UnsubscribeAndAck(&br, w.Receiver(), evReady, id)
	for {
		// Attempt I/O again. This must be done after the call to SubscribeEvents,
		// since the I/O object might have become ready between the previous call
		// to doIO and the call to SubscribeEvents.
		err = doIO()
		if err == nil {
			return /* nil */
		}
		if err != errNotReady {
			return /* err */
		}
		// Block until either the I/O object indicates it is ready, or we are
		// interrupted.
		events := w.Wait()
		if events&evInterrupt != 0 {
			// In the specific case of sentry signal handling, signal delivery
			// is handled by another system, so we aren't responsible for
			// acknowledging evInterrupt.
			return /* errInterrupted */
		}
		// Note that, in a concurrent context, the I/O object might become
		// ready and then not ready again. To handle this:
		//
		//	- evReady must be acknowledged before calling doIO() again (rather
		//		than after), so that if the I/O object becomes ready *again* after
		//		the call to doIO(), the readiness event is not lost.
		//
		//	- We must loop instead of just calling doIO() once after receiving
		//		evReady.
		w.Ack(evReady)
	}
}
