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

// Package interrupt provides an interrupt helper.
package interrupt

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// Receiver receives interrupt notifications from a Forwarder.
type Receiver interface {
	// NotifyInterrupt is called when the Receiver receives an interrupt.
	NotifyInterrupt()
}

// Forwarder states.
const (
	// forwarderDisabled: no interrupt is forwarded, and none is pending.
	forwarderDisabled uint32 = iota

	// forwarderPending: no interrupt is forwarded, and one is pending.
	forwarderPending

	// forwarderEnabled: interrupts go to `Dst` directly.
	forwarderEnabled
)

// Forwarder is a helper for delivering delayed signal interruptions.
//
// This helps platform implementations with Interrupt semantics.
type Forwarder struct {
	// state of the interrupt forwarder.
	state atomicbitops.Uint32

	// Dst is notified while `state` is `forwarderEnabled`. It is immutable,
	// and must be set before any function on `Forwarder` is called.
	Dst Receiver
}

// Enable attempts to enable interrupt forwarding.
// If `f` has already received an interrupt, `Enable` returns `false` and
// consumes the interrupt, which the caller should handle immediately.
// Otherwise (if `Enable` returns true, i.e. successful enablement),
// future calls to `f.NotifyInterrupt()` cause the `Receiver` to be notified,
// until `Disable` is called.
//
// Usage:
//
// ```
//
//	if !f.Enable() {
//		// There was an interrupt, need to handle it.
//		return
//	}
//	defer f.Disable()
//
// ```
//
// Precondition: f must not already be forwarding interrupts.
func (f *Forwarder) Enable() bool {
	if f.state.CompareAndSwap(forwarderDisabled, forwarderEnabled) {
		return true
	}
	if !f.state.CompareAndSwap(forwarderPending, forwarderDisabled) {
		// Enable is written explicitly to fit under the inlining budget,
		// critical for performance. In particular, do not use `fmt.Sprintf`
		// here as this will change its inlining cost and cause a noticeable
		// performance cost on the hot path.
		panic("already forwarding interrupts")
	}
	return false
}

// Disable stops interrupt forwarding.
// If interrupt forwarding is already disabled, Disable is a no-op.
// If an interrupt is already pending, Disable is also a no-op.
func (f *Forwarder) Disable() {
	f.state.CompareAndSwap(forwarderEnabled, forwarderDisabled)
}

// NotifyInterrupt implements Receiver.NotifyInterrupt.
// If interrupt forwarding is enabled, the `Receiver` will be notified.
// Otherwise the interrupt is recorded and will be noticed by the next caller
// of `Enable` exactly once (regardless of how many calls to `NotifyInterrupt`
// are made).
func (f *Forwarder) NotifyInterrupt() {
	for {
		switch f.state.Load() {
		case forwarderEnabled:
			f.Dst.NotifyInterrupt()
			return
		case forwarderPending:
			return
		default:
			if f.state.CompareAndSwap(forwarderDisabled, forwarderPending) {
				return
			}
		}
	}
}

// Preempt preempts the running context. Preempt is a weaker version of
// NotifyInterrupt, it doesn't set the pending flag which is set when a context
// isn't actually running at this moment.
func (f *Forwarder) Preempt() {
	if f.state.Load() == forwarderEnabled {
		f.Dst.NotifyInterrupt()
	}
}
