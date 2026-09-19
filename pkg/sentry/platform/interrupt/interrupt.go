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

import "gvisor.dev/gvisor/pkg/sync"

// Receiver receives interrupt notifications from a Forwarder.
type Receiver interface {
	// NotifyInterrupt is called when the Receiver receives an interrupt.
	//
	// Forwarder calls this synchronously with its mutex held. It must not
	// synchronously call back into that Forwarder. This interface does not
	// identify the calling Forwarder, so checklocks cannot express the
	// nonreentry requirement here.
	NotifyInterrupt()
}

// Forwarder is a helper for delivering delayed signal interruptions.
//
// This helps platform implementations with Interrupt semantics.
type Forwarder struct {
	mu sync.Mutex

	// dst receives forwarded interrupts. It is nil while forwarding is disabled.
	//
	// +checklocks:mu
	dst Receiver

	// pending records an interrupt received while forwarding was disabled.
	// The next Enable consumes it and returns false.
	//
	// +checklocks:mu
	pending bool
}

// Enable attempts to enable interrupt forwarding to r. If f has already
// received an interrupt, Enable does nothing and returns false. Otherwise,
// future calls to f.NotifyInterrupt() cause r.NotifyInterrupt() to be called,
// and Enable returns true.
//
// Usage:
//
//	if !f.Enable(r) {
//		// There was an interrupt.
//		return
//	}
//
// defer f.Disable()
//
// Preconditions:
//   - r must not be nil.
//   - f must not already be forwarding interrupts to a Receiver.
//
// +checklocksexclude:f.mu
func (f *Forwarder) Enable(r Receiver) bool {
	if r == nil {
		panic("nil Receiver")
	}
	f.mu.Lock()
	if f.dst != nil {
		f.mu.Unlock()
		panic("already forwarding interrupts")
	}
	if f.pending {
		f.pending = false
		f.mu.Unlock()
		return false
	}
	f.dst = r
	f.mu.Unlock()
	return true
}

// Disable stops interrupt forwarding. If interrupt forwarding is already
// disabled, Disable is a no-op.
//
// +checklocksexclude:f.mu
func (f *Forwarder) Disable() {
	f.mu.Lock()
	f.dst = nil
	f.mu.Unlock()
}

// NotifyInterrupt implements Receiver.NotifyInterrupt. If interrupt forwarding
// is enabled, the configured Receiver will be notified. Otherwise the
// interrupt will be delivered to the next call to Enable.
//
// +checklocksexclude:f.mu
func (f *Forwarder) NotifyInterrupt() {
	f.mu.Lock()
	if f.dst != nil {
		f.dst.NotifyInterrupt()
	} else {
		f.pending = true
	}
	f.mu.Unlock()
}

// Preempt preempts the running context. Preempt is a weaker version of
// NotifyInterrupt, it doesn't set the pending flag which is set when a context
// isn't actually running at this moment.
//
// +checklocksexclude:f.mu
func (f *Forwarder) Preempt() {
	f.mu.Lock()
	if f.dst != nil {
		f.dst.NotifyInterrupt()
	}
	f.mu.Unlock()
}
