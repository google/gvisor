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

package kernel

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/bits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
)

const (
	// stdSignalCap is the maximum number of instances of a given standard
	// signal that may be pending. ("[If] multiple instances of a standard
	// signal are delivered while that signal is currently blocked, then only
	// one instance is queued.") - signal(7)
	stdSignalCap = 1

	// rtSignalCap is the maximum number of instances of a given realtime
	// signal that may be pending.
	//
	// TODO: In Linux, the minimum signal queue size is
	// RLIMIT_SIGPENDING, which is by default max_threads/2.
	rtSignalCap = 32
)

// pendingSignals holds a collection of pending signals. The zero value of
// pendingSignals is a valid empty collection. pendingSignals is thread-unsafe;
// users must provide synchronization.
type pendingSignals struct {
	// signals contains all pending signals.
	//
	// Note that signals is zero-indexed, but signal 1 is the first valid
	// signal, so signals[0] contains signals with signo 1 etc. This offset is
	// usually handled by using Signal.index().
	signals [linux.SignalMaximum]pendingSignalQueue

	// Bit i of pendingSet is set iff there is at least one signal with signo
	// i+1 pending.
	pendingSet linux.SignalSet
}

// pendingSignalQueue holds a pendingSignalList for a single signal number.
type pendingSignalQueue struct {
	pendingSignalList
	length int
}

type pendingSignal struct {
	// pendingSignalEntry links into a pendingSignalList.
	pendingSignalEntry
	*arch.SignalInfo
}

// enqueue enqueues the given signal. enqueue returns true on success and false
// on failure (if the given signal's queue is full).
//
// Preconditions: info represents a valid signal.
func (p *pendingSignals) enqueue(info *arch.SignalInfo) bool {
	sig := linux.Signal(info.Signo)
	q := &p.signals[sig.Index()]
	if sig.IsStandard() {
		if q.length >= stdSignalCap {
			return false
		}
	} else if q.length >= rtSignalCap {
		return false
	}
	q.pendingSignalList.PushBack(&pendingSignal{SignalInfo: info})
	q.length++
	p.pendingSet |= linux.SignalSetOf(sig)
	return true
}

// dequeue dequeues and returns any pending signal not masked by mask. If no
// unmasked signals are pending, dequeue returns nil.
func (p *pendingSignals) dequeue(mask linux.SignalSet) *arch.SignalInfo {
	// "Real-time signals are delivered in a guaranteed order. Multiple
	// real-time signals of the same type are delivered in the order they were
	// sent. If different real-time signals are sent to a process, they are
	// delivered starting with the lowest-numbered signal. (I.e., low-numbered
	// signals have highest priority.) By contrast, if multiple standard
	// signals are pending for a process, the order in which they are delivered
	// is unspecified. If both standard and real-time signals are pending for a
	// process, POSIX leaves it unspecified which is delivered first. Linux,
	// like many other implementations, gives priority to standard signals in
	// this case." - signal(7)
	lowestPendingUnblockedBit := bits.TrailingZeros64(uint64(p.pendingSet &^ mask))
	if lowestPendingUnblockedBit >= linux.SignalMaximum {
		return nil
	}
	return p.dequeueSpecific(linux.Signal(lowestPendingUnblockedBit + 1))
}

func (p *pendingSignals) dequeueSpecific(sig linux.Signal) *arch.SignalInfo {
	q := &p.signals[sig.Index()]
	ps := q.pendingSignalList.Front()
	if ps == nil {
		return nil
	}
	q.pendingSignalList.Remove(ps)
	q.length--
	if q.length == 0 {
		p.pendingSet &^= linux.SignalSetOf(sig)
	}
	return ps.SignalInfo
}

// discardSpecific causes all pending signals with number sig to be discarded.
func (p *pendingSignals) discardSpecific(sig linux.Signal) {
	q := &p.signals[sig.Index()]
	q.pendingSignalList.Reset()
	q.length = 0
	p.pendingSet &^= linux.SignalSetOf(sig)
}
