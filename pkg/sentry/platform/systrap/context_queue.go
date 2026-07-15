// Copyright 2023 The gVisor Authors.
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

package systrap

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// LINT.IfChange
const (
	// maxEntries is the size of the ringbuffer.
	maxContextQueueEntries uint32 = uint32(maxGuestContexts) + 1
)

type queuedContext struct {
	contextID uint32
	threadID  uint32
}

// contextQueue is a structure shared with the each stub thread that is used to
// signal to stub threads which contexts are ready to resume running.
//
// It is a lockless ringbuffer where threads try to police themselves on whether
// they should continue waiting for a context or go to sleep if they are
// unneeded.
//
// The control words below are atomically read and written by the Sentry and
// by stub threads from different CPUs.
// To avoid false sharing (a write to one word invalidating the cache line for
// cores that only access other words), the words are grouped by writer and
// each group is padded out to its own cache line. A field shares a line only
// with fields written by the same side, so a writer never invalidates a line
// that another core needs for an unrelated read-mostly field.
// The ringbuffer starts on its own cache line instead of sharing the first
// line with the control words. This also guarantees the 8-byte alignment
// required by Go's 64-bit atomic ints.
//
// The layout must stay byte-identical to `context_queue` in
// `sysmsg/sysmsg_lib.c`.
type contextQueue struct {
	// end is an index used for putting new contexts into the ringbuffer.
	// It is written only by the Sentry (add) and read by stub threads.
	end uint32
	_   [hostarch.CacheLineSize - 4]byte

	// start is an index used for taking contexts out of the ringbuffer.
	// It is written only by stub threads and read by both sides.
	start uint32
	_     [hostarch.CacheLineSize - 4]byte

	// Sentry-written control words, read by spinning stub threads.

	// fastPathDisabled is set by the Sentry to make stub threads sleep in a
	// futex instead of spinning when no context is available.
	fastPathDisabled uint32
	// numAwakeContexts is the number of awake contexts. It includes all
	// active contexts and contexts that are running in the Sentry.
	numAwakeContexts uint32
	_                [hostarch.CacheLineSize - 8]byte

	// Stub-written status words, read by the Sentry.

	// numActiveThreads indicates to the sentry how many stubs are running.
	// It is changed only by stub threads.
	numActiveThreads uint32
	// numSpinningThreads indicates to the sentry how many stubs are waiting
	// to receive a context from the queue, and are not doing useful work.
	numSpinningThreads uint32
	_                  [hostarch.CacheLineSize - 8]byte

	// numThreadsToWakeup is the number of threads requested by Sentry to wake up.
	// The Sentry increments it and stub threads decrements.
	// Protected by subprocess.kickSysmsgMu for sentry-side writes.
	//
	// It is written by both sides and is also used for `FUTEX_WAIT` in
	// the stub, `FUTEX_WAKE` in the Sentry. So it gets a line of its own.
	numThreadsToWakeup uint32
	_                  [hostarch.CacheLineSize - 4]byte

	// Words written by both sides.

	// numActiveContext is a number of running and waiting contexts.
	numActiveContexts uint32
	// usedFastPath is set by stub threads when they take the fast path and
	// swapped to zero by the Sentry in `add`.
	usedFastPath uint32
	_            [hostarch.CacheLineSize - 8]byte

	// ringbuffer starts on its own cache line.
	ringbuffer [maxContextQueueEntries]uint64
}

const (
	// Each element of a contextQueue ring buffer is a sum of its index
	// shifted by CQ_INDEX_SHIFT and context_id.
	contextQueueIndexShift = 32
)

// LINT.ThenChange(./sysmsg/sysmsg_lib.c)

func (q *contextQueue) init() {
	for i := uint32(0); i < maxContextQueueEntries; i++ {
		q.ringbuffer[i] = uint64(invalidContextID)
	}
	// Allow tests to trigger overflows of start and end.
	idx := ^uint32(0) - maxContextQueueEntries*4
	atomic.StoreUint32(&q.start, idx)
	atomic.StoreUint32(&q.end, idx)
	atomic.StoreUint32(&q.numActiveThreads, 0)
	atomic.StoreUint32(&q.numSpinningThreads, 0)
	atomic.StoreUint32(&q.numThreadsToWakeup, 0)
	atomic.StoreUint32(&q.numActiveContexts, 0)
	atomic.StoreUint32(&q.numAwakeContexts, 0)
	atomic.StoreUint32(&q.fastPathDisabled, 1)
	atomic.StoreUint32(&q.usedFastPath, 0)
}

func (q *contextQueue) isEmpty() bool {
	return atomic.LoadUint32(&q.start) == atomic.LoadUint32(&q.end)
}

func (q *contextQueue) queuedContexts() uint32 {
	return (atomic.LoadUint32(&q.end) + maxContextQueueEntries - atomic.LoadUint32(&q.start)) % maxContextQueueEntries
}

// add puts the given ctx onto the context queue, and records a state of
// the subprocess after insertion to see if there are more active stub threads
// or more waiting contexts.
func (q *contextQueue) add(ctx *sharedContext) *platform.ContextError {
	ctx.startWaitingTS = cputicks()

	// Let the fast path monitor know the platform is doing work, waking it if
	// it has parked itself while the sandbox was idle.
	fastpath.recordActivity()

	q.setFastPathDisabled(!fastpath.stubFastPath())
	contextID := ctx.contextID
	atomic.AddUint32(&q.numActiveContexts, 1)
	next := atomic.AddUint32(&q.end, 1)
	if (next % maxContextQueueEntries) ==
		(atomic.LoadUint32(&q.start) % maxContextQueueEntries) {
		// reachable only in case of corrupted memory
		return corruptedSharedMemoryErr("context queue is full, indicates tampering with queue counters")
	}
	idx := next - 1
	next = idx % maxContextQueueEntries
	v := (uint64(idx) << contextQueueIndexShift) + uint64(contextID)
	atomic.StoreUint64(&q.ringbuffer[next], v)

	// Check before swapping: usedFastPath is usually zero, and the swap's
	// write would invalidate the cache line for stub threads even when it
	// does not change the value.
	if atomic.LoadUint32(&q.usedFastPath) != 0 && atomic.SwapUint32(&q.usedFastPath, 0) != 0 {
		fastpath.usedStubFastPath.Store(true)
	}
	return nil
}

// setFastPathDisabled makes stub threads sleep (disabled=true) or spin
// (disabled=false) when no context is queued. The word is read by every
// spinning stub thread, so store only on a real change (same reasoning as
// `fastPathState.park`).
// Can't use CAS as it acquires the cache line in exclusive state, even when
// the "C" part of CAS fails.
// A racing `add` storing the opposite value can make the flag contain the
// wrong fastPath decision, but the flag is only advisory.
func (q *contextQueue) setFastPathDisabled(disabled bool) {
	val := uint32(0)
	if disabled {
		val = 1
	}
	if atomic.LoadUint32(&q.fastPathDisabled) != val {
		atomic.StoreUint32(&q.fastPathDisabled, val)
	}
}

func (q *contextQueue) fastPathEnabled() bool {
	return atomic.LoadUint32(&q.fastPathDisabled) == 0
}
