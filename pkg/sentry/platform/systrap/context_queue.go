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
type contextQueue struct {
	// start is an index used for taking contexts out of the ringbuffer.
	start uint32
	// end is an index used for putting new contexts into the ringbuffer.
	end uint32

	// numActiveThreads indicates to the sentry how many stubs are running.
	// It is changed only by stub threads.
	numActiveThreads uint32
	// numSpinningThreads indicates to the sentry how many stubs are waiting
	// to receive a context from the queue, and are not doing useful work.
	numSpinningThreads uint32
	// numThreadsToWakeup is the number of threads requested by Sentry to wake up.
	// The Sentry increments it and stub threads decrements.
	numThreadsToWakeup uint32
	// numActiveContext is a number of running and waiting contexts
	numActiveContexts uint32
	// numAwakeContexts is the number of awake contexts. It includes all
	// active contexts and contexts that are running in the Sentry.
	numAwakeContexts uint32

	fastPathDisabled uint32
	usedFastPath     uint32
	ringbuffer       [maxContextQueueEntries]uint64
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

// add puts the the given ctx onto the context queue, and records a state of
// the subprocess after insertion to see if there are more active stub threads
// or more waiting contexts.
func (q *contextQueue) add(ctx *sharedContext) {
	ctx.startWaitingTS = cputicks()

	if fpState.stubFastPath() {
		q.enableFastPath()
	} else {
		q.disableFastPath()
	}
	contextID := ctx.contextID
	atomic.AddUint32(&q.numActiveContexts, 1)
	next := atomic.AddUint32(&q.end, 1)
	if (next % maxContextQueueEntries) ==
		(atomic.LoadUint32(&q.start) % maxContextQueueEntries) {
		// should be unreachable
		panic("contextQueue is full")
	}
	idx := next - 1
	next = idx % maxContextQueueEntries
	v := (uint64(idx) << contextQueueIndexShift) + uint64(contextID)
	atomic.StoreUint64(&q.ringbuffer[next], v)

	if atomic.SwapUint32(&q.usedFastPath, 0) != 0 {
		fpState.usedStubFastPath.Store(true)
	}
}

func (q *contextQueue) disableFastPath() {
	atomic.StoreUint32(&q.fastPathDisabled, 1)
}

func (q *contextQueue) enableFastPath() {
	atomic.StoreUint32(&q.fastPathDisabled, 0)
}

func (q *contextQueue) fastPathEnabled() bool {
	return atomic.LoadUint32(&q.fastPathDisabled) == 0
}
