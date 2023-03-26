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
	// stubPollingIndex is used by stubs to indicate polling order.
	stubPollingIndex uint32
	// stubPollingIndexBase is used by stubs to indicate to each other how many
	// threads went to sleep.
	stubPollingIndexBase uint32
	// numActiveThreads indicates to the sentry how many stubs are running.
	numActiveThreads uint32
	// numActiveContext is a number of running and waiting contexts
	numActiveContexts uint32
	// ringbuffer is the mmapped region of memory that's shared with the stub
	// threads.
	ringbuffer [maxContextQueueEntries]uint32
}

// LINT.ThenChange(./sysmsg/sysmsg_lib.c)

func (q *contextQueue) init() {
	for i := uint32(0); i < maxContextQueueEntries; i++ {
		q.ringbuffer[i] = invalidContextID
	}
	atomic.StoreUint32(&q.start, 0)
	atomic.StoreUint32(&q.end, 0)
	atomic.StoreUint32(&q.stubPollingIndex, 0)
	atomic.StoreUint32(&q.stubPollingIndexBase, 0)
	atomic.StoreUint32(&q.numActiveThreads, 0)
	atomic.StoreUint32(&q.numActiveContexts, 0)
}

func (q *contextQueue) isEmpty() bool {
	return atomic.LoadUint32(&q.start) == atomic.LoadUint32(&q.end)
}

func (q *contextQueue) queuedContexts() uint32 {
	return (atomic.LoadUint32(&q.end) + maxContextQueueEntries - atomic.LoadUint32(&q.start)) % maxContextQueueEntries
}

func (q *contextQueue) add(contextID uint32) uint32 {
	atomic.AddUint32(&q.numActiveContexts, 1)
	next := atomic.AddUint32(&q.end, 1)
	if (next % maxContextQueueEntries) ==
		(atomic.LoadUint32(&q.start) % maxContextQueueEntries) {
		// should be unreacheable
		panic("contextQueue is full")
	}
	next = (next - 1) % maxContextQueueEntries
	atomic.StoreUint32(&q.ringbuffer[next], contextID)
	return next // remove me
}
