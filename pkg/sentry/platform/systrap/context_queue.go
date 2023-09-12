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

	numSpinningThreads := atomic.LoadUint32(&q.numSpinningThreads)
	numQueued := (idx + 1 + maxContextQueueEntries - atomic.LoadUint32(&q.start)) % maxContextQueueEntries
	if numQueued <= numSpinningThreads {
		ctx.recordSentryToStubLatency = recordLatencyMoreThreads
	} else {
		ctx.recordSentryToStubLatency = recordLatencyMoreContexts
	}
}

func (q *contextQueue) disableFastPath() {
	atomic.StoreUint32(&q.fastPathDisabled, 1)
	numTimesStubFastPathDisabled.Increment()
}

func (q *contextQueue) enableFastPath() {
	atomic.StoreUint32(&q.fastPathDisabled, 0)
	numTimesStubFastPathEnabled.Increment()
}

func (q *contextQueue) fastPathEnabled() bool {
	return atomic.LoadUint32(&q.fastPathDisabled) == 0
}

// At each sentry->stub switch we are monitoring the latency between when we put
// a context into the context queue, and when it's picked up for processing.
// Based on these measurements, we can make adjustments to put the subprocess
// into a more optimal state.
//
// A subprocess can be in one of these states:
//
//   1. Has more active contexts than stub threads.
//      In this state it generally doesn't matter whether the stub threads are
//      running in fastpath mode or not; since they never have a reason to
//      sleep. By monitoring latencies we can still answer these questions:
//      a) Will adding more stub threads to the subprocess improve latency?
//         - If we see switch latencies larger than some arbitrary amount, vote
//           to create a new thread.
//      b) Should we turn on stub fastpath mode in anticipation for when we'll
//         need it?
//         - By recording average latencies while in this state, we can have a
//           useful baseline to compare against in the future.
//
//   2. Has an less-or-equal amount of active contexts as stub threads.
//      With fastpath on, stub threads are kept active because they assume the
//      sentry will return contexts for processing relatively quickly. Because
//      we know that there are guaranteed idle stub threads available to pick up
//      new contexts, we are monitoring to see that contexts get picked very
//      fast; if that's not the case then the system has too much contention to
//      make spinning useful, and we need to disable fastpath to stop
//      contributing to contention.
//
// The rationale behind modeling stub fastpath enablement to be
// subprocess-specific, (rather than sandbox-global like the dispatcher) is that
// fastpath success depends on the workload (one workload may call fast syscalls,
// another may call slow ones). We want to avoid cases where one subprocess
// disables fastpath globally when other subprocesses would be happy to run in
// the fastpath.

const (
	needVotesToKickThread     = 3
	kickNewThreadTimeout      = deepSleepTimeout / 2
	timeoutAfterKickingThread = int64(deepSleepTimeout)

	// The value is 500µs for 2GHz CPU, which should be enough to capture at
	// least ~10 measures in the case of the slow path
	// (and hopefully more in the case of the fast path.)
	recordingPeriod    = 1_000_000
	fastPathBackoffMin = 2
	fastPathBackoffMax = 512
)

func (s *subprocess) recordLatency(latency uint64, excessThreads bool) {
	s.latencyRecordingMu.Lock()
	defer s.latencyRecordingMu.Unlock()

	// Do recording.
	overflowed := false
	total := s.latencyTotal
	s.latencyTotal += latency
	if s.latencyTotal < total {
		overflowed = true
		s.latencyTotal = total
	} else {
		s.numMeasurements++
		s.usedFastPathDuringPeriod = s.usedFastPathDuringPeriod || excessThreads
	}

	// Check if recording period has ended.
	now := uint64(cputicks())
	if s.recordingPeriodStart+recordingPeriod >= now && !overflowed {
		return
	}

	s.recordingPeriodStart = now
	if s.numMeasurements == 0 {
		return
	}

	avg := s.latencyTotal / s.numMeasurements
	s.latencyTotal = 0
	s.numMeasurements = 0

	if s.contextQueue.fastPathEnabled() {
		if !s.usedFastPathDuringPeriod {
			// If stubs never ended up using the fastpath then we
			// can't judge how effective it was.
			s.baselineLatency = avg
			return
		}

		if avg <= s.baselineLatency {
			s.nextFastPathBackoff = max(fastPathBackoffMin, s.nextFastPathBackoff-1)
		} else {
			s.curFastPathBackoff = s.nextFastPathBackoff
			s.nextFastPathBackoff = min(fastPathBackoffMax, s.nextFastPathBackoff*2)
			s.contextQueue.disableFastPath()
		}
	} else {
		s.baselineLatency = avg
		s.curFastPathBackoff--
		if s.curFastPathBackoff == 0 {
			s.contextQueue.enableFastPath()
			s.usedFastPathDuringPeriod = false
		}
	}
}

// recordLatencyMoreContexts records the sentry to stub latency assuming there
// was more contexts in the context queue than threads.
// Precondition: ctx.isAcked() must be true.
func recordLatencyMoreContexts(ctx *sharedContext) {
	if ctx.recordedLatency {
		return
	}
	ctx.recordedLatency = true
	latency := ctx.getAckedDiff()
	if latency == 0 {
		return
	}

	s := ctx.subprocess
	q := s.contextQueue
	if atomic.LoadUint32(&q.numAwakeContexts) > atomic.LoadUint32(&q.numActiveThreads) && latency > kickNewThreadTimeout {
		if total := s.numVotesToKickThread.Add(1); total == needVotesToKickThread {
			now := cputicks()
			if s.lastKickedThreadByVoteTS.Load()+timeoutAfterKickingThread < now {
				if s.kickSysmsgThread() {
					s.lastKickedThreadByVoteTS.Store(now)
				}
			}
			s.numVotesToKickThread.Store(0)
		}
	}

	s.recordLatency(latency, false)

	if latency < handshakeTimeout {
		numStubBoundSwitchesWithinHS.Increment()
	} else if latency < deepSleepTimeout {
		numStubBoundSwitchesWithinDS.Increment()
	} else {
		numStubBoundSwitchesLong.Increment()
	}
}

// recordLatencyMoreThreads records the sentry to stub latency assuming there
// was more active stub threads for the subprocess than contexts in the queue.
// Precondition: ctx.isAcked() must be true.
func recordLatencyMoreThreads(ctx *sharedContext) {
	if ctx.recordedLatency {
		return
	}
	ctx.recordedLatency = true
	latency := ctx.getAckedDiff()
	if latency == 0 {
		return
	}

	ctx.subprocess.recordLatency(latency, true)

	if latency < handshakeTimeout {
		numStubBoundSwitchesWithinHS.Increment()
	} else if latency < deepSleepTimeout {
		numStubBoundSwitchesWithinDS.Increment()
	} else {
		numStubBoundSwitchesLong.Increment()
	}
}
