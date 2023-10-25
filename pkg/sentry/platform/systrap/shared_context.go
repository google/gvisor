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
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/syncevent"
)

const (
	ackReset          uint64 = 0
	stateChangedReset uint64 = 0
)

// sharedContext is an abstraction for interactions that the sentry has to
// perform with memory shared between it and the stub threads used for contexts.
//
// Any access to shared memory should most likely have a getter/setter through
// this struct. This is due to the following reasons:
//   - The memory needs to be read or modified atomically because there is no
//     (trusted) synchronization between the sentry and the stub processes.
//   - Data read from shared memory may require validation before it can be used.
type sharedContext struct {
	contextEntry

	// subprocess is the subprocess that this sharedContext instance belongs to.
	subprocess *subprocess
	// contextID is the ID corresponding to the sysmsg.ThreadContext memory slot
	// that is used for this sharedContext.
	contextID uint32
	// shared is the handle to the shared memory that the sentry task go-routine
	// reads from and writes to.
	// NOTE: Using this handle directly without a getter from this function should
	//       most likely be avoided due to concerns listed above.
	shared *sysmsg.ThreadContext

	// sync is used by the context go-routine to wait for events from the
	// dispatcher.
	sync           syncevent.Waiter
	startWaitingTS int64
	kicked         bool
	// The task associated with the context fell asleep.
	sleeping bool
}

// String returns the ID of this shared context.
func (sc *sharedContext) String() string {
	return strconv.Itoa(int(sc.contextID))
}

const (
	// sharedContextReady indicates that a context has new events.
	sharedContextReady = syncevent.Set(1 << iota)
	// sharedContextKicked indicates that a new stub thread should be woken up.
	sharedContextKicked
	// sharedContextSlowPath indicates that a context has to be waited for in the
	// slow path.
	sharedContextSlowPath
	// sharedContextDispatch indicates that a context go-routine has to start the wait loop.
	sharedContextDispatch
)

func (s *subprocess) getSharedContext() (*sharedContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.threadContextPool.Get()
	if !ok {
		return nil, fmt.Errorf("subprocess has too many active tasks (%d); failed to create a new one", maxGuestContexts)
	}
	s.IncRef()
	sc := sharedContext{
		subprocess: s,
		contextID:  uint32(id),
		shared:     s.getThreadContextFromID(id),
	}
	sc.shared.Init(invalidThreadID)
	sc.sync.Init()
	sc.sleeping = true

	return &sc, nil
}

func (sc *sharedContext) release() {
	if sc == nil {
		return
	}
	if !sc.sleeping {
		sc.subprocess.decAwakeContexts()
	}
	sc.subprocess.threadContextPool.Put(uint64(sc.contextID))
	sc.subprocess.DecRef(sc.subprocess.release)
}

func (sc *sharedContext) isActiveInSubprocess(s *subprocess) bool {
	if sc == nil {
		return false
	}
	return sc.subprocess == s
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt.
func (sc *sharedContext) NotifyInterrupt() {
	// If this context is not being worked on right now we need to mark it as
	// interrupted so the next executor does not start working on it.
	atomic.StoreUint32(&sc.shared.Interrupt, 1)
	if sc.threadID() == invalidThreadID {
		return
	}
	sc.subprocess.sysmsgThreadsMu.Lock()
	defer sc.subprocess.sysmsgThreadsMu.Unlock()

	threadID := atomic.LoadUint32(&sc.shared.ThreadID)
	sysmsgThread, ok := sc.subprocess.sysmsgThreads[threadID]
	if !ok {
		// This is either an invalidThreadID or another garbage value; either way we
		// don't know which thread to interrupt; best we can do is mark the context.
		return
	}

	t := sysmsgThread.thread
	if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(t.tgid), uintptr(t.tid), uintptr(platform.SignalInterrupt)); e != 0 {
		panic(fmt.Sprintf("failed to interrupt the child process %d: %v", t.tid, e))
	}
}

func (sc *sharedContext) state() sysmsg.ContextState {
	return sc.shared.State.Get()
}

func (sc *sharedContext) setState(state sysmsg.ContextState) {
	sc.shared.State.Set(state)
}

func (sc *sharedContext) setInterrupt() {
	atomic.StoreUint32(&sc.shared.Interrupt, 1)
}

func (sc *sharedContext) clearInterrupt() {
	atomic.StoreUint32(&sc.shared.Interrupt, 0)
}

func (sc *sharedContext) setFPStateChanged() {
	atomic.StoreUint64(&sc.shared.FPStateChanged, 1)
}

func (sc *sharedContext) threadID() uint32 {
	return atomic.LoadUint32(&sc.shared.ThreadID)
}

// EnableSentryFastPath indicates that the polling mode is enabled for the
// Sentry. It has to be called before putting the context into the context queue.
func (sc *sharedContext) enableSentryFastPath() {
	atomic.StoreUint32(&sc.shared.SentryFastPath, 1)
}

// DisableSentryFastPath indicates that the polling mode for the sentry is
// disabled for the Sentry.
func (sc *sharedContext) disableSentryFastPath() {
	atomic.StoreUint32(&sc.shared.SentryFastPath, 0)
}

func (sc *sharedContext) isAcked() bool {
	return atomic.LoadUint64(&sc.shared.AckedTime) != ackReset
}

// getAckedTimeDiff returns the time difference between when this context was
// put into the context queue, and when this context was acked by a stub thread.
// Precondition: must be called after isAcked() == true.
//
//go:nosplit
func (sc *sharedContext) getAckedTimeDiff() cpuTicks {
	ackedAt := atomic.LoadUint64(&sc.shared.AckedTime)
	if ackedAt < uint64(sc.startWaitingTS) {
		log.Warningf("likely memory tampering detected: found a condition where ackedAt (%d) < startWaitingTS (%d)", ackedAt, uint64(sc.startWaitingTS))
		return 0
	}
	return cpuTicks(ackedAt - uint64(sc.startWaitingTS))
}

// getStateChangedTimeDiff returns the time difference between the time the
// context state got changed by a stub thread, and now.
//
//go:nosplit
func (sc *sharedContext) getStateChangedTimeDiff() cpuTicks {
	changedAt := atomic.LoadUint64(&sc.shared.StateChangedTime)
	now := uint64(cputicks())
	if now < changedAt {
		log.Warningf("likely memory tampering detected: found a condition where now (%d) < changedAt (%d)", now, changedAt)
		return 0
	}
	return cpuTicks(now - changedAt)
}

func (sc *sharedContext) resetLatencyMeasures() {
	atomic.StoreUint64(&sc.shared.AckedTime, ackReset)
	atomic.StoreUint64(&sc.shared.StateChangedTime, stateChangedReset)
}

const (
	contextPreemptTimeoutNsec = 10 * 1000 * 1000 // 10ms
	contextCheckupTimeoutSec  = 5
	stuckContextTimeout       = 30 * time.Second
)

func (sc *sharedContext) sleepOnState(state sysmsg.ContextState) {
	timeout := unix.Timespec{
		Sec:  0,
		Nsec: contextPreemptTimeoutNsec,
	}
	sentInterruptOnce := false
	deadline := time.Now().Add(stuckContextTimeout)
	for sc.state() == state {
		errno := sc.shared.SleepOnState(state, &timeout)
		if errno == 0 {
			continue
		}
		if errno != unix.ETIMEDOUT {
			panic(fmt.Sprintf("error waiting for state: %v", errno))
		}
		if time.Now().After(deadline) {
			log.Warningf("Systrap task goroutine has been waiting on ThreadContext.State futex too long. ThreadContext: %v", sc)
		}
		if sentInterruptOnce {
			log.Warningf("The context is still running: %v", sc)
			continue
		}

		if !sc.isAcked() || sc.subprocess.contextQueue.isEmpty() {
			continue
		}
		sc.NotifyInterrupt()
		sentInterruptOnce = true
		timeout.Sec = contextCheckupTimeoutSec
		timeout.Nsec = 0
	}
}

type fastPathDispatcher struct {
	// list is used only from the loop method and so it isn't protected by
	// any lock.
	list contextList

	mu sync.Mutex

	// nr is the number of contexts in the queue.
	// +checklocks:mu
	nr int

	// entrants contains new contexts that haven't been added to `list` yet.
	// +checklocks:mu
	entrants contextList
}

var dispatcher fastPathDispatcher

const (
	// deepSleepTimeout is the timeout after which both stub threads and the
	// dispatcher consider whether to stop polling. They need to have elapsed
	// this timeout twice in a row in order to stop, so the actual timeout
	// can be considered to be (deepSleepTimeout*2). Falling asleep after two
	// shorter timeouts instead of one long timeout is done in order to
	// mitigate the effects of rdtsc inaccuracies.
	//
	// The value is 20µs for 2GHz CPU. 40µs matches the sentry<->stub
	// round trip in the pure deep sleep case.
	deepSleepTimeout = uint64(40000)
	handshakeTimeout = uint64(1000)
)

// loop is processing contexts in the queue. Only one instance of it can be
// running, because it has exclusive access to the list.
//
// target is the context associated with the current go-routine.
func (q *fastPathDispatcher) loop(target *sharedContext) {
	done := false
	processed := 0
	firstTimeout := false
	slowPath := false
	startedSpinning := cputicks()
	for {
		var ctx, next *sharedContext

		q.mu.Lock()
		q.nr -= processed
		// Add new contexts to the list.
		q.list.PushBackList(&q.entrants)
		ctx = q.list.Front()
		q.mu.Unlock()

		if done {
			if ctx != nil {
				// Wake up the next go-routine to run the loop.
				ctx.sync.Receiver().Notify(sharedContextDispatch)
			}
			break
		}

		slowPath = !fpState.sentryFastPath() || slowPath
		processed = 0
		now := cputicks()
		for ctx = q.list.Front(); ctx != nil; ctx = next {
			next = ctx.Next()

			event := sharedContextReady
			if ctx.state() == sysmsg.ContextStateNone {
				if slowPath {
					event = sharedContextSlowPath
				} else if !ctx.kicked && uint64(now-ctx.startWaitingTS) > handshakeTimeout {
					if ctx.isAcked() {
						ctx.kicked = true
						continue
					}
					event = sharedContextKicked
				} else {
					continue
				}
			}
			processed++
			q.list.Remove(ctx)
			if ctx == target {
				done = true
			}
			ctx.sync.Receiver().Notify(event)
		}

		if processed != 0 {
			startedSpinning = now
			firstTimeout = false
		} else {
			fpState.usedSentryFastPath.Store(true)
		}
		// If dispatcher has been spinning for too long, send this
		// dispatcher to sleep.
		if uint64(now-startedSpinning) > deepSleepTimeout {
			slowPath = firstTimeout
			firstTimeout = true
		}

		yield()
	}
}

func (q *fastPathDispatcher) waitFor(ctx *sharedContext) syncevent.Set {
	events := syncevent.NoEvents

	q.mu.Lock()
	q.entrants.PushBack(ctx)
	q.nr++
	if q.nr == 1 {
		events = sharedContextDispatch
	}
	q.mu.Unlock()

	for {
		if events&sharedContextDispatch != 0 {
			ctx.sync.Ack(sharedContextDispatch)
			q.loop(ctx)
		}
		events = ctx.sync.WaitAndAckAll()
		if events&sharedContextDispatch == 0 {
			break
		}
	}
	return events
}
