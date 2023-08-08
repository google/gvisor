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
	"runtime"
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
	ackReset uint32 = 0
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
	return atomic.LoadUint32(&sc.shared.Acked) != ackReset
}

func (sc *sharedContext) resetAcked() {
	atomic.StoreUint32(&sc.shared.Acked, ackReset)
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

	// fastPathDisabledTS is the time stamp when the stub fast path was
	// disabled. It is zero if the fast path is enabled.
	fastPathDisabledTS atomic.Uint64
}

var dispatcher fastPathDispatcher

// fastPathContextLimit is the maximum number of contexts after which the fast
// path in stub threads is disabled. Its value can be higher than the number of
// CPU-s, because the Sentry is running with higher priority than stub threads,
// deepSleepTimeout is much shorter than the Linux scheduler timeslice, so the
// only thing that matters here is whether the Sentry handles syscall faster
// than the overhead of scheduling another stub thread.
var fastPathContextLimit = uint32(runtime.GOMAXPROCS(0) * 2)

// fastPathDisabledTimeout is the timeout after which the fast path in stub
// processes will be re-enabled.
const fastPathDisabledTimeout = uint64(200 * 1000 * 1000) // 100ms for 2GHz.

// nrMaxAwakeStubThreads is the maximum number of awake stub threads over all
// subprocesses at the this moment.
var nrMaxAwakeStubThreads atomic.Uint32

// stubFastPathEnabled returns true if the fast path in stub processes is
// enabled. If the fast path is disabled, it revises whether it has to be
// re-enabled or not.
func (q *fastPathDispatcher) stubFastPathEnabled() bool {
	ts := q.fastPathDisabledTS.Load()
	if ts != 0 {
		if uint64(cputicks())-ts < fastPathDisabledTimeout {
			return false
		}
		if nrMaxAwakeStubThreads.Load() > fastPathContextLimit {
			q.fastPathDisabledTS.Store(uint64(cputicks()))
			return false
		}
		q.fastPathDisabledTS.Store(0)
	}
	return true
}

// disableStubFastPath disables the fast path over all subprocesses with active
// contexts.
func (q *fastPathDispatcher) disableStubFastPath() {
	q.fastPathDisabledTS.Store(uint64(cputicks()))
}

// deep_sleep_timeout is the timeout after which we stops polling and fall asleep.
//
// The value is 40µs for 2GHz CPU. This timeout matches the sentry<->stub round
// trip in the pure deep sleep case.
const deepSleepTimeout = uint64(80000)
const handshakeTimeout = uint64(1000)

// loop is processing contexts in the queue. Only one instance of it can be
// running, because it has exclusive access to the list.
//
// target is the context associated with the current go-routine.
func (q *fastPathDispatcher) loop(target *sharedContext) {
	done := false
	processed := 0
	slowPath := false
	start := cputicks()
	for {
		var ctx, next *sharedContext

		q.mu.Lock()
		if processed != 0 || !q.entrants.Empty() {
			start = cputicks()
			slowPath = false
		}
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
		if processed == 0 {
			if uint64(cputicks()-start) > deepSleepTimeout {
				slowPath = true
				// Do one more run to notify all contexts.
				// q.list has to be empty at the end.
				continue
			}
			yield()
		}
	}
}

func (q *fastPathDispatcher) waitFor(ctx *sharedContext) syncevent.Set {
	events := syncevent.Set(0)

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
