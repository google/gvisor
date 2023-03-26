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
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
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
	// subprocess is the subprocess that this sharedContext instance belongs to.
	subprocess *subprocess
	// contextID is the ID corresponding to the sysmsg.ThreadContext memory slot
	// that is used for this sharedContext.
	contextID uint32
	// shared is the handle to the shared memory that the sentry task goroutine
	// reads from and writes to.
	// NOTE: Using this handle directly without a getter from this function should
	//       most likely be avoided due to concerns listed above.
	shared *sysmsg.ThreadContext
}

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

	return &sc, nil
}

func (sc *sharedContext) release() {
	if sc == nil {
		return
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

func (sc *sharedContext) setThreadID(threadID uint32) {
	if contextDecouplingExp {
		panic("context decoupled systrap should never explicitly set ThreadID")
	}
	atomic.StoreUint32(&sc.shared.ThreadID, threadID)
}

// EnableSentryFastPath indicates that the polling mode is enabled for the
// Sentry. It has to be called before putting the context into the context queue.
// This function is used if contextDecouplingExp=true because the fastpath
// is negotiated in ThreadContext.
func (sc *sharedContext) enableSentryFastPath() {
	atomic.StoreUint32(&sc.shared.SentryFastPath, 1)
}

// DisableSentryFastPath indicates that the polling mode for the sentry is
// disabled for the Sentry.
// This function is used if contextDecouplingExp=true because the fastpath
// is negotiated in ThreadContext.
func (sc *sharedContext) disableSentryFastPath() {
	atomic.StoreUint32(&sc.shared.SentryFastPath, 0)
}

func (sc *sharedContext) isAcked() bool {
	return atomic.LoadUint32(&sc.shared.Acked) != ackReset
}

func (sc *sharedContext) resetAcked() {
	atomic.StoreUint32(&sc.shared.Acked, ackReset)
}

func (sc *sharedContext) sleepOnState(state sysmsg.ContextState) {
	if errno := sc.shared.SleepOnState(state, sc); errno != 0 {
		panic(fmt.Sprintf("error waiting for state: %v", errno))
	}
}
