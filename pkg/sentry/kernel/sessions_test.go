// Copyright 2025 The gVisor Authors.
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
	"testing"
	"time"
)

// These tests exercise handleOrphan's locking of thread-group signal handlers
// directly, because the kernel package has no lightweight harness for building
// real Tasks/ThreadGroups. They cover the first (stopped-job detection) loop of
// handleOrphan, which is where the production self-deadlock occurred. The full
// setsid()->CreateSession()->handleOrphan() call chain is covered end-to-end by
// the SetsidWithSharedSignalHandlers syscall test. The second (SIGHUP/SIGCONT
// delivery) loop uses the same "skip the already-held instance" guard as the
// first, but reaching it requires a stopped job and a real thread-group leader,
// so it is not separately unit-tested here.

// orphanTestSetup builds a minimal TaskSet containing thread groups that all
// belong to a single orphaned process group (ancestors == 0). Each thread
// group uses the SignalHandlers instance provided in shs[i]; passing the same
// pointer for multiple entries models thread groups that share signal handlers
// (e.g. clone(CLONE_SIGHAND) without CLONE_THREAD).
//
// It returns the process group so tests can invoke handleOrphan directly.
func orphanTestSetup(shs []*SignalHandlers) *ProcessGroup {
	ts := &TaskSet{}
	ns := &PIDNamespace{
		owner: ts,
		tgids: make(map[*ThreadGroup]ThreadID),
	}
	ts.Root = ns

	pg := &ProcessGroup{ancestors: 0}
	for i, sh := range shs {
		tg := &ThreadGroup{signalHandlers: sh}
		tg.pidns = ns
		tg.processGroup = pg
		ns.tgids[tg] = ThreadID(i + 1)
		if pg.originator == nil {
			pg.originator = tg
		}
	}
	return pg
}

// TestHandleOrphanSharedSignalHandlersNoDeadlock is a regression test for a
// self-deadlock in CreateSession: the caller holds a thread group's
// signalHandlers.mu, and handleOrphan would NestedLock the same instance again
// for another thread group that shares it. NestedLock is not recursive, so the
// goroutine deadlocked on itself. handleOrphan must skip re-locking the
// instance the caller already holds (passed as heldSH).
//
// The held locks, the handleOrphan call, and the unlocks all run on the same
// goroutine, faithfully reproducing the production condition: a single
// goroutine holds the shared signal mutex and then re-enters handleOrphan.
func TestHandleOrphanSharedSignalHandlersNoDeadlock(t *testing.T) {
	shared := &SignalHandlers{}
	// Two distinct thread groups sharing one SignalHandlers instance, both in
	// the orphaned process group.
	pg := orphanTestSetup([]*SignalHandlers{shared, shared})

	done := make(chan struct{})
	go func() {
		// Model CreateSession's held locks on this goroutine: TaskSet.mu
		// (write) and the originator's signal mutex. Then re-enter handleOrphan,
		// which must not try to lock the shared instance again.
		pg.originator.pidns.owner.mu.Lock()
		shared.mu.Lock()
		pg.handleOrphan(shared)
		shared.mu.Unlock()
		pg.originator.pidns.owner.mu.Unlock()
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(10 * time.Second):
		t.Fatal("handleOrphan deadlocked re-locking a shared signalHandlers instance already held by the caller")
	}
}

// TestHandleOrphanLocksUnsharedSignalHandlers verifies that the normal path
// really does (Nested)Lock thread-group signal handlers the caller does not
// already hold, and that the lock participates in synchronization. It holds one
// thread group's signal mutex from a helper goroutine and confirms handleOrphan
// blocks until that mutex is released, rather than silently skipping the lock.
func TestHandleOrphanLocksUnsharedSignalHandlers(t *testing.T) {
	sh1 := &SignalHandlers{}
	sh2 := &SignalHandlers{}
	pg := orphanTestSetup([]*SignalHandlers{sh1, sh2})

	// Hold sh2 from a helper goroutine so handleOrphan must block when it
	// reaches sh2's thread group.
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		sh2.mu.Lock()
		close(held)
		<-release
		sh2.mu.Unlock()
	}()
	<-held

	// Run handleOrphan on its own goroutine (holding TaskSet.mu, as required).
	// With heldSH == nil it must attempt to lock every thread group's signal
	// mutex, so it should block on the held sh2.
	done := make(chan struct{})
	go func() {
		pg.originator.pidns.owner.mu.Lock()
		pg.handleOrphan(nil)
		pg.originator.pidns.owner.mu.Unlock()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("handleOrphan completed without blocking on the held sh2 mutex; it is not locking the normal path")
	case <-time.After(500 * time.Millisecond):
		// Good: blocked waiting for sh2, proving it takes the lock.
	}

	close(release)
	select {
	case <-done:
		// Good: completed once sh2 became available.
	case <-time.After(10 * time.Second):
		t.Fatal("handleOrphan did not complete after sh2 was released")
	}
}
