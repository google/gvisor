// Copyright 2026 The gVisor Authors.
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
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/syncevent"
)

func newTestSharedContext(t *testing.T) *sharedContext {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestStuckSubprocessHelper")
	cmd.Env = append(os.Environ(), "GVISOR_STUCK_SUBPROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start helper subprocess: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	threadID := uint32(1)
	child := &thread{tgid: int32(cmd.Process.Pid), tid: int32(cmd.Process.Pid)}
	queue := &contextQueue{}
	queue.init()
	atomic.AddUint32(&queue.end, 1)
	s := &subprocess{
		contextQueue: queue,
		syscallThread: &syscallThread{
			thread: child,
		},
		sysmsgThreads: map[uint32]*sysmsgThread{
			threadID: {thread: child},
		},
	}
	shared := &sysmsg.ThreadContext{}
	shared.Init(threadID)
	atomic.StoreUint64(&shared.AckedTime, 1)
	return &sharedContext{
		subprocess: s,
		shared:     shared,
	}
}

func TestSleepOnStateStuckContext(t *testing.T) {
	sc := newTestSharedContext(t)

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 15*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
}

func TestSleepOnStateStuckContextWhenStubIsGone(t *testing.T) {
	sc := newTestSharedContext(t)

	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	sc.subprocess.sysmsgThreads[1].thread = missing

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, time.Second, 10*time.Millisecond)
	if !errors.Is(err, errStubThreadGone) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStubThreadGone)
	}
}

func TestSleepOnStateRepeatedInterruptsStillStuck(t *testing.T) {
	sc := newTestSharedContext(t)

	// Interrupts are resent on every checkup wakeup. The resends must not
	// push the stuck deadline out.
	start := time.Now()
	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 30*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("stuck context detection took %v, want under 1s", elapsed)
	}
}

func TestSleepOnStateRecoveredContext(t *testing.T) {
	sc := newTestSharedContext(t)

	stateChanged := make(chan struct{})
	go func() {
		for atomic.LoadUint32(&sc.shared.Interrupt) == 0 {
			time.Sleep(time.Millisecond)
		}
		sc.setState(sysmsg.ContextStateSyscall)
		close(stateChanged)
	}()

	err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 5*time.Millisecond, 10*time.Millisecond)
	<-stateChanged
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

func emptyContextQueue(sc *sharedContext) {
	q := sc.subprocess.contextQueue
	atomic.StoreUint32(&q.end, atomic.LoadUint32(&q.start))
}

// sleepOnStateBounded fails the test instead of hanging if the wait never
// returns.
func sleepOnStateBounded(t *testing.T, sc *sharedContext, stuckTimeout, checkupTimeout time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, stuckTimeout, checkupTimeout) }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		sc.setState(sysmsg.ContextStateSyscall)
		<-done
		t.Fatalf("sleepOnStateWithTimeout did not return")
		return nil
	}
}

func TestSleepOnStateRequestedInterruptEmptyQueue(t *testing.T) {
	sc := newTestSharedContext(t)
	emptyContextQueue(sc)
	sc.NotifyInterrupt()
	// Clear the guest-writable flag so only sentry-side state drives the resend.
	atomic.StoreUint32(&sc.shared.Interrupt, 0)

	err := sleepOnStateBounded(t, sc, 15*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errStuckContext) {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want %v", err, errStuckContext)
	}
	if atomic.LoadUint32(&sc.shared.Interrupt) == 0 {
		t.Fatalf("interrupt was not resent")
	}
}

func TestSleepOnStateRequestedInterruptRecovers(t *testing.T) {
	sc := newTestSharedContext(t)
	emptyContextQueue(sc)
	sc.NotifyInterrupt()
	atomic.StoreUint32(&sc.shared.Interrupt, 0)

	recovered := make(chan struct{})
	go func() {
		defer close(recovered)
		for atomic.LoadUint32(&sc.shared.Interrupt) == 0 {
			if sc.state() != sysmsg.ContextStateNone {
				return
			}
			time.Sleep(time.Millisecond)
		}
		sc.setState(sysmsg.ContextStateSyscall)
	}()
	err := sleepOnStateBounded(t, sc, 5*time.Second, 10*time.Millisecond)
	<-recovered
	if err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
}

func TestSleepOnStateEmptyQueueAfterClearInterrupt(t *testing.T) {
	sc := newTestSharedContext(t)
	emptyContextQueue(sc)
	// A request cleared by the previous switch must not interrupt the next run.
	sc.NotifyInterrupt()
	sc.clearInterrupt()

	go func() {
		time.Sleep(50 * time.Millisecond)
		sc.setState(sysmsg.ContextStateSyscall)
	}()
	if err := sleepOnStateBounded(t, sc, 5*time.Millisecond, 5*time.Millisecond); err != nil {
		t.Fatalf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
	if atomic.LoadUint32(&sc.shared.Interrupt) != 0 {
		t.Fatalf("stub was interrupted with an empty queue and no requested interrupt")
	}
}

func TestStuckState(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.sysmsgThreads[1].msg = &sysmsg.Msg{Line: 42}
	if got := sc.stuckState(); !strings.Contains(got, "line 42") {
		t.Fatalf("stuckState got %q, want the stub line", got)
	}
	delete(sc.subprocess.sysmsgThreads, 1)
	if got := sc.stuckState(); !strings.HasSuffix(got, "no stub thread") {
		t.Fatalf("stuckState without a stub thread got %q, want no stub thread", got)
	}
}

func TestDispatcherSlowPathUnderChurn(t *testing.T) {
	initSleepTimeouts()
	enabled := fastpath.sentryFastPathEnabled.Load()
	fastpath.sentryFastPathEnabled.Store(true)
	// Other contexts completing on every pass keep the dispatcher from ever
	// idling into the slow path; model that by making the idle timeout
	// unreachable.
	idle := deepSleepTimeout
	deepSleepTimeout = ^uint64(0)
	defer func() {
		deepSleepTimeout = idle
		fastpath.sentryFastPathEnabled.Store(enabled)
	}()

	stuck := newTestSharedContext(t)
	stuck.sync.Init()
	stuck.startWaitingTS = cputicks()

	got := make(chan syncevent.Set, 1)
	go func() { got <- dispatcher.waitFor(stuck) }()
	select {
	case events := <-got:
		if events&sharedContextSlowPath == 0 {
			t.Fatalf("stuck context got events %v, want sharedContextSlowPath", events)
		}
	case <-time.After(5 * time.Second):
		stuck.setState(sysmsg.ContextStateSyscall)
		<-got
		t.Fatalf("stuck context was never handed to the slow path")
	}
}

func TestSleepOnStateDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	err := sc.sleepOnState(sysmsg.ContextStateNone)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("sleepOnState got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestWaitOnStateDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	err := sc.subprocess.waitOnState(sc)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("waitOnState got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestKickSysmsgThreadDeadSubprocess(t *testing.T) {
	sc := newTestSharedContext(t)
	sc.subprocess.dead.Store(true)

	if sc.subprocess.kickSysmsgThread() {
		t.Fatalf("kickSysmsgThread got true, want false when subprocess is dead")
	}
}

func TestWithAliveRLockDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	called := false
	err := s.withAliveRLock(func() error {
		called = true
		return nil
	})
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("withAliveRLock got error %v, want %v", err, errDeadSubprocess)
	}
	if called {
		t.Fatalf("withAliveRLock executed callback when dead")
	}
}

func TestSyscallDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	if _, err := s.syscall(unix.SYS_MMAP); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("syscall got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestCreateSysmsgThreadDeadSubprocess(t *testing.T) {
	s := &subprocess{}
	s.dead.Store(true)

	if err := s.createSysmsgThread(); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("createSysmsgThread got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestReleaseDeadSubprocessDecRefs(t *testing.T) {
	sc := newTestSharedContext(t)
	s := sc.subprocess
	s.subprocessRefs.InitRefs()
	s.dead.Store(true)

	released := false
	// Set ref count to 1 and verify DecRef fires.
	s.DecRef(func() {
		released = true
	})
	if !released {
		t.Fatalf("expected subprocess to be released")
	}
}

func TestStuckSubprocessHelper(t *testing.T) {
	if os.Getenv("GVISOR_STUCK_SUBPROCESS_HELPER") == "" {
		return
	}
	select {}
}
