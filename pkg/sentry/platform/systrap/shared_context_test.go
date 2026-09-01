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
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
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

func TestStuckSubprocessHelper(t *testing.T) {
	if os.Getenv("GVISOR_STUCK_SUBPROCESS_HELPER") == "" {
		return
	}
	select {}
}
