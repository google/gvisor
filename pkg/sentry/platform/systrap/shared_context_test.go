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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/pool"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

// startStuckChild starts a child process that never responds
// as a stand-in for a stub process.
func startStuckChild() (*exec.Cmd, error) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"=stuck")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start stuck child: %w", err)
	}
	return cmd, nil
}

func stopChild(cmd *exec.Cmd) {
	cmd.Process.Kill()
	cmd.Wait()
}

func newTestSharedContext(t *testing.T) *sharedContext {
	t.Helper()

	cmd, err := startStuckChild()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopChild(cmd) })
	return newChildSharedContext(cmd.Process.Pid)
}

func newChildSharedContext(pid int) *sharedContext {
	threadID := uint32(1)
	child := &thread{tgid: int32(pid), tid: int32(pid)}
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
	s.syscallThread.subproc = s
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

func TestSleepOnStateHostStall(t *testing.T) {
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	defer readyRead.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"=hoststall")
	cmd.ExtraFiles = []*os.File{readyWrite}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Start()
	readyWrite.Close()
	if err != nil {
		t.Fatalf("cannot start child: %v", err)
	}
	defer cmd.Process.Kill()
	if _, err := io.ReadAll(readyRead); err != nil {
		t.Fatalf("cannot wait for child readiness: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatalf("cannot stop child: %v", err)
	}
	time.Sleep(hostStallThreshold * 2)
	if err := cmd.Process.Signal(unix.SIGCONT); err != nil {
		t.Fatalf("cannot continue child: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child failed: %v\n%s", err, out.String())
	}
}

// hostStallChild waits on a context whose stub thread responds shortly after
// the host stall ends.
// Closes FD 3 once it is about to wait.
func hostStallChild() error {
	unix.CloseOnExec(3)
	cmd, err := startStuckChild()
	if err != nil {
		return err
	}
	defer stopChild(cmd)
	sc := newChildSharedContext(cmd.Process.Pid)
	go func() {
		for last := time.Now(); ; {
			time.Sleep(10 * time.Millisecond)
			now := time.Now()
			if now.Sub(last) > hostStallThreshold {
				break
			}
			last = now
		}
		time.Sleep(100 * time.Millisecond)
		sc.setState(sysmsg.ContextStateSyscall)
	}()
	os.NewFile(3, "marker").Close()
	if err := sc.sleepOnStateWithTimeout(sysmsg.ContextStateNone, 500*time.Millisecond, time.Second); err != nil {
		return fmt.Errorf("sleepOnStateWithTimeout got error %v, want nil", err)
	}
	return nil
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

func TestThreadWaitStoppedWhenSignaled(t *testing.T) {
	sc := newTestSharedContext(t)
	child := sc.subprocess.syscallThread.thread
	child.kill()

	_, err := child.wait(stopped)
	if !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("wait(stopped) got error %v, want %v", err, errDeadSubprocess)
	}
}

func TestThreadWaitECHILD(t *testing.T) {
	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	_, err := missing.wait(stopped)
	if !errors.Is(err, unix.ECHILD) {
		t.Fatalf("wait(stopped) got error %v, want %v", err, unix.ECHILD)
	}
}

func TestThreadSyscallDeadThread(t *testing.T) {
	missing := &thread{tgid: 1 << 30, tid: 1 << 30}
	var regs arch.Registers
	_, err := missing.syscall(&regs)
	if !errors.Is(err, unix.ESRCH) {
		t.Fatalf("syscall got error %v, want %v", err, unix.ESRCH)
	}
}

func TestSysmsgThreadInitDeadThread(t *testing.T) {
	addr, errno := hostsyscall.RawSyscall6(
		unix.SYS_MMAP,
		0,
		hostarch.PageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		0, 0)
	if errno != 0 {
		t.Fatalf("mmap failed: %v", errno)
	}
	defer hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, hostarch.PageSize, 0)

	st := &sysmsgThread{
		thread: &thread{tgid: 1 << 30, tid: 1 << 30},
	}
	if err := st.init(addr, addr); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("sysmsgThread.init got error %v, want %v", err, unix.ESRCH)
	}
}

func TestCreateSysmsgThreadDeadClone(t *testing.T) {
	s := &subprocess{
		requests:        make(chan any, 1),
		sysmsgStackPool: pool.Pool{Start: 0, Limit: 1},
	}
	id, ok := s.sysmsgStackPool.Get()
	if !ok {
		t.Fatalf("failed to allocate stack ID")
	}
	go func() {
		req := (<-s.requests).(requestThread)
		req.thread <- &thread{
			tgid:          1 << 30,
			tid:           1 << 30,
			sysmsgStackID: id,
		}
	}()

	if err := s.createSysmsgThread(); err == nil {
		t.Fatalf("createSysmsgThread succeeded, want error")
	}
	if _, ok := s.sysmsgStackPool.Get(); !ok {
		t.Fatalf("expected sysmsgStackID to be returned to pool on failure")
	}
}

func TestSyscallThreadKillMarksSubprocessDead(t *testing.T) {
	sc := newTestSharedContext(t)
	s := sc.subprocess

	s.syscallThread.kill()
	if !s.dead.Load() {
		t.Fatalf("expected subprocess to be marked dead after syscallThread.kill()")
	}
	if err := s.createSysmsgThread(); !errors.Is(err, errDeadSubprocess) {
		t.Fatalf("createSysmsgThread got error %v, want %v", err, errDeadSubprocess)
	}
	req := requestThread{thread: make(chan *thread, 1)}
	s.handlePtraceSyscallRequest(req)
	if got := <-req.thread; got != nil {
		t.Fatalf("handlePtraceSyscallRequest got %v, want nil when subprocess is dead", got)
	}
}

func TestInitSyscallThreadPoolExhausted(t *testing.T) {
	s := &subprocess{
		sysmsgStackPool: pool.Pool{Start: 0, Limit: 0},
	}
	p := &thread{tgid: 1 << 30, tid: 1 << 30}
	if err := s.initSyscallThread(p, false); err == nil {
		t.Fatalf("initSyscallThread succeeded when pool was exhausted, want error")
	}
}
