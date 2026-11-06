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

package watchdog

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/syncevent"
)

func TestStuckWatchdogUsesTaskAction(t *testing.T) {
	w := &Watchdog{
		Opts: Opts{
			TaskTimeoutAction:    LogWarning,
			StartupTimeoutAction: Panic,
		},
		// Avoid an unrelated stack dump on the logging path.
		lastStackDump: time.Now(),
	}
	// Reporting a stalled monitoring loop must use the task-timeout policy,
	// not the unrelated policy for failing to start the watchdog.
	w.reportStuckWatchdog()
}

func TestStuckGoroutineStacks(t *testing.T) {
	innocent0 := `goroutine 124 [select, 1 minutes]:
gvisor.dev/gvisor/pkg/sentry/ktime.(*SampledTimer).runGoroutine(0xc0008466c0)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/ktime/sampled_timer.go:235 +0xd4
created by gvisor.dev/gvisor/pkg/sentry/ktime.(*SampledTimer).init in goroutine 123
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/ktime/sampled_timer.go:102 +0x239`

	innocent1 := `goroutine 75 gp=0xc000460c40 m=nil [GC worker (idle), 15 minutes]:
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/proc.go:460 +0xce fp=0xc000466f38 sp=0xc000466f18 pc=0x48094e
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/asm_amd64.s:1693 +0x1 fp=0xc000466fe8 sp=0xc000466fe0 pc=0x4896c1
created by runtime.gcBgMarkStartWorkers in goroutine 1
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/mgc.go:1373 +0x105`

	stuckNetstackGoroutine := `goroutine 25916 [sync.RWMutex.RLock, 3 minutes]:
sync.runtime_Semacquire(0x41de33?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/sema.go:71 +0x25
gvisor.dev/gvisor/pkg/sync.(*CrossGoroutineRWMutex).Lock(0xc0006a3b08?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:154 +0x67
gvisor.dev/gvisor/pkg/sync.(*RWMutex).Lock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:292
created by gvisor.dev/gvisor/pkg/tcpip/link/veth.NewPair in goroutine 25922
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/tcpip/link/veth/veth.go:107 +0x2f3`

	stuckTaskGoroutine := `goroutine 26128 [deliberately-not-semacquire, 3 minutes]:
sync.runtime_Semacquire(0x47e205?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/sema.go:71 +0x25
gvisor.dev/gvisor/pkg/sync.(*CrossGoroutineRWMutex).RLock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:78
gvisor.dev/gvisor/pkg/sync.(*RWMutex).RLock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:259
gvisor.dev/gvisor/pkg/sentry/kernel.(*Task).doSyscall(0xc000fae160?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/kernel/task_run.go:97 +0x3e8`

	stuckTasks := make(map[int64]struct{})
	stuckTasks[26128] = struct{}{} // 26128 is stuckTaskGoroutine.
	allStacks := []string{innocent0, stuckNetstackGoroutine, innocent1, stuckTaskGoroutine}
	wantStacks := "\n" + strings.Join([]string{stuckNetstackGoroutine, stuckTaskGoroutine}, "\n\n") + "\n"

	gotStuckStacks := string(stuckGoroutineStacks([]byte(strings.Join(allStacks, "\n\n")), stuckTasks))
	if diff := cmp.Diff(wantStacks, gotStuckStacks); diff != "" {
		t.Errorf("stuckGoroutineStacks() returned unexpected diff (-want +got):\n%s", diff)
	}
}

// TestIdleWaitersNotStuck checks that goroutines idle in sleep.Sleeper.Fetch
// or syncevent.Waiter.WaitAndAckAll are not collated as stuck. Idle netstack
// processors and systrap task goroutines wait there, and a sandbox can have
// enough of them to fill the stuck goroutine section.
func TestIdleWaitersNotStuck(t *testing.T) {
	var s sleep.Sleeper
	var wk sleep.Waker
	s.AddWaker(&wk)
	sleeperDone := make(chan struct{})
	go func() {
		s.Fetch(true /* block */)
		close(sleeperDone)
	}()
	defer func() {
		wk.Assert()
		<-sleeperDone
		s.Done()
	}()

	var w syncevent.Waiter
	w.Init()
	waiterDone := make(chan struct{})
	go func() {
		w.WaitAndAckAll()
		close(waiterDone)
	}()
	defer func() {
		w.Notify(1)
		<-waiterDone
	}()

	idle := []string{
		"pkg/sleep.(*Sleeper).Fetch",
		"pkg/syncevent.(*Waiter).WaitAndAckAll",
	}
	var stacks string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		stacks = string(log.Stacks(true))
		if parked(stacks, idle[0]) && parked(stacks, idle[1]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not park:\n%s", stacks)
		}
	}

	got := string(stuckGoroutineStacks([]byte(stacks), nil))
	for _, fn := range idle {
		if strings.Contains(got, fn) {
			t.Errorf("stuck goroutine section contains idle %s:\n%s", fn, got)
		}
	}
}

// parked returns true if stacks has a goroutine that is parked with fn on its
// stack.
func parked(stacks, fn string) bool {
	for _, g := range strings.Split(stacks, "\n\n") {
		hdr, _, _ := strings.Cut(g, "\n")
		if strings.Contains(g, fn) && !strings.Contains(hdr, "[running") && !strings.Contains(hdr, "[runnable") {
			return true
		}
	}
	return false
}
