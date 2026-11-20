// Copyright 2018 The gVisor Authors.
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
	"math"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

func TestTaskCPU(t *testing.T) {
	for _, test := range []struct {
		mask sched.CPUSet
		tid  ThreadID
		cpu  int32
	}{
		{
			mask: []byte{0xff},
			tid:  1,
			cpu:  1,
		},
		{
			mask: []byte{0xff},
			tid:  10,
			cpu:  2,
		},
		{
			// more than 8 cpus.
			mask: []byte{0xff, 0xff},
			tid:  10,
			cpu:  10,
		},
		{
			// missing the first cpu.
			mask: []byte{0xfe},
			tid:  1,
			cpu:  2,
		},
		{
			mask: []byte{0xfe},
			tid:  10,
			cpu:  4,
		},
		{
			// missing the fifth cpu.
			mask: []byte{0xef},
			tid:  10,
			cpu:  3,
		},
		{
			// only the fifth cpu.
			mask: []byte{0x10},
			tid:  10,
			cpu:  4,
		},
	} {
		assigned := assignCPU(test.mask, test.tid)
		if test.cpu != assigned {
			t.Errorf("assignCPU(%v, %v) got %v, want %v", test.mask, test.tid, assigned, test.cpu)
		}
	}
}

func TestFSCheckpointedMemoryFilesFromContext(t *testing.T) {
	if got := FSCheckpointedMemoryFilesFromContext(nil); got != nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(nil) = %v, want nil", got)
	}
	ctx := context.Background()
	if got := FSCheckpointedMemoryFilesFromContext(ctx); got != nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(ctx) = %v, want nil", got)
	}
	mfs := make(map[checkpoint.ResourceID]struct{})
	ctx = WithFSRestore(ctx, mfs)
	if got := FSCheckpointedMemoryFilesFromContext(ctx); got == nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(ctx) = nil, want non-nil")
	}
}

func TestMatchesPaths(t *testing.T) {
	pathsMap := map[checkpoint.ResourceID]struct{}{
		{ContainerName: "c1", Path: "/data"}: {},
	}
	rid := checkpoint.ResourceID{ContainerName: "c1", Path: "/data"}
	if !matchesPaths(rid, pathsMap, true /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=true) = false, want true", rid)
	}
	if matchesPaths(rid, pathsMap, false /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=false) = true, want false", rid)
	}
}

func TestMatchesPathsDefaultRoot(t *testing.T) {
	pathsMap := map[checkpoint.ResourceID]struct{}{
		{Path: "/"}: {},
	}
	rid := checkpoint.ResourceID{Path: "/"}
	if !matchesPaths(rid, pathsMap, true /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=true) = false, want true", rid)
	}
}

func TestPIDNamespaceLastTID(t *testing.T) {
	ns := newTaskSet(NewRootPIDNamespace(nil)).Root
	if got := ns.LastTID(); got != 0 {
		t.Errorf("ns.LastTID() = %d, want 0", got)
	}
	ns.ReserveInitTID()
	if got := ns.LastTID(); got != initTID {
		t.Errorf("ns.LastTID() = %d, want %d", got, initTID)
	}
	ns.owner.mu.Lock()
	tid, err := ns.allocateTID()
	ns.owner.mu.Unlock()
	if err != nil {
		t.Fatalf("ns.allocateTID() failed: %v", err)
	}
	if got := ns.LastTID(); got != tid {
		t.Errorf("ns.LastTID() = %d, want %d", got, tid)
	}
}

type loadavgTestPlatform struct {
	platform.Platform
}

func (loadavgTestPlatform) ConcurrencyCount() int {
	return 1
}

func newLoadavgTestKernel(t *testing.T) (*Kernel, *mockClocks) {
	t.Helper()
	clocks := &mockClocks{}
	tk := NewTimekeeper()
	_, params := stateTestClocklessTimekeeper(t)
	tk.SetClocks(clocks, params)
	t.Cleanup(tk.Destroy)

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	t.Cleanup(func() { timer.Stop() })

	k := &Kernel{
		Platform:             loadavgTestPlatform{},
		timekeeper:           tk,
		tasks:                newTaskSet(NewRootPIDNamespace(nil)),
		applicationCores:     1,
		taskActivityCh:       make(chan struct{}),
		cpuClockTickTimer:    timer,
		cpuClockTickerWakeCh: make(chan struct{}, 1),
	}
	k.runningTasksCond.L = &k.runningTasksMu
	k.cpuClockTickerStopCond.L = &k.runningTasksMu
	return k, clocks
}

func setMonotonicTime(clocks *mockClocks, d time.Duration) {
	clocks.mu.Lock()
	clocks.monotonic = d.Nanoseconds()
	clocks.mu.Unlock()
}

const loadavgTolerance = 1e-9

func loadavgApproxEqual(got, want [3]float64) bool {
	return math.Abs(got[0]-want[0]) <= loadavgTolerance &&
		math.Abs(got[1]-want[1]) <= loadavgTolerance &&
		math.Abs(got[2]-want[2]) <= loadavgTolerance
}

func TestKernelLoadavgSamplingAndDecay(t *testing.T) {
	k, clocks := newLoadavgTestKernel(t)
	k.runningTasks.Store(2)
	k.blockedTasks.Store(1)

	if got, want := k.Loadavg(), [3]float64{0, 0, 0}; !loadavgApproxEqual(got, want) {
		t.Errorf("at t=0: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want, loadavgTolerance)
	}

	setMonotonicTime(clocks, loadavgSampleInterval-time.Nanosecond)
	if got, want := k.Loadavg(), [3]float64{0, 0, 0}; !loadavgApproxEqual(got, want) {
		t.Errorf("before 5s boundary: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want, loadavgTolerance)
	}

	// Sample at a non-multiple timestamp (5.3s): updateLoadavg must advance by
	// exactly one 5.0s grid window and leave lastLoadavgSample phase-locked at 5.0s.
	setMonotonicTime(clocks, loadavgSampleInterval+300*time.Millisecond)
	want5s := [3]float64{0.239866756112, 0.049585638535, 0.016620455985}
	if got := k.Loadavg(); !loadavgApproxEqual(got, want5s) {
		t.Errorf("at t=5.3s: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want5s, loadavgTolerance)
	}

	// Stale out-of-order timestamps must not rewind lastLoadavgSample or mutate loadavg.
	k.updateLoadavg(ktime.FromNanoseconds(0), 100)
	setMonotonicTime(clocks, loadavgSampleInterval+400*time.Millisecond)
	if got := k.Loadavg(); !loadavgApproxEqual(got, want5s) {
		t.Errorf("after stale sample: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want5s, loadavgTolerance)
	}

	// Decay to zero active tasks on the 10.0s grid boundary (only 4.6s after 5.4s,
	// proving lastLoadavgSample stayed aligned at 5.0s rather than drifting to 5.3s).
	k.runningTasks.Store(0)
	k.blockedTasks.Store(0)
	setMonotonicTime(clocks, 2*loadavgSampleInterval)
	want10s := [3]float64{0.220688069216, 0.048766060019, 0.016528376133}
	if got := k.Loadavg(); !loadavgApproxEqual(got, want10s) {
		t.Errorf("at t=10s: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want10s, loadavgTolerance)
	}
}

func TestKernelLoadavgMultiPeriodEquivalence(t *testing.T) {
	kStep, clocksStep := newLoadavgTestKernel(t)
	kFast, clocksFast := newLoadavgTestKernel(t)
	kStep.runningTasks.Store(4)
	kFast.runningTasks.Store(4)

	const periods = 13
	for i := range periods {
		setMonotonicTime(clocksStep, time.Duration(i+1)*loadavgSampleInterval)
		kStep.Loadavg()
	}
	setMonotonicTime(clocksFast, periods*loadavgSampleInterval)

	gotFast := kFast.Loadavg()
	gotStep := kStep.Loadavg()
	want65s := [3]float64{2.646138299573, 0.779206703928, 0.278703463432}
	if !loadavgApproxEqual(gotStep, want65s) {
		t.Errorf("13 stepwise periods: kStep.Loadavg() = %.12f, want %.12f (tolerance %g)", gotStep, want65s, loadavgTolerance)
	}
	if !loadavgApproxEqual(gotFast, gotStep) {
		t.Errorf("13-period jump: kFast.Loadavg() = %.12f, want kStep.Loadavg() = %.12f (tolerance %g)", gotFast, gotStep, loadavgTolerance)
	}
}

func TestKernelLoadavgIdleWakeup(t *testing.T) {
	k, clocks := newLoadavgTestKernel(t)

	// Waking up after 60s of zero running and zero blocked tasks must account
	// the idle period before runningTasks transitions to 1.
	setMonotonicTime(clocks, 12*loadavgSampleInterval)
	k.incRunningTasks()

	if got, want := k.Loadavg(), [3]float64{0, 0, 0}; !loadavgApproxEqual(got, want) {
		t.Errorf("after 60s idle wakeup: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want, loadavgTolerance)
	}

	// Park again with 2 uninterruptible blocked tasks across one 5s window.
	k.decRunningTasks()
	k.runningTasksMu.Lock()
	k.cpuClockTickerRunning = false
	k.runningTasksMu.Unlock()
	k.blockedTasks.Store(2)
	setMonotonicTime(clocks, 13*loadavgSampleInterval)
	k.incRunningTasks()
	k.blockedTasks.Store(0)
	k.decRunningTasks()

	wantBlocked := [3]float64{0.159911170741, 0.033057092357, 0.011080303990}
	if got := k.Loadavg(); !loadavgApproxEqual(got, wantBlocked) {
		t.Errorf("after blocked wakeup: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, wantBlocked, loadavgTolerance)
	}

	// While cpuClockTickerRunning remains true (slack-window 0 -> 1 transition),
	// incRunningTasks must NOT flush the window as idle before runningTasks becomes 1.
	k.runningTasksMu.Lock()
	k.cpuClockTickerRunning = true
	k.runningTasksMu.Unlock()
	setMonotonicTime(clocks, 14*loadavgSampleInterval)
	k.incRunningTasks()
	t.Cleanup(k.decRunningTasks)

	wantSlack := [3]float64{0.227080964848, 0.049039252858, 0.016559069417}
	if got := k.Loadavg(); !loadavgApproxEqual(got, wantSlack) {
		t.Errorf("after slack-window wakeup: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, wantSlack, loadavgTolerance)
	}
}

func TestKernelLoadavgTicker(t *testing.T) {
	k, clocks := newLoadavgTestKernel(t)
	k.runningTasks.Store(2)
	k.blockedTasks.Store(1)
	k.runningTasksMu.Lock()
	k.cpuClockTickerRunning = true
	k.runningTasksMu.Unlock()

	setMonotonicTime(clocks, loadavgSampleInterval)
	k.cpuClockTickTimer.Reset(time.Nanosecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		k.runCPUClockTicker()
	}()
	t.Cleanup(func() {
		if !k.cpuClockTickTimer.Stop() {
			select {
			case <-k.cpuClockTickTimer.C:
			default:
			}
		}
		select {
		case <-k.cpuClockTickerWakeCh:
		default:
		}
		close(k.cpuClockTickerWakeCh)
		k.runningTasksMu.Lock()
		k.runningTasksCond.Broadcast()
		k.runningTasksMu.Unlock()
		<-done
	})

	for {
		k.loadavgMu.Lock()
		sampled := k.lastLoadavgSample != (ktime.Time{})
		k.loadavgMu.Unlock()
		if sampled {
			break
		}
		runtime.Gosched()
	}

	k.runningTasks.Store(0)
	k.blockedTasks.Store(0)
	k.runningTasksMu.Lock()
	for k.cpuClockTickerRunning {
		select {
		case k.cpuClockTickerWakeCh <- struct{}{}:
		default:
		}
		k.cpuClockTickerStopCond.Wait()
	}
	k.runningTasksMu.Unlock()

	want := [3]float64{0.239866756112, 0.049585638535, 0.016620455985}
	if got := k.Loadavg(); !loadavgApproxEqual(got, want) {
		t.Errorf("after ticker tick: k.Loadavg() = %.12f, want %.12f (tolerance %g)", got, want, loadavgTolerance)
	}
}
