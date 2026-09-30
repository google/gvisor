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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
)

// TestSetCPUMaskToleratesGrowthAcrossSizeBoundary reproduces the guest-
// triggerable crash this fixes: sched_setaffinity builds its mask from one
// ApplicationCores() read, then SetCPUMask re-reads it. CPUSetSize rounds to
// 8-byte (64-CPU) boundaries, so a live grow that crosses one between those
// two reads used to panic the whole sentry, not just the calling task.
func TestSetCPUMaskToleratesGrowthAcrossSizeBoundary(t *testing.T) {
	p, err := ptrace.New()
	if err != nil {
		t.Fatalf("ptrace.New: %v", err)
	}
	// useHostCores makes SetCPUMask return right after its size check,
	// so this test doesn't need a full Task/ThreadGroup/PID-namespace
	// fixture to exercise that check.
	k := &Kernel{Platform: p, useHostCores: true}
	k.applicationCores.Store(32) // CPUSetSize(32) == 8 bytes.

	mask := sched.NewFullCPUSet(32)
	if err := k.SetApplicationCores(96); err != nil { // CPUSetSize(96) == 16 bytes.
		t.Fatalf("SetApplicationCores(96): %v", err)
	}

	task := &Task{k: k}
	if err := task.SetCPUMask(mask); err != nil {
		t.Errorf("SetCPUMask: %v", err)
	}
}

// TestSetCPUMaskRejectsOversizedMask checks the other side of the size
// check: a mask larger than ApplicationCores allows is still a caller bug,
// not a tolerated race, and must still panic.
func TestSetCPUMaskRejectsOversizedMask(t *testing.T) {
	p, err := ptrace.New()
	if err != nil {
		t.Fatalf("ptrace.New: %v", err)
	}
	k := &Kernel{Platform: p, useHostCores: true}
	k.applicationCores.Store(32)

	defer func() {
		if recover() == nil {
			t.Error("SetCPUMask with an oversized mask did not panic")
		}
	}()
	task := &Task{k: k}
	task.SetCPUMask(sched.NewFullCPUSet(96))
}

func newCPUMaskTestTask(t *testing.T, cores uint32) (*Kernel, *Task) {
	t.Helper()
	p, err := ptrace.New()
	if err != nil {
		t.Fatalf("ptrace.New: %v", err)
	}
	k := &Kernel{Platform: p}
	k.applicationCores.Store(cores)
	ts := &TaskSet{}
	ts.Root = &PIDNamespace{owner: ts, tids: make(map[*Task]ThreadID)}
	tg := &ThreadGroup{}
	tg.pidns = ts.Root
	task := &Task{k: k, tg: tg, allowedCPUMask: sched.NewFullCPUSet(uint(cores))}
	ts.Root.tids[task] = 1
	return k, task
}

func TestCPUMaskFollowsGrowthUntilPinned(t *testing.T) {
	k, task := newCPUMaskTestTask(t, 2)

	if err := k.SetApplicationCores(8); err != nil {
		t.Fatalf("SetApplicationCores(8): %v", err)
	}
	if mask, pinned := task.cpuMaskState(); mask.NumCPUs() != 8 || pinned {
		t.Errorf("after grow to 8: mask %v pinned %v, want all 8 CPUs unpinned", mask, pinned)
	}

	narrow := sched.NewCPUSet(8)
	narrow.Set(0)
	narrow.Set(1)
	if err := task.SetCPUMask(narrow); err != nil {
		t.Fatalf("SetCPUMask(0-1): %v", err)
	}
	if err := k.SetApplicationCores(16); err != nil {
		t.Fatalf("SetApplicationCores(16): %v", err)
	}
	if mask, pinned := task.cpuMaskState(); mask.NumCPUs() != 2 || !pinned {
		t.Errorf("pinned to 0-1 then grown to 16: mask %v pinned %v, want 2 CPUs pinned", mask, pinned)
	}

	// Asking for every CPU again is how a task gives up its pin.
	if err := task.SetCPUMask(sched.NewFullCPUSet(16)); err != nil {
		t.Fatalf("SetCPUMask(all): %v", err)
	}
	if err := k.SetApplicationCores(32); err != nil {
		t.Fatalf("SetApplicationCores(32): %v", err)
	}
	if got := task.CPUMask().NumCPUs(); got != 32 {
		t.Errorf("unpinned then grown to 32: CPUMask has %d CPUs, want 32", got)
	}
}
