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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/mm"
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

type pullFullStateErrorContext struct {
	platform.Context
}

func (*pullFullStateErrorContext) PullFullState(platform.AddressSpace, *arch.Context64) error {
	return linuxerr.EIO
}

type pullFullStateErrorPlatform struct {
	platform.Platform
}

func (*pullFullStateErrorPlatform) SupportsAddressSpaceIO() bool { return false }

func (*pullFullStateErrorPlatform) NewAddressSpace() (platform.AddressSpace, error) {
	return &pullFullStateErrorAddressSpace{}, nil
}

type pullFullStateErrorAddressSpace struct {
	platform.AddressSpace
}

func (*pullFullStateErrorAddressSpace) Release() {}

func TestRunInterruptPullFullStateError(t *testing.T) {
	// PullFullState returns an error without accessing application memory.
	// Construct a valid, empty MemoryManager without backing memory or a live
	// platform address space. Unexpected platform operations fail through the
	// nil embedded interfaces above.
	memoryManager, err := mm.NewMemoryManager(&pullFullStateErrorPlatform{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer memoryManager.DecUsers(context.Background())

	tg := &ThreadGroup{signalHandlers: NewSignalHandlers()}
	task := &Task{
		taskNode: taskNode{tg: tg},
		image: TaskImage{
			Arch:          new(arch.Context64),
			MemoryManager: memoryManager,
		},
		p: &pullFullStateErrorContext{},
	}
	tg.tasks.PushBack(task)
	tg.signalHandlers.mu.Lock()
	queued := task.pendingSignals.enqueue(SignalInfoPriv(linux.SIGUSR1), nil)
	tg.signalHandlers.mu.Unlock()
	if !queued {
		t.Fatal("failed to enqueue signal")
	}

	if next := (*runInterrupt)(nil).execute(task); next != (*runExit)(nil) {
		t.Fatalf("runInterrupt returned %T, want *runExit", next)
	}

	// The error path must release the signal mutex before entering runExit.
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	if !tg.exiting {
		t.Error("thread group is not exiting")
	}
	wantStatus := linux.WaitStatusTerminationSignal(linux.SIGILL)
	if got := tg.exitStatus; got != wantStatus {
		t.Errorf("thread group exit status = %v, want %v", got, wantStatus)
	}
	if got := task.exitStatus; got != wantStatus {
		t.Errorf("task exit status = %v, want %v", got, wantStatus)
	}
}
