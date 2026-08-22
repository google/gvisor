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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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

type pullFullStateErrorContext struct {
	platform.Context
}

func (*pullFullStateErrorContext) PullFullState(platform.AddressSpace, *arch.Context64) error {
	return linuxerr.EIO
}

func TestRunInterruptPullFullStateError(t *testing.T) {
	ctx := contexttest.Context(t)
	mf := pgalloc.MemoryFileFromContext(ctx)
	defer mf.Destroy()
	memoryManager, err := mm.NewMemoryManager(platform.FromContext(ctx), mf)
	if err != nil {
		t.Fatal(err)
	}
	defer memoryManager.DecUsers(ctx)

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
