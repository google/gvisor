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
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

func TestParentDeathSignalClearedOnCredentialChange(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Task)
	}{
		{
			name: "uid",
			change: func(task *Task) {
				task.setKUIDsUnchecked(0, 1, 0)
			},
		},
		{
			name: "gid",
			change: func(task *Task) {
				task.setKGIDsUnchecked(0, 1, 0)
			},
		},
	} {
		_ = t.Run(test.name, func(t *testing.T) {
			task := &Task{
				image: TaskImage{MemoryManager: new(mm.MemoryManager)},
			}
			task.creds.Store(auth.NewRootCredentials(auth.NewRootUserNamespace()))
			task.SetParentDeathSignal(linux.SIGUSR1)

			var wg sync.WaitGroup
			wg.Go(func() { test.change(task) })
			// Read before Wait so the reset and read are not ordered by the
			// wait group. Under -race, this checks that the reset takes Task.mu.
			observed := task.ParentDeathSignal()
			wg.Wait()
			if observed != 0 && observed != linux.SIGUSR1 {
				t.Errorf("concurrent ParentDeathSignal() = %d, want 0 or %d", observed, linux.SIGUSR1)
			}
			if got := task.ParentDeathSignal(); got != 0 {
				t.Errorf("ParentDeathSignal() after credential change = %d, want 0", got)
			}
		})
	}
}

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
