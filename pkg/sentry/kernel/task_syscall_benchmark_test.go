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
	_ "unsafe"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"

	pointspb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

type myNullSink struct {
	seccheck.SinkDefaults
}

func (myNullSink) Name() string { return "null" }

// BenchmarkExecuteSyscall measures the internal overhead of seccheck data
// collection during syscall execution.
//
// Unlike end-to-end benchmarks, this benchmark runs the executeSyscall loop with a dummy task and
// a null sink. This isolates the CPU and memory allocation costs of payload generation
// in LoadSeccheckData (e.g., CWD, Time, Credentials) from all IPC and context switch noise.
//
// To run the benchmark:
//
//	make test TARGETS="//pkg/sentry/kernel:kernel_test" \
//	  OPTIONS="--test_arg=-test.bench=BenchmarkExecuteSyscall --test_arg=-test.benchmem --test_output=all --nocache_test_results"
func BenchmarkExecuteSyscall(b *testing.B) {
	testCases := []struct {
		name string
		fm   func() seccheck.FieldMask
	}{
		{
			name: "Empty",
			fm:   func() seccheck.FieldMask { return seccheck.FieldMask{} },
		},
		{
			// Tests a trivial sub-nanosecond struct property read that doesn't allocate memory.
			name: "ThreadStartTime",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtThreadStartTime)
				return fm
			},
		},
		{
			// Tests the interface overhead of reaching into timekeeper and invoking clock functions.
			name: "Time",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtTime)
				return fm
			},
		},
		{
			// Tests locking overhead (task.k.tasks.mu.RLock()) and sets the groundwork for tracking the most
			// expensive path in gVisor: VFS traversal and string-building.
			name: "Cwd",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtCwd)
				return fm
			},
		},
		{
			// Tests protobuf nesting. Calling task.Credentials().LoadSeccheckData(...)
			// dynamically builds out nested structs (euid, suid, fsuid, groups, etc.)
			// and performs heavier allocations.
			name: "Credentials",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtCredentials)
				return fm
			},
		},
		{
			name: "ThreadID",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtThreadID)
				return fm
			},
		},
		{
			name: "ThreadGroupID",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtThreadGroupID)
				return fm
			},
		},
		{
			name: "ThreadGroupStartTime",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtThreadGroupStartTime)
				return fm
			},
		},
		{
			name: "ContainerID",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtContainerID)
				return fm
			},
		},
		{
			name: "ProcessName",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtProcessName)
				return fm
			},
		},
		{
			name: "ParentThreadGroupID",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtParentThreadGroupID)
				return fm
			},
		},
		{
			name: "IsExecSession",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtIsExecSession)
				return fm
			},
		},
		{
			name: "All",
			fm: func() seccheck.FieldMask {
				fm := seccheck.FieldMask{}
				fm.Add(seccheck.FieldCtxtTime)
				fm.Add(seccheck.FieldCtxtThreadID)
				fm.Add(seccheck.FieldCtxtThreadStartTime)
				fm.Add(seccheck.FieldCtxtThreadGroupID)
				fm.Add(seccheck.FieldCtxtThreadGroupStartTime)
				fm.Add(seccheck.FieldCtxtContainerID)
				fm.Add(seccheck.FieldCtxtCredentials)
				fm.Add(seccheck.FieldCtxtCwd)
				fm.Add(seccheck.FieldCtxtProcessName)
				fm.Add(seccheck.FieldCtxtParentThreadGroupID)
				fm.Add(seccheck.FieldCtxtIsExecSession)
				return fm
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			seccheck.Global = seccheck.State{}
			seccheck.Initialize()

			pt := seccheck.GetPointForSyscall(seccheck.SyscallEnter, 0)
			reqs := []seccheck.PointReq{
				{
					Pt: pt,
					Fields: seccheck.FieldSet{
						Context: tc.fm(),
					},
				},
			}
			seccheck.Global.AppendSink(myNullSink{}, reqs)

			_, params := stateTestClocklessTimekeeper(b)
			tk := NewTimekeeper()
			tk.SetClocks(&mockClocks{}, params)

			k := &Kernel{
				timekeeper: tk,
				tasks:      &TaskSet{},
			}

			creds := auth.NewRootCredentials(auth.NewRootUserNamespace())

			task := &Task{
				k: k,
			}

			st := &SyscallTable{
				Missing: func(task *Task, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
					return 0, nil
				},
			}
			st.pointCallbacks[0] = func(task *Task, fields seccheck.FieldSet, ctxData *pointspb.ContextData, info SyscallInfo) (proto.Message, pointspb.MessageType) {
				return nil, pointspb.MessageType(0)
			}

			tg := &ThreadGroup{
				threadGroupNode: threadGroupNode{
					leader: task,
				},
			}
			task.tg = tg

			pidns := &PIDNamespace{
				tids:  map[*Task]ThreadID{task: 1},
				tgids: map[*ThreadGroup]ThreadID{tg: 1},
			}
			k.tasks.Root = pidns

			ti := TaskImage{
				st: st,
			}
			task.image = ti
			task.creds.Store(creds)

			cwd := &FSContext{}
			task.fsContext.Store(cwd)

			task.SyscallTable().FeatureEnable.EnableAll(SecCheckEnter)

			var args arch.SyscallArguments

			for b.Loop() {
				task.executeSyscall(0, args)
			}
		})
	}
}
