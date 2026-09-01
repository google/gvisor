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

package scsdk

import (
	"testing"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func TestProcessTrackerAndPipeEnrichment(t *testing.T) {
	pt := NewProcessTracker()

	// Simulate an ExecveInfo event for process A ("cat foo").
	// Design Decision: Only standard ExecveInfo events carry the full strings (BinaryPath, Argv).
	execA := &pb.ExecveInfo{
		ContextData: &pb.ContextData{
			ThreadGroupId:          100,
			ThreadGroupStartTimeNs: 1000,
			ContainerId:            "test-container",
			ProcessName:            "cat",
		},
		BinaryPath: "/bin/cat",
		Argv:       []string{"cat", "foo"},
	}

	eventA := pt.ProcessExecve(ToExecutionEvent(execA))
	if eventA.Process == nil {
		t.Fatalf("got nil, want ProcessInfo for cat")
	}
	if eventA.Process.BinaryPath != "/bin/cat" {
		t.Errorf("got binary %q, want %q", eventA.Process.BinaryPath, "/bin/cat")
	}

	// Simulate an ExecveInfo event for process B ("grep bar") which receives piped input from A.
	// Design Decision: Notice that PipeInputProc ONLY contains ContextData (TGID=100, StartTime=1000)
	// without any string fields, eliminating kernel string copy overhead.
	execB := &pb.ExecveInfo{
		ContextData: &pb.ContextData{
			ThreadGroupId:          101,
			ThreadGroupStartTimeNs: 1010,
			ContainerId:            "test-container",
			ProcessName:            "grep",
		},
		BinaryPath: "/bin/grep",
		Argv:       []string{"grep", "bar"},
		PipeInputProc: &pb.PipeProcInfo{
			ContextData: &pb.ContextData{
				ThreadGroupId:          100,
				ThreadGroupStartTimeNs: 1000,
			},
		},
	}

	eventB := pt.ProcessExecve(ToExecutionEvent(execB))
	if eventB.PipeInputSibling == nil {
		t.Fatalf("got nil, want PipeInputSibling to be resolved from tracker")
	}
	if eventB.PipeInputSibling.BinaryPath != "/bin/cat" {
		t.Errorf("got sibling binary %q, want %q", eventB.PipeInputSibling.BinaryPath, "/bin/cat")
	}
	if len(eventB.PipeInputSibling.Argv) != 2 || eventB.PipeInputSibling.Argv[1] != "foo" {
		t.Errorf("got sibling argv %v, want [cat foo]", eventB.PipeInputSibling.Argv)
	}

	// Simulate TaskExit for process A and verify cleanup.
	pt.ProcessTaskExit(ToTaskExitEvent(&pb.TaskExit{
		ContextData: &pb.ContextData{
			ThreadGroupId:          100,
			ThreadGroupStartTimeNs: 1000,
		},
	}))
	keyA := ProcessKey{ThreadGroupID: 100, ThreadGroupStartTimeNs: 1000}
	if info := pt.Lookup(keyA); info != nil {
		t.Errorf("got %v, want process A to be unregistered after exit", info)
	}
}
