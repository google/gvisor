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
	pointspb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// ProcessContext uniquely identifies a thread-group/process and its environment
// at the time of an event.
type ProcessContext struct {
	ThreadGroupID          int32
	ThreadGroupStartTimeNs int64
	ContainerID            string
	ProcessName            string
	ParentThreadGroupID    int32
}

// ExecutionEvent provides a Go presentation of the ExecveInfo protobuf.
type ExecutionEvent struct {
	Context    ProcessContext
	BinaryPath string
	Argv       []string
	Env        []string

	// Sibling pipes for enriching the event.
	PipeInputSiblingContext  *ProcessContext
	PipeOutputSiblingContext *ProcessContext
}

// ToProcessContext translates a raw ContextData protobuf into the ProcessContext struct.
func ToProcessContext(ctx *pointspb.ContextData) ProcessContext {
	if ctx == nil {
		return ProcessContext{}
	}
	return ProcessContext{
		ThreadGroupID:          ctx.GetThreadGroupId(),
		ThreadGroupStartTimeNs: ctx.GetThreadGroupStartTimeNs(),
		ContainerID:            ctx.GetContainerId(),
		ProcessName:            ctx.GetProcessName(),
		ParentThreadGroupID:    ctx.GetParentThreadGroupId(),
	}
}

// ToProcessContextPtr translates a raw ContextData protobuf into the ProcessContext struct,
// returning nil if the input is nil.
func ToProcessContextPtr(ctx *pointspb.ContextData) *ProcessContext {
	if ctx == nil {
		return nil
	}
	c := ToProcessContext(ctx)
	return &c
}

// ToExecutionEvent translates a raw ExecveInfo protobuf into the ExecutionEvent struct.
// It handles all the defensive nil-checking so SDK consumers don't have to.
func ToExecutionEvent(execve *pointspb.ExecveInfo) *ExecutionEvent {
	if execve == nil {
		return nil
	}

	ev := &ExecutionEvent{
		Context:    ToProcessContext(execve.GetContextData()),
		BinaryPath: execve.GetBinaryPath(),
	}

	if len(execve.GetArgv()) > 0 {
		ev.Argv = append([]string(nil), execve.GetArgv()...)
	}
	if len(execve.GetEnv()) > 0 {
		ev.Env = append([]string(nil), execve.GetEnv()...)
	}

	if pipeIn := execve.GetPipeInputProc(); pipeIn != nil {
		ev.PipeInputSiblingContext = ToProcessContextPtr(pipeIn.GetContextData())
	}
	if pipeOut := execve.GetPipeOutputProc(); pipeOut != nil {
		ev.PipeOutputSiblingContext = ToProcessContextPtr(pipeOut.GetContextData())
	}

	return ev
}

// TaskExitEvent provides a Go presentation of the TaskExit protobuf.
type TaskExitEvent struct {
	Context    ProcessContext
	ExitStatus int32
}

// ToTaskExitEvent translates a raw TaskExit protobuf into the SDK struct.
func ToTaskExitEvent(exit *pointspb.TaskExit) *TaskExitEvent {
	if exit == nil {
		return nil
	}
	return &TaskExitEvent{
		Context:    ToProcessContext(exit.GetContextData()),
		ExitStatus: exit.GetExitStatus(),
	}
}
