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

// ProcessTracker can be used by a trace consumer to track historical process metadata (PID, start
// time, binary path, argv, and env) and automatically enriches ExecveInfo events with sibling
// process information (PipeInputSibling and PipeOutputSibling) when processes are connected via
// stdin or stdout pipes.
//
// Usage:
//
//	// Initialize a ProcessTracker in your monitoring daemon:
//	pt := scsdk.NewProcessTracker()
//
//	// Whenever a protobuf message arrives (from Unix socket, gRPC, or file):
//	switch msg := protoMsg.(type) {
//	case *pb.ExecveInfo:
//		// Map the raw protobuf to a SDK event:
//		execEvent := scsdk.ToExecutionEvent(msg)
//		// ProcessExecve updates the tracker table and returns an EnrichedExecveEvent
//		// where PipeInputSibling and PipeOutputSibling are automatically resolved.
//		enriched := pt.ProcessExecve(execEvent)
//		fmt.Printf("Process executed: %s (PID %d, Argv: %v)\n",
//			enriched.Process.BinaryPath, enriched.Process.Key.ThreadGroupID, enriched.Process.Argv)
//
//		if sib := enriched.PipeInputSibling; sib != nil {
//			fmt.Printf("  <- Piped input from sibling: %s (PID %d, Argv: %v)\n",
//				sib.BinaryPath, sib.Key.ThreadGroupID, sib.Argv)
//		}
//		if sib := enriched.PipeOutputSibling; sib != nil {
//			fmt.Printf("  -> Piped output to sibling: %s (PID %d, Argv: %v)\n",
//				sib.BinaryPath, sib.Key.ThreadGroupID, sib.Argv)
//		}
//
//	case *pb.TaskExit:
//		exitEvent := scsdk.ToTaskExitEvent(msg)
//		// ProcessTaskExit cleans up tracked state when a thread group exits.
//		pt.ProcessTaskExit(exitEvent)
//	}

package scsdk

import (
	"sync"
)

// ProcessKey uniquely identifies a task/thread-group across time, safe against PID recycling.
type ProcessKey struct {
	ThreadGroupID          int32
	ThreadGroupStartTimeNs int64
}

// ProcessInfo contains tracked state for a process inside a gVisor sandbox.
type ProcessInfo struct {
	Key                 ProcessKey
	ContainerID         string
	ProcessName         string
	BinaryPath          string
	Argv                []string
	Env                 []string
	ParentThreadGroupID int32
}

// EnrichedExecveEvent contains the ExecveInfo protobuf event and automatically resolved
// sibling process information for stdin/stdout pipes.
//
// By decoupling string storage from the PipeProcInfo proto message,
// PipeInputSibling and PipeOutputSibling provide full binary/argv details without
// kernel-side string copying overhead.
type EnrichedExecveEvent struct {
	Event             *ExecutionEvent
	Process           *ProcessInfo
	PipeInputSibling  *ProcessInfo
	PipeOutputSibling *ProcessInfo
}

// ProcessTracker manages the lifecycle of process metadata across Seccheck events.
type ProcessTracker struct {
	mu        sync.RWMutex
	processes map[ProcessKey]*ProcessInfo
}

// NewProcessTracker creates an initialized ProcessTracker.
func NewProcessTracker() *ProcessTracker {
	return &ProcessTracker{
		processes: make(map[ProcessKey]*ProcessInfo),
	}
}

// Lookup returns the ProcessInfo matching key, or nil if untracked.
func (pt *ProcessTracker) Lookup(key ProcessKey) *ProcessInfo {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.processes[key]
}

// LookupFromContext creates a ProcessKey from a ProcessContext and returns the tracked process.
func (pt *ProcessTracker) LookupFromContext(ctx ProcessContext) *ProcessInfo {
	key := ProcessKey{
		ThreadGroupID:          ctx.ThreadGroupID,
		ThreadGroupStartTimeNs: ctx.ThreadGroupStartTimeNs,
	}
	return pt.Lookup(key)
}

// RegisterOrUpdate records process metadata from an ExecutionEvent.
func (pt *ProcessTracker) RegisterOrUpdate(execve *ExecutionEvent) *ProcessInfo {
	key := ProcessKey{
		ThreadGroupID:          execve.Context.ThreadGroupID,
		ThreadGroupStartTimeNs: execve.Context.ThreadGroupStartTimeNs,
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	info, exists := pt.processes[key]
	if !exists {
		info = &ProcessInfo{Key: key}
		pt.processes[key] = info
	}
	info.ContainerID = execve.Context.ContainerID
	info.ProcessName = execve.Context.ProcessName
	info.ParentThreadGroupID = execve.Context.ParentThreadGroupID
	info.BinaryPath = execve.BinaryPath
	info.Argv = append([]string(nil), execve.Argv...)
	info.Env = append([]string(nil), execve.Env...)
	return info
}

// Unregister deletes process metadata upon task exit given its context.
func (pt *ProcessTracker) Unregister(ctx ProcessContext) {
	key := ProcessKey{
		ThreadGroupID:          ctx.ThreadGroupID,
		ThreadGroupStartTimeNs: ctx.ThreadGroupStartTimeNs,
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.processes, key)
}

// ProcessExecve processes an ExecutionEvent, updates state, and returns an
// enriched event.
//
// Because PipeProcInfo only transports ContextData, we resolve full sibling
// process info (binary, argv) by querying our ProcessTracker using the TGID and StartTime.
func (pt *ProcessTracker) ProcessExecve(execve *ExecutionEvent) *EnrichedExecveEvent {
	if execve == nil {
		return nil
	}

	// Update our tracker with the current process's binary, argv, and env.
	currentProc := pt.RegisterOrUpdate(execve)

	// Resolve sibling process information via ContextData keys from PipeInputProc/PipeOutputProc.
	var inSibling, outSibling *ProcessInfo
	if execve.PipeInputSiblingContext != nil {
		inSibling = pt.LookupFromContext(*execve.PipeInputSiblingContext)
	}
	if execve.PipeOutputSiblingContext != nil {
		outSibling = pt.LookupFromContext(*execve.PipeOutputSiblingContext)
	}

	return &EnrichedExecveEvent{
		Event:             execve,
		Process:           currentProc,
		PipeInputSibling:  inSibling,
		PipeOutputSibling: outSibling,
	}
}

// ProcessTaskExit processes an TaskExitEvent and cleans up tracker state.
func (pt *ProcessTracker) ProcessTaskExit(exit *TaskExitEvent) {
	if exit != nil {
		pt.Unregister(exit.Context)
	}
}
