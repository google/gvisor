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
//	// 1. Initialize a ProcessTracker in your monitoring daemon:
//	pt := scsdk.NewProcessTracker()
//
//	// 2. Whenever a protobuf message arrives (from Unix socket, gRPC, or file):
//	switch msg := protoMsg.(type) {
//	case *pb.ExecveInfo:
//		// ProcessExecve updates the tracker table and returns an EnrichedExecveEvent
//		// where PipeInputSibling and PipeOutputSibling are automatically resolved.
//		enriched := pt.ProcessExecve(msg)
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
//		// ProcessTaskExit cleans up tracked state when a thread group exits.
//		pt.ProcessTaskExit(msg)
//	}

// Package scsdk provides integration utilities for gVisor SecCheck consumers.
package scsdk

import (
	"sync"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
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
	Raw               *pb.ExecveInfo
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

// LookupFromContext creates a ProcessKey from a ContextData and returns the tracked process.
func (pt *ProcessTracker) LookupFromContext(ctx *pb.ContextData) *ProcessInfo {
	if ctx == nil {
		return nil
	}
	key := ProcessKey{
		ThreadGroupID:          ctx.GetThreadGroupId(),
		ThreadGroupStartTimeNs: ctx.GetThreadGroupStartTimeNs(),
	}
	return pt.Lookup(key)
}

// RegisterOrUpdate records process metadata from an ExecveInfo event.
func (pt *ProcessTracker) RegisterOrUpdate(execve *pb.ExecveInfo) *ProcessInfo {
	ctx := execve.GetContextData()
	if ctx == nil {
		return nil
	}
	key := ProcessKey{
		ThreadGroupID:          ctx.GetThreadGroupId(),
		ThreadGroupStartTimeNs: ctx.GetThreadGroupStartTimeNs(),
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	info, exists := pt.processes[key]
	if !exists {
		info = &ProcessInfo{Key: key}
		pt.processes[key] = info
	}
	info.ContainerID = ctx.GetContainerId()
	info.ProcessName = ctx.GetProcessName()
	info.ParentThreadGroupID = ctx.GetParentThreadGroupId()
	info.BinaryPath = execve.GetBinaryPath()
	info.Argv = append([]string(nil), execve.GetArgv()...)
	info.Env = append([]string(nil), execve.GetEnv()...)
	return info
}

// Unregister deletes process metadata upon task exit.
func (pt *ProcessTracker) Unregister(ctx *pb.ContextData) {
	if ctx == nil {
		return
	}
	key := ProcessKey{
		ThreadGroupID:          ctx.GetThreadGroupId(),
		ThreadGroupStartTimeNs: ctx.GetThreadGroupStartTimeNs(),
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.processes, key)
}

// ProcessExecve processes a raw ExecveInfo protobuf message, updates state, and returns an
// enriched event.
//
// Because PipeProcInfo only transports ContextData, we resolve full sibling
// process info (binary, argv) by querying our ProcessTracker using the TGID and StartTime.
func (pt *ProcessTracker) ProcessExecve(execve *pb.ExecveInfo) *EnrichedExecveEvent {
	// 1. Update our tracker with the current process's binary, argv, and env.
	currentProc := pt.RegisterOrUpdate(execve)

	// 2. Resolve sibling process information via ContextData keys from PipeInputProc/PipeOutputProc.
	var inSibling, outSibling *ProcessInfo
	if pipeIn := execve.GetPipeInputProc(); pipeIn != nil {
		inSibling = pt.LookupFromContext(pipeIn.GetContextData())
	}
	if pipeOut := execve.GetPipeOutputProc(); pipeOut != nil {
		outSibling = pt.LookupFromContext(pipeOut.GetContextData())
	}

	return &EnrichedExecveEvent{
		Raw:               execve,
		Process:           currentProc,
		PipeInputSibling:  inSibling,
		PipeOutputSibling: outSibling,
	}
}

// ProcessTaskExit processes a raw TaskExit protobuf message and cleans up tracker state.
func (pt *ProcessTracker) ProcessTaskExit(exit *pb.TaskExit) {
	pt.Unregister(exit.GetContextData())
}
