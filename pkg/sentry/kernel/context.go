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
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is the kernel package's type for context.Context.Value keys.
type contextID int

const (
	// CtxCanTrace is a Context.Value key for a function with the same
	// signature and semantics as kernel.Task.CanTrace.
	CtxCanTrace contextID = iota

	// CtxKernel is a Context.Value key for a Kernel.
	CtxKernel

	// CtxPIDNamespace is a Context.Value key for a PIDNamespace.
	CtxPIDNamespace

	// CtxTask is a Context.Value key for a Task.
	CtxTask

	// CtxUTSNamespace is a Context.Value key for a UTSNamespace.
	CtxUTSNamespace

	// CtxIPCNamespace is a Context.Value key for a IPCNamespace.
	CtxIPCNamespace
)

// ContextCanTrace returns true if ctx is permitted to trace t, in the same sense
// as kernel.Task.CanTrace.
func ContextCanTrace(ctx context.Context, t *Task, attach bool) bool {
	if v := ctx.Value(CtxCanTrace); v != nil {
		return v.(func(*Task, bool) bool)(t, attach)
	}
	return false
}

// KernelFromContext returns the Kernel in which ctx is executing, or nil if
// there is no such Kernel.
func KernelFromContext(ctx context.Context) *Kernel {
	if v := ctx.Value(CtxKernel); v != nil {
		return v.(*Kernel)
	}
	return nil
}

// PIDNamespaceFromContext returns the PID namespace in which ctx is executing,
// or nil if there is no such PID namespace.
func PIDNamespaceFromContext(ctx context.Context) *PIDNamespace {
	if v := ctx.Value(CtxPIDNamespace); v != nil {
		return v.(*PIDNamespace)
	}
	return nil
}

// UTSNamespaceFromContext returns the UTS namespace in which ctx is executing,
// or nil if there is no such UTS namespace.
func UTSNamespaceFromContext(ctx context.Context) *UTSNamespace {
	if v := ctx.Value(CtxUTSNamespace); v != nil {
		return v.(*UTSNamespace)
	}
	return nil
}

// IPCNamespaceFromContext returns the IPC namespace in which ctx is executing,
// or nil if there is no such IPC namespace. It takes a reference on the
// namespace.
func IPCNamespaceFromContext(ctx context.Context) *IPCNamespace {
	if v := ctx.Value(CtxIPCNamespace); v != nil {
		return v.(*IPCNamespace)
	}
	return nil
}

// TaskFromContext returns the Task associated with ctx, or nil if there is no
// such Task.
func TaskFromContext(ctx context.Context) *Task {
	if v := ctx.Value(CtxTask); v != nil {
		return v.(*Task)
	}
	return nil
}
