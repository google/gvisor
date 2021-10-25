// Copyright 2020 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Deadline implements context.Context.Deadline.
func (t *Task) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done implements context.Context.Done.
func (t *Task) Done() <-chan struct{} {
	return nil
}

// Err implements context.Context.Err.
func (t *Task) Err() error {
	return nil
}

// Value implements context.Context.Value.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Value(key interface{}) interface{} {
	// This function is very hot; skip this check outside of +race builds.
	if sync.RaceEnabled {
		t.assertTaskGoroutine()
	}
	return t.contextValue(key, true /* isTaskGoroutine */)
}

func (t *Task) contextValue(key interface{}, isTaskGoroutine bool) interface{} {
	switch key {
	case CtxCanTrace:
		return t.CanTrace
	case CtxKernel:
		return t.k
	case CtxPIDNamespace:
		return t.tg.pidns
	case CtxUTSNamespace:
		if !isTaskGoroutine {
			t.mu.Lock()
			defer t.mu.Unlock()
		}
		return t.utsns
	case CtxIPCNamespace:
		if !isTaskGoroutine {
			t.mu.Lock()
			defer t.mu.Unlock()
		}
		ipcns := t.ipcns
		ipcns.IncRef()
		return ipcns
	case CtxTask:
		return t
	case auth.CtxCredentials:
		return t.creds.Load()
	case context.CtxThreadGroupID:
		return int32(t.tg.ID())
	case fs.CtxRoot:
		if !isTaskGoroutine {
			t.mu.Lock()
			defer t.mu.Unlock()
		}
		return t.fsContext.RootDirectory()
	case vfs.CtxRoot:
		if !isTaskGoroutine {
			t.mu.Lock()
			defer t.mu.Unlock()
		}
		return t.fsContext.RootDirectoryVFS2()
	case vfs.CtxMountNamespace:
		if !isTaskGoroutine {
			t.mu.Lock()
			defer t.mu.Unlock()
		}
		t.mountNamespaceVFS2.IncRef()
		return t.mountNamespaceVFS2
	case fs.CtxDirentCacheLimiter:
		return t.k.DirentCacheLimiter
	case inet.CtxStack:
		return t.NetworkContext()
	case ktime.CtxRealtimeClock:
		return t.k.RealtimeClock()
	case limits.CtxLimits:
		return t.tg.limits
	case linux.CtxSignalNoInfoFunc:
		return func(sig linux.Signal) error {
			return t.SendSignal(SignalInfoNoInfo(sig, t, t))
		}
	case pgalloc.CtxMemoryFile:
		return t.k.mf
	case pgalloc.CtxMemoryFileProvider:
		return t.k
	case platform.CtxPlatform:
		return t.k
	case uniqueid.CtxGlobalUniqueID:
		return t.k.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return t.k
	case uniqueid.CtxInotifyCookie:
		return t.k.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return t.k
	default:
		return nil
	}
}

// taskAsyncContext implements context.Context for a goroutine that performs
// work on behalf of a Task, but is not the task goroutine.
type taskAsyncContext struct {
	context.NoopSleeper

	t *Task
}

// AsyncContext returns a context.Context representing t. The returned
// context.Context is intended for use by goroutines other than t's task
// goroutine; for example, signal delivery to t will not interrupt goroutines
// that are blocking using the returned context.Context.
func (t *Task) AsyncContext() context.Context {
	return taskAsyncContext{t: t}
}

// Debugf implements log.Logger.Debugf.
func (ctx taskAsyncContext) Debugf(format string, v ...interface{}) {
	ctx.t.Debugf(format, v...)
}

// Infof implements log.Logger.Infof.
func (ctx taskAsyncContext) Infof(format string, v ...interface{}) {
	ctx.t.Infof(format, v...)
}

// Warningf implements log.Logger.Warningf.
func (ctx taskAsyncContext) Warningf(format string, v ...interface{}) {
	ctx.t.Warningf(format, v...)
}

// IsLogging implements log.Logger.IsLogging.
func (ctx taskAsyncContext) IsLogging(level log.Level) bool {
	return ctx.t.IsLogging(level)
}

// Deadline implements context.Context.Deadline.
func (ctx taskAsyncContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done implements context.Context.Done.
func (ctx taskAsyncContext) Done() <-chan struct{} {
	return nil
}

// Err implements context.Context.Err.
func (ctx taskAsyncContext) Err() error {
	return nil
}

// Value implements context.Context.Value.
func (ctx taskAsyncContext) Value(key interface{}) interface{} {
	return ctx.t.contextValue(key, false /* isTaskGoroutine */)
}
