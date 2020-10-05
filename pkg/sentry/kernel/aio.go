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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
)

// AIOCallback is an function that does asynchronous I/O on behalf of a task.
type AIOCallback func(context.Context)

// QueueAIO queues an AIOCallback which will be run asynchronously.
func (t *Task) QueueAIO(cb AIOCallback) {
	ctx := taskAsyncContext{t: t}
	wg := &t.TaskSet().aioGoroutines
	wg.Add(1)
	go func() {
		cb(ctx)
		wg.Done()
	}()
}

type taskAsyncContext struct {
	context.NoopSleeper
	t *Task
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
	return ctx.t.Deadline()
}

// Done implements context.Context.Done.
func (ctx taskAsyncContext) Done() <-chan struct{} {
	return ctx.t.Done()
}

// Err implements context.Context.Err.
func (ctx taskAsyncContext) Err() error {
	return ctx.t.Err()
}

// Value implements context.Context.Value.
func (ctx taskAsyncContext) Value(key interface{}) interface{} {
	return ctx.t.Value(key)
}
