// Copyright 2018 Google LLC
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

// Package context defines the sentry's Context type.
package context

import (
	"gvisor.googlesource.com/gvisor/pkg/amutex"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

type contextID int

// Globally accessible values from a context. These keys are defined in the
// context package to resolve dependency cycles by not requiring the caller to
// import packages usually required to get these information.
const (
	// CtxThreadGroupID is the current thread group ID when a context represents
	// a task context. The value is represented as an int32.
	CtxThreadGroupID contextID = iota
)

// ThreadGroupIDFromContext returns the current thread group ID when ctx
// represents a task context.
func ThreadGroupIDFromContext(ctx Context) (tgid int32, ok bool) {
	if tgid := ctx.Value(CtxThreadGroupID); tgid != nil {
		return tgid.(int32), true
	}
	return 0, false
}

// A Context represents a thread of execution (hereafter "goroutine" to reflect
// Go idiosyncrasy). It carries state associated with the goroutine across API
// boundaries.
//
// While Context exists for essentially the same reasons as Go's standard
// context.Context, the standard type represents the state of an operation
// rather than that of a goroutine. This is a critical distinction:
//
// - Unlike context.Context, which "may be passed to functions running in
// different goroutines", it is *not safe* to use the same Context in multiple
// concurrent goroutines.
//
// - It is *not safe* to retain a Context passed to a function beyond the scope
// of that function call.
//
// In both cases, values extracted from the Context should be used instead.
type Context interface {
	log.Logger
	amutex.Sleeper

	// UninterruptibleSleepStart indicates the beginning of an uninterruptible
	// sleep state (equivalent to Linux's TASK_UNINTERRUPTIBLE). If deactivate
	// is true and the Context represents a Task, the Task's AddressSpace is
	// deactivated.
	UninterruptibleSleepStart(deactivate bool)

	// UninterruptibleSleepFinish indicates the end of an uninterruptible sleep
	// state that was begun by a previous call to UninterruptibleSleepStart. If
	// activate is true and the Context represents a Task, the Task's
	// AddressSpace is activated. Normally activate is the same value as the
	// deactivate parameter passed to UninterruptibleSleepStart.
	UninterruptibleSleepFinish(activate bool)

	// Value returns the value associated with this Context for key, or nil if
	// no value is associated with key. Successive calls to Value with the same
	// key returns the same result.
	//
	// A key identifies a specific value in a Context. Functions that wish to
	// retrieve values from Context typically allocate a key in a global
	// variable then use that key as the argument to Context.Value. A key can
	// be any type that supports equality; packages should define keys as an
	// unexported type to avoid collisions.
	Value(key interface{}) interface{}
}

type logContext struct {
	log.Logger
	NoopSleeper
}

// Value implements Context.Value.
func (logContext) Value(key interface{}) interface{} {
	return nil
}

// NoopSleeper is a noop implementation of amutex.Sleeper and
// Context.UninterruptibleSleep* methods for anonymous embedding in other types
// that do not want to notify kernel.Task about sleeps.
type NoopSleeper struct {
	amutex.NoopSleeper
}

// UninterruptibleSleepStart does nothing.
func (NoopSleeper) UninterruptibleSleepStart(bool) {}

// UninterruptibleSleepFinish does nothing.
func (NoopSleeper) UninterruptibleSleepFinish(bool) {}

// bgContext is the context returned by context.Background.
var bgContext = &logContext{Logger: log.Log()}

// Background returns an empty context using the default logger.
//
// Users should be wary of using a Background context. Please tag any use with
// FIXME and a note to remove this use.
//
// Generally, one should use the Task as their context when available, or avoid
// having to use a context in places where a Task is unavailable.
//
// Using a Background context for tests is fine, as long as no values are
// needed from the context in the tested code paths.
func Background() Context {
	return bgContext
}
