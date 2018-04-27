// Copyright 2018 Google Inc.
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

// This file implements task stops, which represent the equivalent of Linux's
// uninterruptible sleep states in a way that is compatible with save/restore.
// Task stops comprise both internal stops (which form part of the task's
// "normal" control flow) and external stops (which do not); see README.md for
// details.
//
// There are multiple interfaces for interacting with stops because there are
// multiple cases to consider:
//
// - A task goroutine can begin a stop on its associated task (e.g. a
// vfork() syscall stopping the calling task until the child task releases its
// MM). In this case, calling Task.interrupt is both unnecessary (the task
// goroutine obviously cannot be blocked in Task.block or executing application
// code) and undesirable (as it may spuriously interrupt a in-progress
// syscall).
//
// Beginning internal stops in this case is implemented by
// Task.beginInternalStop / Task.beginInternalStopLocked. As of this writing,
// there are no instances of this case that begin external stops, except for
// autosave; however, autosave terminates the sentry without ending the
// external stop, so the spurious interrupt is moot.
//
// - An arbitrary goroutine can begin a stop on an unrelated task (e.g. all
// tasks being stopped in preparation for state checkpointing). If the task
// goroutine may be in Task.block or executing application code, it must be
// interrupted by Task.interrupt for it to actually enter the stop; since,
// strictly speaking, we have no way of determining this, we call
// Task.interrupt unconditionally.
//
// Beginning external stops in this case is implemented by
// Task.BeginExternalStop. As of this writing, there are no instances of this
// case that begin internal stops.
//
// - An arbitrary goroutine can end a stop on an unrelated task (e.g. an
// exiting task resuming a sibling task that has been blocked in an execve()
// syscall waiting for other tasks to exit). In this case, Task.endStopCond
// must be notified to kick the task goroutine out of Task.doStop.
//
// Ending internal stops in this case is implemented by
// Task.endInternalStopLocked. Ending external stops in this case is
// implemented by Task.EndExternalStop.
//
// - Hypothetically, a task goroutine can end an internal stop on its
// associated task. As of this writing, there are no instances of this case.
// However, any instances of this case could still use the above functions,
// since notifying Task.endStopCond would be unnecessary but harmless.

import (
	"fmt"
	"sync/atomic"
)

// A TaskStop is a condition visible to the task control flow graph that
// prevents a task goroutine from running or exiting, i.e. an internal stop.
//
// NOTE: Most TaskStops don't contain any data; they're
// distinguished by their type. The obvious way to implement such a TaskStop
// is:
//
//     type groupStop struct{}
//     func (groupStop) Killable() bool { return true }
//     ...
//     t.beginInternalStop(groupStop{})
//
// However, this doesn't work because the state package can't serialize values,
// only pointers. Furthermore, the correctness of save/restore depends on the
// ability to pass a TaskStop to endInternalStop that will compare equal to the
// TaskStop that was passed to beginInternalStop, even if a save/restore cycle
// occurred between the two. As a result, the current idiom is to always use a
// typecast nil for data-free TaskStops:
//
//     type groupStop struct{}
//     func (*groupStop) Killable() bool { return true }
//     ...
//     t.beginInternalStop((*groupStop)(nil))
//
// This is pretty gross, but the alternatives seem grosser.
type TaskStop interface {
	// Killable returns true if Task.Kill should end the stop prematurely.
	// Killable is analogous to Linux's TASK_WAKEKILL.
	Killable() bool
}

// beginInternalStop indicates the start of an internal stop that applies to t.
//
// Preconditions: The task must not already be in an internal stop (i.e. t.stop
// == nil). The caller must be running on the task goroutine.
func (t *Task) beginInternalStop(s TaskStop) {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.beginInternalStopLocked(s)
}

// Preconditions: The signal mutex must be locked. All preconditions for
// Task.beginInternalStop also apply.
func (t *Task) beginInternalStopLocked(s TaskStop) {
	if t.stop != nil {
		panic(fmt.Sprintf("Attempting to enter internal stop %#v when already in internal stop %#v", s, t.stop))
	}
	t.Debugf("Entering internal stop %#v", s)
	t.stop = s
	t.beginStopLocked()
}

// endInternalStopLocked indicates the end of an internal stop that applies to
// t. endInternalStopLocked does not wait for the task to resume.
//
// The caller is responsible for ensuring that the internal stop they expect
// actually applies to t; this requires holding the signal mutex which protects
// t.stop, which is why there is no endInternalStop that locks the signal mutex
// for you.
//
// Preconditions: The signal mutex must be locked. The task must be in an
// internal stop (i.e. t.stop != nil).
func (t *Task) endInternalStopLocked() {
	if t.stop == nil {
		panic("Attempting to leave non-existent internal stop")
	}
	t.Debugf("Leaving internal stop %#v", t.stop)
	t.stop = nil
	t.endStopLocked()
}

// BeginExternalStop indicates the start of an external stop that applies to t.
// BeginExternalStop does not wait for t's task goroutine to stop.
func (t *Task) BeginExternalStop() {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.beginStopLocked()
	t.interrupt()
}

// EndExternalStop indicates the end of an external stop started by a previous
// call to Task.BeginExternalStop. EndExternalStop does not wait for t's task
// goroutine to resume.
func (t *Task) EndExternalStop() {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.endStopLocked()
}

// beginStopLocked increments t.stopCount to indicate that a new internal or
// external stop applies to t.
//
// Preconditions: The signal mutex must be locked.
func (t *Task) beginStopLocked() {
	if newval := atomic.AddInt32(&t.stopCount, 1); newval <= 0 {
		// Most likely overflow.
		panic(fmt.Sprintf("Invalid stopCount: %d", newval))
	}
}

// endStopLocked decerements t.stopCount to indicate that an existing internal
// or external stop no longer applies to t.
//
// Preconditions: The signal mutex must be locked.
func (t *Task) endStopLocked() {
	if newval := atomic.AddInt32(&t.stopCount, -1); newval < 0 {
		panic(fmt.Sprintf("Invalid stopCount: %d", newval))
	} else if newval == 0 {
		t.endStopCond.Signal()
	}
}

// BeginExternalStop indicates the start of an external stop that applies to
// all current and future tasks in ts. BeginExternalStop does not wait for
// task goroutines to stop.
func (ts *TaskSet) BeginExternalStop() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.stopCount++
	if ts.stopCount <= 0 {
		panic(fmt.Sprintf("Invalid stopCount: %d", ts.stopCount))
	}
	if ts.Root == nil {
		return
	}
	for t := range ts.Root.tids {
		t.tg.signalHandlers.mu.Lock()
		t.beginStopLocked()
		t.tg.signalHandlers.mu.Unlock()
		t.interrupt()
	}
}

// EndExternalStop indicates the end of an external stop started by a previous
// call to TaskSet.BeginExternalStop. EndExternalStop does not wait for task
// goroutines to resume.
func (ts *TaskSet) EndExternalStop() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.stopCount--
	if ts.stopCount < 0 {
		panic(fmt.Sprintf("Invalid stopCount: %d", ts.stopCount))
	}
	if ts.Root == nil {
		return
	}
	for t := range ts.Root.tids {
		t.tg.signalHandlers.mu.Lock()
		t.endStopLocked()
		t.tg.signalHandlers.mu.Unlock()
	}
}
