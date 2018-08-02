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

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// TaskResources is the subset of a task's data provided by its creator that is
// not provided by the loader.
type TaskResources struct {
	// SignalMask is the set of signals whose delivery is currently blocked.
	//
	// FIXME: Determine if we also need RealSignalMask
	SignalMask linux.SignalSet

	// FSContext is the filesystem context.
	*FSContext

	// FDMap provides access to files to the task.
	*FDMap

	// Tracks abstract sockets that are in use.
	AbstractSockets *AbstractSocketNamespace
}

// newTaskResources returns a new TaskResources, taking an additional reference
// on fdm.
func newTaskResources(fdm *FDMap, fc *FSContext) *TaskResources {
	fdm.IncRef()
	return &TaskResources{
		FDMap:           fdm,
		FSContext:       fc,
		AbstractSockets: NewAbstractSocketNamespace(),
	}
}

// release releases all resources held by the TaskResources. release is called
// by the task when it exits.
func (tr *TaskResources) release() {
	tr.FDMap.DecRef()
	tr.FDMap = nil
	tr.FSContext.DecRef()
	tr.FSContext = nil
	tr.AbstractSockets = nil
}

// Fork returns a duplicate of tr.
//
// FIXME: Preconditions: When tr is owned by a Task, that task's
// signal mutex must be locked, or Fork must be called by the task's goroutine.
func (tr *TaskResources) Fork(shareFiles bool, shareFSContext bool) *TaskResources {
	var fdmap *FDMap
	if shareFiles {
		fdmap = tr.FDMap
		fdmap.IncRef()
	} else {
		fdmap = tr.FDMap.Fork()
	}

	var fsc *FSContext
	if shareFSContext {
		fsc = tr.FSContext
		fsc.IncRef()
	} else {
		fsc = tr.FSContext.Fork()
	}

	return &TaskResources{
		SignalMask:      tr.SignalMask,
		FDMap:           fdmap,
		FSContext:       fsc,
		AbstractSockets: tr.AbstractSockets,
	}
}

// FDMap returns t's FDMap.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) FDMap() *FDMap {
	return t.tr.FDMap
}

// FSContext returns t's FSContext.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) FSContext() *FSContext {
	return t.tr.FSContext
}

// MountNamespace returns t's MountNamespace. MountNamespace does not take an additional
// reference on the returned MountNamespace.
func (t *Task) MountNamespace() *fs.MountNamespace {
	return t.k.mounts
}

// AbstractSockets returns t's AbstractSocketNamespace.
func (t *Task) AbstractSockets() *AbstractSocketNamespace {
	return t.tr.AbstractSockets
}

// IsChrooted returns true if the root directory of t's FSContext is not the
// root directory of t's MountNamespace.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) IsChrooted() bool {
	realRoot := t.k.mounts.Root()
	defer realRoot.DecRef()
	root := t.tr.FSContext.RootDirectory()
	if root != nil {
		defer root.DecRef()
	}
	return root != realRoot
}
