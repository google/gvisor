// Copyright 2022 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func getTaskCurrentWorkingDirectory(t *Task) string {
	// Grab the filesystem context first since it needs tasks.mu to be locked.
	// It's safe to unlock and use the values obtained here as long as there's
	// no way to modify root and wd from a separate task.
	t.k.tasks.mu.RLock()
	root := t.FSContext().RootDirectory()
	wd := t.FSContext().WorkingDirectory()
	t.k.tasks.mu.RUnlock()

	// Perform VFS operations outside of task mutex to avoid circular locking with
	// filesystem mutexes.
	var cwd string
	if root.Ok() {
		defer root.DecRef(t)
		if wd.Ok() {
			defer wd.DecRef(t)
			vfsObj := root.Mount().Filesystem().VirtualFilesystem()
			cwd, _ = vfsObj.PathnameWithDeleted(t, root, wd)
		}
	}
	return cwd
}

// LoadSeccheckData sets info from the task based on mask.
func LoadSeccheckData(t *Task, mask seccheck.FieldMask, info *pb.ContextData) {
	var cwd string
	if mask.Contains(seccheck.FieldCtxtCwd) {
		cwd = getTaskCurrentWorkingDirectory(t)
	}
	t.k.tasks.mu.RLock()
	defer t.k.tasks.mu.RUnlock()
	LoadSeccheckDataLocked(t, mask, info, cwd)
}

// LoadSeccheckDataLocked sets info from the task based on mask.
//
// Preconditions: The TaskSet mutex must be locked.
func LoadSeccheckDataLocked(t *Task, mask seccheck.FieldMask, info *pb.ContextData, cwd string) {
	if mask.Contains(seccheck.FieldCtxtTime) {
		info.TimeNs = t.k.RealtimeClock().Now().Nanoseconds()
	}
	if mask.Contains(seccheck.FieldCtxtThreadID) {
		info.ThreadId = int32(t.k.tasks.Root.tids[t])
	}
	if mask.Contains(seccheck.FieldCtxtThreadStartTime) {
		info.ThreadStartTimeNs = t.startTime.Nanoseconds()
	}
	if mask.Contains(seccheck.FieldCtxtThreadGroupID) {
		info.ThreadGroupId = int32(t.k.tasks.Root.tgids[t.tg])
	}
	if mask.Contains(seccheck.FieldCtxtThreadGroupStartTime) {
		info.ThreadGroupStartTimeNs = t.tg.leader.startTime.Nanoseconds()
	}
	if mask.Contains(seccheck.FieldCtxtContainerID) {
		info.ContainerId = t.tg.leader.ContainerID()
	}
	if mask.Contains(seccheck.FieldCtxtCwd) {
		info.Cwd = cwd
	}
	if mask.Contains(seccheck.FieldCtxtProcessName) {
		info.ProcessName = t.Name()
	}
	t.Credentials().LoadSeccheckData(mask, info)
}
