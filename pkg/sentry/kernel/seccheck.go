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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func LoadSeccheckInfoFromContext(ctx context.Context, req seccheck.FieldMask, info *pb.Common) {
	t := TaskFromContext(ctx)
	if t != nil {
		t.k.tasks.mu.Lock()
		defer t.k.tasks.mu.Unlock()
	}
	LoadSeccheckInfoLocked(t, req, info)
}

func LoadSeccheckInfo(t *Task, req seccheck.FieldMask, info *pb.Common) {
	t.k.tasks.mu.RLock()
	defer t.k.tasks.mu.RUnlock()
	LoadSeccheckInfoLocked(t, req, info)
}

// LoadSeccheckInfoLocked ...
//
// Preconditions: The TaskSet mutex must be locked.
func LoadSeccheckInfoLocked(t *Task, req seccheck.FieldMask, info *pb.Common) {
	if req.Contains(seccheck.FieldCommonTime) {
		info.TimeNs = t.k.RealtimeClock().Now().Nanoseconds()
	}

	if t == nil {
		return
	}
	if req.Contains(seccheck.FieldCommonThreadID) {
		info.ThreadId = int32(t.k.tasks.Root.tids[t])
	}
	if req.Contains(seccheck.FieldCommonThreadStartTime) {
		info.ThreadStartTimeNs = t.startTime.Nanoseconds()
	}
	if req.Contains(seccheck.FieldCommonThreadGroupID) {
		info.ThreadGroupId = int32(t.k.tasks.Root.tgids[t.tg])
	}
	if req.Contains(seccheck.FieldCommonThreadGroupStartTime) {
		info.ThreadGroupStartTimeNs = t.tg.leader.startTime.Nanoseconds()
	}
	if req.Contains(seccheck.FieldCommonContainerID) {
		info.ContainerId = t.tg.leader.ContainerID()
	}
	if req.Contains(seccheck.FieldCommonCwd) {
		root := t.FSContext().RootDirectoryVFS2()
		defer root.DecRef(t)
		wd := t.FSContext().WorkingDirectoryVFS2()
		defer wd.DecRef(t)
		vfsObj := root.Mount().Filesystem().VirtualFilesystem()
		info.Cwd, _ = vfsObj.PathnameWithDeleted(t, root, wd)
	}
	if req.Contains(seccheck.FieldCommonProcessName) {
		info.ProcessName = t.Name()
	}
	t.Credentials().LoadSeccheckInfo(req, info)
}
