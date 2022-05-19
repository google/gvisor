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

// Package procfs holds utilities for getting procfs information for sandboxed
// processes.
package procfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// ProcessProcfsDump contains the procfs dump for one process.
type ProcessProcfsDump struct {
	// PID is the process ID.
	PID int32 `json:"pid,omitempty"`
	// Exe is the symlink target of /proc/[pid]/exe.
	Exe string `json:"exe,omitempty"`
}

// getMM returns t's MemoryManager. On success, the MemoryManager's users count
// is incremented, and must be decremented by the caller when it is no longer
// in use.
func getMM(t *kernel.Task) *mm.MemoryManager {
	var mm *mm.MemoryManager
	t.WithMuLocked(func(*kernel.Task) {
		mm = t.MemoryManager()
	})
	if mm == nil || !mm.IncUsers() {
		return nil
	}
	return mm
}

func getExecutablePath(ctx context.Context, pid kernel.ThreadID, mm *mm.MemoryManager) string {
	exec := mm.Executable()
	if exec == nil {
		log.Warningf("No executable found for PID %s", pid)
		return ""
	}
	defer exec.DecRef(ctx)

	return exec.PathnameWithDeleted(ctx)
}

// Dump returns a procfs dump for process pid. t must be a task in process pid.
func Dump(t *kernel.Task, pid kernel.ThreadID) (ProcessProcfsDump, error) {
	ctx := t.AsyncContext()

	mm := getMM(t)
	if mm == nil {
		return ProcessProcfsDump{}, fmt.Errorf("no MM found for PID %s", pid)
	}
	defer mm.DecUsers(ctx)

	return ProcessProcfsDump{
		PID: int32(pid),
		Exe: getExecutablePath(ctx, pid, mm),
	}, nil
}
