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
	"bytes"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// ProcessProcfsDump contains the procfs dump for one process.
type ProcessProcfsDump struct {
	// PID is the process ID.
	PID int32 `json:"pid,omitempty"`
	// Exe is the symlink target of /proc/[pid]/exe.
	Exe string `json:"exe,omitempty"`
	// Args is /proc/[pid]/cmdline split into an array.
	Args []string `json:"args,omitempty"`
	// Env is /proc/[pid]/environ split into an array.
	Env []string `json:"env,omitempty"`
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

func getMetadataArray(ctx context.Context, pid kernel.ThreadID, mm *mm.MemoryManager, metaType proc.MetadataType) []string {
	buf := bytes.Buffer{}
	if err := proc.GetMetadata(ctx, mm, &buf, metaType); err != nil {
		log.Warningf("failed to get %v metadata for PID %s: %v", metaType, pid, err)
		return nil
	}
	// As per proc(5), /proc/[pid]/cmdline may have "a further null byte after
	// the last string". Similarly, for /proc/[pid]/environ "there may be a null
	// byte at the end". So trim off the last null byte if it exists.
	return strings.Split(strings.TrimSuffix(buf.String(), "\000"), "\000")
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
		PID:  int32(pid),
		Exe:  getExecutablePath(ctx, pid, mm),
		Args: getMetadataArray(ctx, pid, mm, proc.Cmdline),
		Env:  getMetadataArray(ctx, pid, mm, proc.Environ),
	}, nil
}
